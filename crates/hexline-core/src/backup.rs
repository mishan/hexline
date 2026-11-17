//! A held identity's backups at its registrar (`identity-registrar.md`
//! §9, design §2.2): the identity sealed by a passphrase the person
//! chooses, put, changed by putting again, and removed; and a new
//! recovery code, shown, typed back, and put in place of the one before.
//! Each is signed by the identity, so each is asked for with its seed, and
//! the seed is wiped after.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hl_identity::envelope::{Kind, Secret};
use hl_identity::{EnvelopePut, IdentityKey, KeyEnvelope, RecoveryCode};
use hxng_client::auth;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::restore::{b64, discovered, endpoint, now, registrar_base, SecretKind};
use crate::CoreError;

/// Puts `identity_seed`'s identity at `registrar` sealed by `passphrase`,
/// in place of any passphrase backup before. Refused `bad_passphrase` for
/// one shorter than [`MIN_PASSPHRASE`], before anything is asked; as the
/// registrar refuses
/// (`not_registered`, `frozen`, `revoked`), and `no_envelopes` where it
/// keeps none.
#[uniffi::export(async_runtime = "tokio")]
pub async fn backup_passphrase(
    identity_seed: Vec<u8>,
    registrar: String,
    passphrase: String,
) -> Result<(), CoreError> {
    let (seed, passphrase) = (Zeroizing::new(identity_seed), Zeroizing::new(passphrase));
    if passphrase.trim().chars().count() < MIN_PASSPHRASE {
        return Err(refused("bad_passphrase"));
    }
    let id = identity(&seed)?;
    let turn = Turn::begin(&id);
    Aborting(crate::connection::RUNTIME.spawn(async move {
        let (envelope, keys) = tokio::task::block_in_place(|| {
            KeyEnvelope::seal(&id, &Secret::Passphrase(&passphrase))
        })
        .map_err(|e| protocol(&format!("sealing: {e}")))?;
        drop(passphrase);
        put(
            &registrar,
            &turn,
            |host, time| EnvelopePut::store(&id, host, time, &envelope, &keys),
            "stored",
        )
        .await
    }))
    .await
}

/// Removes `identity_seed`'s backup of `kind` at `registrar`: done as well
/// if there was none.
#[uniffi::export(async_runtime = "tokio")]
pub async fn backup_delete(
    identity_seed: Vec<u8>,
    registrar: String,
    kind: SecretKind,
) -> Result<(), CoreError> {
    let id = identity(&Zeroizing::new(identity_seed))?;
    let turn = Turn::begin(&id);
    Aborting(crate::connection::RUNTIME.spawn(async move {
        let kind = match kind {
            SecretKind::Passphrase => Kind::Passphrase,
            SecretKind::RecoveryCode => Kind::RecoveryCode,
        };
        put(
            &registrar,
            &turn,
            |host, time| EnvelopePut::delete(&id, host, kind, time),
            "deleted",
        )
        .await
    }))
    .await
}

/// The shortest passphrase a backup is sealed by, in characters: what an
/// envelope fetched by its handle alone is guessed against.
pub const MIN_PASSPHRASE: usize = 10;

/// [`MIN_PASSPHRASE`], for the app to say and check before the key is asked for.
#[uniffi::export]
pub fn min_passphrase() -> u32 {
    MIN_PASSPHRASE as u32
}

/// A new recovery code for a held identity: kept here alone until the
/// person has typed it back, then put at the registrar in place of the one
/// before, which opens nothing after. Dropped, or put, it wipes the code.
#[derive(uniffi::Object)]
pub struct RecoveryCodeSetup {
    state: Mutex<NewCode>,
}

struct NewCode {
    code: Option<RecoveryCode>,
    confirmed: bool,
}

#[uniffi::export]
impl RecoveryCodeSetup {
    #[uniffi::constructor]
    pub fn new() -> Arc<RecoveryCodeSetup> {
        Arc::new(RecoveryCodeSetup {
            state: Mutex::new(NewCode {
                code: Some(RecoveryCode::generate()),
                confirmed: false,
            }),
        })
    }

    /// The code, to show once: none once it has been typed back.
    pub fn code(&self) -> Option<Vec<u8>> {
        let s = self.lock();
        s.code
            .as_ref()
            .filter(|_| !s.confirmed)
            .map(|c| c.display().as_bytes().to_vec())
    }

    /// Whether `typed` is the code, as read off paper.
    pub fn confirm(&self, typed: Vec<u8>) -> bool {
        let typed = Zeroizing::new(typed);
        let mut s = self.lock();
        let right = match (
            &s.code,
            std::str::from_utf8(&typed)
                .ok()
                .and_then(RecoveryCode::parse),
        ) {
            (Some(kept), Some(typed)) => typed.display() == kept.display(),
            _ => false,
        };
        s.confirmed |= right;
        right
    }

    /// Puts `identity_seed`'s identity at `registrar` sealed by the code,
    /// in place of the recovery backup before: `unconfirmed` until it is
    /// typed back, `committed` once put; otherwise as
    /// [`backup_passphrase`] is refused.
    #[uniffi::method(async_runtime = "tokio")]
    pub async fn put(
        self: Arc<Self>,
        identity_seed: Vec<u8>,
        registrar: String,
    ) -> Result<(), CoreError> {
        let id = identity(&Zeroizing::new(identity_seed))?;
        let turn = Turn::begin(&id);
        Aborting(crate::connection::RUNTIME.spawn(async move {
            let (envelope, keys) = {
                let s = self.lock();
                let code = s.code.as_ref().ok_or_else(|| refused("committed"))?;
                if !s.confirmed {
                    return Err(refused("unconfirmed"));
                }
                tokio::task::block_in_place(|| KeyEnvelope::seal(&id, &Secret::RecoveryCode(code)))
                    .map_err(|e| protocol(&format!("sealing: {e}")))?
            };
            put(
                &registrar,
                &turn,
                |host, time| EnvelopePut::store(&id, host, time, &envelope, &keys),
                "stored",
            )
            .await?;
            self.lock().code = None;
            Ok(())
        }))
        .await
    }
}

impl RecoveryCodeSetup {
    fn lock(&self) -> std::sync::MutexGuard<'_, NewCode> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The last time a registration or a put was signed for, in this process,
/// setups' commits and backups alike: the next signs a later one, as the
/// registrar keeps an identity's last time and refuses one no later.
static SIGNED: AtomicU64 = AtomicU64::new(0);

/// `time` signed by another, a setup resumed with a time of its own: never
/// signed again.
pub(crate) fn signed_at(time: u64) {
    SIGNED.fetch_max(time, Ordering::SeqCst);
}

pub(crate) fn signing_time() -> u64 {
    let now = now();
    let mut last = SIGNED.load(Ordering::SeqCst);
    loop {
        let next = now.max(last + 1);
        match SIGNED.compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

/// `sign`'s put, for the registrar's host and a time, sent to `registrar`'s
/// envelopes, its answer holding `answered: true`.
async fn put(
    registrar: &str,
    turn: &Turn,
    sign: impl FnOnce(&str, u64) -> Result<Vec<u8>, hl_identity::Error>,
    answered: &str,
) -> Result<(), CoreError> {
    let base = registrar_base(registrar)?;
    let http = auth::http_client(base.as_str(), None)?;
    let reg = discovered(&http, &base).await?;
    let envelopes = endpoint(&base, &reg.envelopes)?;
    // Asked last before signing: a put signed after a newer backup began
    // would replace what that one saved.
    if !turn.current() {
        return Err(refused("superseded"));
    }
    let request = sign(&reg.host, signing_time()).map_err(|e| protocol(&e.to_string()))?;
    let reply = auth::put(&http, &envelopes, json!({ "request": b64(&request) })).await?;
    if reply.get(answered).and_then(Value::as_bool) != Some(true) {
        return Err(protocol(&format!("the registrar did not say {answered}")));
    }
    Ok(())
}

/// Each identity's backup operations, in the order they were asked for: a
/// later one supersedes any begun before it that has not yet signed, from
/// whichever of the app's screens it came.
struct Turn {
    identity: [u8; 32],
    number: u64,
}

static TURNS: Mutex<Option<std::collections::HashMap<[u8; 32], u64>>> = Mutex::new(None);

impl Turn {
    fn begin(id: &IdentityKey) -> Turn {
        let mut turns = TURNS.lock().unwrap_or_else(|e| e.into_inner());
        let number = turns
            .get_or_insert_with(Default::default)
            .entry(id.public())
            .or_default();
        *number += 1;
        Turn {
            identity: id.public(),
            number: *number,
        }
    }

    /// Whether no backup of the identity was begun after this one.
    fn current(&self) -> bool {
        let turns = TURNS.lock().unwrap_or_else(|e| e.into_inner());
        turns.as_ref().and_then(|t| t.get(&self.identity)) == Some(&self.number)
    }
}

/// A backup's work on the core's runtime, aborted if the app stops waiting
/// for it: a put it gave up on is not sent.
struct Aborting(tokio::task::JoinHandle<Result<(), CoreError>>);

impl std::future::Future for Aborting {
    type Output = Result<(), CoreError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0)
            .poll(cx)
            .map(|done| done.unwrap_or_else(|_| Err(protocol("the backup stopped"))))
    }
}

impl Drop for Aborting {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn identity(seed: &[u8]) -> Result<IdentityKey, CoreError> {
    let seed: &[u8; 32] = seed.try_into().map_err(|_| refused("bad_seed"))?;
    Ok(IdentityKey::from_seed(seed))
}

fn refused(code: &str) -> CoreError {
    CoreError::Refused {
        code: code.into(),
        detail: String::new(),
    }
}

fn protocol(detail: &str) -> CoreError {
    CoreError::Protocol {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_begun_later_supersedes_one_begun_before_it_and_no_other_identitys() {
        let (alice, bob) = (IdentityKey::generate(), IdentityKey::generate());
        let first = Turn::begin(&alice);
        let theirs = Turn::begin(&bob);
        assert!(first.current());
        let second = Turn::begin(&alice);
        assert!(!first.current(), "superseded");
        assert!(second.current() && theirs.current());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_backup_given_up_on_does_not_go_on() {
        let sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = sent.clone();
        let work = Aborting(crate::connection::RUNTIME.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            flag.store(true, Ordering::SeqCst);
            Ok(())
        }));
        drop(work);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(!sent.load(Ordering::SeqCst));
    }
}
