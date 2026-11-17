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
    crate::connection::RUNTIME
        .spawn(async move {
            let id = identity(&seed)?;
            let (envelope, keys) = tokio::task::block_in_place(|| {
                KeyEnvelope::seal(&id, &Secret::Passphrase(&passphrase))
            })
            .map_err(|e| protocol(&format!("sealing: {e}")))?;
            drop(passphrase);
            put(
                &registrar,
                |host, time| EnvelopePut::store(&id, host, time, &envelope, &keys),
                "stored",
            )
            .await
        })
        .await
        .unwrap_or_else(|_| Err(protocol("the backup stopped")))
}

/// Removes `identity_seed`'s backup of `kind` at `registrar`: done as well
/// if there was none.
#[uniffi::export(async_runtime = "tokio")]
pub async fn backup_delete(
    identity_seed: Vec<u8>,
    registrar: String,
    kind: SecretKind,
) -> Result<(), CoreError> {
    let seed = Zeroizing::new(identity_seed);
    crate::connection::RUNTIME
        .spawn(async move {
            let id = identity(&seed)?;
            let kind = match kind {
                SecretKind::Passphrase => Kind::Passphrase,
                SecretKind::RecoveryCode => Kind::RecoveryCode,
            };
            put(
                &registrar,
                |host, time| EnvelopePut::delete(&id, host, kind, time),
                "deleted",
            )
            .await
        })
        .await
        .unwrap_or_else(|_| Err(protocol("the backup stopped")))
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
        let seed = Zeroizing::new(identity_seed);
        crate::connection::RUNTIME
            .spawn(async move {
                let id = identity(&seed)?;
                let (envelope, keys) = {
                    let s = self.lock();
                    let code = s.code.as_ref().ok_or_else(|| refused("committed"))?;
                    if !s.confirmed {
                        return Err(refused("unconfirmed"));
                    }
                    tokio::task::block_in_place(|| {
                        KeyEnvelope::seal(&id, &Secret::RecoveryCode(code))
                    })
                    .map_err(|e| protocol(&format!("sealing: {e}")))?
                };
                put(
                    &registrar,
                    |host, time| EnvelopePut::store(&id, host, time, &envelope, &keys),
                    "stored",
                )
                .await?;
                self.lock().code = None;
                Ok(())
            })
            .await
            .unwrap_or_else(|_| Err(protocol("the backup stopped")))
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
    sign: impl FnOnce(&str, u64) -> Result<Vec<u8>, hl_identity::Error>,
    answered: &str,
) -> Result<(), CoreError> {
    let base = registrar_base(registrar)?;
    let http = auth::http_client(base.as_str(), None)?;
    let reg = discovered(&http, &base).await?;
    let envelopes = endpoint(&base, &reg.envelopes)?;
    let request = sign(&reg.host, signing_time()).map_err(|e| protocol(&e.to_string()))?;
    let reply = auth::put(&http, &envelopes, json!({ "request": b64(&request) })).await?;
    if reply.get(answered).and_then(Value::as_bool) != Some(true) {
        return Err(protocol(&format!("the registrar did not say {answered}")));
    }
    Ok(())
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
