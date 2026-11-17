//! What a phone holding its identity key does with it (design §2.1, the
//! holder): the seed is the app's to keep behind a key that asks for the
//! person each time, and comes here only for the one operation it was
//! unwrapped for.

use std::sync::{Arc, Mutex};

use hl_identity::envelope::Secret;
use hl_identity::{
    Card, DeviceKey, EnvelopePut, Fingerprint, IdentityKey, KeyEnvelope, RecoveryCode,
    RegisterRequest, SuccessorCode,
};
use hxng_client::auth;
use serde_json::json;
use zeroize::Zeroizing;

use crate::restore::{
    b64, bytes, certify, discovered, endpoint, issued, now, ours, registrar_base, with_attestation,
};
use crate::CoreError;

/// An identity key just made, with the card it signed for itself: its
/// seed, for the app to wrap at once and then wipe.
#[derive(uniffi::Record)]
pub struct NewIdentity {
    pub seed: Vec<u8>,
    pub card: Vec<u8>,
    pub fingerprint: String,
}

/// A new identity key named `name`, and its card.
#[uniffi::export]
pub fn new_identity(name: String) -> Result<NewIdentity, CoreError> {
    let key = IdentityKey::generate();
    let card = Card::new(&key, name, now())
        .sign(&key, Vec::new())
        .map_err(|_| refused("bad_name"))?;
    Ok(NewIdentity {
        seed: key.seed().to_vec(),
        card,
        fingerprint: key.fingerprint().to_string(),
    })
}

/// A device this phone's own identity certified for itself: its seed, for
/// the app to wrap under the device key's store and then wipe, and its
/// certificate.
#[derive(uniffi::Record)]
pub struct HolderMinted {
    pub device_seed: Vec<u8>,
    pub cert: Vec<u8>,
}

/// A new device for the identity whose seed is `identity_seed`, named
/// `device_name`, certified by it as a holder's own: to log in, message and
/// manage, never to vouch (design §2.3). `card` must be that identity's,
/// so a seed paired with another's card is refused rather than minted for.
#[uniffi::export]
pub fn holder_mint(
    identity_seed: Vec<u8>,
    card: Vec<u8>,
    device_name: String,
) -> Result<HolderMinted, CoreError> {
    let seed = Zeroizing::new(identity_seed);
    let seed: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| refused("bad_seed"))?;
    let id = IdentityKey::from_seed(seed);
    let card = Card::parse(&card).map_err(|_| refused("bad_card"))?;
    if Fingerprint::of(&card.identity) != id.fingerprint() {
        return Err(refused("wrong_identity"));
    }
    let device = DeviceKey::generate();
    let cert = certify(&id, &device, &device_name)?;
    Ok(HolderMinted {
        device_seed: device.seed().to_vec(),
        cert,
    })
}

/// A holder's identity being made (design §2.1): its key, the successor
/// its card commits to and its recovery code, all kept here alone until
/// the person has typed both codes back. Then the app holds the seed
/// ([`HolderSetup::identity_seed`]), keeps the device minted for this
/// phone ([`HolderSetup::mint`]) and says so ([`HolderSetup::held`]),
/// and only then is anything sent ([`HolderSetup::commit`]): the
/// registration that commits the successor, the attested card put where
/// the registrar serves it, and the recovery code's envelope. Until the
/// registration answers, nothing is lost by starting again; after it the
/// seed is held, and the setup is for that handle alone. Once committed,
/// or dropped, it wipes what it kept.
///
/// The codes cross as bytes, for the app to wipe its copies; what it
/// shows the person is a string the runtime may keep (design §2.2).
#[derive(uniffi::Object)]
pub struct HolderSetup {
    state: Mutex<Setup>,
    /// A commit is under way: from its start through its cleanup.
    committing: std::sync::atomic::AtomicBool,
    #[cfg(feature = "live-tests")]
    fault: std::sync::atomic::AtomicBool,
    #[cfg(feature = "live-tests")]
    pause: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}

struct Setup {
    fingerprint: String,
    seed: Zeroizing<[u8; 32]>,
    card: Vec<u8>,
    /// Until it is typed back: then only its hash, in the card, is kept.
    successor: Option<SuccessorCode>,
    recovery: Option<RecoveryCode>,
    recovery_confirmed: bool,
    /// This phone's device, minted here: what the card is put by.
    device: Option<(Zeroizing<[u8; 32]>, Vec<u8>)>,
    held: bool,
    /// The registrar and handle, once fixed: by a resume, or by a
    /// registration the registrar answered.
    target: Option<(String, String)>,
    /// The card carries the registrar's attestation for the target.
    registered: bool,
    /// The time the last commit signed for: the next signs a later one, as
    /// the registrar refuses a request it has seen.
    signed: u64,
}

/// What a commit made of the card: the same, carrying the registrar's
/// attestation for the handle.
#[derive(Debug, uniffi::Record)]
pub struct HolderCommitted {
    pub card: Vec<u8>,
}

#[uniffi::export]
impl HolderSetup {
    /// A new identity named `name`, whose card commits to a successor.
    #[uniffi::constructor]
    pub fn new(name: String) -> Result<Arc<HolderSetup>, CoreError> {
        let id = IdentityKey::generate();
        let successor = SuccessorCode::generate();
        let mut card = Card::new(&id, name, issued());
        card.successor = Some(successor.commitment());
        let card = card
            .sign(&id, Vec::new())
            .map_err(|_| refused("bad_name"))?;
        Ok(HolderSetup::with(Setup {
            fingerprint: id.fingerprint().to_string(),
            seed: id.seed(),
            card,
            successor: Some(successor),
            recovery: Some(RecoveryCode::generate()),
            recovery_confirmed: false,
            device: None,
            held: false,
            target: None,
            registered: false,
            signed: 0,
        }))
    }

    /// A setup this phone holds, kept unfinished: its commit may never
    /// have answered (the process ended), so it is committed again, at
    /// `registrar` as `handle` alone, by the device kept for it. Its
    /// card's successor stands, as the registrar may hold it already, so
    /// there is none to type back. The recovery code is new, and once
    /// this commits, it replaces any the identity was sealed under
    /// before: one written down for an earlier commit opens nothing.
    #[uniffi::constructor]
    pub fn resume(
        identity_seed: Vec<u8>,
        card: Vec<u8>,
        registrar: String,
        handle: String,
        device_seed: Vec<u8>,
        device_cert: Vec<u8>,
    ) -> Result<Arc<HolderSetup>, CoreError> {
        let seed = seed32(identity_seed)?;
        let device = seed32(device_seed)?;
        let id = IdentityKey::from_seed(&seed);
        let parsed = Card::parse(&card).map_err(|_| refused("bad_card"))?;
        if Fingerprint::of(&parsed.identity) != id.fingerprint() {
            return Err(refused("wrong_identity"));
        }
        crate::identity::cert_for_device(device_cert.clone(), card.clone(), device.to_vec())
            .map_err(|_| refused("bad_device"))?;
        Ok(HolderSetup::with(Setup {
            fingerprint: id.fingerprint().to_string(),
            seed,
            card,
            successor: None,
            recovery: Some(RecoveryCode::generate()),
            recovery_confirmed: false,
            device: Some((device, device_cert)),
            held: true,
            target: Some((registrar, handle)),
            registered: false,
            // The process before may have signed in this second.
            signed: now(),
        }))
    }

    pub fn fingerprint(&self) -> String {
        self.lock().fingerprint.clone()
    }

    pub fn card(&self) -> Vec<u8> {
        self.lock().card.clone()
    }

    /// The successor's code, to show once: none once it has been typed
    /// back, or for a resumed setup.
    pub fn successor_code(&self) -> Option<Vec<u8>> {
        let s = self.lock();
        s.successor
            .as_ref()
            .map(|code| code.display().as_bytes().to_vec())
    }

    /// Whether `typed` is the successor's code; if so it is let go of.
    pub fn confirm_successor(&self, typed: Vec<u8>) -> bool {
        let typed = Zeroizing::new(typed);
        let mut s = self.lock();
        let typed = std::str::from_utf8(&typed)
            .ok()
            .and_then(SuccessorCode::parse);
        let right = match (&s.successor, typed) {
            (Some(kept), Some(typed)) => *kept.key().seed() == *typed.key().seed(),
            _ => false,
        };
        if right {
            s.successor = None;
        }
        right
    }

    /// The recovery code, to show once: none once it has been typed back.
    pub fn recovery_code(&self) -> Option<Vec<u8>> {
        let s = self.lock();
        s.recovery
            .as_ref()
            .filter(|_| !s.recovery_confirmed)
            .map(|c| c.display().as_bytes().to_vec())
    }

    /// Whether `typed` is the recovery code, as read off paper.
    pub fn confirm_recovery(&self, typed: Vec<u8>) -> bool {
        let typed = Zeroizing::new(typed);
        let mut s = self.lock();
        let right = match (
            &s.recovery,
            std::str::from_utf8(&typed)
                .ok()
                .and_then(RecoveryCode::parse),
        ) {
            (Some(kept), Some(typed)) => typed.display() == kept.display(),
            _ => false,
        };
        s.recovery_confirmed |= right;
        right
    }

    /// The identity's seed, for the app to hold and then wipe, once both
    /// codes are typed back: `unconfirmed` before.
    pub fn identity_seed(&self) -> Result<Vec<u8>, CoreError> {
        let s = self.confirmed()?;
        Ok(s.seed.to_vec())
    }

    /// This phone's device, certified by the identity as a holder's own;
    /// the setup keeps it, to put the card by. `busy` while a commit is
    /// under way.
    pub fn mint(&self, device_name: String) -> Result<HolderMinted, CoreError> {
        let mut s = self.confirmed_idle()?;
        let id = IdentityKey::from_seed(&s.seed);
        let device = DeviceKey::generate();
        let cert = certify(&id, &device, &device_name)?;
        s.device = Some((device.seed(), cert.clone()));
        // Not the device the app said it keeps, until it says so of this one.
        s.held = false;
        Ok(HolderMinted {
            device_seed: device.seed().to_vec(),
            cert,
        })
    }

    /// The app holds the seed and keeps the device minted: the commit may
    /// be asked for. `unminted` before [`HolderSetup::mint`], `busy` while a
    /// commit is under way.
    pub fn held(&self) -> Result<(), CoreError> {
        let mut s = self.confirmed_idle()?;
        if s.device.is_none() {
            return Err(refused("unminted"));
        }
        s.held = true;
        Ok(())
    }

    /// Registers `handle` at `registrar` (with `invite` where it asks for
    /// one), committing the successor, puts the attested card where the
    /// registrar serves it, and puts the identity there sealed by the
    /// recovery code.
    ///
    /// Refused as the registrar refuses before it registers (a handle
    /// taken, an invite wanted), which leaves the codes to commit again,
    /// with another handle; `no_envelopes` where it keeps none;
    /// `unconfirmed` before both codes are typed back and `unheld` before
    /// [`HolderSetup::held`], and `busy` while another commit is under
    /// way. Once the registrar has registered the
    /// handle, anything that fails is `registered_not_backed_up`, to ask
    /// again with the same handle, and a commit at another registrar or
    /// as another handle is `registered_as`, the handle in its detail.
    #[uniffi::method(async_runtime = "tokio")]
    pub async fn commit(
        self: Arc<Self>,
        registrar: String,
        handle: String,
        invite: Option<String>,
    ) -> Result<HolderCommitted, CoreError> {
        if self
            .committing
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(refused("busy"));
        }
        // Let go of when the commit ends, however it ends, the app's wait
        // for it canceled or not.
        let under_way = Committing(self);
        crate::connection::RUNTIME
            .spawn(async move {
                let setup = &under_way.0;
                setup.committing(&registrar, &handle, invite).await
            })
            .await
            .unwrap_or_else(|_| Err(protocol("the commit stopped")))
    }
}

impl HolderSetup {
    fn with(setup: Setup) -> Arc<HolderSetup> {
        Arc::new(HolderSetup {
            state: Mutex::new(setup),
            committing: Default::default(),
            #[cfg(feature = "live-tests")]
            fault: Default::default(),
            #[cfg(feature = "live-tests")]
            pause: Default::default(),
        })
    }

    /// The next commit fails once the registrar has registered it, as a
    /// link lost after that would.
    #[cfg(feature = "live-tests")]
    pub fn fail_after_registering(&self) {
        self.fault.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The next commit waits once the registrar has registered it, saying
    /// so on the first, until the second is sent.
    #[cfg(feature = "live-tests")]
    pub fn hold_after_registering(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (said, registered) = tokio::sync::oneshot::channel();
        let (release, waited) = tokio::sync::oneshot::channel();
        *self.pause.lock().unwrap() = Some((said, waited));
        (registered, release)
    }

    /// [`HolderSetup::confirmed`], and `busy` while a commit is under way:
    /// its cleanup lets go of the device, so a device minted or said held
    /// meanwhile would go with it. The flag is read under the state's lock,
    /// which a commit takes after setting it and before taking its device,
    /// so a change made here either comes before that and is what it takes,
    /// or is refused.
    fn confirmed_idle(&self) -> Result<std::sync::MutexGuard<'_, Setup>, CoreError> {
        let s = self.confirmed()?;
        if self.committing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(refused("busy"));
        }
        Ok(s)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Setup> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn confirmed(&self) -> Result<std::sync::MutexGuard<'_, Setup>, CoreError> {
        let s = self.lock();
        if s.recovery.is_none() {
            return Err(refused("committed"));
        }
        if s.successor.is_some() || !s.recovery_confirmed {
            return Err(refused("unconfirmed"));
        }
        Ok(s)
    }

    async fn committing(
        &self,
        registrar: &str,
        handle: &str,
        invite: Option<String>,
    ) -> Result<HolderCommitted, CoreError> {
        // Taken at once, so a commit that ends before registering lets its
        // test know.
        #[cfg(feature = "live-tests")]
        let pause = self.pause.lock().unwrap().take();
        let base = registrar_base(registrar)?;
        // Sealed before anything is asked: Argon2id over 64 MiB, the code
        // never leaving this object.
        let (seed, card, envelope, keys, time, device, registered) = {
            let mut s = self.confirmed()?;
            if !s.held {
                return Err(refused("unheld"));
            }
            if let Some((r, h)) = &s.target {
                if r != registrar || h != handle {
                    return Err(CoreError::Refused {
                        code: "registered_as".into(),
                        detail: h.clone(),
                    });
                }
            }
            s.signed = later(s.signed, now());
            let id = IdentityKey::from_seed(&s.seed);
            let recovery = s.recovery.as_ref().expect("confirmed");
            let (envelope, keys) = tokio::task::block_in_place(|| {
                KeyEnvelope::seal(&id, &Secret::RecoveryCode(recovery))
            })
            .map_err(|e| protocol(&format!("sealing: {e}")))?;
            let (device, cert) = s.device.as_ref().expect("held");
            (
                s.seed.clone(),
                s.card.clone(),
                envelope,
                keys,
                s.signed,
                (device.clone(), cert.clone()),
                s.registered,
            )
        };
        let id = IdentityKey::from_seed(&seed);
        let http = auth::http_client(base.as_str(), None)?;
        let reg = discovered(&http, &base).await?;
        let envelopes = endpoint(&base, &reg.envelopes)?;
        let card = if registered {
            card
        } else {
            let register = endpoint(&base, &reg.register)?;
            let request = RegisterRequest {
                identity: id.public(),
                registrar: reg.host.clone(),
                handle: handle.to_owned(),
                time,
                successor: Card::parse(&card).ok().and_then(|c| c.successor),
                proof: invite
                    .map(|i| i.trim().to_owned())
                    .filter(|i| !i.is_empty()),
            }
            .sign(&id)
            .map_err(|e| protocol(&e.to_string()))?;
            let reply =
                match auth::post(&http, &register, Some(json!({ "request": b64(&request) }))).await
                {
                    Ok(reply) => reply,
                    Err(e) => {
                        let e = CoreError::from(e);
                        // Refused the handle, this identity does not hold it: a
                        // resumed setup may take another.
                        if let CoreError::Refused { code, .. } = &e {
                            if code.starts_with("handle_") {
                                self.lock().target = None;
                            }
                        }
                        return Err(e);
                    }
                };
            let attestation = bytes(&reply, "attestation")?;
            if !ours(&attestation, &reg, &id, handle) {
                return Err(protocol(
                    "the attestation is not the registrar's for this handle",
                ));
            }
            let card = with_attestation(&id, &card, &attestation)?;
            let mut s = self.lock();
            s.card = card.clone();
            s.registered = true;
            s.target = Some((registrar.to_owned(), handle.to_owned()));
            card
        };
        // The handle is the identity's from here: whatever fails is told
        // apart, for the same handle to be asked for again.
        #[cfg(feature = "live-tests")]
        if let Some((said, waited)) = pause {
            let _ = said.send(());
            let _ = waited.await;
        }
        let backed_up = async {
            #[cfg(feature = "live-tests")]
            if self.fault.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(protocol("a link lost after registering"));
            }
            put_card(&http, &base, &device, &card).await?;
            let put = EnvelopePut::store(&id, &reg.host, time, &envelope, &keys)
                .map_err(|e| protocol(&e.to_string()))?;
            let reply = auth::put(&http, &envelopes, json!({ "request": b64(&put) })).await?;
            if reply.get("stored").and_then(serde_json::Value::as_bool) != Some(true) {
                return Err(protocol("the registrar did not say it stored the envelope"));
            }
            Ok::<_, CoreError>(())
        };
        if let Err(e) = backed_up.await {
            return Err(CoreError::Refused {
                code: "registered_not_backed_up".into(),
                detail: e.to_string(),
            });
        }
        // Committed: nothing more is asked of it, and what it kept goes.
        let mut s = self.lock();
        s.recovery = None;
        s.device = None;
        s.successor = None;
        zeroize::Zeroize::zeroize(&mut *s.seed);
        Ok(HolderCommitted { card })
    }
}

/// A commit under way, its setup's to let go of as it ends.
struct Committing(Arc<HolderSetup>);

impl Drop for Committing {
    fn drop(&mut self) {
        self.0
            .committing
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Whether `name` makes a certificate a server reads, refused
/// `bad_device_name` if not: asked before any code is shown, as a mint
/// would refuse it after.
#[uniffi::export]
pub fn check_device_name(name: String) -> Result<(), CoreError> {
    crate::restore::check_name(&name)
}

/// Whether a holder's identity may be set up at `registrar`: one that
/// registers handles and keeps the recovery code's envelope. Refused
/// `bad_registrar`, `not_a_registrar` or `no_envelopes` as
/// [`HolderSetup::commit`] would be, before any code is shown.
#[uniffi::export(async_runtime = "tokio")]
pub async fn check_holder_registrar(registrar: String) -> Result<(), CoreError> {
    crate::connection::RUNTIME
        .spawn(async move {
            let base = registrar_base(&registrar)?;
            let http = auth::http_client(base.as_str(), None)?;
            let reg = discovered(&http, &base).await?;
            endpoint(&base, &reg.envelopes)?;
            endpoint(&base, &reg.register).map(drop)
        })
        .await
        .unwrap_or_else(|_| Err(protocol("the check stopped")))
}

/// The time a commit signs: later than the last, as the registrar refuses
/// a request it has seen, and never behind the clock.
fn later(signed: u64, now: u64) -> u64 {
    now.max(signed + 1)
}

/// The card put at the registrar's `/identity/card`, by `device` signed in
/// there: where a server that has only the handle reads it (§6.4), and
/// what records the successor it commits to.
async fn put_card(
    http: &hxng_client::reqwest::Client,
    base: &hxng_client::reqwest::Url,
    device: &(Zeroizing<[u8; 32]>, Vec<u8>),
    card: &[u8],
) -> Result<(), CoreError> {
    let ws = format!("ws{}", base.as_str().trim_start_matches("http"));
    let device = auth::Device {
        key: DeviceKey::from_seed(&device.0),
        cert: device.1.clone(),
        card: card.to_vec(),
    };
    let admitted = auth::identity_token(&ws, &device, false, None, None).await?;
    let resp = http
        .put(base.join("/identity/card").expect("a path"))
        .bearer_auth(admitted.token.expose())
        .header("Content-Type", "application/cbor")
        .body(card.to_vec())
        .send()
        .await
        .map_err(|e| CoreError::Connect {
            detail: e.to_string(),
        })?;
    let status = resp.status();
    let reply: serde_json::Value = resp.json().await.unwrap_or_default();
    if status.is_success() {
        return Ok(());
    }
    Err(CoreError::Refused {
        code: reply
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("card_refused")
            .into(),
        detail: status.to_string(),
    })
}

fn seed32(seed: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    let seed = Zeroizing::new(seed);
    let fixed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| refused("bad_seed"))?;
    Ok(Zeroizing::new(fixed))
}

fn protocol(detail: &str) -> CoreError {
    CoreError::Protocol {
        detail: detail.into(),
    }
}

fn refused(code: &str) -> CoreError {
    CoreError::Refused {
        code: code.into(),
        detail: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::{caps, DeviceCert};

    #[test]
    fn a_holder_mints_its_own_device_to_log_in_message_and_manage_and_never_vouch() {
        let made = new_identity("Alice".into()).unwrap();
        let minted = holder_mint(made.seed.clone(), made.card.clone(), "Hexline".into()).unwrap();
        let info =
            crate::identity::cert_for_device(minted.cert.clone(), made.card, minted.device_seed)
                .unwrap();
        assert_eq!(info.fingerprint, made.fingerprint);
        let cert = DeviceCert::parse(&minted.cert).unwrap();
        assert_eq!(cert.caps, Some(caps::LOGIN | caps::MESSAGE | caps::MANAGE));
        assert_eq!(cert.name.as_deref(), Some("Hexline"));
    }

    fn refused_as<T>(r: Result<T, CoreError>) -> String {
        match r {
            Err(CoreError::Refused { code, .. }) => code,
            Err(e) => panic!("not a refusal: {e:?}"),
            Ok(_) => panic!("not refused"),
        }
    }

    fn text(code: Option<Vec<u8>>) -> String {
        String::from_utf8(code.expect("a code to show")).unwrap()
    }

    #[test]
    fn a_setups_card_commits_to_the_successor_its_code_writes_down() {
        let setup = HolderSetup::new("Alice".into()).unwrap();
        let code = text(setup.successor_code());
        let successor = SuccessorCode::parse(&code).unwrap();
        let card = Card::parse(&setup.card()).unwrap();
        assert_eq!(card.successor, Some(successor.commitment()));
        assert_eq!(
            Fingerprint::of(&card.identity).to_string(),
            setup.fingerprint()
        );
    }

    #[test]
    fn nothing_is_handed_out_until_both_codes_are_typed_back() {
        let setup = HolderSetup::new("Alice".into()).unwrap();
        assert_eq!(refused_as(setup.identity_seed()), "unconfirmed");
        let successor = text(setup.successor_code());
        let recovery = text(setup.recovery_code());
        assert!(!setup.confirm_successor(recovery.clone().into_bytes()));
        assert!(!setup.confirm_successor(
            SuccessorCode::of(&IdentityKey::from_seed(&[1; 32]))
                .display()
                .as_bytes()
                .to_vec()
        ));
        assert!(!setup.confirm_recovery(successor.clone().into_bytes()));
        assert!(!setup.confirm_recovery(RecoveryCode::generate().display().as_bytes().to_vec()));
        assert!(setup.confirm_successor(successor.clone().into_bytes()));
        assert_eq!(setup.successor_code(), None, "let go of once typed back");
        assert!(
            !setup.confirm_successor(successor.into_bytes()),
            "and not asked again"
        );
        assert_eq!(
            refused_as(setup.mint("Hexline".into())),
            "unconfirmed",
            "the successor alone"
        );
        assert!(setup.confirm_recovery(recovery.to_lowercase().replace('-', "").into_bytes()));
        assert_eq!(setup.recovery_code(), None, "shown no more once typed back");
        let seed = setup.identity_seed().unwrap();
        assert_eq!(
            IdentityKey::from_seed(&seed.as_slice().try_into().unwrap())
                .fingerprint()
                .to_string(),
            setup.fingerprint()
        );
        assert_eq!(refused_as(setup.held()), "unminted");
        let minted = setup.mint("Hexline".into()).unwrap();
        let info = crate::identity::cert_for_device(minted.cert, setup.card(), minted.device_seed)
            .unwrap();
        assert_eq!(info.fingerprint, setup.fingerprint());
        assert!(info.can_manage && !info.can_vouch);
        setup.held().unwrap();
    }

    #[test]
    fn a_resumed_setup_keeps_its_card_and_asks_a_new_recovery_code_alone() {
        let first = HolderSetup::new("Alice".into()).unwrap();
        let id = IdentityKey::generate();
        let mut card = Card::new(&id, "Bob", now());
        card.successor = Some([7; 32]);
        let card = card.sign(&id, Vec::new()).unwrap();
        let device = DeviceKey::generate();
        let cert = certify(&id, &device, "Pixel").unwrap();
        let resume = |seed: Vec<u8>, card: Vec<u8>, device: Vec<u8>, cert: Vec<u8>| {
            HolderSetup::resume(seed, card, "reg.example".into(), "bob".into(), device, cert)
        };
        let ds = device.seed().to_vec();
        let resumed = resume(id.seed().to_vec(), card.clone(), ds.clone(), cert.clone()).unwrap();
        assert_eq!(resumed.card(), card);
        assert_eq!(resumed.successor_code(), None);
        assert_ne!(resumed.recovery_code(), first.recovery_code());
        assert!(resumed.confirm_recovery(resumed.recovery_code().unwrap()));
        assert_eq!(resumed.identity_seed().unwrap(), id.seed().to_vec());
        let other = certify(&id, &DeviceKey::generate(), "Pixel").unwrap();
        for (seed, card, device, cert, code) in [
            (
                id.seed().to_vec(),
                first.card(),
                ds.clone(),
                cert.clone(),
                "wrong_identity",
            ),
            (
                id.seed()[..31].to_vec(),
                card.clone(),
                ds.clone(),
                cert.clone(),
                "bad_seed",
            ),
            (
                id.seed().to_vec(),
                b"not a card".to_vec(),
                ds.clone(),
                cert.clone(),
                "bad_card",
            ),
            (
                id.seed().to_vec(),
                card.clone(),
                ds.clone(),
                other,
                "bad_device",
            ),
        ] {
            assert_eq!(refused_as(resume(seed, card, device, cert)), code);
        }
    }

    #[test]
    fn each_commit_signs_a_time_later_than_the_last_and_never_behind_the_clock() {
        for (signed, now, want) in [
            (0, 1000, 1000),
            (1000, 1000, 1001),
            (1001, 1000, 1002),
            (900, 1000, 1000),
        ] {
            assert_eq!(later(signed, now), want, "{signed} at {now}");
        }
    }

    #[test]
    fn a_seed_is_minted_for_only_with_its_own_card() {
        let alice = new_identity("Alice".into()).unwrap();
        let bob = new_identity("Bob".into()).unwrap();
        for (seed, card, code) in [
            (alice.seed.clone(), bob.card.clone(), "wrong_identity"),
            (alice.seed[..31].to_vec(), alice.card.clone(), "bad_seed"),
            (alice.seed.clone(), b"not a card".to_vec(), "bad_card"),
        ] {
            match holder_mint(seed, card, "Hexline".into()) {
                Err(CoreError::Refused { code: c, .. }) => assert_eq!(c, code),
                other => panic!("{code}: {:?}", other.map(|_| ())),
            }
        }
    }
}
