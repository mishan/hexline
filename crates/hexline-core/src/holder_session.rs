//! A holder enrolling another device (identity-enrollment.md §5, design
//! §2.1): a session opened at a mailbox, its code shown with the mailbox's
//! host (and a QR code of them where the spec allows one), the request it
//! is sent waited for, and answered: a certificate for the device, minted
//! by the identity key the person opens for it, or a denial.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hl_identity::enroll::PAIRING_SECRET_BYTES;
use hl_identity::{caps, Bundle, DeviceCert, EnrollRequest, Fingerprint, IdentityKey, PublicKey};
use hxng_client::auth;
use hxng_client::reqwest::Url;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::enroll::mailbox_base;
use crate::epoch::{at_floor, published_at, registrars_of, signed_out, Published};
use crate::restore::{b64, endpoint, issued};
use crate::CoreError;

/// How long one poll of the session waits for a request: the mailbox
/// answers within 30 seconds (§5.3), and a slow network is given the rest.
const LONG_POLL: Duration = Duration::from_secs(45);
/// Polls that fail in a row before the wait gives up: a network change
/// mid-wait is passing, and the session outlasts it.
const POLL_TRIES: u32 = 3;
/// A certificate a holder mints for another device, as `hlid`'s default,
/// and the most it mints.
const LIFETIME: u64 = hl_identity::cert::RECOMMENDED_LIFETIME;
/// A request made longer ago than this is taken for a replay (§5.3).
const SKEW: u64 = 300;
/// How long an expiry waits for its session to be given back.
const RELEASE_WAIT: Duration = Duration::from_secs(2);
/// A request's lifetime at the mailbox (§10), from when it was received.
const REQUEST_SECS: u64 = 300;
/// A session's lifetime (§10): the most a mailbox may say it has.
const SESSION_SECS: u64 = 600;
/// A revocation's `until` from a signer that may not know the device's
/// latest certificate (registrar §4.4).
const UNKNOWN_UNTIL: u64 = 2 * 365 * 24 * 3600;
const DAY: u64 = 24 * 3600;
/// How long a request waits for each of its identity's registrars to say
/// where its floor is before it is shown at the floor the rest, and this
/// phone, know.
const FLOOR_WAIT: Duration = Duration::from_secs(10);
/// What a device whose key may be a copy is told: only a new key helps.
const SIGNED_OUT: &str = "this device's key was signed out; make a new one and enroll again";

/// A session at a mailbox, for one device to be enrolled by this phone's
/// identity. The code admits one request.
#[derive(uniffi::Object)]
pub struct HolderSession {
    http: hxng_client::reqwest::Client,
    sessions: String,
    secret: Zeroizing<String>,
    code: String,
    host: String,
    expires_in: u64,
    /// When the mailbox ends the session: a wait ends then, whatever a long
    /// poll is doing.
    deadline: Mutex<tokio::time::Instant>,
    card: Vec<u8>,
    /// Where the identity's floor is read, and what this phone keeps of it.
    registrars: Vec<String>,
    kept: u64,
    listed: Vec<(PublicKey, u64)>,
    /// Drawn for the QR code, where there is one: a request carrying `pair`
    /// was scanned from it.
    pairing: Option<Zeroizing<[u8; PAIRING_SECRET_BYTES]>>,
    qr: Option<Qr>,
    #[cfg(feature = "live-tests")]
    qr_url: Option<String>,
    asked: Mutex<Option<Asked>>,
    /// The code admits one request: once that is answered, the session is spent.
    spent: std::sync::atomic::AtomicBool,
    /// Held while an answer is made, so two answers make one.
    answering: tokio::sync::Mutex<()>,
    canceled: tokio::sync::watch::Sender<bool>,
}

/// A QR code's modules, row by row, `size` to a side: true for dark.
#[derive(Clone, uniffi::Record)]
pub struct Qr {
    pub size: u32,
    pub modules: Vec<bool>,
}

/// Capabilities a certificate carries, or a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, uniffi::Record)]
pub struct Caps {
    pub login: bool,
    pub message: bool,
    pub manage: bool,
    pub vouch: bool,
}

impl Caps {
    fn of(bits: u64) -> Caps {
        Caps {
            login: bits & caps::LOGIN != 0,
            message: bits & caps::MESSAGE != 0,
            manage: bits & caps::MANAGE != 0,
            vouch: bits & caps::VOUCH != 0,
        }
    }
}

/// What a device asks of the holder and what it will get, for the person
/// to judge (§6).
#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct HolderRequest {
    /// The device's key, to answer for and to know it by.
    pub device: Vec<u8>,
    /// The device key's fingerprint as the device shows it, to compare.
    pub fingerprint: String,
    pub name: Option<String>,
    /// It came by the QR code, its pairing checked: no fingerprint to compare.
    pub scanned: bool,
    /// It renews a device this identity certified, still in its time, for
    /// no more than that certificate gave (§8).
    pub renewal: bool,
    /// What it asks for: none where it leaves that to the holder.
    pub asks: Option<Caps>,
    pub asks_days: Option<u64>,
    /// What it gets, managing aside.
    pub gets: Caps,
    /// Whether the holder may let it manage: it asked to, or left it to the holder.
    pub may_manage: bool,
    /// The lifetime it gets, in seconds: a renewal's may be under a day.
    pub gets_secs: u64,
}

/// The request being asked about, and what was decided it may get.
#[derive(Clone)]
struct Asked {
    id: String,
    request: EnrollRequest,
    decided: Decided,
    /// What the person was shown of it: the same for every wait that returns it.
    shown: HolderRequest,
    /// The answer made for it by [`HolderSession::certify`], until it is delivered.
    bundle: Option<Vec<u8>>,
    /// When the mailbox lets the request go: no answer after.
    deadline: tokio::time::Instant,
    /// What the identity's registrars said of its devices as it arrived.
    published: Published,
}

/// What a request may be certified for (§6, §8).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Decided {
    renewal: bool,
    /// Its capabilities, managing aside.
    caps: u64,
    may_manage: bool,
    /// Seconds.
    lifetime: u64,
}

/// A certificate this phone minted for another device: what the phone
/// keeps of it, to revoke it by.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Certified {
    pub device: Vec<u8>,
    pub name: Option<String>,
    pub can_manage: bool,
    pub expires: u64,
    /// The device epoch it was minted in: the highest floor known for the
    /// identity, for the phone to keep.
    #[uniffi(default = 0)]
    pub epoch: u64,
}

/// What this phone keeps of an identity it holds, for a session to mint
/// at its floor and to know which keys a reset signed out.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HolderKept {
    /// The registrar it was set up or restored at, read beside those its
    /// card's attestations name.
    pub registrar: Option<String>,
    /// The device epoch last learned for it.
    pub epoch: u64,
    /// The devices it certified.
    pub devices: Vec<ListedDevice>,
}

/// A device a holder certified, and the epoch it certified it in.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ListedDevice {
    pub device: Vec<u8>,
    pub epoch: u64,
}

/// Why a device is revoked, as the registrar's record says it (registrar §4.4).
#[derive(Debug, Clone, Copy, PartialEq, uniffi::Enum)]
pub enum RevokeReason {
    Lost,
    Stolen,
    Retired,
}

impl RevokeReason {
    fn code(self) -> u64 {
        match self {
            RevokeReason::Lost => 1,
            RevokeReason::Stolen => 2,
            RevokeReason::Retired => 3,
        }
    }
}

/// How a wait for a request ended where a new code is the way on.
#[derive(Debug, Clone, Copy, PartialEq, uniffi::Enum)]
pub enum CertifyEnd {
    /// The code ran out, or admitted its one request.
    Expired,
    /// The server keeps no mailbox to certify through.
    NoMailbox,
    /// A request carrying a pairing this session did not draw, said no to unasked.
    Unpaired,
    /// A request from a device whose clock is far from this phone's, said no to unasked.
    Stale,
    /// A request no device makes, said no to unasked.
    Unreadable,
    /// A request for a certificate that signs in nowhere, said no to unasked.
    NoLogin,
    /// A request for a key a reset or a revocation signed out, said no to
    /// unasked: the device is to make a new one.
    SignedOut,
}

/// The end a session's refusal `code` says, if it is one.
#[uniffi::export]
pub fn certify_end(code: String) -> Option<CertifyEnd> {
    Some(match code.as_str() {
        "expired" | "used" => CertifyEnd::Expired,
        "no_mailbox" => CertifyEnd::NoMailbox,
        "unpaired_request" => CertifyEnd::Unpaired,
        "stale_request" => CertifyEnd::Stale,
        "unreadable_request" => CertifyEnd::Unreadable,
        "no_login_request" => CertifyEnd::NoLogin,
        "signed_out_request" => CertifyEnd::SignedOut,
        _ => return None,
    })
}

/// A device's key as a holder's prompt shows it (enrollment §6), for a
/// list of devices to name each by.
#[uniffi::export]
pub fn device_fingerprint_of(device: Vec<u8>) -> Result<String, CoreError> {
    let key: [u8; 32] = device.try_into().map_err(|_| refused("bad_device"))?;
    Ok(Fingerprint::of(&key).short())
}

/// Opens a session at `mailbox` (a host, or a server's address) for the
/// identity whose card is `card`, of which this phone keeps `kept`.
/// Refused `no_mailbox` where it serves none, as the enrollee's are.
#[uniffi::export(async_runtime = "tokio")]
pub async fn open_holder_session(
    mailbox: String,
    card: Vec<u8>,
    kept: HolderKept,
) -> Result<Arc<HolderSession>, CoreError> {
    crate::connection::RUNTIME
        .spawn(async move { HolderSession::open(&mailbox, card, kept).await })
        .await
        .unwrap_or_else(|_| Err(protocol("the session stopped")))
}

#[uniffi::export]
impl HolderSession {
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// The mailbox's host, shown beside the code: the enrollee must use it.
    pub fn host(&self) -> String {
        self.host.clone()
    }

    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }

    /// The identity a device asking will be certified for, as §5.1 shows
    /// it beside the code.
    pub fn identity(&self) -> String {
        hl_identity::Card::parse(&self.card)
            .map(|c| Fingerprint::of(&c.identity).short())
            .unwrap_or_default()
    }

    /// The QR code to show beside the code: only where the mailbox's web
    /// client is on its own origin (§5.6).
    pub fn qr(&self) -> Option<Qr> {
        self.qr.clone()
    }

    /// The request the session is sent, waited for. Refused `expired` once
    /// the session is gone, `canceled` by [`HolderSession::cancel`], and
    /// `used` once its one request is answered. A request that does not
    /// read, whose pairing does not hold, made too long ago, or for a key
    /// signed out, is denied unasked, spending the code: refused
    /// `unreadable_request`, `unpaired_request`, `stale_request` or
    /// `signed_out_request`.
    #[uniffi::method(async_runtime = "tokio")]
    pub async fn next_request(self: Arc<Self>) -> Result<HolderRequest, CoreError> {
        crate::connection::RUNTIME
            .spawn(async move { self.waiting().await })
            .await
            .unwrap_or_else(|_| Err(protocol("the session stopped")))
    }

    /// Certifies `device`, the device asked about, with the identity whose
    /// seed is `identity_seed`: for what it gets, managing with `manage`
    /// where it may, under the name it asked for, at the identity's floor as
    /// it stands as the certificate is signed. The certificate is kept
    /// here until [`HolderSession::deliver`] sends it, so the caller can
    /// record it first: one that may be out in the world is one it can
    /// revoke. Refused `not_asked` for any other device, `manage_not_asked`
    /// for managing where it may not, `used` once the session's one request
    /// is answered or certified, and `canceled` once the session is. One
    /// the floor has risen past since it was asked, or that `listed`, the
    /// devices this phone lists now, shows below it, is denied, refused
    /// `signed_out_request`: the list the session was opened with may not
    /// have read.
    #[uniffi::method(async_runtime = "tokio")]
    pub async fn certify(
        self: Arc<Self>,
        identity_seed: Vec<u8>,
        manage: bool,
        device: Vec<u8>,
        listed: Vec<ListedDevice>,
    ) -> Result<Certified, CoreError> {
        let seed = Zeroizing::new(identity_seed);
        let listed = pairs(&listed);
        crate::connection::RUNTIME
            .spawn(async move { self.certifying(&seed, manage, &device, &listed).await })
            .await
            .unwrap_or_else(|_| Err(protocol("the session stopped")))
    }

    /// Returns when the request asked about can no longer be answered, its
    /// session or the request itself gone at the mailbox, or at once if
    /// none is asked about.
    #[uniffi::method(async_runtime = "tokio")]
    pub async fn answer_ends(self: Arc<Self>) {
        let _ = crate::connection::RUNTIME
            .spawn(async move {
                let Some(deadline) = self.lock().as_ref().map(|a| a.deadline) else {
                    return;
                };
                let session = *self.deadline.lock().unwrap_or_else(|e| e.into_inner());
                tokio::time::sleep_until(deadline.min(session)).await;
            })
            .await;
    }

    /// Sends the device the certificate [`HolderSession::certify`] made.
    /// Refused `used` once it is sent, `nothing_certified` before, and
    /// `canceled` once the session is.
    #[uniffi::method(async_runtime = "tokio")]
    pub async fn deliver(self: Arc<Self>) -> Result<(), CoreError> {
        crate::connection::RUNTIME
            .spawn(async move {
                let _answering = self.answering.lock().await;
                let asked = self.unanswered()?;
                let bundle = asked.bundle.ok_or_else(|| refused("nothing_certified"))?;
                self.answer(json!({ "id": asked.id, "bundle": b64(&bundle) }))
                    .await
            })
            .await
            .unwrap_or_else(|_| Err(protocol("the session stopped")))
    }

    /// Says no to the device asked about, giving `reason`. Refused `used`
    /// once the session's one request is answered or certified, and
    /// `canceled` once the session is.
    #[uniffi::method(async_runtime = "tokio")]
    pub async fn deny(self: Arc<Self>, reason: String) -> Result<(), CoreError> {
        crate::connection::RUNTIME
            .spawn(async move {
                let _answering = self.answering.lock().await;
                let asked = self.unanswered()?;
                if asked.bundle.is_some() {
                    return Err(refused("used"));
                }
                self.answer(json!({ "id": asked.id, "denied": reason }))
                    .await
            })
            .await
            .unwrap_or_else(|_| Err(protocol("the session stopped")))
    }

    /// Ends a wait for a request, and gives the session back, so its code
    /// admits nobody from now on. An answer under way finishes; none starts
    /// after.
    pub fn cancel(self: Arc<Self>) {
        // Kept for a wait begun after it, as well as told to one under way.
        self.canceled.send_replace(true);
        // Given back after an answer under way, which the DELETE would otherwise beat.
        crate::connection::RUNTIME.spawn(async move {
            let _answering = self.answering.lock().await;
            let _ = self.release().await;
        });
    }
}

impl HolderSession {
    /// What the QR code says, as a camera would read it: a web client's
    /// address with the code, the mailbox, the identity and the pairing.
    #[cfg(feature = "live-tests")]
    pub fn qr_url(&self) -> Option<String> {
        self.qr_url.clone()
    }

    /// The session's end brought forward to now, as if it had been shown
    /// for as long as the mailbox keeps it.
    #[cfg(feature = "live-tests")]
    pub fn run_out(&self) {
        *self.deadline.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
    }

    /// The session closed at the mailbox (`DELETE`, §5.1), which keeps any
    /// answer already made for the enrollee to collect, on its own task for
    /// whoever would rather not wait. Best effort: a session not given back
    /// ends at its expiry anyway.
    fn release(&self) -> tokio::task::JoinHandle<()> {
        let request = self
            .http
            .delete(format!("{}/{}", self.sessions, *self.secret));
        crate::connection::RUNTIME.spawn(async move {
            let _ = request.send().await;
        })
    }

    async fn open(
        mailbox: &str,
        card: Vec<u8>,
        kept: HolderKept,
    ) -> Result<Arc<HolderSession>, CoreError> {
        let parsed = hl_identity::Card::parse(&card).map_err(|_| refused("bad_card"))?;
        let registrars = registrars_of(kept.registrar.as_slice(), &parsed);
        let listed = pairs(&kept.devices);
        let base = mailbox_base(mailbox)?;
        let http = auth::http_client(base.as_str(), None)?;
        let (enroll, web) = discovered(&http, &base).await?;
        let sessions = format!("{enroll}/sessions");
        let opened = auth::post(&http, &sessions, None).await?;
        let text = |k: &str| opened.get(k).and_then(Value::as_str).map(str::to_owned);
        let secret =
            Zeroizing::new(text("session").ok_or_else(|| protocol("the mailbox gave no session"))?);
        let code = text("code").ok_or_else(|| protocol("the mailbox gave no code"))?;
        // With its port, which the enrollee has to use too.
        let host = match base.port() {
            Some(port) => format!("{}:{port}", base.host_str().unwrap_or_default()),
            None => base.host_str().unwrap_or_default().to_owned(),
        };
        let (pairing, qr) = match web.filter(|w| w.origin() == base.origin()) {
            Some(web) => {
                let mut secret = Zeroizing::new([0u8; PAIRING_SECRET_BYTES]);
                getrandom::fill(&mut *secret).map_err(|e| protocol(&e.to_string()))?;
                let identity = hl_identity::Card::parse(&card)
                    .map_err(|_| refused("bad_card"))?
                    .identity;
                let mut url = web;
                url.set_fragment(Some(&format!(
                    "enroll={code}&mailbox={host}&identity={}&pair={}",
                    Fingerprint::of(&identity),
                    b64(&*secret)
                )));
                // A web client too long-winded for a QR code leaves the typed code.
                match qr_of(url.as_str()) {
                    Ok(qr) => (Some(secret), Some((qr, url.to_string()))),
                    Err(_) => (None, None),
                }
            }
            None => (None, None),
        };
        #[cfg(feature = "live-tests")]
        let qr_url = qr.as_ref().map(|(_, url)| url.clone());
        let qr = qr.map(|(qr, _)| qr);
        let expires_in = opened
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(SESSION_SECS)
            .min(SESSION_SECS);
        Ok(Arc::new(HolderSession {
            http,
            sessions,
            secret,
            code,
            host,
            expires_in,
            deadline: Mutex::new(tokio::time::Instant::now() + Duration::from_secs(expires_in)),
            card,
            registrars,
            kept: kept.epoch,
            listed,
            pairing,
            qr,
            #[cfg(feature = "live-tests")]
            qr_url,
            asked: Mutex::new(None),
            spent: Default::default(),
            answering: Default::default(),
            canceled: tokio::sync::watch::channel(false).0,
        }))
    }

    async fn waiting(&self) -> Result<HolderRequest, CoreError> {
        let mut canceled = self.canceled.subscribe();
        let url = format!("{}/{}", self.sessions, *self.secret);
        let mut failed = 0;
        loop {
            if self.spent.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(refused("used"));
            }
            if *canceled.borrow() {
                return Err(refused("canceled"));
            }
            // Asked once, it is asked as it was shown: what is approved is what the person saw.
            if let Some(asked) = self.lock().as_ref() {
                if self.past(asked) {
                    return Err(refused("expired"));
                }
                return Ok(asked.shown.clone());
            }
            let deadline = *self.deadline.lock().unwrap_or_else(|e| e.into_inner());
            let polled = tokio::select! {
                polled = auth::get_waiting(&self.http, &url, LONG_POLL) => polled,
                _ = canceled.changed() => return Err(refused("canceled")),
                _ = tokio::time::sleep_until(deadline) => {
                    // Given a moment, so a code shown as expired is one, but no
                    // more: a stalled network does not hold up the expiry.
                    let _ = tokio::time::timeout(RELEASE_WAIT, self.release()).await;
                    return Err(refused("expired"));
                }
            };
            let passing = match &polled {
                Err(hxng_client::driver::Error::Connect(_)) => true,
                Ok((status, _)) => matches!(status, 502..=504),
                Err(_) => false,
            };
            if passing && failed + 1 < POLL_TRIES {
                failed += 1;
                tokio::time::sleep(Duration::from_secs(1 << failed)).await;
                continue;
            }
            let (status, body) = polled?;
            failed = 0;
            match status {
                200 => {}
                404 | 410 => return Err(refused("expired")),
                429 => {
                    return Err(CoreError::RateLimited {
                        retry_after: crate::restore::retry_after(&body),
                    })
                }
                _ => return Err(protocol(&format!("the mailbox answered {status}"))),
            }
            let reply: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let pending = reply
                .get("pending")
                .and_then(Value::as_array)
                .ok_or_else(|| protocol("the mailbox gave no pending list"))?;
            let Some(first) = pending.first() else {
                continue;
            };
            let id = first
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            // Its time left from when the mailbox received it, by the mailbox's clock
            // read against this phone's.
            let left = request_left(
                first.get("received").and_then(Value::as_u64),
                crate::restore::now(),
            );
            let request_deadline = tokio::time::Instant::now() + Duration::from_secs(left);
            let request = first
                .get("request")
                .and_then(Value::as_str)
                .and_then(crate::restore::unb64)
                .and_then(|r| EnrollRequest::parse(&r).ok());
            let Some(request) = request else {
                return self
                    .refuse_unasked(&id, "a request that does not read", "unreadable_request")
                    .await;
            };
            let scanned = request.pair.is_some();
            let paired = self
                .pairing
                .as_ref()
                .is_some_and(|secret| request.pair_matches(secret));
            if scanned && !paired {
                return self
                    .refuse_unasked(&id, "a pairing that does not hold", "unpaired_request")
                    .await;
            }
            if crate::restore::now().abs_diff(request.time) > SKEW {
                return self
                    .refuse_unasked(&id, "a request out of its time", "stale_request")
                    .await;
            }
            let card = hl_identity::Card::parse(&self.card).map_err(|_| refused("bad_card"))?;
            // Read before the request is shown, so what the person is asked
            // about is not a key a reset signed out; a registrar that does
            // not answer leaves the floor the rest, and this phone, know.
            let published = tokio::select! {
                p = published_at(&self.registrars, &card.identity, FLOOR_WAIT) => p,
                _ = canceled.changed() => return Err(refused("canceled")),
                _ = tokio::time::sleep_until(request_deadline.min(deadline)) => {
                    return Err(refused("expired"))
                }
            };
            let floor = at_floor(&card.identity, self.kept.max(published.epoch), |f| f);
            let prev = own_prev(&request, &card.identity);
            if signed_out(
                &request.device,
                prev.as_ref(),
                floor,
                &self.listed,
                &published,
            ) {
                return self
                    .refuse_unasked(&id, SIGNED_OUT, "signed_out_request")
                    .await;
            }
            let decided = match decide(&request, &card.identity, crate::restore::now()) {
                Ok(decided) => decided,
                Err((why, code)) => return self.refuse_unasked(&id, why, code).await,
            };
            let asked = HolderRequest {
                device: request.device.to_vec(),
                fingerprint: Fingerprint::of(&request.device).short(),
                name: request.name.clone(),
                scanned,
                renewal: decided.renewal,
                asks: request.caps.map(Caps::of),
                asks_days: request.days,
                gets: Caps::of(decided.caps),
                may_manage: decided.may_manage,
                gets_secs: decided.lifetime,
            };
            // Under the answer lock, so a wait alongside this one does not say no
            // to unasked what this one has shown, nor show what it said no to.
            let _answering = self.answering.lock().await;
            if *self.canceled.borrow() {
                return Err(refused("canceled"));
            }
            if self.spent.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(refused("used"));
            }
            let session = *self.deadline.lock().unwrap_or_else(|e| e.into_inner());
            if tokio::time::Instant::now() >= request_deadline.min(session) {
                return Err(refused("expired"));
            }
            return Ok(settle(
                &self.asked,
                Asked {
                    id,
                    request,
                    decided,
                    shown: asked,
                    bundle: None,
                    deadline: request_deadline,
                    published,
                },
            ));
        }
    }

    async fn certifying(
        &self,
        seed: &[u8],
        manage: bool,
        device: &[u8],
        listed: &[(PublicKey, u64)],
    ) -> Result<Certified, CoreError> {
        let seed: &[u8; 32] = seed.try_into().map_err(|_| refused("bad_seed"))?;
        let id = IdentityKey::from_seed(seed);
        let card = hl_identity::Card::parse(&self.card).map_err(|_| refused("bad_card"))?;
        if card.identity != id.public() {
            return Err(refused("wrong_identity"));
        }
        let _answering = self.answering.lock().await;
        let Asked {
            id: asked_id,
            request,
            decided,
            bundle,
            published,
            ..
        } = self.unanswered()?;
        if bundle.is_some() {
            return Err(refused("used"));
        }
        if request.device.as_slice() != device {
            return Err(refused("not_asked"));
        }
        if manage && !decided.may_manage {
            return Err(refused("manage_not_asked"));
        }
        let mut cert = DeviceCert::for_keys(
            &id,
            request.device,
            request.device_enc,
            issued(),
            decided.lifetime,
        )
        .map_err(|e| protocol(&e.to_string()))?;
        cert.caps = Some(decided.caps | if manage { caps::MANAGE } else { 0 });
        cert.name = request.name.clone();
        let expires = cert.expires;
        let can_manage = cert.caps.unwrap_or(0) & caps::MANAGE != 0;
        // A `prev` this identity signed was minted at a floor known then.
        let prev = own_prev(&request, &id.public());
        let listed: Vec<_> = self.listed.iter().chain(listed).copied().collect();
        // As does each device listed, certified at a floor known then.
        let known = listed
            .iter()
            .map(|(_, e)| *e)
            .chain(prev.as_ref().map(|p| p.epoch))
            .max()
            .unwrap_or(0);
        let minted = at_floor(&id.public(), known, |floor| {
            // The floor may have risen since the request was shown.
            (!signed_out(&request.device, prev.as_ref(), floor, &listed, &published)).then(|| {
                cert.epoch = floor;
                cert.sign(&id)
            })
        });
        let Some(signed) = minted else {
            self.answer(json!({ "id": asked_id, "denied": SIGNED_OUT }))
                .await?;
            return Err(refused("signed_out_request"));
        };
        let epoch = cert.epoch;
        DeviceCert::parse(&signed).map_err(|_| refused("bad_device_name"))?;
        let bundle = Bundle {
            cert: signed,
            card: self.card.clone(),
        };
        if let Some(asked) = self.lock().as_mut() {
            asked.bundle = Some(bundle.encode());
        }
        Ok(Certified {
            device: request.device.to_vec(),
            name: request.name,
            can_manage,
            expires,
            epoch,
        })
    }

    /// The request asked about, if it is not answered yet and the session
    /// is not canceled.
    fn unanswered(&self) -> Result<Asked, CoreError> {
        if *self.canceled.borrow() {
            return Err(refused("canceled"));
        }
        if self.spent.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(refused("used"));
        }
        let asked = self
            .lock()
            .clone()
            .ok_or_else(|| refused("nothing_asked"))?;
        if self.past(&asked) {
            return Err(refused("expired"));
        }
        Ok(asked)
    }

    /// Whether `asked` can no longer be answered: its request or its session gone.
    fn past(&self, asked: &Asked) -> bool {
        let session = *self.deadline.lock().unwrap_or_else(|e| e.into_inner());
        tokio::time::Instant::now() >= asked.deadline.min(session)
    }

    /// Its one answer: once the mailbox has it, the session is spent and
    /// given back, its slot at the mailbox freed for whoever drops it.
    async fn answer(&self, body: Value) -> Result<(), CoreError> {
        let url = format!("{}/{}/answers", self.sessions, *self.secret);
        auth::post(&self.http, &url, Some(body))
            .await
            .map_err(|e| answer_refusal(CoreError::from(e)))?;
        self.spent.store(true, std::sync::atomic::Ordering::SeqCst);
        // Given a moment, so a session opened next is not refused for this one's
        // place; no more, so a stalled DELETE does not hold up an answer made.
        let _ = tokio::time::timeout(RELEASE_WAIT, self.release()).await;
        Ok(())
    }

    /// Denies the request `id` for `why`, the person never asked, and is
    /// refused `code` for it: the code is spent on it.
    async fn refuse_unasked(
        &self,
        id: &str,
        why: &str,
        code: &str,
    ) -> Result<HolderRequest, CoreError> {
        let _answering = self.answering.lock().await;
        if *self.canceled.borrow() {
            return Err(refused("canceled"));
        }
        // One shown already, by a wait alongside this one, is the person's to answer.
        if let Some(asked) = self.lock().as_ref() {
            return Ok(asked.shown.clone());
        }
        self.answer(json!({ "id": id, "denied": why })).await?;
        Err(refused(code))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Asked>> {
        self.asked.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Seconds left of a request the mailbox `received` (by its clock), at
/// `now` (by this phone's): its age taken as up to `SKEW` less than the
/// two clocks say, as a phone fast by that much would otherwise find every
/// request expired as it is shown; a late answer is the mailbox's to refuse.
fn request_left(received: Option<u64>, now: u64) -> u64 {
    let age = received.map_or(0, |at| now.saturating_sub(at).saturating_sub(SKEW));
    REQUEST_SECS.saturating_sub(age)
}

/// A refusal of an answer as the app is to read it: the mailbox's
/// `not_found` is the session or its request gone, which is the request
/// expired.
fn answer_refusal(e: CoreError) -> CoreError {
    match e {
        CoreError::Refused { code, .. } if code == "not_found" => refused("expired"),
        e => e,
    }
}

/// `asked` kept in `slot` and what it shows, unless a wait alongside this
/// one kept one first: then that, and what was shown of it, stand.
fn settle(slot: &Mutex<Option<Asked>>, asked: Asked) -> HolderRequest {
    let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
    slot.get_or_insert(asked).shown.clone()
}

/// What `request` may be certified for by `identity`, at `now`: logging
/// in and messaging, managing where the holder says so, never vouching,
/// nothing it did not ask for, and for no longer than it asked or than
/// `LIFETIME`. A renewal (§8) is one whose `prev` is this identity's for
/// the same device, still in its time, and asks for no more than `prev`
/// gave, and lasted long enough to be renewed: it gets no more either.
/// Refused, with why and a code, for zero days or for no login.
fn decide(
    request: &EnrollRequest,
    identity: &[u8; 32],
    now: u64,
) -> Result<Decided, (&'static str, &'static str)> {
    if request.days == Some(0) {
        return Err(("a request for no days", "unreadable_request"));
    }
    let asked_life = request.days.map(|d| d.saturating_mul(DAY));
    let prev = match request.prev_cert() {
        Some(Ok(prev)) if prev.identity == *identity && prev.device == request.device => Some(prev),
        _ => None,
    };
    let prev = prev.filter(|prev| {
        let life = prev.expires.saturating_sub(prev.issued);
        // A renewal for no longer than `prev`, issued backdated, must not be
        // due to be renewed again by the time the enrollee checks it, after
        // delivery and whatever skew there is between the two clocks: the
        // enrollee refuses one that is (`short_renewal`).
        let issued = now.saturating_sub(crate::restore::BACKDATE);
        !crate::enroll::renewal_due(issued, issued.saturating_add(life), now + SKEW)
            && prev.expires > now
            && request
                .caps
                .is_none_or(|asked| asked & !prev.caps.unwrap_or(u64::MAX) == 0)
            && asked_life.is_none_or(|asked| asked <= life)
    });
    let mut bits = (caps::LOGIN | caps::MESSAGE | caps::MANAGE) & request.caps.unwrap_or(u64::MAX);
    let mut lifetime = asked_life.unwrap_or(LIFETIME).min(LIFETIME);
    if let Some(prev) = &prev {
        bits &= prev.caps.unwrap_or(u64::MAX);
        lifetime = lifetime.min(prev.expires.saturating_sub(prev.issued));
    }
    if bits & caps::LOGIN == 0 {
        return Err(("a request for no sign-in", "no_login_request"));
    }
    Ok(Decided {
        renewal: prev.is_some(),
        caps: bits & !caps::MANAGE,
        may_manage: bits & caps::MANAGE != 0,
        lifetime,
    })
}

/// `devices` as their keys and epochs, any whose key is not one left out.
fn pairs(devices: &[ListedDevice]) -> Vec<(PublicKey, u64)> {
    devices
        .iter()
        .filter_map(|d| Some((d.device.as_slice().try_into().ok()?, d.epoch)))
        .collect()
}

/// `request`'s `prev`, if `identity` signed it for the device asking.
fn own_prev(request: &EnrollRequest, identity: &PublicKey) -> Option<DeviceCert> {
    request
        .prev_cert()
        .and_then(Result::ok)
        .filter(|p| p.identity == *identity)
}

/// A revocation's `until`: the latest expiry known for the device, or as
/// long as a signer that may not know the latest writes, whichever is later.
fn revocation_until(known: u64, time: u64) -> u64 {
    known.max(time.saturating_add(UNKNOWN_UNTIL))
}

/// The mailbox's prefix and its web client, from discovery (§3).
async fn discovered(
    http: &hxng_client::reqwest::Client,
    base: &Url,
) -> Result<(String, Option<Url>), CoreError> {
    let (status, body) = auth::get(
        http,
        base.join("/.well-known/hotline").expect("a path").as_str(),
    )
    .await?;
    if status == 429 {
        return Err(CoreError::RateLimited {
            retry_after: crate::restore::retry_after(&body),
        });
    }
    let doc: Value = (status == 200)
        .then(|| serde_json::from_slice(&body).ok())
        .flatten()
        .ok_or_else(|| refused("no_mailbox"))?;
    let block = ["identity", "registrar"]
        .iter()
        .map(|b| &doc[b])
        .find(|block| block["endpoints"]["enroll"].is_string())
        .ok_or_else(|| refused("no_mailbox"))?;
    let enroll = endpoint(
        base,
        block["endpoints"]["enroll"].as_str().unwrap_or_default(),
    )
    .map_err(|_| refused("no_mailbox"))?;
    let web = block["web"].as_str().and_then(|w| Url::parse(w).ok());
    Ok((enroll, web))
}

fn qr_of(url: &str) -> Result<Qr, CoreError> {
    let code = qrcode::QrCode::new(url.as_bytes()).map_err(|e| protocol(&e.to_string()))?;
    Ok(Qr {
        size: code.width() as u32,
        modules: code
            .to_colors()
            .into_iter()
            .map(|c| c == qrcode::Color::Dark)
            .collect(),
    })
}

/// A device's revocation (registrar §4.4), signed by the identity whose
/// seed is `identity_seed` and posted to `registrar`'s records: `device`, a
/// device's public key this phone certified, for `reason`, the latest
/// certificate this phone knows of for it ending at `until`; for at least
/// two years, as it may have been renewed elsewhere. Refused `own_device`
/// for `this_device`, this phone's own: that is the identity's to revoke,
/// or to delete from the phone.
#[uniffi::export(async_runtime = "tokio")]
pub async fn revoke_device(
    identity_seed: Vec<u8>,
    registrar: String,
    device: Vec<u8>,
    reason: RevokeReason,
    until: u64,
    this_device: Vec<u8>,
) -> Result<(), CoreError> {
    if device == this_device {
        return Err(refused("own_device"));
    }
    let seed = Zeroizing::new(identity_seed);
    crate::connection::RUNTIME
        .spawn(async move {
            let seed: &[u8; 32] = seed
                .as_slice()
                .try_into()
                .map_err(|_| refused("bad_seed"))?;
            let id = IdentityKey::from_seed(seed);
            let device: [u8; 32] = device.try_into().map_err(|_| refused("bad_device"))?;
            let time = crate::backup::signing_time();
            let record = hl_identity::DeviceRevocation {
                identity: id.public(),
                device,
                time,
                until: revocation_until(until, time),
                reason: Some(reason.code()),
                signer: None,
                signer_cert: None,
            }
            .sign(&id)
            .map_err(|e| protocol(&e.to_string()))?;
            let base = crate::restore::registrar_base(&registrar)?;
            let http = auth::http_client(base.as_str(), None)?;
            let reg = crate::restore::discovered(&http, &base).await?;
            let records = endpoint(&base, &reg.records)?;
            let reply =
                auth::post(&http, &records, Some(json!({ "record": b64(&record) }))).await?;
            if reply.get("published").and_then(Value::as_bool) != Some(true) {
                return Err(protocol("the registrar did not publish the revocation"));
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(protocol("the revocation stopped")))
}

fn refused(code: &str) -> CoreError {
    CoreError::Refused {
        code: code.into(),
        detail: String::new(),
        successor: None,
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
    use hl_identity::DeviceKey;

    const NOW: u64 = 1_800_000_000;
    const LM: u64 = caps::LOGIN | caps::MESSAGE;

    fn request(caps: Option<u64>, days: Option<u64>) -> (EnrollRequest, DeviceKey) {
        let device = DeviceKey::generate();
        let mut r = EnrollRequest::new(&device, NOW);
        r.caps = caps;
        r.days = days;
        (r, device)
    }

    #[test]
    fn a_device_gets_what_it_asked_for_within_what_the_holder_gives_and_never_vouch() {
        let id = IdentityKey::generate();
        let all = LM | caps::MANAGE | caps::VOUCH;
        // Asked caps and days, then the caps, may_manage and days it gets.
        for (asked, days, caps, may_manage, gets_days) in [
            (None, None, LM, true, 90),
            (Some(all), None, LM, true, 90),
            (Some(LM), Some(7), LM, false, 7),
            (Some(caps::LOGIN), Some(400), caps::LOGIN, false, 90),
            (
                Some(caps::LOGIN | caps::MANAGE),
                None,
                caps::LOGIN,
                true,
                90,
            ),
        ] {
            let decided = decide(&request(asked, days).0, &id.public(), NOW).unwrap();
            assert_eq!(
                (decided.caps, decided.may_manage, decided.lifetime / DAY),
                (caps, may_manage, gets_days),
                "{asked:?} {days:?}"
            );
            assert!(!decided.renewal);
        }
        for (asked, days, code) in [
            (Some(caps::VOUCH), None, "no_login_request"),
            (Some(0), None, "no_login_request"),
            (Some(caps::MESSAGE | caps::MANAGE), None, "no_login_request"),
            (None, Some(0), "unreadable_request"),
        ] {
            let refused = decide(&request(asked, days).0, &id.public(), NOW).unwrap_err();
            assert_eq!(refused.1, code, "{asked:?} {days:?}");
        }
    }

    #[test]
    fn a_renewal_is_the_same_device_in_its_time_asking_for_no_more_than_it_has() {
        let id = IdentityKey::generate();
        let prev = |device: &DeviceKey, issued: u64, life: u64, caps: u64| {
            let mut cert = DeviceCert::for_device(&id, device, issued, life).unwrap();
            cert.caps = Some(caps);
            cert.sign(&id)
        };
        let month = 30 * DAY;
        // prev's issued, lifetime and caps; what is asked; renewal, and what it gets.
        for (issued, life, had, asked, days, renewal, caps, gets_days) in [
            (NOW - DAY, month, LM, None, None, true, LM, 30),
            (
                NOW - DAY,
                month,
                caps::LOGIN,
                None,
                Some(7),
                true,
                caps::LOGIN,
                7,
            ),
            // Lapsed: enrolled afresh.
            (NOW - 2 * month, month, LM, None, None, false, LM, 90),
            // Asking for more than it had: enrolled afresh.
            (NOW - DAY, month, caps::LOGIN, Some(LM), None, false, LM, 90),
            (NOW - DAY, month, LM, None, Some(60), false, LM, 60),
            // Too short to renew: its renewal, backdated, would be due as it was made.
            (NOW - 30, 60, LM, None, None, false, LM, 90),
            (NOW - 30, 900, LM, None, None, false, LM, 90),
            (NOW - 30, 960, LM, None, None, true, LM, 0),
        ] {
            let (mut r, device) = request(asked, days);
            r.prev = Some(prev(&device, issued, life, had));
            let decided = decide(&r, &id.public(), NOW).unwrap();
            assert_eq!(
                (decided.renewal, decided.caps, decided.lifetime / DAY),
                (renewal, caps, gets_days),
                "{issued} {had} {asked:?} {days:?}"
            );
        }
        // Another identity's certificate, or another device's, renews nothing.
        let (mut r, _) = request(None, None);
        r.prev = Some(prev(&DeviceKey::generate(), NOW - DAY, month, LM));
        assert!(!decide(&r, &id.public(), NOW).unwrap().renewal);
    }

    #[test]
    fn a_request_asked_about_stays_as_it_was_shown_whatever_a_later_wait_decides() {
        let id = IdentityKey::generate();
        let asked = |days| {
            let (request, _) = request(None, Some(days));
            let decided = decide(&request, &id.public(), NOW).unwrap();
            let shown = HolderRequest {
                device: request.device.to_vec(),
                fingerprint: String::new(),
                name: None,
                scanned: false,
                renewal: false,
                asks: None,
                asks_days: Some(days),
                gets: Caps::of(decided.caps),
                may_manage: decided.may_manage,
                gets_secs: decided.lifetime,
            };
            Asked {
                id: days.to_string(),
                request,
                decided,
                shown,
                bundle: None,
                deadline: tokio::time::Instant::now(),
                published: Published::default(),
            }
        };
        let slot = Mutex::new(None);
        assert_eq!(settle(&slot, asked(7)).gets_secs, 7 * DAY);
        let mut certified = slot.lock().unwrap().clone().unwrap();
        certified.bundle = Some(vec![1]);
        *slot.lock().unwrap() = Some(certified);
        assert_eq!(
            settle(&slot, asked(30)).gets_secs,
            7 * DAY,
            "what was shown"
        );
        let kept = slot.lock().unwrap().clone().unwrap();
        assert_eq!((kept.id.as_str(), kept.bundle), ("7", Some(vec![1])));
    }

    #[test]
    fn a_request_is_given_its_time_from_a_mailbox_whose_clock_differs() {
        for (received, left) in [
            (None, REQUEST_SECS),
            (Some(NOW), REQUEST_SECS),
            // This phone 300 s fast: the request is not taken for spent.
            (Some(NOW - 300), REQUEST_SECS),
            (Some(NOW - 500), 100),
            (Some(NOW - 900), 0),
            // This phone slow: no more than the request's whole time.
            (Some(NOW + 600), REQUEST_SECS),
        ] {
            assert_eq!(request_left(received, NOW), left, "{received:?}");
        }
    }

    #[test]
    fn a_request_gone_at_the_mailbox_is_answered_as_expired() {
        let gone = CoreError::Refused {
            code: "not_found".into(),
            detail: String::new(),
            successor: None,
        };
        assert!(
            matches!(answer_refusal(gone), CoreError::Refused { code, .. } if code == "expired")
        );
    }

    #[test]
    fn a_revocation_lasts_at_least_as_long_as_a_renewal_elsewhere_could() {
        for (known, until) in [
            (NOW + 90 * DAY, NOW + UNKNOWN_UNTIL),
            (NOW + 3 * UNKNOWN_UNTIL, NOW + 3 * UNKNOWN_UNTIL),
            (0, NOW + UNKNOWN_UNTIL),
        ] {
            assert_eq!(revocation_until(known, NOW), until, "{known}");
        }
    }

    /// A session at `sessions` for `card`'s identity, as [`HolderSession::open`]
    /// makes one, reading its floor from `registrars`.
    fn session(
        sessions: String,
        card: Vec<u8>,
        registrars: Vec<String>,
        kept: u64,
        listed: Vec<(PublicKey, u64)>,
    ) -> HolderSession {
        HolderSession {
            http: auth::http_client("http://127.0.0.1", None).unwrap(),
            sessions,
            secret: Zeroizing::new("s".into()),
            code: "K7PM-QX2D".into(),
            host: "127.0.0.1".into(),
            expires_in: SESSION_SECS,
            deadline: Mutex::new(tokio::time::Instant::now() + Duration::from_secs(SESSION_SECS)),
            card,
            registrars,
            kept,
            listed,
            pairing: None,
            qr: None,
            #[cfg(feature = "live-tests")]
            qr_url: None,
            asked: Mutex::new(None),
            spent: Default::default(),
            answering: Default::default(),
            canceled: tokio::sync::watch::channel(false).0,
        }
    }

    /// A mailbox with `request`, as signed, pending since `received`,
    /// taking every answer: what it was answered.
    async fn mailbox(request: &[u8], received: u64) -> (String, Arc<Mutex<Vec<Value>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let pending = json!({ "pending": [{
            "id": "r1",
            "received": received,
            "request": b64(request),
        }] })
        .to_string();
        let answers = Arc::new(Mutex::new(Vec::new()));
        let kept = answers.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/sessions", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut got = Vec::new();
                let mut buf = [0; 4096];
                // The head, and as much of the body as it says there is.
                let (head, body) = loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    got.extend_from_slice(&buf[..n]);
                    let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
                        if n == 0 {
                            break (String::new(), Vec::new());
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&got[..end]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map_or(0, |n| n.trim().parse().unwrap());
                    if got.len() >= end + 4 + len || n == 0 {
                        break (head, got[end + 4..].to_vec());
                    }
                };
                let reply = if head.starts_with("get ") {
                    pending.clone()
                } else {
                    if head.starts_with("post ") {
                        kept.lock()
                            .unwrap()
                            .push(serde_json::from_slice(&body).unwrap());
                    }
                    "{}".into()
                };
                let out = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = s.write_all(out.as_bytes()).await;
            }
        });
        (base, answers)
    }

    fn epoch_in(certified: &HolderSession) -> u64 {
        let bundle = certified.lock().as_ref().unwrap().bundle.clone().unwrap();
        DeviceCert::parse(&Bundle::parse(&bundle).unwrap().cert)
            .unwrap()
            .epoch
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_is_shown_and_certified_at_the_floor_its_registrars_publish() {
        let gone = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        // What the registrar publishes (none for one not reached), the
        // epoch kept, the epoch the device is listed at, and the epoch it
        // is certified at, or none for a key signed out.
        for (publishes, kept, listed, want) in [
            (Some(3), 1, None, Some(3)),
            (None, 2, None, Some(2)),
            (Some(3), 0, Some(1), None),
            (Some(3), 0, Some(3), Some(3)),
        ] {
            let id = IdentityKey::generate();
            let card = hl_identity::Card::new(&id, "Alice", 10)
                .sign(&id, Vec::new())
                .unwrap();
            let registrar = match publishes {
                Some(epoch) => {
                    let records = vec![crate::epoch::tests::reset(&id, epoch)];
                    crate::epoch::tests::registrar_publishing(records, 8)
                        .await
                        .to_string()
                }
                None => gone.clone(),
            };
            let device = DeviceKey::generate();
            let request = EnrollRequest::new(&device, crate::restore::now());
            let (sessions, answers) = mailbox(&request.sign(&device), crate::restore::now()).await;
            let devices = listed.map(|e| (device.public(), e)).into_iter().collect();
            let s = Arc::new(session(sessions, card, vec![registrar], kept, devices));
            let case = format!("{publishes:?} {kept} {listed:?}");
            let outcome = s.waiting().await;
            assert_eq!(
                crate::epoch::held_floor(s.card.clone()),
                publishes.unwrap_or(kept),
                "{case}: the floor read is the app's to keep, whatever the request came to"
            );
            match want {
                Some(epoch) => {
                    let shown = outcome.unwrap();
                    let certified = s
                        .certifying(&*id.seed(), false, &shown.device, &[])
                        .await
                        .unwrap();
                    assert_eq!((certified.epoch, epoch_in(&s)), (epoch, epoch), "{case}");
                    assert!(answers.lock().unwrap().is_empty(), "{case}");
                }
                None => {
                    let refused = outcome.unwrap_err();
                    assert!(
                        matches!(&refused, CoreError::Refused { code, .. } if code == "signed_out_request"),
                        "{case}: {refused:?}"
                    );
                    assert_eq!(
                        *answers.lock().unwrap(),
                        vec![json!({ "id": "r1", "denied": SIGNED_OUT })],
                        "{case}"
                    );
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_certificate_is_signed_at_the_floor_as_it_stands_when_it_is_signed() {
        // The floor once the request was shown, the epoch of the `prev` it
        // renews if it renews one, the devices listed when it is approved
        // (whether each is the one asking, and its epoch), and the epoch it
        // is certified at, or none for a renewal the floor has passed since
        // it was asked about or a key listed below it.
        for (floor, prev, listed, want) in [
            (4, None, vec![], Some(4)),
            (2, Some(5), vec![], Some(5)),
            (3, Some(3), vec![], Some(3)),
            (6, Some(5), vec![], None),
            (2, None, vec![(true, 1)], None),
            (2, None, vec![(true, 2)], Some(2)),
            // Another listed device was certified at a floor learned since.
            (0, None, vec![(false, 7)], Some(7)),
            (0, None, vec![(true, 1), (false, 7)], None),
        ] {
            let id = IdentityKey::generate();
            let card = hl_identity::Card::new(&id, "Alice", 10)
                .sign(&id, Vec::new())
                .unwrap();
            let device = DeviceKey::generate();
            let now = crate::restore::now();
            let mut request = EnrollRequest::new(&device, now);
            request.prev = prev.map(|epoch| {
                let mut c = DeviceCert::for_device(&id, &device, now - DAY, 30 * DAY).unwrap();
                c.caps = Some(LM);
                c.epoch = epoch;
                c.sign(&id)
            });
            let (sessions, answers) = mailbox(&request.sign(&device), crate::restore::now()).await;
            // Opened with nothing kept, as a session opened before a reset is.
            let s = Arc::new(session(sessions, card, Vec::new(), 0, Vec::new()));
            let shown = s.waiting().await.unwrap();
            assert_eq!(shown.renewal, prev.is_some());
            at_floor(&id.public(), floor, |_| ());
            let listed: Vec<_> = listed
                .into_iter()
                .map(|(asking, e)| (if asking { device.public() } else { [9; 32] }, e))
                .collect();
            let certified = s
                .certifying(&*id.seed(), false, &shown.device, &listed)
                .await;
            let case = format!("{floor} {prev:?} {listed:?}");
            match want {
                Some(epoch) => {
                    assert_eq!(certified.unwrap().epoch, epoch, "{case}");
                    assert_eq!(epoch_in(&s), epoch, "{case}");
                }
                None => {
                    assert!(
                        matches!(&certified, Err(CoreError::Refused { code, .. }) if code == "signed_out_request"),
                        "{case}: {:?}",
                        certified.map(|c| c.epoch)
                    );
                    assert_eq!(
                        *answers.lock().unwrap(),
                        vec![json!({ "id": "r1", "denied": SIGNED_OUT })],
                        "{case}"
                    );
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_is_not_shown_once_it_or_its_session_has_ended() {
        // How long ago the mailbox received it, how long the session has
        // left, and whether one registrar never answers beside one that
        // publishes 5, whose floor is kept all the same.
        for (age, left, silent) in [(0, 1, true), (REQUEST_SECS + SKEW, SESSION_SECS, false)] {
            let id = IdentityKey::generate();
            let card = hl_identity::Card::new(&id, "Alice", 10)
                .sign(&id, Vec::new())
                .unwrap();
            let registrars = if silent {
                let five = vec![crate::epoch::tests::reset(&id, 5)];
                vec![
                    crate::epoch::tests::silent().await,
                    crate::epoch::tests::registrar_publishing(five, 8)
                        .await
                        .to_string(),
                ]
            } else {
                Vec::new()
            };
            let device = DeviceKey::generate();
            let now = crate::restore::now();
            let (sessions, _) =
                mailbox(&EnrollRequest::new(&device, now).sign(&device), now - age).await;
            let s = Arc::new(session(sessions, card.clone(), registrars, 0, Vec::new()));
            *s.deadline.lock().unwrap() = tokio::time::Instant::now() + Duration::from_secs(left);
            let started = tokio::time::Instant::now();
            let got = s.waiting().await;
            assert!(
                matches!(&got, Err(CoreError::Refused { code, .. }) if code == "expired"),
                "{age} {left}: {got:?}"
            );
            assert!(
                started.elapsed() < FLOOR_WAIT,
                "{age} {left}: not waited out"
            );
            let kept = if silent { 5 } else { 0 };
            assert_eq!(crate::epoch::held_floor(card), kept, "{age} {left}");
        }
    }
}
