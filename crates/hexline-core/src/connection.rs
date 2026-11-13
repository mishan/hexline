//! One server, as the app sees it: a connection it opens and the core
//! keeps, the requests it makes, and the updates it is handed in batches.
//!
//! A supervisor task owns each connection's life. It hands the app its
//! updates, and when the link goes it gets it back: resuming the session
//! where the server allows, syncing where the gap cannot be replayed,
//! logging in again where the session has expired, with backoff between
//! tries that a network change cuts short. It stops only for a hang-up, a
//! kick, a refusal, or another device taking the session. In the
//! background it lets the link go after a while, and takes it back when
//! the app comes to the front.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use hxng_client::auth::{self, Device};
use hxng_client::driver::{self, Client, Start, Update, Updates};
use hxng_client::{LoginParams, Output, Resumable, Token};
use serde_json::{json, Value};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::{sleep, timeout, Instant};

use crate::model::{ChatLine, HistoryPage, User};

/// The runtime every connection's task and pump runs on. uniffi's own
/// is one thread, shared with whatever else polls through it; this one is
/// the core's, so the app's callbacks and its calls never wait on each
/// other's thread.
static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("hexline-core")
        .enable_all()
        .build()
        .expect("a tokio runtime")
});

/// Backoff between tries to get a link back: doubling from the first,
/// capped, with up to a quarter more at random so phones a server lost at
/// once do not all come back at once.
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How long the link is kept once the app is in the background (design
/// §3): long enough for a quick switch away and back, short enough that a
/// phone in a pocket is soon detached and reached by push instead.
const LINGER: Duration = Duration::from_secs(60);
/// A link that lived this long was a good one: the next loss starts the
/// backoff again. One lost sooner carries its backoff on, so a server that
/// takes a link and drops it is not tried as fast as it answers.
const STABLE: Duration = Duration::from_secs(30);
/// How long a hang-up waits for the link to close, and a sync for its reply.
const CLOSING: Duration = Duration::from_secs(5);
const SYNCING: Duration = Duration::from_secs(20);

const BATCH: usize = 256;

#[derive(Debug, uniffi::Error)]
pub enum CoreError {
    /// The server could not be reached. (`detail`, not `message`, which
    /// Kotlin's exceptions have.)
    Connect { detail: String },
    /// The server answered with an error `code` (hotline-ng.md §10). Also
    /// `kicked` and `replaced`, for a session that ended so while it was
    /// being taken back.
    Refused { code: String, detail: String },
    /// The server broke the protocol, and the connection was dropped.
    Protocol { detail: String },
    /// There is no connection to ask.
    Closed,
    /// Logged in, or logging in, already: one connection at a time.
    Busy,
}

/// What resumes the session, kept while the connection lives and handed
/// to the app by [`ServerConnection::saved`] as bytes it keeps as they are.
#[derive(Clone)]
struct Kept {
    /// `last_seq` is the last event the app was handed, so a resume
    /// replays nothing it has and skips nothing it has not.
    resumable: Resumable,
    /// The session's own uid, which a resume keeps and a sync does not say.
    self_uid: u16,
    /// The login's capabilities, which a resume keeps and does not repeat.
    caps: Vec<String>,
    /// Begun with no credentials: logging in again without any is the same
    /// guest, where for an account it would be someone else.
    guest: bool,
    /// The identity the session is, and what the server made of it, for a
    /// session an identity logged in to.
    fingerprint: Option<String>,
    outcome: Option<String>,
}

impl Kept {
    fn encode(&self) -> Vec<u8> {
        let r = &self.resumable;
        json!({
            "v": 1,
            "session": r.session,
            "token": r.token.expose(),
            "last_seq": r.last_seq,
            "needs_sync": r.needs_sync,
            "self_uid": self.self_uid,
            "caps": self.caps,
            "guest": self.guest,
            "fingerprint": self.fingerprint,
            "outcome": self.outcome,
        })
        .to_string()
        .into_bytes()
    }

    /// `None` for anything but what [`Kept::encode`] wrote: a session that
    /// does not read is one to log in again for.
    fn decode(bytes: &[u8]) -> Option<Kept> {
        let v: Value = serde_json::from_slice(bytes).ok()?;
        (v.get("v")? == 1).then_some(())?;
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Kept {
            resumable: Resumable {
                session: text("session")?,
                token: Token::new(text("token")?),
                last_seq: v.get("last_seq")?.as_u64()?,
                needs_sync: v.get("needs_sync")?.as_bool()?,
            },
            self_uid: u16::try_from(v.get("self_uid")?.as_u64()?).ok()?,
            caps: v
                .get("caps")?
                .as_array()?
                .iter()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect(),
            guest: v.get("guest")?.as_bool()?,
            // Absent from a session saved before identities were.
            fingerprint: text("fingerprint"),
            outcome: text("outcome"),
        })
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::Connect { detail } | CoreError::Protocol { detail } => f.write_str(detail),
            CoreError::Refused { code, detail } => write!(f, "{code}: {detail}"),
            CoreError::Closed => f.write_str("not connected"),
            CoreError::Busy => f.write_str("already connected"),
        }
    }
}

impl From<driver::Error> for CoreError {
    fn from(e: driver::Error) -> Self {
        match e {
            driver::Error::Connect(detail) => CoreError::Connect { detail },
            driver::Error::Refused(r) => CoreError::Refused {
                code: r.error.code,
                detail: r.error.text,
            },
            driver::Error::Protocol(p) => CoreError::Protocol {
                detail: p.to_string(),
            },
            driver::Error::Closed | driver::Error::Rejected(_) => CoreError::Closed,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct LoginInfo {
    pub server_name: String,
    pub caps: Vec<String>,
    /// Whether the server lets this session survive a lost connection
    /// (§2); the core resumes it when it can.
    pub can_resume: bool,
    /// The identity this session is, and what the server made of it
    /// (hotline-ng-identity.md §5.3), when it logged in as one.
    pub fingerprint: Option<String>,
    pub outcome: Option<String>,
}

/// What the app is told, in order.
#[derive(Debug, uniffi::Enum)]
pub enum CoreUpdate {
    /// Everyone present, this session included, and the subject: the
    /// first update of every connection, and again whole whenever the
    /// server says the app's copy may be behind. Every update after it
    /// applies to it. Before one that follows a sync come the events the
    /// server sent ahead of it, which it supersedes.
    Roster {
        self_uid: u16,
        users: Vec<User>,
        subject: String,
    },
    UserJoined {
        user: User,
    },
    UserChanged {
        user: User,
    },
    UserParted {
        uid: u16,
    },
    Chat {
        line: ChatLine,
    },
    /// The lobby's subject, or with `room` a room's topic.
    Subject {
        subject: String,
        room: Option<u64>,
    },
    /// A server notice, such as a kick's announcement.
    Notice {
        text: String,
        room: Option<u64>,
    },
    /// An administrator's message to everyone.
    Broadcast {
        nick: String,
        text: String,
    },
    /// This session was kicked: the `Closed` after it is not to be resumed.
    Kicked,
    /// An event this build does not show yet, as its JSON: still in order,
    /// so nothing after it is told out of turn.
    Other {
        ev: String,
        data: String,
    },
    /// The link went; the core is getting it back. `attempt` counts from 1.
    Reconnecting {
        attempt: u32,
    },
    /// The link is back. With `gap`, events were missed (a resync, or a
    /// fresh login once the session had expired): a `Roster` follows, and
    /// lines said meanwhile are history's to fill in.
    Reconnected {
        gap: bool,
        /// After a fresh login, what it was: the server may have made of an
        /// identity something else than before (hotline-ng-identity.md §5.3).
        info: Option<LoginInfo>,
    },
    /// The server refused to take the session back, with its `code`: the
    /// `Closed` that follows is for good.
    Refused {
        code: String,
    },
    /// The connection is over for good, and the core will not reconnect:
    /// hung up, kicked, refused, or taken by another device (`replaced`).
    Closed {
        can_resume: bool,
        replaced: bool,
    },
}

/// Implemented by the app: called on one of the core's threads, a batch
/// at a time, in order. It hands the batch on and returns: blocking here,
/// or waiting on a call into the core, holds up the connection's updates.
/// One that throws is taken for an app no longer listening, and the
/// connection is closed.
#[uniffi::export(with_foreign)]
pub trait UpdateSink: Send + Sync {
    fn deliver(&self, updates: Vec<CoreUpdate>);
}

/// What the app asks of a connection's supervisor.
enum Control {
    /// End the connection: with `logout`, the session too.
    HangUp {
        logout: bool,
    },
    /// The network changed: try now rather than at the end of a backoff.
    Nudge,
    Foreground(bool),
}

/// What a connection shares between its supervisor and the app's calls.
/// Not where the supervisor's own handle is: the supervisor holds this, and
/// it ends when the app lets go of the connection.
struct Shared {
    sink: Arc<dyn UpdateSink>,
    /// The live link, for requests; `None` while there is none.
    client: Mutex<Option<Client>>,
    kept: Mutex<Option<Kept>>,
    foreground: AtomicBool,
    linger_ms: AtomicU64,
}

impl Shared {
    /// False when the app threw: it is taken for one no longer listening.
    fn deliver(&self, updates: Vec<CoreUpdate>) -> bool {
        updates.is_empty() || catch_unwind(AssertUnwindSafe(|| self.sink.deliver(updates))).is_ok()
    }

    fn linger(&self) -> Instant {
        let ms = self.linger_ms.load(Ordering::Relaxed).min(86_400_000);
        Instant::now() + Duration::from_millis(ms)
    }

    fn closed(&self) -> CoreUpdate {
        CoreUpdate::Closed {
            can_resume: self.kept.lock().unwrap().is_some(),
            replaced: false,
        }
    }
}

/// Where the connection is in its life. One lock for all of it, so a call
/// never finds the connection between two of them.
enum Phase {
    Idle,
    /// A login under way; `ending` is a hang-up asked for meanwhile, and
    /// whether it logs out.
    Connecting {
        ending: Option<bool>,
    },
    Running(Supervisor),
}

struct Supervisor {
    control: mpsc::UnboundedSender<Control>,
    /// Closed when the supervisor is done and has told the app its last.
    done: watch::Receiver<()>,
}

impl Supervisor {
    fn running(&self) -> bool {
        self.done.has_changed().is_ok()
    }
}

/// The phase and the signal that it changed, for the app's calls and the
/// task that makes a login, never for the supervisor.
struct Life {
    phase: Mutex<Phase>,
    changed: Notify,
}

#[derive(uniffi::Object)]
pub struct ServerConnection {
    url: String,
    shared: Arc<Shared>,
    life: Arc<Life>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ServerConnection {
    #[uniffi::constructor]
    pub fn new(url: String, sink: Arc<dyn UpdateSink>) -> Arc<Self> {
        Arc::new(ServerConnection {
            url,
            shared: Arc::new(Shared {
                sink,
                client: Mutex::new(None),
                kept: Mutex::new(None),
                foreground: AtomicBool::new(true),
                linger_ms: AtomicU64::new(LINGER.as_millis() as u64),
            }),
            life: Arc::new(Life {
                phase: Mutex::new(Phase::Idle),
                changed: Notify::new(),
            }),
        })
    }

    /// Log in, or with `saved` (what [`ServerConnection::saved`] gave)
    /// resume that session and log in only if it has expired. The
    /// credentials are kept, in memory and for this connection's life, to
    /// log in again should the session expire while the link is down; an
    /// account's session is not logged in again without them, so a lapsed
    /// one is refused `session_expired` rather than made a guest.
    pub async fn login(
        &self,
        login: Option<String>,
        password: Option<String>,
        saved: Option<Vec<u8>>,
    ) -> Result<LoginInfo, CoreError> {
        let params = LoginParams {
            login,
            password,
            ..LoginParams::default()
        };
        self.start(Credentials::Password(params), saved).await
    }

    /// Log in as an identity, proving `device` to the server first
    /// (hotline-ng-auth.md §6.2), or with `saved` resume that session. The
    /// device is proved again for each new login, and never for a resume.
    /// With `create`, a server whose policy allows it makes an account for
    /// an identity it has none for.
    pub async fn login_identity(
        &self,
        device: DeviceIdentity,
        create: bool,
        saved: Option<Vec<u8>>,
    ) -> Result<LoginInfo, CoreError> {
        let (device, fingerprint) = device.open()?;
        let creds = Credentials::Identity {
            device: Box::new(device),
            create,
            fingerprint,
        };
        self.start(creds, saved).await
    }
}

impl ServerConnection {
    async fn start(
        &self,
        creds: Credentials,
        saved: Option<Vec<u8>>,
    ) -> Result<LoginInfo, CoreError> {
        {
            let mut phase = self.life.phase.lock().unwrap();
            match &*phase {
                Phase::Connecting { .. } => return Err(CoreError::Busy),
                Phase::Running(s) if s.running() => return Err(CoreError::Busy),
                _ => *phase = Phase::Connecting { ending: None },
            }
        }
        let (url, shared, life) = (self.url.clone(), self.shared.clone(), self.life.clone());
        // On the core's runtime, so the phase is settled even if the app
        // stops waiting for the answer.
        RUNTIME
            .spawn(async move {
                let made = begin(&url, &creds, saved.as_deref()).await;
                let settle = |phase: Phase| {
                    *life.phase.lock().unwrap() = phase;
                    life.changed.notify_waiters();
                };
                let link = match made {
                    Ok(link) => link,
                    Err(e) => {
                        settle(Phase::Idle);
                        return Err(e);
                    }
                };
                // Read and acted on under one lock, so a hang-up comes
                // before the supervisor exists or is sent to it.
                let ending = {
                    let mut phase = life.phase.lock().unwrap();
                    match &*phase {
                        Phase::Connecting {
                            ending: Some(logout),
                        } => Some(*logout),
                        _ => {
                            let info = link.info.clone();
                            // Before the answer: a request made as soon as
                            // login returns has a link to go on.
                            *shared.client.lock().unwrap() = Some(link.client.clone());
                            let (control, rx) = mpsc::unbounded_channel();
                            let (done_tx, done) = watch::channel(());
                            RUNTIME.spawn(async move {
                                supervise(url, creds, link, shared, rx).await;
                                drop(done_tx);
                            });
                            *phase = Phase::Running(Supervisor { control, done });
                            life.changed.notify_waiters();
                            return Ok(info);
                        }
                    }
                };
                // Hung up while connecting: the app is shown nothing of it.
                if let Some(logout) = ending {
                    end(&url, &shared, Some(link), logout).await;
                }
                settle(Phase::Idle);
                Err(CoreError::Closed)
            })
            .await
            .expect("a login does not panic")
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl ServerConnection {
    pub async fn chat(&self, text: String) -> Result<(), CoreError> {
        let client = self.client()?;
        RUNTIME
            .spawn(async move { client.request("chat", json!({ "text": text })).await })
            .await
            .expect("a request does not panic")?
            .map(|_| ())
            .map_err(|e| CoreError::Refused {
                code: e.code,
                detail: e.text,
            })
    }

    /// A page of lobby lines, oldest first, by line id: the newest `limit`
    /// below `before` (or the newest of all), scrolling back; or with
    /// `after`, the oldest `limit` above it, catching up after a gap.
    /// `has_more` says more lie beyond the page in the direction it went.
    /// `not_available` where the server keeps no history.
    pub async fn history(
        &self,
        before: Option<u64>,
        after: Option<u64>,
        limit: u32,
    ) -> Result<HistoryPage, CoreError> {
        let client = self.client()?;
        let mut params = json!({ "limit": limit.clamp(1, 200) });
        if let Some(before) = before {
            params["before"] = json!(before);
        }
        if let Some(after) = after {
            params["after"] = json!(after);
        }
        let ok = RUNTIME
            .spawn(async move { client.request("history", params).await })
            .await
            .expect("a request does not panic")?
            .map_err(|e| CoreError::Refused {
                code: e.code,
                detail: e.text,
            })?;
        Ok(HistoryPage {
            lines: ok
                .get("lines")
                .and_then(Value::as_array)
                .map(|ls| ls.iter().filter_map(ChatLine::from_json).collect())
                .unwrap_or_default(),
            has_more: ok.get("has_more").and_then(Value::as_bool).unwrap_or(false),
        })
    }

    /// Leaves: logs the session out and ends the connection, a login under
    /// way included. Not `close`, which Kotlin's `AutoCloseable` has.
    /// Returns once the app has been handed the connection's last update,
    /// so a login after it starts clean.
    pub async fn disconnect(&self) {
        loop {
            let changed = self.life.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let done = match &mut *self.life.phase.lock().unwrap() {
                Phase::Idle => return,
                Phase::Connecting { ending } => {
                    *ending = Some(true);
                    None
                }
                Phase::Running(s) => {
                    let _ = s.control.send(Control::HangUp { logout: true });
                    Some(s.done.clone())
                }
            };
            match done {
                Some(mut done) => {
                    while done.changed().await.is_ok() {}
                    return;
                }
                None => changed.await,
            }
        }
    }

    /// Ends the connection without waiting: for a caller with no time
    /// left, such as an app whose screen is going away. Without `logout`
    /// the session stays resumable, for [`ServerConnection::saved`]. The
    /// last update is still delivered, on a core thread.
    pub fn hang_up(&self, logout: bool) {
        match &mut *self.life.phase.lock().unwrap() {
            Phase::Idle => {}
            Phase::Connecting { ending } => *ending = Some(ending.unwrap_or(false) || logout),
            Phase::Running(s) => {
                let _ = s.control.send(Control::HangUp { logout });
            }
        }
    }

    /// The network changed: a link being got back is tried at once.
    pub fn network_changed(&self) {
        self.control(Control::Nudge);
    }

    /// The app came to the front, or went to the back (design §3).
    pub fn set_foreground(&self, foreground: bool) {
        self.shared.foreground.store(foreground, Ordering::SeqCst);
        self.control(Control::Foreground(foreground));
    }

    /// How long the link is kept in the background, for tests that cannot
    /// wait the default.
    pub fn set_background_linger(&self, millis: u64) {
        self.shared.linger_ms.store(millis, Ordering::Relaxed);
    }

    /// What resumes this session after the app is restarted: bytes to keep
    /// as a secret, since they hold the session's token, and to hand back
    /// to [`ServerConnection::login`] or [`ServerConnection::login_identity`].
    /// `None` once the session cannot be resumed. As of the last batch the
    /// app has returned from, never ahead of it: one taken while a batch is
    /// being handed over resumes before that batch, which comes again, its
    /// lines with their ids.
    pub fn saved(&self) -> Option<Vec<u8>> {
        self.shared.kept.lock().unwrap().as_ref().map(Kept::encode)
    }
}

impl ServerConnection {
    fn client(&self) -> Result<Client, CoreError> {
        self.shared
            .client
            .lock()
            .unwrap()
            .clone()
            .ok_or(CoreError::Closed)
    }

    fn control(&self, c: Control) {
        if let Phase::Running(s) = &*self.life.phase.lock().unwrap() {
            let _ = s.control.send(c);
        }
    }
}

/// A link made whole: what to tell the app before its updates, and what
/// resumes the session it carries.
struct Link {
    client: Client,
    updates: Updates,
    first: Vec<CoreUpdate>,
    info: LoginInfo,
    kept: Option<Kept>,
    /// The session is a guest's.
    guest: bool,
    /// Events were missed: the session is new, or was synced.
    gap: bool,
    /// Made by a login, not a resume.
    fresh: bool,
}

/// A resume refused for good, where a login may still do.
fn gone(code: &str) -> bool {
    matches!(code, "session_expired" | "bad_request")
}

/// The first link: the saved session resumed, or a login.
async fn begin(url: &str, creds: &Credentials, saved: Option<&[u8]>) -> Result<Link, CoreError> {
    let kept = saved.map(Kept::decode);
    if matches!(kept, Some(None)) && !creds.may_log_in_again(false) {
        return Err(CoreError::Refused {
            code: "session_expired".into(),
            detail: "the saved session does not read".into(),
        });
    }
    // A saved session another identity's, or a password's for an
    // identity, is not this login's to resume: it logs in afresh.
    if let Some(kept) = kept
        .flatten()
        .filter(|k| k.fingerprint.as_deref() == creds.fingerprint())
    {
        let start = Start::Resume(kept.resumable.clone());
        match establish(url, &start, Some(&kept), true, None).await {
            Err(CoreError::Refused { code, detail }) if gone(&code) => {
                if !creds.may_log_in_again(kept.guest) {
                    return Err(CoreError::Refused { code, detail });
                }
            }
            other => return other,
        }
    }
    log_in(url, creds).await
}

fn identity_field(self_user: &Value, key: &str) -> Option<String> {
    self_user
        .get("identity")
        .and_then(|i| i.get(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// How a connection logs in, kept for its life to log in again.
enum Credentials {
    Password(LoginParams),
    Identity {
        device: Box<Device>,
        create: bool,
        /// The identity the device's certificate is for.
        fingerprint: String,
    },
}

impl Credentials {
    /// Whether a lapsed session may be logged in again with these: an
    /// identity always, a password if there is a login, and none only for
    /// a session that was a guest's to begin with.
    /// The identity these credentials log in as, if any.
    fn fingerprint(&self) -> Option<&str> {
        match self {
            Credentials::Password(_) => None,
            Credentials::Identity { fingerprint, .. } => Some(fingerprint),
        }
    }

    fn may_log_in_again(&self, guest: bool) -> bool {
        match self {
            Credentials::Password(p) => p.login.is_some() || guest,
            Credentials::Identity { .. } => true,
        }
    }
}

/// A new login: a password's, or an identity's on a socket its device
/// was just proved for.
async fn log_in(url: &str, creds: &Credentials) -> Result<Link, CoreError> {
    match creds {
        Credentials::Password(p) => {
            establish(url, &Start::Login(p.clone()), None, false, None).await
        }
        Credentials::Identity {
            device,
            create,
            fingerprint,
        } => {
            let start = Start::Login(LoginParams::default());
            // A challenge lapsed between its two requests, or a token the
            // upgrade refused (a server restarted, a slow link): proved
            // once more, then taken as the answer.
            let mut again = true;
            let mut link = loop {
                let tried = async {
                    let token = auth::identity_token(url, device, *create, None).await?;
                    establish(url, &start, None, false, Some(&token)).await
                }
                .await;
                match tried {
                    Err(CoreError::Refused { code, .. })
                        if again
                            && matches!(code.as_str(), "unknown_challenge" | "token_refused") =>
                    {
                        again = false
                    }
                    other => break other?,
                }
            };
            // The session the server made is the identity's, or the token
            // never reached it (a front that strips `Authorization` lets
            // the upgrade in unauthenticated) and this is someone else.
            if link.info.fingerprint.as_deref() != Some(fingerprint) {
                link.client.close();
                return Err(CoreError::Refused {
                    code: "identity_not_honored".into(),
                    detail: "the server did not log this session in as the identity proved".into(),
                });
            }
            // No login named, but no guest's either: the identity logs in again.
            link.guest = false;
            if let Some(k) = link.kept.as_mut() {
                k.guest = false;
            }
            Ok(link)
        }
    }
}

/// A device's keys as the app holds them: the 32-byte seed its key is
/// made from, the certificate its identity signed, and the identity's card.
/// The seed is as secret as a password. The core wipes the copy it keeps;
/// the copies the FFI makes on the way are not wiped, nor is the array the
/// app handed over unless the app wipes it. Seeds made in the core will
/// end the crossing.
#[derive(uniffi::Record)]
pub struct DeviceIdentity {
    pub device_seed: Vec<u8>,
    pub cert: Vec<u8>,
    pub card: Vec<u8>,
}

impl DeviceIdentity {
    /// The device, and the fingerprint of the identity its certificate is for.
    fn open(self) -> Result<(Device, String), CoreError> {
        // Wrapped first, so every way out wipes it.
        let seed = zeroize::Zeroizing::new(self.device_seed);
        let seed: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Protocol {
                detail: "a device seed is 32 bytes".into(),
            })?;
        let fingerprint = hl_identity::DeviceCert::parse(&self.cert)
            .map(|c| hl_identity::Fingerprint::of(&c.identity).to_string())
            .map_err(|e| CoreError::Protocol {
                detail: format!("the device certificate does not read: {e}"),
            })?;
        let device = Device {
            key: hl_identity::DeviceKey::from_seed(seed),
            cert: self.cert,
            card: self.card,
        };
        Ok((device, fingerprint))
    }
}

/// Open a link and make it whole: a login's roster, or after a resume a
/// sync where the gap cannot be replayed or, `cold`, there is no roster
/// to apply a replay to. `known` is the session as kept.
async fn establish(
    url: &str,
    start: &Start,
    known: Option<&Kept>,
    cold: bool,
    token: Option<&Token>,
) -> Result<Link, CoreError> {
    let (client, answer, mut updates) = driver::connect_with(url, start, None, token).await?;
    let uid = |user: &Value| {
        User::from_json(user)
            .map(|u| u.uid)
            .ok_or(CoreError::Protocol {
                detail: "the session's own user does not read".into(),
            })
    };
    let resumed = |last_seq, self_uid| {
        let (Start::Resume(r), Some(k)) = (start, known) else {
            return None;
        };
        Some(Kept {
            resumable: Resumable {
                last_seq,
                // Any sync is done before the link is handed on.
                needs_sync: false,
                ..r.clone()
            },
            self_uid,
            caps: k.caps.clone(),
            guest: k.guest,
            fingerprint: k.fingerprint.clone(),
            outcome: k.outcome.clone(),
        })
    };
    let info = |name: String| LoginInfo {
        server_name: name,
        caps: known.map(|k| k.caps.clone()).unwrap_or_default(),
        can_resume: true,
        fingerprint: known.and_then(|k| k.fingerprint.clone()),
        outcome: known.and_then(|k| k.outcome.clone()),
    };
    let guest = known.is_some_and(|k| k.guest);
    match answer {
        Output::LoggedIn(ok) => {
            let self_uid = uid(&ok.self_user)?;
            let guest = matches!(start, Start::Login(p) if p.login.is_none());
            Ok(Link {
                first: vec![CoreUpdate::Roster {
                    self_uid,
                    users: ok.users.iter().filter_map(User::from_json).collect(),
                    subject: ok.server.subject.clone(),
                }],
                info: LoginInfo {
                    server_name: ok.server.name.clone(),
                    caps: ok.caps.clone(),
                    can_resume: ok.detach.is_some(),
                    fingerprint: identity_field(&ok.self_user, "fingerprint"),
                    outcome: identity_field(&ok.self_user, "outcome"),
                },
                kept: ok.detach.is_some().then(|| Kept {
                    resumable: Resumable {
                        session: ok.session.clone(),
                        token: ok.token.clone(),
                        last_seq: ok.seq,
                        needs_sync: false,
                    },
                    self_uid,
                    caps: ok.caps.clone(),
                    guest,
                    fingerprint: identity_field(&ok.self_user, "fingerprint"),
                    outcome: identity_field(&ok.self_user, "outcome"),
                }),
                guest,
                gap: true,
                fresh: true,
                client,
                updates,
            })
        }
        Output::Resumed { ok, must_sync } => {
            let self_uid = uid(&ok.self_user)?;
            let (first, name, last_seq) = if must_sync || cold {
                resync(&client, &mut updates, self_uid).await?
            } else {
                let Start::Resume(r) = start else {
                    unreachable!("only a resume is answered as one")
                };
                (Vec::new(), String::new(), r.last_seq)
            };
            Ok(Link {
                first,
                info: info(name),
                kept: resumed(last_seq, self_uid),
                guest,
                gap: must_sync,
                fresh: false,
                client,
                updates,
            })
        }
        Output::ResyncRequired => {
            let self_uid = known.map(|k| k.self_uid).ok_or(CoreError::Protocol {
                detail: "a resync for a session not kept".into(),
            })?;
            let (first, name, last_seq) = resync(&client, &mut updates, self_uid).await?;
            Ok(Link {
                first,
                info: info(name),
                kept: resumed(last_seq, self_uid),
                guest,
                gap: true,
                fresh: false,
                client,
                updates,
            })
        }
        _ => Err(CoreError::Protocol {
            detail: "a handshake answered as something else".into(),
        }),
    }
}

/// `sync`, and the updates around it in order: the events the snapshot
/// already holds, the roster it gives, then those sent after it. With the
/// server's name and the seq to go on from.
async fn resync(
    client: &Client,
    updates: &mut Updates,
    self_uid: u16,
) -> Result<(Vec<CoreUpdate>, String, u64), CoreError> {
    let mut drained: Vec<(u64, CoreUpdate)> = Vec::new();
    // A link that ends here ends for good if it was kicked or taken: said
    // as a refusal, so the session is not taken back.
    let mut take = |u: Option<Update>| match u {
        Some(Update::Event { seq, ev, data }) => {
            drained.push((seq, event(ev, data)));
            Ok(())
        }
        Some(Update::Closed { lost, .. }) if lost.replaced => Err(ended("replaced")),
        _ if drained.iter().any(|(_, u)| matches!(u, CoreUpdate::Kicked)) => Err(ended("kicked")),
        _ => Err(CoreError::Closed),
    };
    // Drained while waiting: a driver with a full queue reads no reply.
    let ok = timeout(SYNCING, async {
        let sync = client.sync();
        tokio::pin!(sync);
        loop {
            tokio::select! {
                biased;
                ok = &mut sync => break ok,
                u = updates.recv() => take(u)?,
            }
        }
        .map_err(CoreError::from)
    })
    .await
    .map_err(|_| CoreError::Closed)??
    // Not a refusal of the session, which the handshake already took.
    .map_err(|e| CoreError::Protocol {
        detail: format!("sync refused: {}", e.code),
    })?;
    // The driver queues what it read before the reply ahead of it.
    while let Ok(u) = updates.try_recv() {
        take(Some(u))?;
    }
    let last_seq = drained.iter().map(|(s, _)| *s).fold(ok.seq, u64::max);
    let (before, after): (Vec<_>, Vec<_>) = drained.into_iter().partition(|(s, _)| *s <= ok.seq);
    let mut first: Vec<_> = before.into_iter().map(|(_, u)| u).collect();
    first.push(CoreUpdate::Roster {
        self_uid,
        users: ok.users.iter().filter_map(User::from_json).collect(),
        subject: ok.server.subject,
    });
    first.extend(after.into_iter().map(|(_, u)| u));
    Ok((first, ok.server.name, last_seq))
}

fn ended(code: &str) -> CoreError {
    CoreError::Refused {
        code: code.into(),
        detail: String::new(),
    }
}

/// Whether a refusal may pass if the core tries again later.
fn for_now(code: &str) -> bool {
    matches!(
        code,
        "rate_limited" | "too_many_connections" | "server_full" | "server_error"
    )
}

/// How a link ended.
enum Ended {
    /// The app hung up, or let go of the connection; `logout` if it
    /// asked for the session to end too.
    HungUp { logout: bool },
    /// For good, with the last update to tell; or with none, the app threw.
    Over(Vec<CoreUpdate>),
    /// Lost, the session still resumable or not.
    Lost { resumable: bool },
}

async fn supervise(
    url: String,
    creds: Credentials,
    mut link: Link,
    shared: Arc<Shared>,
    mut control: mpsc::UnboundedReceiver<Control>,
) {
    let mut foreground = shared.foreground.load(Ordering::SeqCst);
    let mut announce = false;
    let mut backoff = BACKOFF_FIRST;
    loop {
        let began = Instant::now();
        let guest = link.guest;
        let ended = pump(&mut link, &shared, &mut control, &mut foreground, announce).await;
        *shared.client.lock().unwrap() = None;
        match ended {
            Ended::HungUp { logout } => {
                if logout {
                    end(&url, &shared, None, true).await;
                }
                shared.deliver(vec![shared.closed()]);
                return;
            }
            Ended::Over(last) => {
                *shared.kept.lock().unwrap() = None;
                shared.deliver(last);
                return;
            }
            Ended::Lost { resumable: false } => *shared.kept.lock().unwrap() = None,
            Ended::Lost { resumable: true } => {}
        }
        let mut delay = if began.elapsed() >= STABLE {
            backoff = BACKOFF_FIRST;
            jitter(BACKOFF_FIRST)
        } else {
            let d = backoff + jitter(backoff / 4);
            backoff = (backoff * 2).min(BACKOFF_MAX);
            d
        };
        let mut attempt = 0u32;
        let mut last_try: Option<Instant> = None;
        link = loop {
            attempt += 1;
            // Told as soon as it is so; in the background, where nothing
            // is tried, once the app is back.
            let reconnecting = || vec![CoreUpdate::Reconnecting { attempt }];
            let told = foreground;
            if told && !shared.deliver(reconnecting()) {
                return;
            }
            let earliest = last_try.map_or_else(Instant::now, |t| t + BACKOFF_FIRST);
            if let Held::HangUp { logout } =
                hold(delay, earliest, &mut control, &mut foreground).await
            {
                end(&url, &shared, None, logout).await;
                shared.deliver(vec![shared.closed()]);
                return;
            }
            if !told && !shared.deliver(reconnecting()) {
                return;
            }
            last_try = Some(Instant::now());
            let known = shared.kept.lock().unwrap().clone();
            let tried = async {
                match &known {
                    Some(k) => {
                        let start = Start::Resume(k.resumable.clone());
                        establish(&url, &start, Some(k), false, None).await
                    }
                    None => log_in(&url, &creds).await,
                }
            };
            tokio::pin!(tried);
            let tried = loop {
                tokio::select! {
                    t = &mut tried => break t,
                    c = control.recv() => match c {
                        Some(Control::Foreground(f)) => foreground = f,
                        Some(Control::Nudge) => {}
                        Some(Control::HangUp { logout }) => {
                            hang_up_trying(&url, &shared, tried, logout).await;
                            return;
                        }
                        None => {
                            hang_up_trying(&url, &shared, tried, false).await;
                            return;
                        }
                    }
                }
            };
            let refused = match tried {
                Ok(l) => break l,
                Err(CoreError::Refused { code, .. }) if known.is_some() && gone(&code) => {
                    // Let go while the link was down: log in again, now,
                    // if that is still this person.
                    *shared.kept.lock().unwrap() = None;
                    if creds.may_log_in_again(guest) {
                        delay = Duration::ZERO;
                        continue;
                    }
                    code
                }
                Err(CoreError::Refused { code, .. }) if !for_now(&code) => code,
                Err(_) => {
                    delay = backoff + jitter(backoff / 4);
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            };
            *shared.kept.lock().unwrap() = None;
            shared.deliver(match refused.as_str() {
                "kicked" => vec![
                    CoreUpdate::Kicked,
                    CoreUpdate::Closed {
                        can_resume: false,
                        replaced: false,
                    },
                ],
                "replaced" => vec![CoreUpdate::Closed {
                    can_resume: false,
                    replaced: true,
                }],
                _ => vec![
                    CoreUpdate::Refused { code: refused },
                    CoreUpdate::Closed {
                        can_resume: false,
                        replaced: false,
                    },
                ],
            });
            return;
        };
        announce = true;
    }
}

/// A hang-up while a link is being made: the try is given a moment to
/// land, so a session it made is kept or logged out rather than lost.
async fn hang_up_trying(
    url: &str,
    shared: &Shared,
    tried: std::pin::Pin<&mut impl std::future::Future<Output = Result<Link, CoreError>>>,
    logout: bool,
) {
    let link = timeout(CLOSING, tried).await.ok().and_then(Result::ok);
    end(url, shared, link, logout).await;
    shared.deliver(vec![shared.closed()]);
}

/// Let a session go as the app asked: kept for a resume, or with
/// `logout` ended on the server, over `link` or, with none, a resume
/// made for the purpose. Bounded, as a hang-up is.
async fn end(url: &str, shared: &Shared, link: Option<Link>, logout: bool) {
    if let Some(l) = link {
        if logout {
            *shared.kept.lock().unwrap() = None;
            let _ = timeout(CLOSING, l.client.request("logout", json!({}))).await;
        } else if l.kept.is_some() {
            *shared.kept.lock().unwrap() = l.kept;
        }
        l.client.close();
        return;
    }
    if !logout {
        return;
    }
    let Some(kept) = shared.kept.lock().unwrap().take() else {
        return;
    };
    let _ = timeout(CLOSING, async {
        let start = Start::Resume(kept.resumable);
        if let Ok((client, _, _updates)) = driver::connect(url, &start, None).await {
            let _ = client.request("logout", json!({})).await;
            client.close();
        }
    })
    .await;
}

/// How a wait before a try ended.
enum Held {
    Go,
    HangUp { logout: bool },
}

/// Wait `delay` before a try. A nudge cuts it short, though not to
/// before `earliest`, so a network that changes often is not a server
/// tried as often. In the background, wait until the app is at the
/// front, then try at once.
async fn hold(
    delay: Duration,
    earliest: Instant,
    control: &mut mpsc::UnboundedReceiver<Control>,
    foreground: &mut bool,
) -> Held {
    let wait = sleep(delay);
    tokio::pin!(wait);
    loop {
        let c = if *foreground {
            tokio::select! {
                () = &mut wait => return Held::Go,
                c = control.recv() => c,
            }
        } else {
            control.recv().await
        };
        match c {
            Some(Control::Nudge) if *foreground => {
                let at = earliest.max(Instant::now());
                if at < wait.deadline() {
                    wait.as_mut().reset(at);
                }
            }
            Some(Control::Nudge) => {}
            Some(Control::Foreground(f)) => {
                let back = f && !*foreground;
                *foreground = f;
                if back {
                    return Held::Go;
                }
            }
            Some(Control::HangUp { logout }) => return Held::HangUp { logout },
            None => return Held::HangUp { logout: false },
        }
    }
}

/// Hand the app a link's updates until it ends, the app hangs up, or the
/// app has been in the background past the linger. What resumes the
/// session is kept as of the last update the app was handed.
async fn pump(
    link: &mut Link,
    shared: &Shared,
    control: &mut mpsc::UnboundedReceiver<Control>,
    foreground: &mut bool,
    announce: bool,
) -> Ended {
    *shared.client.lock().unwrap() = Some(link.client.clone());
    let mut first = std::mem::take(&mut link.first);
    let mut kicked = first.iter().any(|u| matches!(u, CoreUpdate::Kicked));
    if announce {
        first.insert(
            0,
            CoreUpdate::Reconnected {
                gap: link.gap,
                info: link.fresh.then(|| link.info.clone()),
            },
        );
    }
    if !shared.deliver(first) {
        link.client.close();
        return Ended::Over(Vec::new());
    }
    *shared.kept.lock().unwrap() = link.kept.take();
    let mut lingering = (!*foreground).then(|| shared.linger());
    // Set once the app hangs up: the link is given so long to close.
    let mut closing: Option<Instant> = None;
    let mut logout = false;
    let mut listening = true;
    let mut batch = Vec::with_capacity(BATCH);
    loop {
        let deadline = closing.or(lingering);
        let due = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            n = link.updates.recv_many(&mut batch, BATCH) => {
                if n == 0 {
                    return Ended::Lost { resumable: true };
                }
                let mut out = Vec::with_capacity(batch.len());
                let mut last_seq = None;
                let mut lost = None;
                for u in batch.drain(..) {
                    match u {
                        Update::Event { seq, ev, data } => {
                            last_seq = Some(seq);
                            let u = event(ev, data);
                            kicked |= matches!(u, CoreUpdate::Kicked);
                            out.push(u);
                        }
                        Update::Closed { lost: l, .. } => lost = Some(l),
                    }
                }
                if !shared.deliver(out) {
                    link.client.close();
                    return Ended::Over(Vec::new());
                }
                if let (Some(seq), Some(k)) = (last_seq, shared.kept.lock().unwrap().as_mut()) {
                    k.resumable.last_seq = seq;
                }
                if let Some(l) = lost {
                    if l.resumable.is_none() && closing.is_some() {
                        *shared.kept.lock().unwrap() = None;
                    }
                    return if closing.is_some() {
                        Ended::HungUp { logout }
                    } else if kicked || l.replaced {
                        Ended::Over(vec![CoreUpdate::Closed {
                            can_resume: false,
                            replaced: l.replaced,
                        }])
                    } else {
                        Ended::Lost { resumable: l.resumable.is_some() }
                    };
                }
            }
            // Still heard while closing, so a logout asked for after a
            // hang-up is not lost.
            c = control.recv(), if listening => match c {
                Some(Control::HangUp { logout: out }) => {
                    let first = closing.is_none();
                    closing.get_or_insert(Instant::now() + CLOSING);
                    if out && !logout {
                        logout = true;
                        let client = link.client.clone();
                        RUNTIME.spawn(async move {
                            let _ = client.request("logout", json!({})).await;
                            client.close();
                        });
                    } else if first {
                        link.client.close();
                    }
                }
                // The app let go of the connection.
                None => {
                    listening = false;
                    closing.get_or_insert(Instant::now() + CLOSING);
                    link.client.close();
                }
                Some(Control::Foreground(f)) => {
                    if f != *foreground {
                        lingering = (!f).then(|| shared.linger());
                    }
                    *foreground = f;
                }
                Some(Control::Nudge) => {}
            },
            () = due => {
                if closing.is_some() {
                    return Ended::HungUp { logout };
                }
                lingering = None;
                link.client.close();
            }
        }
    }
}

/// Up to `max`, at random enough to spread retries.
fn jitter(max: Duration) -> Duration {
    Duration::from_millis(rand_millis(max.as_millis() as u64))
}

/// Up to `max` milliseconds, from the clock's low bits: spreading retries
/// needs no more than that.
fn rand_millis(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos % max
}

/// One event as the app is told it; one this build cannot read as what it
/// says it is goes on as `Other`, rather than missing.
fn event(ev: String, data: Value) -> CoreUpdate {
    let user = || data.get("user").and_then(User::from_json);
    let text = |k| data.get(k).and_then(Value::as_str).map(str::to_owned);
    let room = data.get("room").and_then(Value::as_u64).filter(|&r| r != 0);
    let typed = match ev.as_str() {
        "user_joined" => user().map(|user| CoreUpdate::UserJoined { user }),
        "user_changed" => user().map(|user| CoreUpdate::UserChanged { user }),
        "user_parted" => data
            .get("uid")
            .and_then(Value::as_u64)
            .and_then(|u| u16::try_from(u).ok())
            .map(|uid| CoreUpdate::UserParted { uid }),
        "chat" => ChatLine::from_json(&data).map(|line| CoreUpdate::Chat { line }),
        "subject" => text("subject").map(|subject| CoreUpdate::Subject { subject, room }),
        "notice" => text("text").map(|text| CoreUpdate::Notice { text, room }),
        "broadcast" => data
            .get("from")
            .and_then(|f| f.get("nick"))
            .and_then(Value::as_str)
            .zip(text("text"))
            .map(|(nick, text)| CoreUpdate::Broadcast {
                nick: nick.to_owned(),
                text,
            }),
        "kicked" => Some(CoreUpdate::Kicked),
        _ => None,
    };
    typed.unwrap_or_else(|| CoreUpdate::Other {
        ev,
        data: data.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_session_reads_back_as_itself_and_nothing_else_reads() {
        let kept = Kept {
            resumable: Resumable {
                session: "s_1".into(),
                token: Token::new("secret".into()),
                last_seq: 7,
                needs_sync: false,
            },
            self_uid: 3,
            caps: vec!["history".into()],
            guest: false,
            fingerprint: Some("hl1qexample".into()),
            outcome: Some("linked".into()),
        };
        let back = Kept::decode(&kept.encode()).unwrap();
        assert_eq!(back.encode(), kept.encode());
        let mut v2: Value = serde_json::from_slice(&kept.encode()).unwrap();
        v2["v"] = json!(2);
        let mut uid: Value = serde_json::from_slice(&kept.encode()).unwrap();
        uid["self_uid"] = json!(70000);
        for bad in [
            b"junk".to_vec(),
            v2.to_string().into_bytes(),
            uid.to_string().into_bytes(),
        ] {
            assert!(
                Kept::decode(&bad).is_none(),
                "{}",
                String::from_utf8_lossy(&bad)
            );
        }
    }

    #[test]
    fn events_are_typed_or_passed_on_as_themselves() {
        let user = json!({ "uid": 3, "nick": "Alice" });
        let cases: Vec<(&str, Value, &str)> = vec![
            ("user_joined", json!({ "user": user }), "UserJoined"),
            ("user_changed", json!({ "user": user }), "UserChanged"),
            ("user_parted", json!({ "uid": 3 }), "UserParted"),
            ("user_parted", json!({ "uid": 70000 }), "Other"),
            (
                "chat",
                json!({ "from": { "uid": 3, "nick": "Alice" }, "text": "hi", "at": 1 }),
                "Chat",
            ),
            ("subject", json!({ "subject": "welcome" }), "Subject"),
            (
                "notice",
                json!({ "text": "alice was kicked", "room": 4 }),
                "Notice",
            ),
            (
                "broadcast",
                json!({ "from": { "uid": 1, "nick": "admin" }, "text": "restart at 5" }),
                "Broadcast",
            ),
            ("kicked", json!({}), "Kicked"),
            ("msg", json!({ "text": "later" }), "Other"),
            (
                "user_joined",
                json!({ "user": { "nick": "no uid" } }),
                "Other",
            ),
        ];
        for (ev, data, want) in cases {
            let got = format!("{:?}", event(ev.into(), data.clone()));
            assert!(got.starts_with(want), "{ev} {data}: {got}");
        }
        assert!(matches!(
            event("subject".into(), json!({ "subject": "topic", "room": 4 })),
            CoreUpdate::Subject { room: Some(4), .. }
        ));
    }
}
