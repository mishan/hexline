//! Enrolled-device mode (design §2.1, hxd-ng's `identity-enrollment.md`):
//! a holder of the identity key certifies a device key made here. The
//! phone posts a signed request to a mailbox under the code the holder
//! shows, waits for the answer, and checks it as it would a paste: a
//! certificate for this device's two keys, and the card of the identity
//! that signed it. Renewal asks the same holder again, by the old
//! certificate where the holder stands by for its identity, and by a code
//! where none does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hl_identity::{caps, Bundle, Card, DeviceCert, DeviceKey, EnrollRequest, Fingerprint};
use hxng_client::auth;
use hxng_client::reqwest::Url;
use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::restore::{b64, bytes, check_name, endpoint, now};
use crate::CoreError;

/// What a first enrollment asks for (design §2.3): logging in, messages
/// and managing the identity's devices. A holder's default policy gives a
/// device it did not make less, and every screen works without `manage`.
const ASKED: u64 = caps::LOGIN | caps::MESSAGE | caps::MANAGE;

/// The mailbox's long poll (§5.5), and a little more for the reply to
/// arrive in before it is given up on.
const LONG_POLL: Duration = Duration::from_secs(35);

/// How long a request lives at the mailbox (§5.2) when it does not say.
const REQUEST_LIFE: u64 = 300;

/// The least time between two asks for an answer: a mailbox that answers
/// "not yet" at once is not asked again at once.
const POLL_FLOOR: Duration = Duration::from_secs(1);

/// The largest certificate a server takes beside `signs` and `sealed`
/// (`hotline-ng.md` §6.1), as a restored device's is held to.
const MAX_CERT: usize = 512;

/// The longest wait between two polls a dropped link makes.
const MOST_BACKOFF: Duration = Duration::from_secs(8);

/// The slack past a request's life the phone waits for its answer: the
/// post's reply took a while to come, and the mailbox rounds the life it
/// tells down to the second.
const SLACK: Duration = Duration::from_secs(5);

/// The longest reply a mailbox gives (an answer is a certificate and a card).
const MOST_REPLY: usize = 64 * 1024;

/// A holder's reason for saying no, as words it may have chosen: short,
/// and nothing but letters, digits, `_`, `-` and spaces, or none. The app
/// shows them as the holder's.
fn denial(reason: &str) -> String {
    let fits = reason.len() <= 32
        && reason
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' '));
    if fits {
        reason.to_owned()
    } else {
        String::new()
    }
}

/// A certificate this phone may keep, from a holder's answer, with what
/// the phone shows before it is kept: whose device it has become (§5.5).
#[derive(Debug, uniffi::Record)]
pub struct Enrolled {
    pub cert: Vec<u8>,
    pub card: Vec<u8>,
    /// The identity that signed both.
    pub fingerprint: String,
    /// Its first eight characters, as the holder shows them.
    pub short: String,
    /// The name the identity's card gives it.
    pub name: String,
    /// What the certificate lets the device do, and for how long.
    pub info: crate::CertInfo,
}

/// This phone asking to be a device of an identity: a device key made
/// here, or for a renewal the one it has, and its request at a mailbox.
/// The key stays here until [`Enrollee::seed`] hands it to the app to
/// keep, and is wiped when this is dropped.
#[derive(uniffi::Object)]
pub struct Enrollee {
    device: DeviceKey,
    /// The certificate a renewal is for (§8).
    prev: Option<Vec<u8>>,
    /// The identity an answer must be from: a renewal's, or one this phone
    /// already holds a device of.
    expected: Mutex<Option<Fingerprint>>,
    /// The request was sent, whatever came back: a holder may have been asked.
    sent: AtomicBool,
    /// An enrollment is under way: one at a time, as one device has one answer.
    in_flight: AtomicBool,
    stopped: AtomicBool,
    stop: Notify,
}

#[uniffi::export(async_runtime = "tokio")]
impl Enrollee {
    /// A new device key, to enroll.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Enrollee {
            device: DeviceKey::generate(),
            prev: None,
            expected: Mutex::new(None),
            sent: AtomicBool::new(false),
            in_flight: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            stop: Notify::new(),
        })
    }

    /// The device `seed` makes, to renew its certificate `cert`: the same
    /// device asking again (§8). Refused if `cert` is not that device's.
    #[uniffi::constructor]
    pub fn renewing(seed: Vec<u8>, cert: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        let seed = zeroize::Zeroizing::new(seed);
        let seed: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| protocol("a device seed is 32 bytes"))?;
        let device = DeviceKey::from_seed(seed);
        let c = DeviceCert::parse(&cert)
            .map_err(|e| protocol(&format!("the certificate does not read: {e}")))?;
        if c.device != device.public() {
            return Err(protocol("the certificate is another device's"));
        }
        Ok(Arc::new(Enrollee {
            device,
            prev: Some(cert),
            expected: Mutex::new(Some(Fingerprint::of(&c.identity))),
            sent: AtomicBool::new(false),
            in_flight: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            stop: Notify::new(),
        }))
    }

    /// Refuse an answer from any identity but `fingerprint`'s: a device
    /// enrolled afresh to renew an identity is still to become that one's,
    /// whatever became of the device it replaces.
    pub fn expect_identity(&self, fingerprint: String) -> Result<(), CoreError> {
        let fp = Fingerprint::parse(&fingerprint).ok_or_else(|| protocol("not a fingerprint"))?;
        *self.expected.lock().unwrap() = Some(fp);
        Ok(())
    }

    /// The device's fingerprint as the holder shows it (§6), for the
    /// person to compare before the holder's prompt is answered.
    pub fn device_fingerprint(&self) -> String {
        Fingerprint::of(&self.device.public()).short()
    }

    /// Ask the holder at `mailbox` (a host, or a server's address) to
    /// certify this device as `name`, by the `code` it shows, or with no
    /// code for a renewal routed to a holder standing by for the identity
    /// (§8). Waits for the answer, and refuses one that is not for this
    /// device, or for a renewal not of the identity it renews. Refused
    /// `unknown_code`, `no_holder`, `denied` (with the holder's reason),
    /// `expired`, `answer_lost` (the holder may have answered, and the
    /// answer did not arrive), `canceled`, or as the mailbox refused; or
    /// rate limited, where the mailbox's last word was to wait.
    ///
    /// One at a time: a second while one is under way is refused `busy`.
    pub async fn enroll(
        self: Arc<Self>,
        mailbox: String,
        code: Option<String>,
        name: String,
    ) -> Result<Enrolled, CoreError> {
        if self.in_flight.swap(true, Ordering::SeqCst) {
            return Err(refused("busy"));
        }
        // Made at once, so a task aborted before it ever runs still clears it.
        let flight = Flight(self.clone());
        // Dropped (the app's call canceled), the task goes with it.
        let task = Aborting(crate::connection::RUNTIME.spawn(async move {
            let _flight = flight;
            self.run(&mailbox, code.as_deref(), &name).await
        }));
        task.wait().await
    }

    /// Stops a wait for an answer, which ends `canceled`.
    pub fn cancel(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.stop.notify_waiters();
    }

    /// Whether a request was sent at all, so a holder may have been asked
    /// even where the mailbox's reply was lost or the send cut short.
    pub fn may_have_asked(&self) -> bool {
        self.sent.load(Ordering::SeqCst)
    }

    /// The device's seed, for the app to keep beside the certificate and
    /// then wipe.
    pub fn seed(&self) -> Vec<u8> {
        self.device.seed().to_vec()
    }
}

impl Enrollee {
    /// [`Enrollee::attempt`], ended by [`Enrollee::cancel`] wherever it is,
    /// discovery and the request's post included.
    async fn run(
        &self,
        mailbox: &str,
        code: Option<&str>,
        name: &str,
    ) -> Result<Enrolled, CoreError> {
        let stopped = self.stop.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.stopped.load(Ordering::SeqCst) {
            return Err(refused("canceled"));
        }
        tokio::select! {
            _ = &mut stopped => Err(refused("canceled")),
            done = self.attempt(mailbox, code, name) => done,
        }
    }

    async fn attempt(
        &self,
        mailbox: &str,
        code: Option<&str>,
        name: &str,
    ) -> Result<Enrolled, CoreError> {
        let code = code.map(enrollment_code).transpose()?;
        let prev = match &self.prev {
            Some(c) => Some(DeviceCert::parse(c).map_err(|e| protocol(&e.to_string()))?),
            None => None,
        };
        if code.is_none() && prev.is_none() {
            return Err(refused("bad_code"));
        }
        check_name(name)?;
        let base = mailbox_base(mailbox)?;
        let http = Http {
            http: auth::http_client(base.as_str(), None)?,
            base,
        };
        let enrolled = self
            .ask(&http, code.as_deref(), prev.as_ref(), name)
            .await?;
        behind_reset(&enrolled.cert, &enrolled.card, &http.base, FLOOR_WAIT).await?;
        Ok(enrolled)
    }

    /// The request posted to `mailbox` and its answer waited for: every
    /// step the link takes, behind [`Mailbox`], so the wait can be run
    /// against a script on a clock a test moves.
    async fn ask<M: Mailbox>(
        &self,
        mailbox: &M,
        code: Option<&str>,
        prev: Option<&DeviceCert>,
        name: &str,
    ) -> Result<Enrolled, CoreError> {
        let enroll = mailbox.discover().await?;

        let mut request = EnrollRequest::new(&self.device, now());
        request.name = Some(name.to_owned());
        // A renewal asks for no more than it has (§8); a holder refuses one
        // that does.
        request.caps = match prev {
            Some(p) => p.caps,
            None => Some(ASKED),
        };
        request.prev = self.prev.clone();
        let mut body = json!({ "request": b64(&request.sign(&self.device)) });
        if let Some(code) = code {
            body["code"] = json!(code);
        }
        self.sent.store(true, Ordering::SeqCst);
        let posted = mailbox.post(&format!("{enroll}/requests"), body).await?;
        let secret = posted
            .get("request")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("the mailbox gave no request"))?
            .to_owned();
        let life = posted
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(REQUEST_LIFE)
            .min(REQUEST_LIFE);
        let posted_at = tokio::time::Instant::now();
        let deadline = posted_at + Duration::from_secs(life) + SLACK;
        // When the mailbox last said the request would be gone.
        let mut expires = posted_at + Duration::from_secs(life);
        let url = format!("{enroll}/requests/{secret}");
        // Asked for, the request is waited on whatever the link does: a
        // dropped poll, a front that is briefly down and a mailbox asking
        // for room are all asked again under the same secret until the
        // request's life is out.
        let mut backoff = POLL_FLOOR;
        // The mailbox hands an answer, or a denial, over again for a minute
        // after it is first fetched, then forgets it; an older mailbox, once.
        // One cut short on its way, or taken by a poll this phone gave up on
        // (the mailbox's side of it waits on), is fetched again by the next
        // poll inside that minute. Gone after it, "expired" would tell the
        // person the holder never said.
        let mut lost = false;
        let mut abandoned = false;
        // A mailbox whose last word was to wait: the wait it asked for.
        let mut busy: Option<Option<u64>> = None;
        let ended = |lost: bool, busy: Option<Option<u64>>| match busy {
            _ if lost => refused("answer_lost"),
            Some(retry_after) => CoreError::RateLimited { retry_after },
            None => refused("expired"),
        };
        let bundle = loop {
            let asked = tokio::time::Instant::now();
            // Never past the request's life, however long a poll may wait.
            let left = deadline.saturating_duration_since(asked);
            if left.is_zero() {
                return Err(ended(lost, busy));
            }
            let again = match mailbox.poll(&url, LONG_POLL.min(left)).await {
                Polled::Reply {
                    status,
                    body,
                    retry_after,
                } => {
                    // The mailbox's last word, until it says another.
                    busy = None;
                    let reply: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    match status {
                        200 => break bytes(&reply, "bundle")?,
                        // Not yet: asked again a floor later, and its deadline
                        // ends it at the top of the loop.
                        202 => {
                            backoff = POLL_FLOOR;
                            if let Some(s) = reply.get("expires_in").and_then(Value::as_u64) {
                                // No longer than any request lives, so the
                                // sum is one an Instant holds.
                                expires = tokio::time::Instant::now()
                                    + Duration::from_secs(s.min(REQUEST_LIFE));
                            }
                            tokio::time::sleep_until((asked + POLL_FLOOR).min(deadline)).await;
                            continue;
                        }
                        // Gone while it still had life: a poll given up on
                        // may have taken its answer.
                        404 | 410 => {
                            let early = tokio::time::Instant::now() < expires;
                            return Err(ended(lost || (abandoned && early), None));
                        }
                        403 => {
                            return Err(CoreError::Refused {
                                code: "denied".into(),
                                detail: denial(
                                    reply
                                        .get("denied")
                                        .and_then(Value::as_str)
                                        .unwrap_or_default(),
                                ),
                                successor: None,
                            })
                        }
                        // As long as the mailbox asks, never less than the floor.
                        429 => {
                            let asked = crate::restore::retry_after(&body).or(retry_after);
                            busy = Some(asked);
                            asked.map(|s| Duration::from_secs(s).max(POLL_FLOOR))
                        }
                        // A front between here and the mailbox, down or giving
                        // up on a long poll (a CDN's 52x among them): the
                        // request is still there. Not what no server does.
                        501 | 505 => {
                            return Err(protocol(&format!("the mailbox answered {status}")))
                        }
                        500..=599 => None,
                        _ => return Err(protocol(&format!("the mailbox answered {status}"))),
                    }
                }
                Polled::Dropped => {
                    abandoned = true;
                    None
                }
                Polled::Cut => None,
                Polled::Lost => {
                    lost = true;
                    None
                }
                Polled::Failed(e) => return Err(e),
            };
            let wait = again.unwrap_or_else(|| {
                let wait = backoff;
                backoff = (backoff * 2).min(MOST_BACKOFF);
                wait
            });
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(wait.min(left)).await;
        };
        self.checked(&bundle)
    }

    /// The answer as the paste was checked (§5.5): a certificate for this
    /// device's signing and encryption keys alike, signed by the identity
    /// whose card it comes with, in its time, that lets the device log in
    /// and that a server takes; and from the identity expected, if one is.
    fn checked(&self, bundle: &[u8]) -> Result<Enrolled, CoreError> {
        let bundle = Bundle::parse(bundle).map_err(|e| protocol(&format!("the answer: {e}")))?;
        let (cert, card) = bundle
            .open()
            .map_err(|e| protocol(&format!("the answer does not hold: {e}")))?;
        if cert.device != self.device.public() || cert.device_enc != self.device.public_enc() {
            return Err(refused("wrong_device"));
        }
        if self
            .expected
            .lock()
            .unwrap()
            .is_some_and(|fp| fp != Fingerprint::of(&cert.identity))
        {
            return Err(refused("wrong_identity"));
        }
        if bundle.cert.len() > MAX_CERT || !cert.allows(caps::LOGIN) {
            return Err(refused("cert_unusable"));
        }
        // The phone never holds vouch (design §2.3): a holder granting it
        // grants more than any screen here would use.
        if cert.allows(caps::VOUCH) {
            return Err(refused("cert_vouches"));
        }
        crate::identity::in_time(&bundle.cert)?;
        // A renewal that is itself already due would be asked for again at
        // once, every day: no renewal at all.
        if self.prev.is_some() && renewal_due(cert.issued, cert.expires, now()) {
            return Err(refused("short_renewal"));
        }
        let fingerprint = Fingerprint::of(&cert.identity);
        let info = crate::cert_info(
            bundle.cert.clone(),
            bundle.card.clone(),
            self.device.public().to_vec(),
            self.device.public_enc().to_vec(),
        )?;
        Ok(Enrolled {
            info,
            cert: bundle.cert,
            card: bundle.card,
            fingerprint: fingerprint.to_string(),
            short: fingerprint.short(),
            name: card.name,
        })
    }
}

/// How long an enrollee reads its new certificate's floor for.
const FLOOR_WAIT: Duration = Duration::from_secs(10);

/// Refused `behind_reset` for a certificate below the floor its card's
/// registrars publish, each read for up to `wait`, and the mailbox that
/// sent it where it is one of them by host: the holder that answered had
/// not learned of a reset, and servers that have refuse the certificate.
/// One not read in time is passed over. The certificate's time is read
/// again after, as the wait may have outlasted it.
async fn behind_reset(
    cert_bytes: &[u8],
    card: &[u8],
    mailbox: &Url,
    wait: Duration,
) -> Result<(), CoreError> {
    let cert = DeviceCert::parse(cert_bytes).map_err(|e| protocol(&e.to_string()))?;
    let card = Card::parse(card).map_err(|e| protocol(&e.to_string()))?;
    let mut registrars = crate::epoch::registrars_of(&[], &card);
    let host = mailbox.host_str().unwrap_or_default();
    let at_mailbox = mailbox.origin().ascii_serialization();
    if registrars.iter().any(|r| r == host)
        && crate::restore::registrar_base(host).ok().as_ref() != Some(mailbox)
    {
        registrars.push(at_mailbox);
    }
    let published = crate::epoch::published_at(&registrars, &card.identity, wait).await;
    if cert.check_floor(published.epoch).is_err() {
        return Err(refused("behind_reset"));
    }
    crate::identity::in_time(cert_bytes)
}

/// Clears an enrollment's in-flight mark however it ends, aborted before
/// it began included.
struct Flight(Arc<Enrollee>);

impl Drop for Flight {
    fn drop(&mut self) {
        self.0.in_flight.store(false, Ordering::SeqCst);
    }
}

/// A spawned enrollment, aborted if what waits for it is dropped.
struct Aborting(tokio::task::JoinHandle<Result<Enrolled, CoreError>>);

impl Aborting {
    async fn wait(mut self) -> Result<Enrolled, CoreError> {
        (&mut self.0)
            .await
            .unwrap_or_else(|_| Err(protocol("the enrollment stopped")))
    }
}

impl Drop for Aborting {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A code as typed, in the form the holder shows it (§5.1): case, spaces
/// and the hyphen do not matter, and Crockford's look-alikes read as what
/// they look like, as the mailbox reads them. Refused `bad_code` unless
/// eight symbols of its alphabet are left.
#[uniffi::export]
pub fn enrollment_code(code: &str) -> Result<String, CoreError> {
    const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let symbols: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            'U' => 'V',
            c => c,
        })
        .collect();
    if symbols.len() != 8 || !symbols.chars().all(|c| ALPHABET.contains(c)) {
        return Err(refused("bad_code"));
    }
    Ok(format!("{}-{}", &symbols[..4], &symbols[4..]))
}

/// The name `card` gives its identity, if it reads.
#[uniffi::export]
pub fn card_name(card: Vec<u8>) -> Option<String> {
    Card::parse(&card).ok().map(|c| c.name)
}

/// Of two cards of one identity, the newer by its `updated`: a renewal's
/// answer may carry a card older than one this phone already keeps.
/// `offered` where they are not both of one identity.
#[uniffi::export]
pub fn newer_card(kept: Vec<u8>, offered: Vec<u8>) -> Vec<u8> {
    match (Card::parse(&kept), Card::parse(&offered)) {
        (Ok(k), Ok(o)) if k.identity == o.identity && k.updated > o.updated => kept,
        _ => offered,
    }
}

/// Whether a certificate from `issued` to `expires` is due to be renewed at
/// `now`: with a third of its life or less left (`hotline-ng-identity.md`
/// §3.3), when a holder standing by renews it with nobody typing.
#[uniffi::export]
pub fn renewal_due(issued: u64, expires: u64, now: u64) -> bool {
    let life = expires.saturating_sub(issued);
    expires.saturating_sub(now).saturating_mul(3) <= life
}

/// What one poll for an answer came to.
pub(crate) enum Polled {
    /// The mailbox answered: a status, the whole body, and the seconds a
    /// `Retry-After` header asks for.
    Reply {
        status: u16,
        body: Vec<u8>,
        retry_after: Option<u64>,
    },
    /// The link dropped, or the poll outwaited its time, before a reply:
    /// worth asking again under the same secret.
    Dropped,
    /// An answer (200) or a denial (403) whose body was cut short: handed
    /// over, and a mailbox that hands it over once has forgotten it.
    Lost,
    /// Any other reply cut short: answered, so nothing was left waiting at
    /// the mailbox, and worth asking again.
    Cut,
    /// A fault asking again would not mend: a scheme the client refuses,
    /// a reply longer than any answer.
    Failed(CoreError),
}

/// A mailbox as the enrollment reaches it: over HTTP for real, or a script
/// for the tests of the wait, which a real socket would hold to real time.
pub(crate) trait Mailbox {
    /// The mailbox's prefix, from its server's discovery.
    async fn discover(&self) -> Result<String, CoreError>;
    async fn post(&self, url: &str, body: Value) -> Result<Value, CoreError>;
    /// A long poll of `url`, given up on after `wait`.
    async fn poll(&self, url: &str, wait: Duration) -> Polled;
}

struct Http {
    http: hxng_client::reqwest::Client,
    base: Url,
}

impl Mailbox for Http {
    async fn discover(&self) -> Result<String, CoreError> {
        discovered(&self.http, &self.base).await
    }

    async fn post(&self, url: &str, body: Value) -> Result<Value, CoreError> {
        Ok(auth::post(&self.http, url, Some(body)).await?)
    }

    async fn poll(&self, url: &str, wait: Duration) -> Polled {
        let mut resp = match self.http.get(url).timeout(wait).send().await {
            Ok(r) => r,
            // An https-only client refusing a plain URL; a TLS failure mid-wait
            // is a network change more often than not, and asked again.
            Err(e) if e.is_builder() => {
                return Polled::Failed(CoreError::Connect {
                    detail: e.to_string(),
                })
            }
            Err(_) => return Polled::Dropped,
        };
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok());
        let mut body = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() > MOST_REPLY => {
                    return Polled::Failed(protocol("a reply longer than any answer"))
                }
                Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                Ok(None) => {
                    return Polled::Reply {
                        status,
                        body,
                        retry_after,
                    }
                }
                Err(_) if matches!(status, 200 | 403) => return Polled::Lost,
                Err(_) => return Polled::Cut,
            }
        }
    }
}

/// Where a mailbox is reached: `https://host` for a host, or the origin of
/// a server's address (`wss://` or `ws://`, `https://` or `http://`), which
/// is where its discovery is. Plain http only to this machine, refused
/// `cleartext_mailbox` elsewhere: over it anyone on the path could see the
/// code and swap the request or the answer, leaving both bindings to the
/// person's comparison alone (design §9).
pub(crate) fn mailbox_base(mailbox: &str) -> Result<Url, CoreError> {
    let text = mailbox.trim();
    let text = if text.contains("://") {
        text.to_owned()
    } else {
        format!("https://{text}")
    };
    let mut url = Url::parse(&text).map_err(|_| refused("bad_mailbox"))?;
    let scheme = match url.scheme() {
        "https" | "wss" => "https",
        "http" | "ws" => "http",
        _ => return Err(refused("bad_mailbox")),
    };
    if url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(refused("bad_mailbox"));
    }
    let host = url.host_str().unwrap_or_default();
    let loopback = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if scheme == "http" && !loopback {
        return Err(refused("cleartext_mailbox"));
    }
    url.set_scheme(scheme).map_err(|_| refused("bad_mailbox"))?;
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// The mailbox's prefix, from the server's discovery (§3), on its own
/// origin and no other. Refused `no_mailbox` where it serves none.
async fn discovered(http: &hxng_client::reqwest::Client, base: &Url) -> Result<String, CoreError> {
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
    let path = ["identity", "registrar"]
        .iter()
        .find_map(|block| doc[block]["endpoints"]["enroll"].as_str())
        .ok_or_else(|| refused("no_mailbox"))?;
    endpoint(base, path).map_err(|_| refused("no_mailbox"))
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_certificate_below_the_floor_its_cards_registrar_publishes_is_refused() {
        use crate::epoch::tests::{registrar_publishing, reset};
        use hl_identity::{Attestation, IdentityKey, ServerKey};
        let id = IdentityKey::generate();
        let mailbox = registrar_publishing(vec![reset(&id, 2)], 8).await;
        let key = ServerKey::from_seed(&[5; 32]);
        let card = |registrar: &str| {
            let att = Attestation {
                identity: id.public(),
                registrar: registrar.into(),
                registrar_key: key.public(),
                handle: "alice".into(),
                registered: 1,
                issued: 1,
                expires: u64::MAX / 2,
                level: None,
            }
            .sign(&key);
            let att = hl_identity::cbor::decode_canonical(&att).unwrap();
            Card::new(&id, "Alice", 10).sign(&id, vec![att]).unwrap()
        };
        let cert = |epoch| {
            let device = DeviceKey::generate();
            let mut c = DeviceCert::for_device(&id, &device, now(), 86_400).unwrap();
            c.epoch = epoch;
            c.sign(&id)
        };
        for (epoch, attested, refused_as) in [
            (1, "127.0.0.1", Some("behind_reset")),
            (2, "127.0.0.1", None),
            (3, "127.0.0.1", None),
            // A floor the card names no registrar for is not learned.
            (1, "elsewhere.invalid", None),
        ] {
            let got = behind_reset(&cert(epoch), &card(attested), &mailbox, FLOOR_WAIT).await;
            let got = got.err().map(|e| match e {
                CoreError::Refused { code, .. } => code,
                e => panic!("{e:?}"),
            });
            assert_eq!(got.as_deref(), refused_as, "epoch {epoch} at {attested}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_certificate_that_lapses_while_its_floor_is_read_is_refused() {
        use hl_identity::{Attestation, IdentityKey, ServerKey};
        let id = IdentityKey::generate();
        // Its one registrar takes the connection and never answers.
        let mailbox = Url::parse(&crate::epoch::tests::silent().await).unwrap();
        let key = ServerKey::from_seed(&[5; 32]);
        let att = Attestation {
            identity: id.public(),
            registrar: "127.0.0.1".into(),
            registrar_key: key.public(),
            handle: "alice".into(),
            registered: 1,
            issued: 1,
            expires: u64::MAX / 2,
            level: None,
        }
        .sign(&key);
        let att = hl_identity::cbor::decode_canonical(&att).unwrap();
        let card = Card::new(&id, "Alice", 10).sign(&id, vec![att]).unwrap();
        // In its time for a second more, by the skew a server allows.
        let issued = now() - 1_000;
        let life = now() + 1 - hxng_client::auth::CLOCK_SKEW - issued;
        let cert = DeviceCert::for_device(&id, &DeviceKey::generate(), issued, life)
            .unwrap()
            .sign(&id);
        crate::identity::in_time(&cert).unwrap();
        let got = behind_reset(&cert, &card, &mailbox, Duration::from_secs(3)).await;
        match got {
            Err(CoreError::Refused { code, .. }) => assert_eq!(code, "cert_expired"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_code_is_read_as_the_mailbox_reads_it_and_shown_as_the_holder_shows_it() {
        for (typed, want) in [
            ("K7PM-4XWE", Some("K7PM-4XWE")),
            ("k7pm4xwe", Some("K7PM-4XWE")),
            (" k7pm 4xwe ", Some("K7PM-4XWE")),
            ("IL0O-uuuu", Some("1100-VVVV")),
            ("K7PM-4XW", None),
            ("K7PM-4XWE9", None),
            ("K7PM_4XWE", None),
            ("", None),
        ] {
            assert_eq!(enrollment_code(typed).ok().as_deref(), want, "{typed:?}");
        }
    }

    #[test]
    fn a_certificate_is_due_for_renewal_with_a_third_of_its_life_left() {
        for (now, due) in [
            (0, false),
            (599, false),
            (600, true),
            (899, true),
            (2000, true),
        ] {
            assert_eq!(renewal_due(0, 900, now), due, "{now}");
        }
    }

    #[test]
    fn an_answer_is_kept_only_from_the_identity_expected_and_only_if_it_signs_in_without_vouching()
    {
        use hl_identity::{Card, IdentityKey};
        let alice = IdentityKey::generate();
        let mallory = IdentityKey::generate();
        let phone = Enrollee::new();
        let answer = |id: &IdentityKey, caps: Option<u64>| {
            let mut cert = DeviceCert::for_keys(
                id,
                phone.device.public(),
                phone.device.public_enc(),
                now(),
                86_400,
            )
            .unwrap();
            cert.caps = caps;
            Bundle {
                cert: cert.sign(id),
                card: Card::new(id, "Alice", now()).sign(id, Vec::new()).unwrap(),
            }
            .encode()
        };
        let code = |r: Result<Enrolled, CoreError>| match r {
            Ok(_) => "kept".to_owned(),
            Err(CoreError::Refused { code, .. }) => code,
            Err(e) => format!("{e:?}"),
        };
        const WEB: Option<u64> = Some(caps::LOGIN | caps::MESSAGE);
        assert_eq!(
            code(phone.checked(&answer(&mallory, WEB))),
            "kept",
            "none expected"
        );
        // No caps is every cap, vouch among them.
        assert_eq!(code(phone.checked(&answer(&mallory, None))), "cert_vouches");
        assert_eq!(
            code(phone.checked(&answer(&mallory, Some(caps::LOGIN | caps::VOUCH)))),
            "cert_vouches"
        );
        assert_eq!(
            code(phone.checked(&answer(&alice, Some(caps::MESSAGE)))),
            "cert_unusable"
        );
        // A renewal whose old device is gone still names its identity.
        phone
            .expect_identity(Fingerprint::of(&alice.public()).to_string())
            .unwrap();
        assert_eq!(
            code(phone.checked(&answer(&mallory, WEB))),
            "wrong_identity"
        );
        assert_eq!(code(phone.checked(&answer(&alice, WEB))), "kept");
    }

    #[test]
    fn a_renewal_already_due_again_is_refused() {
        use hl_identity::{Card, IdentityKey};
        let alice = IdentityKey::generate();
        let device = DeviceKey::generate();
        let web = |mut c: DeviceCert| {
            c.caps = Some(caps::LOGIN | caps::MESSAGE);
            c.sign(&alice)
        };
        let cert = |issued: u64, life: u64| {
            web(
                DeviceCert::for_keys(&alice, device.public(), device.public_enc(), issued, life)
                    .unwrap(),
            )
        };
        let renewing = Enrollee::renewing(device.seed().to_vec(), cert(now(), 86_400)).unwrap();
        let card = Card::new(&alice, "Alice", now())
            .sign(&alice, Vec::new())
            .unwrap();
        let answer = |cert: Vec<u8>| {
            Bundle {
                cert,
                card: card.clone(),
            }
            .encode()
        };
        let code = |r: Result<Enrolled, CoreError>| match r {
            Ok(_) => "kept".to_owned(),
            Err(CoreError::Refused { code, .. }) => code,
            Err(e) => format!("{e:?}"),
        };
        assert_eq!(
            code(renewing.checked(&answer(cert(now(), 3 * 86_400)))),
            "kept"
        );
        // Two of its three days gone already.
        let stale = cert(now() - 2 * 86_400, 3 * 86_400);
        assert_eq!(code(renewing.checked(&answer(stale))), "short_renewal");
        // A first enrollment's certificate is the holder's to make so.
        let first = Enrollee::new();
        let theirs = web(DeviceCert::for_keys(
            &alice,
            first.device.public(),
            first.device.public_enc(),
            now() - 2 * 86_400,
            3 * 86_400,
        )
        .unwrap());
        assert_eq!(code(first.checked(&answer(theirs))), "kept");
    }

    #[test]
    fn a_holders_reason_is_kept_only_as_words_it_could_have_chosen() {
        for (said, shown) in [
            ("not_mine", "not_mine"),
            ("declined", "declined"),
            ("too many", "too many"),
            ("Call me at evil.example", ""),
            ("\u{202e}reversed", ""),
            (&"x".repeat(33), ""),
        ] {
            assert_eq!(denial(said), shown, "{said:?}");
        }
    }

    #[test]
    fn the_newer_card_of_one_identity_is_kept() {
        use hl_identity::IdentityKey;
        let alice = IdentityKey::generate();
        let card = |updated| {
            Card::new(&alice, "Alice", updated)
                .sign(&alice, Vec::new())
                .unwrap()
        };
        let bob = IdentityKey::generate();
        let bobs = Card::new(&bob, "Bob", 900).sign(&bob, Vec::new()).unwrap();
        assert_eq!(newer_card(card(900), card(100)), card(900));
        assert_eq!(newer_card(card(100), card(900)), card(900));
        assert_eq!(newer_card(bobs, card(100)), card(100), "another identity's");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancel_ends_an_enrollment_still_finding_its_mailbox() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Takes the connection and never answers.
        let held = tokio::spawn(async move { listener.accept().await });
        let phone = Enrollee::new();
        let asking = tokio::spawn(phone.clone().enroll(
            format!("http://127.0.0.1:{port}"),
            Some("K7PM-4XWE".into()),
            "Hexline".into(),
        ));
        // Held open until the test is done.
        let _connection = held.await;
        phone.cancel();
        let ended = tokio::time::timeout(Duration::from_secs(5), asking)
            .await
            .expect("canceled at once")
            .unwrap();
        assert!(
            matches!(ended, Err(CoreError::Refused { ref code, .. }) if code == "canceled"),
            "{ended:?}"
        );
        assert!(!phone.may_have_asked());
    }

    /// A mailbox whose requests live `life` seconds and whose polls are
    /// answered `polls` in turn, the last again and again: each a status and
    /// a body. Hands back its port, and when each poll came.
    async fn mailbox(
        life: u64,
        polls: Vec<(u16, String)>,
    ) -> (u16, Arc<Mutex<Vec<std::time::Instant>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let times = asked.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (status, body) = if head.starts_with("GET /.well-known/hotline") {
                    (
                        200,
                        r#"{"identity":{"endpoints":{"enroll":"/identity/enroll"}}}"#.to_owned(),
                    )
                } else if head.starts_with("POST /identity/enroll/requests") {
                    (201, format!(r#"{{"request":"r1","expires_in":{life}}}"#))
                } else {
                    let mut t = times.lock().unwrap();
                    t.push(std::time::Instant::now());
                    polls[(t.len() - 1).min(polls.len() - 1)].clone()
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        (port, asked)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_mailbox_saying_not_yet_is_asked_again_a_second_later_until_it_answers() {
        use hl_identity::IdentityKey;
        let alice = IdentityKey::generate();
        let phone = Enrollee::new();
        let mut cert = DeviceCert::for_keys(
            &alice,
            phone.device.public(),
            phone.device.public_enc(),
            now(),
            86_400,
        )
        .unwrap();
        cert.caps = Some(caps::LOGIN | caps::MESSAGE);
        let bundle = Bundle {
            cert: cert.sign(&alice),
            card: Card::new(&alice, "Alice", now())
                .sign(&alice, Vec::new())
                .unwrap(),
        }
        .encode();
        let not_yet = (202, r#"{"expires_in":50}"#.to_owned());
        let answer = (200, format!(r#"{{"bundle":"{}"}}"#, b64(&bundle)));
        let (port, asked) = mailbox(60, vec![not_yet.clone(), not_yet, answer]).await;
        let enrolled = tokio::time::timeout(
            Duration::from_secs(20),
            phone.clone().enroll(
                format!("http://127.0.0.1:{port}"),
                Some("K7PM-4XWE".into()),
                "Hexline".into(),
            ),
        )
        .await
        .expect("answered in time")
        .unwrap();
        assert_eq!(enrolled.name, "Alice");
        let times = asked.lock().unwrap().clone();
        assert_eq!(times.len(), 3);
        for pair in times.windows(2) {
            assert!(
                pair[1] - pair[0] >= Duration::from_millis(900),
                "asked again too soon"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_past_its_life_or_gone_from_the_mailbox_has_expired() {
        // Not yet, past the request's life; and the request gone, either way.
        for (life, status, body) in [
            (1, 202, r#"{"expires_in":1}"#),
            (60, 410, ""),
            (60, 404, ""),
        ] {
            let (port, _) = mailbox(life, vec![(status, body.to_owned())]).await;
            let ended = tokio::time::timeout(
                Duration::from_secs(20),
                Enrollee::new().enroll(
                    format!("http://127.0.0.1:{port}"),
                    Some("K7PM-4XWE".into()),
                    "Hexline".into(),
                ),
            )
            .await
            .expect("ended in time");
            assert!(
                matches!(ended, Err(CoreError::Refused { ref code, .. }) if code == "expired"),
                "{status}: {ended:?}"
            );
        }
    }

    #[test]
    fn a_card_is_read_for_its_name_and_a_tie_keeps_the_card_answered() {
        use hl_identity::IdentityKey;
        let alice = IdentityKey::generate();
        let card = |name: &str| {
            Card::new(&alice, name, 900)
                .sign(&alice, Vec::new())
                .unwrap()
        };
        assert_eq!(card_name(card("Alice")).as_deref(), Some("Alice"));
        assert_eq!(card_name(vec![1, 2, 3]), None);
        // Of two cards updated at once, the answer's is as good as the one kept.
        assert_eq!(newer_card(card("Old"), card("New")), card("New"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_wait_ends_with_its_requests_life_however_long_a_poll_hangs() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // A mailbox whose requests live a second, and whose polls never answer.
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = if head.starts_with("GET /.well-known/hotline") {
                    r#"{"identity":{"endpoints":{"enroll":"/identity/enroll"}}}"#
                } else if head.starts_with("POST /identity/enroll/requests") {
                    r#"{"request":"r1","expires_in":1}"#
                } else {
                    held.push(s);
                    continue;
                };
                let status = if head.starts_with("POST") {
                    "201 Created"
                } else {
                    "200 OK"
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        let started = std::time::Instant::now();
        let ended = Enrollee::new()
            .enroll(
                format!("http://127.0.0.1:{port}"),
                Some("K7PM-4XWE".into()),
                "Hexline".into(),
            )
            .await;
        assert!(
            matches!(ended, Err(CoreError::Refused { ref code, .. }) if code == "expired"),
            "{ended:?}"
        );
        // Its life and the slack after it, not a long poll more.
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_device_waits_for_one_answer_at_a_time() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let held = tokio::spawn(async move { listener.accept().await });
        let phone = Enrollee::new();
        let mailbox = format!("http://127.0.0.1:{port}");
        let first = tokio::spawn(phone.clone().enroll(
            mailbox.clone(),
            Some("K7PM-4XWE".into()),
            "Hexline".into(),
        ));
        let _connection = held.await;
        let second = phone
            .clone()
            .enroll(mailbox.clone(), Some("K7PM-4XWE".into()), "Hexline".into())
            .await;
        assert!(
            matches!(second, Err(CoreError::Refused { ref code, .. }) if code == "busy"),
            "{second:?}"
        );
        // The first's call let go of, its task goes, and another may ask.
        first.abort();
        let _ = first.await;
        for _ in 0..100 {
            if !phone.in_flight.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !phone.in_flight.load(Ordering::SeqCst),
            "the aborted one's mark cleared"
        );
    }

    #[test]
    fn an_enrollment_let_go_of_before_its_task_ran_leaves_the_device_free() {
        use std::future::Future;
        let phone = Enrollee::new();
        for _ in 0..50 {
            let mut call = Box::pin(phone.clone().enroll(
                "http://127.0.0.1:9".into(),
                Some("K7PM-4XWE".into()),
                "Hexline".into(),
            ));
            // Polled once, so it is in flight, then let go of at once.
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(call.as_mut().poll(&mut cx).is_pending());
            drop(call);
            for _ in 0..100 {
                if !phone.in_flight.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(!phone.in_flight.load(Ordering::SeqCst), "still in flight");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_whose_reply_is_lost_may_have_asked_a_holder() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Discovery answered; the post taken and its reply never sent.
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                if buf[..n].starts_with(b"GET /.well-known/hotline") {
                    let body = r#"{"identity":{"endpoints":{"enroll":"/identity/enroll"}}}"#;
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                }
            }
        });
        let phone = Enrollee::new();
        let ended = phone
            .clone()
            .enroll(
                format!("http://127.0.0.1:{port}"),
                Some("K7PM-4XWE".into()),
                "Hexline".into(),
            )
            .await;
        assert!(matches!(ended, Err(CoreError::Connect { .. })), "{ended:?}");
        assert!(phone.may_have_asked());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_mailbox_asked_too_often_says_how_long_to_wait() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0; 1024];
            let _ = s.read(&mut buf).await;
            let body = r#"{"error":"rate_limited","retry_after":7}"#;
            let reply = format!(
                "HTTP/1.1 429 Too Many Requests\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(reply.as_bytes()).await.unwrap();
        });
        let base = mailbox_base(&format!("http://127.0.0.1:{port}")).unwrap();
        let http = auth::http_client(base.as_str(), None).unwrap();
        match discovered(&http, &base).await {
            Err(CoreError::RateLimited { retry_after }) => assert_eq!(retry_after, Some(7)),
            other => panic!("{other:?}"),
        }
    }

    /// A certificate for `phone` from a holder who approved it, as the
    /// mailbox's 200 carries it.
    fn approved(phone: &Enrollee) -> Vec<u8> {
        use hl_identity::IdentityKey;
        let alice = IdentityKey::generate();
        let mut cert = DeviceCert::for_keys(
            &alice,
            phone.device.public(),
            phone.device.public_enc(),
            now(),
            86_400,
        )
        .unwrap();
        cert.caps = Some(caps::LOGIN | caps::MESSAGE);
        let bundle = Bundle {
            cert: cert.sign(&alice),
            card: Card::new(&alice, "Alice", now())
                .sign(&alice, Vec::new())
                .unwrap(),
        }
        .encode();
        format!(r#"{{"bundle":"{}"}}"#, b64(&bundle)).into_bytes()
    }

    /// What a scripted mailbox does with one poll.
    #[derive(Clone, Debug)]
    enum Step {
        NotYet,
        /// Not yet, and the request gone in so many seconds.
        NotYetFor(u64),
        Answer,
        Denied,
        Gone,
        Busy(Option<u64>),
        /// Asking for room by its `Retry-After` header alone, nested
        /// under `error` as the ng port puts it, or both.
        BusyHeader(u64),
        BusyNested(u64),
        Front(u16),
        Dropped,
        Lost,
        Broken,
    }

    /// A mailbox that answers its polls as `steps` say, each after its
    /// delay (one past the poll's wait is the poll timing out), and "not
    /// yet" once they run out. Run on paused time, its delays cost nothing.
    struct Script {
        found: bool,
        life: u64,
        answer: Vec<u8>,
        steps: Mutex<std::collections::VecDeque<(Duration, Step)>>,
        posts: std::sync::atomic::AtomicUsize,
        polls: Mutex<Vec<tokio::time::Instant>>,
        /// What each poll was answered, a timed-out one as dropped.
        heard: Mutex<Vec<Step>>,
    }

    impl Script {
        fn new(phone: &Enrollee, life: u64, steps: &[(Duration, Step)]) -> Script {
            Script {
                found: true,
                life,
                answer: approved(phone),
                steps: Mutex::new(steps.iter().cloned().collect()),
                posts: Default::default(),
                polls: Default::default(),
                heard: Default::default(),
            }
        }

        fn polls(&self) -> Vec<tokio::time::Instant> {
            self.polls.lock().unwrap().clone()
        }
    }

    impl Mailbox for Script {
        async fn discover(&self) -> Result<String, CoreError> {
            if self.found {
                Ok("https://hl.example/identity/enroll".into())
            } else {
                Err(refused("no_mailbox"))
            }
        }

        async fn post(&self, _: &str, _: Value) -> Result<Value, CoreError> {
            self.posts.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "request": "r1", "expires_in": self.life }))
        }

        async fn poll(&self, _: &str, wait: Duration) -> Polled {
            self.polls.lock().unwrap().push(tokio::time::Instant::now());
            let (delay, step) = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or((Duration::ZERO, Step::NotYet));
            let step = if delay > wait {
                tokio::time::sleep(wait).await;
                Step::Dropped
            } else {
                tokio::time::sleep(delay).await;
                step
            };
            self.heard.lock().unwrap().push(step.clone());
            let reply = |status, body: &[u8]| Polled::Reply {
                status,
                body: body.to_vec(),
                retry_after: None,
            };
            match step {
                Step::NotYet => reply(202, b"{}"),
                Step::NotYetFor(s) => reply(202, json!({ "expires_in": s }).to_string().as_bytes()),
                Step::Answer => reply(200, &self.answer),
                Step::Denied => reply(403, br#"{"denied":"not_mine"}"#),
                Step::Gone => reply(410, b""),
                Step::Busy(after) => reply(
                    429,
                    json!({ "error": "rate_limited", "retry_after": after })
                        .to_string()
                        .as_bytes(),
                ),
                Step::BusyHeader(after) => Polled::Reply {
                    status: 429,
                    body: Vec::new(),
                    retry_after: Some(after),
                },
                Step::BusyNested(after) => reply(
                    429,
                    json!({ "error": { "code": "rate_limited", "retry_after": after } })
                        .to_string()
                        .as_bytes(),
                ),
                Step::Front(status) => reply(status, b""),
                Step::Dropped => Polled::Dropped,
                Step::Lost => Polled::Lost,
                Step::Broken => Polled::Failed(protocol("a reply longer than any answer")),
            }
        }
    }

    fn outcome(r: &Result<Enrolled, CoreError>) -> String {
        match r {
            Ok(_) => "kept".to_owned(),
            Err(CoreError::Refused { code, .. }) => code.clone(),
            Err(e) => format!("{e:?}"),
        }
    }

    const S: fn(u64) -> Duration = Duration::from_secs;

    async fn asked(phone: &Enrollee, script: &Script) -> (String, Duration) {
        let started = tokio::time::Instant::now();
        let r = phone.ask(script, Some("K7PM-4XWE"), None, "Hexline").await;
        (outcome(&r), started.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_lasts_its_requests_life_and_the_slack_after_it() {
        let phone = Enrollee::new();
        let script = Script::new(&phone, 10, &[]);
        assert_eq!(asked(&phone, &script).await, ("expired".into(), S(15)));
        let polls = script.polls();
        assert_eq!(polls.len(), 15, "a second apart, from the start to the end");
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_link_is_asked_again_later_each_time_up_to_a_ceiling() {
        let phone = Enrollee::new();
        let mut steps = vec![(Duration::ZERO, Step::Dropped); 7];
        steps.push((Duration::ZERO, Step::Answer));
        let script = Script::new(&phone, 300, &steps);
        assert_eq!(asked(&phone, &script).await.0, "kept");
        let polls = script.polls();
        let gaps: Vec<Duration> = polls.windows(2).map(|w| w[1] - w[0]).collect();
        assert_eq!(gaps, [1, 2, 4, 8, 8, 8, 8].map(S));
    }

    #[tokio::test(start_paused = true)]
    async fn a_front_down_or_a_mailbox_asking_for_room_does_not_end_the_wait() {
        for (step, gap) in [
            (Step::Front(500), S(1)),
            (Step::Front(502), S(1)),
            (Step::Front(503), S(1)),
            (Step::Front(504), S(1)),
            (Step::Front(522), S(1)),
            (Step::Busy(Some(7)), S(7)),
            (Step::Busy(Some(0)), S(1)),
            (Step::Busy(None), S(1)),
            (Step::BusyHeader(7), S(7)),
            (Step::BusyNested(5), S(5)),
        ] {
            let phone = Enrollee::new();
            let script = Script::new(
                &phone,
                300,
                &[
                    (Duration::ZERO, step.clone()),
                    (Duration::ZERO, Step::Answer),
                ],
            );
            assert_eq!(asked(&phone, &script).await.0, "kept", "{step:?}");
            let polls = script.polls();
            assert_eq!(polls[1] - polls[0], gap, "{step:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_mailbox_asking_for_more_room_than_the_request_has_left_is_waited_on_to_its_end() {
        let phone = Enrollee::new();
        let script = Script::new(&phone, 3, &[(Duration::ZERO, Step::Busy(Some(100)))]);
        let (ended, took) = asked(&phone, &script).await;
        assert_eq!(
            (ended.as_str(), took),
            ("RateLimited { retry_after: Some(100) }", S(8))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_mailbox_asking_for_room_then_unheard_from_ends_rate_limited() {
        let phone = Enrollee::new();
        let mut steps = vec![(Duration::ZERO, Step::Busy(Some(2)))];
        steps.extend(vec![(Duration::ZERO, Step::Dropped); 10]);
        let script = Script::new(&phone, 5, &steps);
        let (ended, took) = asked(&phone, &script).await;
        assert_eq!(
            (ended.as_str(), took),
            ("RateLimited { retry_after: Some(2) }", S(10))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_lost_on_its_way_is_told_apart_from_no_answer() {
        let z = Duration::ZERO;
        for (steps, ends) in [
            (vec![(z, Step::Lost), (z, Step::Gone)], "answer_lost"),
            (vec![(z, Step::Lost)], "answer_lost"),
            // A poll given up on, its mailbox side taking the answer.
            (vec![(z, Step::Dropped), (z, Step::Gone)], "answer_lost"),
            // Gone early with nothing given up on: the holder's session ended.
            (vec![(z, Step::NotYet), (z, Step::Gone)], "expired"),
            // Gone when the mailbox last said it would be, or before.
            (
                vec![(z, Step::NotYetFor(0)), (z, Step::Dropped), (z, Step::Gone)],
                "expired",
            ),
            (
                vec![
                    (z, Step::NotYetFor(10)),
                    (z, Step::Dropped),
                    (z, Step::Gone),
                ],
                "answer_lost",
            ),
            // A life no request has is held to the one it may have.
            (
                vec![
                    (z, Step::NotYetFor(u64::MAX)),
                    (z, Step::Dropped),
                    (z, Step::Gone),
                ],
                "answer_lost",
            ),
            (vec![(z, Step::Gone)], "expired"),
        ] {
            let phone = Enrollee::new();
            let script = Script::new(&phone, 30, &steps);
            assert_eq!(asked(&phone, &script).await.0, ends, "{steps:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_fault_asking_again_would_meet_ends_the_wait_at_once() {
        for step in [
            Step::Broken,
            Step::Front(501),
            Step::Front(505),
            Step::Front(400),
        ] {
            let phone = Enrollee::new();
            let script = Script::new(&phone, 300, &[(Duration::ZERO, step.clone())]);
            let (ended, took) = asked(&phone, &script).await;
            assert_ne!(ended, "kept");
            assert_eq!(
                (script.polls().len(), took),
                (1, Duration::ZERO),
                "{step:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_mailbox_that_is_not_found_is_never_asked() {
        let phone = Enrollee::new();
        let mut script = Script::new(&phone, 300, &[]);
        script.found = false;
        assert_eq!(asked(&phone, &script).await.0, "no_mailbox");
        assert_eq!(script.posts.load(Ordering::SeqCst), 0);
        assert!(!phone.may_have_asked());
    }

    mod waits {
        use super::*;
        use proptest::prelude::*;

        fn step() -> impl Strategy<Value = Step> {
            prop_oneof![
                Just(Step::NotYet),
                prop_oneof![0u64..60, Just(u64::MAX)].prop_map(Step::NotYetFor),
                Just(Step::Answer),
                Just(Step::Denied),
                Just(Step::Gone),
                proptest::option::of(prop_oneof![0u64..40, Just(u64::MAX)]).prop_map(Step::Busy),
                prop_oneof![Just(500u16), Just(502), Just(503), Just(504), Just(522)]
                    .prop_map(Step::Front),
                Just(Step::Dropped),
                Just(Step::Lost),
            ]
        }

        fn transient() -> impl Strategy<Value = Step> {
            prop_oneof![
                Just(Step::NotYet),
                proptest::option::of(0u64..10).prop_map(Step::Busy),
                prop_oneof![Just(500u16), Just(502), Just(503), Just(504), Just(522)]
                    .prop_map(Step::Front),
                Just(Step::Dropped),
            ]
        }

        /// The script run on a paused clock: what it ended as, how long it
        /// took, when it polled, what each poll heard, how often it posted,
        /// and whether it says a holder may have been asked.
        #[allow(clippy::type_complexity)]
        fn run(
            life: u64,
            steps: &[(Duration, Step)],
        ) -> (
            String,
            Duration,
            Vec<tokio::time::Instant>,
            Vec<Step>,
            usize,
            bool,
        ) {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap()
                .block_on(async {
                    let phone = Enrollee::new();
                    let script = Script::new(&phone, life, steps);
                    let (ended, took) = asked(&phone, &script).await;
                    let posts = script.posts.load(Ordering::SeqCst);
                    let heard = script.heard.lock().unwrap().clone();
                    (
                        ended,
                        took,
                        script.polls(),
                        heard,
                        posts,
                        phone.may_have_asked(),
                    )
                })
        }

        proptest! {
            // A fixed seed and count, and nothing written to the tree: a
            // run is the same run wherever it runs, and a failure prints
            // its case to be pinned as a test of its own.
            #![proptest_config(ProptestConfig {
                cases: 256,
                rng_seed: proptest::test_runner::RngSeed::Fixed(0x0068_6578_6c69_6e65),
                failure_persistence: None,
                ..ProptestConfig::default()
            })]

            #[test]
            fn a_wait_keeps_its_bounds_and_ends_as_its_mailbox_said(
                life in 1u64..300,
                steps in proptest::collection::vec(((0u64..60).prop_map(Duration::from_secs), step()), 0..12),
            ) {
                let (ended, took, polls, heard, posts, may) = run(life, &steps);
                prop_assert!(took <= Duration::from_secs(life) + SLACK, "{took:?}");
                for w in polls.windows(2) {
                    prop_assert!(w[1] - w[0] >= POLL_FLOOR, "polled again too soon");
                }
                prop_assert_eq!(posts, 1);
                prop_assert!(may);
                let last = heard.last();
                let lost = heard.iter().any(|s| matches!(s, Step::Lost));
                let gone = matches!(last, Some(Step::Gone));
                let given_up = heard.iter().any(|s| matches!(s, Step::Dropped));
                let to_its_end = took == Duration::from_secs(life) + SLACK;
                match ended.as_str() {
                    "kept" => prop_assert!(matches!(last, Some(Step::Answer))),
                    "denied" => prop_assert!(matches!(last, Some(Step::Denied))),
                    "answer_lost" => prop_assert!(lost || (gone && given_up)),
                    // Never early: gone, or the request's whole life waited.
                    "expired" => prop_assert!(!lost && (gone || to_its_end)),
                    other => prop_assert!(
                        other.starts_with("RateLimited")
                            && matches!(
                                heard.iter().rev().find(|s| !matches!(s, Step::Dropped)),
                                Some(Step::Busy(_))
                            )
                            && to_its_end,
                        "ended {}", other
                    ),
                }
            }

            #[test]
            fn an_approved_request_is_answered_whatever_passing_faults_came_first(
                faults in proptest::collection::vec(((0u64..10).prop_map(Duration::from_secs), transient()), 0..10),
                delay in 0u64..10,
            ) {
                let mut steps = faults;
                steps.push((Duration::from_secs(delay), Step::Answer));
                let (ended, ..) = run(300, &steps);
                prop_assert_eq!(ended, "kept");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_cut_short_and_then_gone_was_lost_on_its_way() {
        // A "not yet" cut short hands nothing over, and its poll was
        // answered, so none was left at the mailbox to take the answer.
        for (first, ends) in [
            ("200 OK", "answer_lost"),
            // A denial is forgotten as an answer is.
            ("403 Forbidden", "answer_lost"),
            ("202 Accepted", "expired"),
        ] {
            assert_eq!(cut_short_then_gone(first).await, ends, "{first}");
        }
    }

    async fn cut_short_then_gone(first: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut polls = 0;
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let reply = if head.starts_with("GET /.well-known/hotline") {
                    let body = r#"{"identity":{"endpoints":{"enroll":"/identity/enroll"}}}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                } else if head.starts_with("POST") {
                    let body = r#"{"request":"r1","expires_in":60}"#;
                    format!("HTTP/1.1 201 Created\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
                } else {
                    polls += 1;
                    if polls == 1 {
                        // The head, and the link gone before the rest of it.
                        format!("HTTP/1.1 {first}\r\ncontent-length: 500\r\nconnection: close\r\n\r\n{{\"bundle\":\"AAAA")
                    } else {
                        "HTTP/1.1 410 Gone\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                            .to_owned()
                    }
                };
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        let ended = tokio::time::timeout(
            Duration::from_secs(20),
            Enrollee::new().enroll(
                format!("http://127.0.0.1:{port}"),
                Some("K7PM-4XWE".into()),
                "Hexline".into(),
            ),
        )
        .await
        .expect("ended in time");
        outcome(&ended)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_longer_than_any_answer_is_not_asked_for_again() {
        // Not yet, as long as a reply may be (64 KiB) and a byte longer.
        for (size, polls) in [(64 * 1024, 2), (64 * 1024 + 1, 1)] {
            let phone = Enrollee::new();
            let answer = String::from_utf8(approved(&phone)).unwrap();
            let (port, asked) = mailbox(60, vec![(202, "x".repeat(size)), (200, answer)]).await;
            let ended = tokio::time::timeout(
                Duration::from_secs(20),
                phone.enroll(
                    format!("http://127.0.0.1:{port}"),
                    Some("K7PM-4XWE".into()),
                    "Hexline".into(),
                ),
            )
            .await
            .expect("ended in time");
            assert_eq!(ended.is_ok(), polls == 2, "{size}: {ended:?}");
            assert_eq!(asked.lock().unwrap().len(), polls, "{size}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_mailbox_asking_for_room_by_its_header_alone_is_heard() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 3\r\ncontent-length: 0\r\n\r\n")
                .await;
        });
        let base = format!("http://127.0.0.1:{port}/");
        let http = Http {
            http: auth::http_client(&base, None).unwrap(),
            base: Url::parse(&base).unwrap(),
        };
        let polled = http.poll(&format!("{base}x"), Duration::from_secs(5)).await;
        assert!(
            matches!(
                polled,
                Polled::Reply {
                    status: 429,
                    retry_after: Some(3),
                    ..
                }
            ),
            "the header read"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_a_client_refusing_the_url_is_not_asked_again() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Plain HTTP where TLS was asked for: the link's TLS fails.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = [0; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });
        let refused_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let https = Http {
            http: auth::http_client("https://127.0.0.1/", None).unwrap(),
            base: Url::parse("https://127.0.0.1/").unwrap(),
        };
        for (url, lasting) in [
            // TLS failing mid-wait, most often a network change: asked again.
            (format!("https://127.0.0.1:{tls_port}/x"), false),
            // A client held to https refusing a plain URL.
            (format!("http://127.0.0.1:{tls_port}/x"), true),
            (format!("https://127.0.0.1:{refused_port}/x"), false),
        ] {
            let polled = https.poll(&url, Duration::from_secs(5)).await;
            let failed = matches!(polled, Polled::Failed(_));
            let dropped = matches!(polled, Polled::Dropped);
            assert_eq!((failed, dropped), (lasting, !lasting), "{url}");
        }
    }

    #[test]
    fn a_mailbox_is_reached_at_the_origin_of_what_was_typed() {
        for (typed, want) in [
            ("hl.example", Some("https://hl.example/")),
            ("wss://hl.example/ng", Some("https://hl.example/")),
            ("ws://127.0.0.1:5700/ng", Some("http://127.0.0.1:5700/")),
            ("http://localhost:5700", Some("http://localhost:5700/")),
            ("ws://[::1]:5700/ng", Some("http://[::1]:5700/")),
            ("ws://hl.example/ng", None),
            ("http://10.0.0.2:5700", None),
            ("https://hl.example:8443", Some("https://hl.example:8443/")),
            ("ftp://hl.example", None),
            ("https://user@hl.example", None),
            ("not a host", None),
        ] {
            assert_eq!(
                mailbox_base(typed).ok().map(|u| u.to_string()).as_deref(),
                want,
                "{typed}"
            );
        }
    }
}
