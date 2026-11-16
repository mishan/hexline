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

use hl_identity::{
    caps, Bundle, Card, DeviceCert, DeviceKey, EnrollRequest, Fingerprint, PublicKey,
};
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
    expected: Mutex<Option<PublicKey>>,
    /// The request has reached the mailbox, its answer read.
    posted: AtomicBool,
    /// The request was sent, whatever came back: a holder may have been asked.
    sent: AtomicBool,
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
            posted: AtomicBool::new(false),
            sent: AtomicBool::new(false),
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
            expected: Mutex::new(Some(c.identity)),
            posted: AtomicBool::new(false),
            sent: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            stop: Notify::new(),
        }))
    }

    /// Refuse an answer from any identity but the one `cert` (another
    /// device's, expired or not) is of: a lapsed device of an identity
    /// enrolls afresh, and is still to become that identity's.
    pub fn expect_identity_of(&self, cert: Vec<u8>) -> Result<(), CoreError> {
        let c = DeviceCert::parse(&cert)
            .map_err(|e| protocol(&format!("the certificate does not read: {e}")))?;
        *self.expected.lock().unwrap() = Some(c.identity);
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
    /// `expired`, `canceled`, or as the mailbox refused.
    pub async fn enroll(
        self: Arc<Self>,
        mailbox: String,
        code: Option<String>,
        name: String,
    ) -> Result<Enrolled, CoreError> {
        crate::connection::RUNTIME
            .spawn(async move { self.run(&mailbox, code.as_deref(), &name).await })
            .await
            .unwrap_or_else(|_| Err(protocol("the enrollment stopped")))
    }

    /// Stops a wait for an answer, which ends `canceled`.
    pub fn cancel(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.stop.notify_waiters();
    }

    /// Whether a request has reached the mailbox, so a holder may have been
    /// asked, whatever came of it.
    pub fn posted(&self) -> bool {
        self.posted.load(Ordering::SeqCst)
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
        let http = auth::http_client(base.as_str(), None)?;
        let enroll = discovered(&http, &base).await?;

        let mut request = EnrollRequest::new(&self.device, now());
        request.name = Some(name.to_owned());
        // A renewal asks for no more than it has (§8); a holder refuses one
        // that does.
        request.caps = match &prev {
            Some(p) => p.caps,
            None => Some(ASKED),
        };
        request.prev = self.prev.clone();
        let mut body = json!({ "request": b64(&request.sign(&self.device)) });
        if let Some(code) = &code {
            body["code"] = json!(code);
        }
        self.sent.store(true, Ordering::SeqCst);
        let posted = auth::post(&http, &format!("{enroll}/requests"), Some(body)).await?;
        self.posted.store(true, Ordering::SeqCst);
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(life + 5);
        let url = format!("{enroll}/requests/{secret}");
        // Asked for, the request is waited on whatever the link does: a
        // dropped poll is asked again under the same secret until the
        // request's life is out.
        let mut backoff = POLL_FLOOR;
        let bundle = loop {
            let asked = tokio::time::Instant::now();
            // Never past the request's life, however long a poll may wait.
            let left = deadline.saturating_duration_since(asked);
            if left.is_zero() {
                return Err(refused("expired"));
            }
            let (status, body) = match auth::get_waiting(&http, &url, LONG_POLL.min(left)).await {
                Ok(got) => got,
                Err(hxng_client::driver::Error::Connect(_)) => {
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if left.is_zero() {
                        return Err(refused("expired"));
                    }
                    tokio::time::sleep(backoff.min(left)).await;
                    backoff = (backoff * 2).min(MOST_BACKOFF);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            backoff = POLL_FLOOR;
            let reply: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            match status {
                200 => break bytes(&reply, "bundle")?,
                202 if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep_until(asked + POLL_FLOOR).await;
                    continue;
                }
                202 | 404 | 410 => return Err(refused("expired")),
                403 => {
                    return Err(CoreError::Refused {
                        code: "denied".into(),
                        detail: denial(
                            reply
                                .get("denied")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                        ),
                    })
                }
                429 => {
                    return Err(CoreError::RateLimited {
                        retry_after: reply.get("retry_after").and_then(Value::as_u64),
                    })
                }
                _ => return Err(protocol(&format!("the mailbox answered {status}"))),
            }
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
            .is_some_and(|id| id != cert.identity)
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

/// Where a mailbox is reached: `https://host` for a host, or the origin of
/// a server's address (`wss://` or `ws://`, `https://` or `http://`), which
/// is where its discovery is. Plain http only to this machine, refused
/// `cleartext_mailbox` elsewhere: over it anyone on the path could see the
/// code and swap the request or the answer, leaving both bindings to the
/// person's comparison alone (design §9).
fn mailbox_base(mailbox: &str) -> Result<Url, CoreError> {
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
        // Another device's certificate, long expired, still names its identity.
        let lapsed = DeviceCert::for_keys(&alice, [1; 32], [2; 32], 0, 1)
            .unwrap()
            .sign(&alice);
        phone.expect_identity_of(lapsed).unwrap();
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
        assert!(!phone.posted());
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
        assert!(phone.may_have_asked() && !phone.posted());
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
