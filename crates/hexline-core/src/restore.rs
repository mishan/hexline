//! Envelope mode (design §2.1): an identity a registrar keeps sealed
//! (`identity-registrar.md` §9) made this phone's for a while. The
//! passphrase or recovery code opens the envelope here, the identity key
//! certifies a device key made for this phone, and the identity key is
//! dropped: what the app keeps is the device's seed, its certificate and
//! the identity's card, as for any device.

use hl_identity::envelope::{Kdf, Keys, Kind, Secret};
use hl_identity::{
    caps, cbor, Attestation, Card, DeviceCert, DeviceKey, Fingerprint, IdentityKey, KeyEnvelope,
    RecoveryCode, RegisterRequest,
};
use hxng_client::auth;
use hxng_client::reqwest::Url;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::CoreError;

/// What opens a registrar's envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SecretKind {
    Passphrase,
    RecoveryCode,
}

/// A device of the identity, made here: for the app to keep as
/// [`crate::cert_for_device`] reads it, and to wipe `seed` once kept.
#[derive(uniffi::Record)]
pub struct Restored {
    pub seed: Vec<u8>,
    pub cert: Vec<u8>,
    pub card: Vec<u8>,
    pub fingerprint: String,
    /// The registrar keeps no card for the identity, so this one is new
    /// and commits to no successor; the identity's other devices may show
    /// another.
    pub new_card: bool,
    /// The card carries an attestation the registrar issued just now.
    /// Without one, a server whose policy wants one lets the identity in
    /// as a guest.
    pub attested: bool,
}

/// How long a device made from an envelope is certified for: the
/// recommended lifetime, renewed by opening the envelope again.
const LIFETIME: u64 = hl_identity::cert::RECOMMENDED_LIFETIME;

/// Open `handle`'s envelope at `registrar` with `secret` and make this
/// phone a device of the identity it holds, named `device_name`.
/// `registrar` is a host, or a base URL for one reached otherwise.
/// Refused `not_found` when the registrar has no envelope of that kind for
/// the handle that this secret opens: it answers a wrong secret and a
/// missing envelope alike.
#[uniffi::export(async_runtime = "tokio")]
pub async fn restore_identity(
    registrar: String,
    handle: String,
    kind: SecretKind,
    secret: String,
    device_name: String,
) -> Result<Restored, CoreError> {
    let secret = Zeroizing::new(secret);
    crate::connection::RUNTIME
        .spawn(async move { restore(&registrar, &handle, kind, secret, &device_name).await })
        .await
        .unwrap_or_else(|_| Err(protocol("the restore stopped")))
        .map(|(restored, _)| restored)
}

/// A restore (as [`restore_identity`]) for a phone that will hold the
/// identity (design §2.1): the identity's seed comes back beside the
/// device, for the app to seal behind a Key B at once and then wipe.
#[derive(uniffi::Record)]
pub struct HeldRestore {
    pub device: Restored,
    pub identity_seed: Vec<u8>,
}

/// [`restore_identity`], keeping the identity's seed to be held.
#[uniffi::export(async_runtime = "tokio")]
pub async fn restore_identity_to_hold(
    registrar: String,
    handle: String,
    kind: SecretKind,
    secret: String,
    device_name: String,
) -> Result<HeldRestore, CoreError> {
    let secret = Zeroizing::new(secret);
    crate::connection::RUNTIME
        .spawn(async move { restore(&registrar, &handle, kind, secret, &device_name).await })
        .await
        .unwrap_or_else(|_| Err(protocol("the restore stopped")))
        .map(|(device, seed)| HeldRestore {
            device,
            identity_seed: seed.to_vec(),
        })
}

/// The device made, and the identity's seed: dropped, and so wiped, by a
/// caller that does not hold it.
async fn restore(
    registrar: &str,
    handle: &str,
    kind: SecretKind,
    secret: Zeroizing<String>,
    device_name: &str,
) -> Result<(Restored, Zeroizing<[u8; 32]>), CoreError> {
    // Everything that can be refused here is, before the registrar is
    // asked anything: each fetch counts toward the handle's lockout.
    let base = registrar_base(registrar)?;
    check_name(device_name)?;
    let (kind, code) = match kind {
        SecretKind::Passphrase if secret.trim().is_empty() => {
            return Err(refused("bad_passphrase"))
        }
        SecretKind::Passphrase => (Kind::Passphrase, None),
        SecretKind::RecoveryCode => (
            Kind::RecoveryCode,
            Some(RecoveryCode::parse(&secret).ok_or_else(|| refused("bad_recovery_code"))?),
        ),
    };
    let http = auth::http_client(base.as_str(), None)?;
    let reg = discovered(&http, &base).await?;
    let envelopes = endpoint(&base, reg.envelopes()?)?;
    let register = endpoint(&base, &reg.register)?;

    // The salt first: the registrar answers every handle with one.
    let params = auth::post(
        &http,
        &format!("{envelopes}/params"),
        Some(json!({ "handle": handle, "kind": kind as u8 })),
    )
    .await?;
    let kdf =
        Kdf::parse(&bytes(&params, "kdf")?).map_err(|e| protocol(&format!("the salt: {e}")))?;
    // Argon2id over 64 MiB, and then the secret is gone.
    let keys = {
        let secret = match &code {
            Some(code) => Secret::RecoveryCode(code),
            None => Secret::Passphrase(&secret),
        };
        derive(&secret, kdf)?
    };
    drop((secret, code));
    let reply = auth::post(
        &http,
        &format!("{envelopes}/fetch"),
        Some(json!({ "handle": handle, "kind": kind as u8, "auth": b64(keys.auth()) })),
    )
    .await?;
    let identity: [u8; 32] = bytes(&reply, "identity")?
        .try_into()
        .map_err(|_| protocol("the identity is not 32 bytes"))?;
    let envelope = KeyEnvelope::parse(&bytes(&reply, "envelope")?)
        .map_err(|e| protocol(&format!("the envelope: {e}")))?;
    // Before the key is opened: it is held for its signatures and the
    // reissue alone.
    let kept_card = card_kept(&http, &base, &identity).await?;
    // This device's certificate has no epoch kept anywhere to fall back
    // on: one minted below a reset would be refused at once.
    let floor = crate::epoch::published(&http, &base, &reg, &identity)
        .await?
        .epoch;

    let id = envelope
        .open(&identity, &keys)
        // The registrar checked the secret before it answered: an
        // envelope that does not open now is not the one that was put.
        .map_err(|e| protocol(&format!("the envelope did not open: {e}")))?;
    drop(keys);
    let device = DeviceKey::generate();
    let cert = crate::epoch::at_floor(&identity, floor, |floor| {
        certify(&id, &device, device_name, floor)
    })?;
    let (card, new_card) = match kept_card {
        Some(card) => (card, false),
        None => (
            Card::new(&id, handle, issued())
                .sign(&id, Vec::new())
                .map_err(|e| protocol(&e.to_string()))?,
            true,
        ),
    };
    let successor = Card::parse(&card).ok().and_then(|c| c.successor);
    let (card, attested) = match reattest(&http, &reg, &register, &id, handle, successor).await? {
        Some(attestation) => (with_attestation(&id, &card, &attestation)?, true),
        None => (card, false),
    };
    let fingerprint = id.fingerprint().to_string();
    let seed = id.seed();
    drop(id);
    Ok((
        Restored {
            seed: device.seed().to_vec(),
            cert,
            card,
            fingerprint,
            new_card,
            attested,
        },
        seed,
    ))
}

/// The phone's certificate: login, messages and managing, no vouch, since
/// the identity key that could is not kept (design §8); as long as
/// recommended, in device epoch `epoch`, and read back as a server will
/// read it.
pub(crate) fn certify(
    id: &IdentityKey,
    device: &DeviceKey,
    name: &str,
    epoch: u64,
) -> Result<Vec<u8>, CoreError> {
    let mut cert =
        DeviceCert::for_keys(id, device.public(), device.public_enc(), issued(), LIFETIME)
            .map_err(|e| protocol(&e.to_string()))?;
    cert.caps = Some(caps::LOGIN | caps::MESSAGE | caps::MANAGE);
    cert.name = Some(name.to_owned());
    cert.epoch = epoch;
    let cert = cert.sign(id);
    if DeviceCert::parse(&cert).is_err() || cert.len() > MAX_CERT {
        return Err(refused("bad_device_name"));
    }
    Ok(cert)
}

/// A server refuses `signs` and `sealed` to a certificate larger than this
/// (hotline-ng.md §6.1).
const MAX_CERT: usize = 512;

/// Whether `name` makes a certificate a server reads: one signed with
/// keys made for the purpose, so no fetch is charged for a name that
/// would make the restored device useless. At the highest epoch, so the
/// name fits whatever floor it is minted at.
pub(crate) fn check_name(name: &str) -> Result<(), CoreError> {
    let (id, device) = (IdentityKey::generate(), DeviceKey::generate());
    certify(&id, &device, name, hl_identity::cert::EPOCH_MAX).map(drop)
}

/// The base a registrar is reached at: `https://host` for a host, or a
/// URL that names nothing but an origin. Plain http only to this
/// machine, since what is sent is half of what the secret derives.
pub(crate) fn registrar_base(registrar: &str) -> Result<Url, CoreError> {
    let text = if registrar.contains("://") {
        registrar.to_owned()
    } else {
        format!("https://{registrar}")
    };
    let url = Url::parse(&text).map_err(|_| refused("bad_registrar"))?;
    let host = url.host_str().unwrap_or_default();
    let local = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let origin_only = url.path() == "/" && url.query().is_none() && url.fragment().is_none();
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && local);
    if !origin_only || !scheme_ok || !url.username().is_empty() || url.password().is_some() {
        return Err(refused("bad_registrar"));
    }
    Ok(url)
}

/// `path` as discovery gives it, on the registrar's own origin and no
/// other: a path that would move it (`@host`, `//host`, `.suffix`, a port)
/// is refused.
pub(crate) fn endpoint(base: &Url, path: &str) -> Result<String, CoreError> {
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(refused("not_a_registrar"));
    }
    let url = base.join(path).map_err(|_| refused("not_a_registrar"))?;
    if url.origin() != base.origin() {
        return Err(refused("not_a_registrar"));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// What a registrar's discovery document says of it.
pub(crate) struct Registrar {
    pub(crate) host: String,
    /// Its key, and any it is retiring: what an attestation may be signed by.
    pub(crate) keys: Vec<[u8; 32]>,
    /// None where it keeps no envelopes: refused `no_envelopes` by [`Registrar::envelopes`].
    envelopes: Option<String>,
    pub(crate) register: String,
    pub(crate) records: String,
}

impl Registrar {
    pub(crate) fn envelopes(&self) -> Result<&str, CoreError> {
        self.envelopes
            .as_deref()
            .ok_or_else(|| refused("no_envelopes"))
    }
}

/// The registrar, from its discovery document.
pub(crate) async fn discovered(
    http: &hxng_client::reqwest::Client,
    base: &Url,
) -> Result<Registrar, CoreError> {
    let (status, body) = auth::get(
        http,
        base.join("/.well-known/hotline").expect("a path").as_str(),
    )
    .await?;
    // 503: there, and unable to answer just now.
    if status == 429 || status == 503 {
        return Err(CoreError::RateLimited {
            retry_after: retry_after(&body),
        });
    }
    let doc = (status == 200)
        .then(|| serde_json::from_slice::<Value>(&body).ok())
        .flatten()
        .ok_or_else(|| refused("not_a_registrar"))?;
    registrar_of(&doc, base)
}

/// The registrar `doc`, a discovery document fetched from `base`, says
/// is there: none unless it names itself by the host it was reached at, as
/// what it signs for is that host's, and a registrar naming another could
/// gather requests signed for that one.
pub(crate) fn registrar_of(doc: &Value, base: &Url) -> Result<Registrar, CoreError> {
    let block = doc
        .get("registrar")
        .ok_or_else(|| refused("not_a_registrar"))?;
    let text = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_owned);
    let key = |v: &Value| -> Option<[u8; 32]> { bytes(v, "key").ok()?.try_into().ok() };
    let endpoints = block.get("endpoints");
    let keys: Vec<[u8; 32]> = key(block)
        .into_iter()
        .chain(
            block
                .get("retiring")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(key),
        )
        .collect();
    Ok(Registrar {
        host: text(block.get("host"))
            .filter(|host| *host == base.host_str().unwrap_or_default())
            .ok_or_else(|| refused("not_a_registrar"))?,
        envelopes: text(endpoints.and_then(|e| e.get("envelopes"))),
        register: text(endpoints.and_then(|e| e.get("register")))
            .ok_or_else(|| refused("not_a_registrar"))?,
        records: text(endpoints.and_then(|e| e.get("records")))
            .unwrap_or_else(|| "/registrar/records".into()),
        keys,
    })
}

/// A fresh attestation for `handle` from the registrar, while the
/// identity key is in hand to ask for it (§6.1's reissue): the card a
/// server is shown carries it, and with none a server's default policy
/// lets the identity in as a guest alone. `None` if the registrar would
/// not reissue, which leaves the card as it was; asked too often, the
/// restore waits, since a device restored now would be let in as a guest.
async fn reattest(
    http: &hxng_client::reqwest::Client,
    reg: &Registrar,
    register: &str,
    id: &IdentityKey,
    handle: &str,
    successor: Option<[u8; 32]>,
) -> Result<Option<Vec<u8>>, CoreError> {
    // The commitment the registrar holds is the card's: a request that
    // dropped it would be refused.
    let request = RegisterRequest {
        identity: id.public(),
        registrar: reg.host.clone(),
        handle: handle.to_owned(),
        time: now(),
        successor,
        proof: None,
    }
    .sign(id)
    .map_err(|e| protocol(&e.to_string()))?;
    let reply = match auth::post(http, register, Some(json!({ "request": b64(&request) }))).await {
        Ok(reply) => reply,
        Err(e) => {
            return match CoreError::from(e) {
                limited @ CoreError::RateLimited { .. } => Err(limited),
                _ => Ok(None),
            }
        }
    };
    let Ok(signed) = bytes(&reply, "attestation") else {
        return Ok(None);
    };
    Ok(ours(&signed, reg, id, handle).then_some(signed))
}

/// Whether `signed` is `reg`'s attestation of `id` as `handle`, on a key
/// it publishes.
pub(crate) fn ours(signed: &[u8], reg: &Registrar, id: &IdentityKey, handle: &str) -> bool {
    Attestation::parse(signed).is_ok_and(|att| {
        att.identity == id.public()
            && att.registrar == reg.host
            && att.handle == handle
            && reg.keys.contains(&att.registrar_key)
    })
}

/// `card` re-signed with `attestation` in place of any other for the
/// same handle at the same registrar, every other kept as signed.
pub(crate) fn with_attestation(
    id: &IdentityKey,
    card: &[u8],
    attestation: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let parsed = Card::parse(card).map_err(|e| protocol(&format!("the card: {e}")))?;
    let new = Attestation::parse(attestation).map_err(|e| protocol(&e.to_string()))?;
    let mut kept = parsed.embedded_attestations.clone();
    kept.retain(|v| {
        !(matches!(v.get("registrar"), Some(cbor::Value::Text(h)) if *h == new.registrar)
            && matches!(v.get("handle"), Some(cbor::Value::Text(h)) if *h == new.handle))
    });
    kept.push(cbor::decode_canonical(attestation).map_err(|e| protocol(&e.to_string()))?);
    let mut next = parsed.clone();
    next.updated = issued().max(parsed.updated + 1);
    let signed = next.sign(id, kept).map_err(|e| protocol(&e.to_string()))?;
    Card::parse(&signed).map_err(|e| protocol(&e.to_string()))?;
    Ok(signed)
}

/// The identity's card as the registrar keeps it: `None` only when it
/// keeps none. Any other failure is passed up, since a new card made in
/// its place would carry no attestation and commit to no successor.
/// Signed by the identity, it is the one source of the identity's
/// successor commitment a restore may trust (identity-registrar.md §9.4).
async fn card_kept(
    http: &hxng_client::reqwest::Client,
    base: &Url,
    identity: &[u8; 32],
) -> Result<Option<Vec<u8>>, CoreError> {
    let path = format!("/identity/card/{}", Fingerprint::of(identity));
    let (status, body) = auth::get(http, base.join(&path).expect("a path").as_str()).await?;
    match status {
        200 if Card::parse(&body).is_ok_and(|c| c.identity == *identity) => Ok(Some(body)),
        200 => Err(protocol("the registrar's card is not this identity's")),
        // The lookup's `successor` is not taken in its place: it is
        // unauthenticated (identity-registrar.md §6.3).
        404 => Ok(None),
        // 503: the registrar cannot check the card just now.
        429 | 503 => Err(CoreError::RateLimited {
            retry_after: retry_after(&body),
        }),
        _ => Err(refused("server_error")),
    }
}

/// The wait a 429's body asks for, flat or under `error` as the registrar
/// and the ng port each put it.
pub(crate) fn retry_after(body: &[u8]) -> Option<u64> {
    let v: Value = serde_json::from_slice(body).ok()?;
    v.get("retry_after")
        .or_else(|| v.get("error").and_then(|e| e.get("retry_after")))
        .and_then(Value::as_u64)
}

/// Now, less the clock skew a server allows: a phone's clock ahead of the
/// server's must not make the certificate not yet valid there.
/// How far back a certificate's issue time is set, for a verifier whose
/// clock is behind this one's.
pub(crate) const BACKDATE: u64 = 300;

pub(crate) fn issued() -> u64 {
    now().saturating_sub(BACKDATE)
}

pub(crate) fn derive(secret: &Secret<'_>, kdf: Kdf) -> Result<Keys, CoreError> {
    // The secret is borrowed, so the work cannot move to another thread:
    // block in place, which the core's multi-threaded runtime allows.
    tokio::task::block_in_place(|| Keys::derive(secret, kdf))
        .map_err(|e| protocol(&format!("deriving: {e}")))
}

pub(crate) fn bytes(reply: &Value, key: &str) -> Result<Vec<u8>, CoreError> {
    use base64::Engine;
    reply
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .ok()
        })
        .ok_or_else(|| protocol(&format!("the reply's {key} does not read")))
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

pub(crate) fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    #[test]
    fn a_429s_wait_is_read_wherever_its_body_puts_it() {
        let cases: [(&[u8], Option<u64>); 4] = [
            (br#"{"error":"rate_limited","retry_after":60}"#, Some(60)),
            (
                br#"{"error":{"code":"rate_limited","retry_after":5}}"#,
                Some(5),
            ),
            (br#"{"error":"rate_limited"}"#, None),
            (b"Too many requests", None),
        ];
        for (body, want) in cases {
            assert_eq!(retry_after(body), want, "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn a_registrar_is_reached_at_an_origin_and_plain_http_only_here() {
        for (given, base) in [
            ("reg.example", Some("https://reg.example/")),
            ("https://reg.example", Some("https://reg.example/")),
            ("http://127.0.0.1:5700", Some("http://127.0.0.1:5700/")),
            ("http://reg.example", None),
            ("https://reg.example/path", None),
            ("https://user@reg.example", None),
            ("not a host", None),
        ] {
            assert_eq!(
                registrar_base(given).ok().map(|u| u.to_string()).as_deref(),
                base,
                "{given}"
            );
        }
    }

    #[test]
    fn a_registrar_is_one_only_under_the_host_it_was_reached_at() {
        let doc = |host: &str| {
            json!({ "registrar": {
                "host": host,
                "endpoints": { "envelopes": "/registrar/envelopes", "register": "/registrar/register" },
            } })
        };
        for (reached, named, ours) in [
            ("https://reg.example", "reg.example", true),
            ("https://REG.example:8443", "reg.example", true),
            ("http://127.0.0.1:5700", "127.0.0.1", true),
            ("https://reg.example", "other.example", false),
            ("https://reg.example", "REG.example", false),
            ("http://localhost:5700", "127.0.0.1", false),
        ] {
            let got = registrar_of(&doc(named), &Url::parse(reached).unwrap());
            assert_eq!(got.is_ok(), ours, "{named} at {reached}");
        }
    }

    #[test]
    fn a_registrar_keeping_no_envelopes_takes_records_and_refuses_backups() {
        let doc = json!({ "registrar": {
            "host": "reg.example",
            "endpoints": { "register": "/registrar/register" },
        } });
        let reg = registrar_of(&doc, &Url::parse("https://reg.example").unwrap()).unwrap();
        assert_eq!(reg.records, "/registrar/records");
        assert!(
            matches!(reg.envelopes(), Err(CoreError::Refused { code, .. }) if code == "no_envelopes")
        );
    }

    #[test]
    fn a_discovered_path_stays_on_the_registrars_origin() {
        let base = Url::parse("https://reg.example").unwrap();
        assert_eq!(
            endpoint(&base, "/registrar/envelopes").ok().as_deref(),
            Some("https://reg.example/registrar/envelopes")
        );
        for path in [
            "@evil.example/x",
            "//evil.example/x",
            ".evil.example/x",
            ":8443/x",
            "registrar",
        ] {
            assert!(endpoint(&base, path).is_err(), "{path}");
        }
    }

    #[test]
    fn a_renewal_replaces_its_handles_attestation_and_keeps_what_it_cannot_read() {
        let id = IdentityKey::from_seed(&[1; 32]);
        let reg = hl_identity::ServerKey::from_seed(&[3; 32]);
        let att = |handle: &str, issued| Attestation {
            identity: id.public(),
            registrar: "reg.example".into(),
            registrar_key: reg.public(),
            handle: handle.into(),
            registered: 1_600_000_000,
            issued,
            expires: 1_800_000_000,
            level: None,
        };
        // As a newer registrar might issue it: a `v` this version does not read.
        let newer = |handle| {
            let cbor::Value::Map(mut entries) = att(handle, 1_700_000_000).signed_value(&reg)
            else {
                unreachable!("attestations are maps")
            };
            for (k, v) in &mut entries {
                if *k == cbor::Value::Text("v".into()) {
                    *v = cbor::Value::Uint(2);
                }
            }
            cbor::Value::Map(entries)
        };
        let mut card = Card::new(&id, "Alice", 10);
        // A key a newer card might carry, that this version does not know.
        card.extra.insert("future".into(), cbor::Value::Uint(42));
        let card = card.sign(&id, vec![newer("alice"), newer("alt")]).unwrap();
        let fresh = att("alice", 1_750_000_000).sign(&reg);
        let renewed = Card::parse(&with_attestation(&id, &card, &fresh).unwrap()).unwrap();
        assert_eq!(
            renewed.embedded_attestations,
            vec![newer("alt"), cbor::decode_canonical(&fresh).unwrap()]
        );
        assert_eq!(renewed.extra.get("future"), Some(&cbor::Value::Uint(42)));
    }

    /// A registrar answering every request `status`, with no body.
    async fn answering(status: u16) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let _ = s.read(&mut [0; 4096]).await;
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        base
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_registrar_that_cannot_answer_now_is_waited_for_not_taken_for_none() {
        fn told<T>(r: &Result<T, CoreError>, none: impl Fn(&T) -> bool) -> &'static str {
            match r {
                Ok(t) if none(t) => "none",
                Err(CoreError::RateLimited { .. }) => "wait",
                _ => "other",
            }
        }
        for (status, want) in [(404, ("none", "other")), (503, ("wait", "wait"))] {
            let base = answering(status).await;
            let http = auth::http_client(base.as_str(), None).unwrap();
            let card = card_kept(&http, &base, &[1; 32]).await;
            let reg = discovered(&http, &base).await;
            assert_eq!(
                (told(&card, Option::is_none), told(&reg, |_| false)),
                want,
                "{status}"
            );
        }
    }

    /// A request's first line and its body, or none for a connection that
    /// closed first.
    async fn request(s: &mut tokio::net::TcpStream) -> Option<(String, Vec<u8>)> {
        use tokio::io::AsyncReadExt;
        let mut got = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = s.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            got.extend_from_slice(&buf[..n]);
            let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&got[..end]).to_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map_or(0, |n| n.trim().parse().unwrap());
            if got.len() >= end + 4 + len {
                let line = head.lines().next().unwrap_or_default().to_owned();
                return Some((line, got[end + 4..end + 4 + len].to_vec()));
            }
        }
    }

    /// The commitment each registration a registrar was sent asked for.
    type Asked = std::sync::Arc<std::sync::Mutex<Vec<Option<[u8; 32]>>>>;

    /// A registrar keeping `id`'s envelope under `passphrase`, answering
    /// its card's fetch with `card`, attesting every registration, and
    /// publishing `id`'s device epoch `floor`, 0 for none, or failing the
    /// records' fetch for none at all.
    async fn registrar_serving(
        id: &IdentityKey,
        passphrase: &str,
        card: (u16, Vec<u8>),
        floor: Option<u64>,
    ) -> (Url, Asked) {
        use tokio::io::AsyncWriteExt;
        let (envelope, _) = KeyEnvelope::seal(id, &Secret::Passphrase(passphrase)).unwrap();
        let reg = hl_identity::ServerKey::from_seed(&[3; 32]);
        let identity = id.public();
        let opened = IdentityKey::from_seed(&id.seed());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = asked.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let Some((line, body)) = request(&mut s).await else {
                    continue;
                };
                let json = |v: Value| (200, v.to_string().into_bytes());
                let (status, reply) = match line.split(' ').nth(1).unwrap_or_default() {
                    "/.well-known/hotline" => json(json!({ "registrar": {
                        "host": "127.0.0.1",
                        "key": b64(&reg.public()),
                        "endpoints": {
                            "envelopes": "/registrar/envelopes",
                            "register": "/registrar/register",
                        },
                    } })),
                    "/registrar/envelopes/params" => {
                        json(json!({ "kdf": b64(&envelope.kdf.encode()) }))
                    }
                    "/registrar/envelopes/fetch" => json(json!({
                        "identity": b64(&identity),
                        "envelope": b64(&envelope.encode()),
                    })),
                    "/registrar/register" => {
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        let req = hl_identity::RegisterRequest::parse(
                            &unb64(body["request"].as_str().unwrap()).unwrap(),
                        )
                        .unwrap();
                        kept.lock().unwrap().push(req.successor);
                        let attestation = Attestation {
                            identity: req.identity,
                            registrar: req.registrar,
                            registrar_key: reg.public(),
                            handle: req.handle,
                            registered: now(),
                            issued: now(),
                            expires: now() + 86_400,
                            level: None,
                        };
                        json(json!({ "attestation": b64(&attestation.sign(&reg)) }))
                    }
                    path if path.starts_with("/identity/card/") => card.clone(),
                    path if path.starts_with("/registrar/records/") => match floor {
                        Some(floor) => {
                            let list = hl_identity::SignedList {
                                registrar: "127.0.0.1".into(),
                                issued: 1,
                                expires: u64::MAX / 2,
                                fingerprint: Some(Fingerprint::of(&identity).0),
                                since: None,
                                more: false,
                                entries: (floor > 0)
                                    .then(|| (1, crate::epoch::tests::reset(&opened, floor)))
                                    .into_iter()
                                    .collect(),
                            };
                            (200, list.sign(hl_identity::ListKind::Records, &reg))
                        }
                        None => (500, Vec::new()),
                    },
                    _ => (404, Vec::new()),
                };
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    reply.len()
                );
                let _ = s.write_all(&[head.as_bytes(), &reply].concat()).await;
            }
        });
        (base, asked)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_restore_keeps_a_card_the_identity_signed_and_its_commitment() {
        let id = IdentityKey::from_seed(&[1; 32]);
        let commitment = [9; 32];
        let mut card = Card::new(&id, "Alice", 10);
        card.successor = Some(commitment);
        card.extra.insert("future".into(), cbor::Value::Uint(42));
        let card = card.sign(&id, Vec::new()).unwrap();
        // The card with its name changed after it was signed.
        let forged = {
            let cbor::Value::Map(mut entries) = cbor::decode_canonical(&card).unwrap() else {
                unreachable!("cards are maps")
            };
            for (k, v) in &mut entries {
                if *k == cbor::Value::Text("name".into()) {
                    *v = cbor::Value::Text("Mallory".into());
                }
            }
            cbor::encode(&cbor::Value::Map(entries))
        };
        let other = IdentityKey::from_seed(&[2; 32]);
        let others = Card::new(&other, "Alice", 10)
            .sign(&other, Vec::new())
            .unwrap();

        // The restored card's commitment, whether it is new and whether it
        // kept what it carried; and the commitment each registration asked for.
        type Got = Result<(Option<[u8; 32]>, bool, bool), &'static str>;
        let cases: [(_, Got, Vec<_>); 5] = [
            (
                (200, card),
                Ok((Some(commitment), false, true)),
                vec![Some(commitment)],
            ),
            ((404, Vec::new()), Ok((None, true, false)), vec![None]),
            ((200, forged), Err("protocol"), vec![]),
            ((200, others), Err("protocol"), vec![]),
            ((503, Vec::new()), Err("wait"), vec![]),
        ];
        for (case, (served, want, want_asked)) in cases.into_iter().enumerate() {
            let (base, asked) = registrar_serving(&id, "correct horse", served, Some(0)).await;
            let got: Got = match restore(
                base.as_str(),
                "alice",
                SecretKind::Passphrase,
                Zeroizing::new("correct horse".into()),
                "Pixel",
            )
            .await
            {
                Ok((restored, _)) => {
                    assert!(restored.attested, "case {case}");
                    let card = Card::parse(&restored.card).unwrap();
                    assert_eq!(card.identity, id.public(), "case {case}");
                    Ok((
                        card.successor,
                        restored.new_card,
                        card.extra.get("future") == Some(&cbor::Value::Uint(42)),
                    ))
                }
                Err(CoreError::Protocol { .. }) => Err("protocol"),
                Err(CoreError::RateLimited { .. }) => Err("wait"),
                Err(_) => Err("other"),
            };
            assert_eq!(got, want, "case {case}");
            assert_eq!(*asked.lock().unwrap(), want_asked, "case {case}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_restored_device_is_certified_at_its_registrars_floor_and_never_without_it() {
        let id = IdentityKey::generate();
        let card = Card::new(&id, "Alice", 10).sign(&id, Vec::new()).unwrap();
        for (floor, want) in [(Some(0), Ok(0)), (Some(4), Ok(4)), (None, Err("protocol"))] {
            let (base, _) =
                registrar_serving(&id, "correct horse", (200, card.clone()), floor).await;
            let restored = restore(
                base.as_str(),
                "alice",
                SecretKind::Passphrase,
                Zeroizing::new("correct horse".into()),
                "Pixel",
            )
            .await;
            let got = match restored {
                Ok((r, _)) => Ok(DeviceCert::parse(&r.cert).unwrap().epoch),
                Err(CoreError::Protocol { .. }) => Err("protocol"),
                Err(_) => Err("other"),
            };
            assert_eq!(got, want, "{floor:?}");
        }
    }

    #[test]
    fn a_name_a_server_could_not_read_is_refused_before_anything_is_asked() {
        assert!(check_name("Pixel 9").is_ok());
        for name in ["", " Pixel", "Pixel ", "Pixel\u{200b}", &"x".repeat(65)] {
            assert!(check_name(name).is_err(), "{name:?}");
        }
    }
}
