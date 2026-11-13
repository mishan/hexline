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
}

async fn restore(
    registrar: &str,
    handle: &str,
    kind: SecretKind,
    secret: Zeroizing<String>,
    device_name: &str,
) -> Result<Restored, CoreError> {
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
    let envelopes = endpoint(&base, &reg.envelopes)?;
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

    let id = envelope
        .open(&identity, &keys)
        // The registrar checked the secret before it answered: an
        // envelope that does not open now is not the one that was put.
        .map_err(|e| protocol(&format!("the envelope did not open: {e}")))?;
    drop(keys);
    let device = DeviceKey::generate();
    let cert = certify(&id, &device, device_name)?;
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
    let (card, attested) = match reattest(&http, &reg, &register, &id, handle, successor).await {
        Some(attestation) => (with_attestation(&id, &card, &attestation)?, true),
        None => (card, false),
    };
    let fingerprint = id.fingerprint().to_string();
    drop(id);
    Ok(Restored {
        seed: device.seed().to_vec(),
        cert,
        card,
        fingerprint,
        new_card,
        attested,
    })
}

/// The phone's certificate: login, messages and managing, no vouch, since
/// the identity key that could is not kept (design §8); as long as
/// recommended, and read back as a server will read it.
fn certify(id: &IdentityKey, device: &DeviceKey, name: &str) -> Result<Vec<u8>, CoreError> {
    let mut cert =
        DeviceCert::for_keys(id, device.public(), device.public_enc(), issued(), LIFETIME)
            .map_err(|e| protocol(&e.to_string()))?;
    cert.caps = Some(caps::LOGIN | caps::MESSAGE | caps::MANAGE);
    cert.name = Some(name.to_owned());
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
/// would make the restored device useless.
fn check_name(name: &str) -> Result<(), CoreError> {
    certify(&IdentityKey::generate(), &DeviceKey::generate(), name).map(drop)
}

/// The base a registrar is reached at: `https://host` for a host, or a
/// URL that names nothing but an origin. Plain http only to this
/// machine, since what is sent is half of what the secret derives.
fn registrar_base(registrar: &str) -> Result<Url, CoreError> {
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
fn endpoint(base: &Url, path: &str) -> Result<String, CoreError> {
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
struct Registrar {
    host: String,
    /// Its key, and any it is retiring: what an attestation may be signed by.
    keys: Vec<[u8; 32]>,
    envelopes: String,
    register: String,
}

/// The registrar, from its discovery document.
async fn discovered(
    http: &hxng_client::reqwest::Client,
    base: &Url,
) -> Result<Registrar, CoreError> {
    let (status, body) = auth::get(
        http,
        base.join("/.well-known/hotline").expect("a path").as_str(),
    )
    .await?;
    if status == 429 {
        return Err(CoreError::RateLimited { retry_after: None });
    }
    let doc = (status == 200)
        .then(|| serde_json::from_slice::<Value>(&body).ok())
        .flatten()
        .ok_or_else(|| refused("not_a_registrar"))?;
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
        host: text(block.get("host")).ok_or_else(|| refused("not_a_registrar"))?,
        envelopes: text(endpoints.and_then(|e| e.get("envelopes")))
            .ok_or_else(|| refused("no_envelopes"))?,
        register: text(endpoints.and_then(|e| e.get("register")))
            .ok_or_else(|| refused("not_a_registrar"))?,
        keys,
    })
}

/// A fresh attestation for `handle` from the registrar, while the
/// identity key is in hand to ask for it (§6.1's reissue): the card a
/// server is shown carries it, and with none a server's default policy
/// lets the identity in as a guest alone. `None` if the registrar would
/// not reissue, which leaves the card as it was.
async fn reattest(
    http: &hxng_client::reqwest::Client,
    reg: &Registrar,
    register: &str,
    id: &IdentityKey,
    handle: &str,
    successor: Option<[u8; 32]>,
) -> Option<Vec<u8>> {
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
    .ok()?;
    let reply = auth::post(http, register, Some(json!({ "request": b64(&request) })))
        .await
        .ok()?;
    let signed = bytes(&reply, "attestation").ok()?;
    let att = Attestation::parse(&signed).ok()?;
    (att.identity == id.public()
        && att.registrar == reg.host
        && reg.keys.contains(&att.registrar_key))
    .then_some(signed)
}

/// `card` re-signed with `attestation` in place of any other for the
/// same handle at the same registrar, every other kept as signed.
fn with_attestation(
    id: &IdentityKey,
    card: &[u8],
    attestation: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let parsed = Card::parse(card).map_err(|e| protocol(&format!("the card: {e}")))?;
    let new = Attestation::parse(attestation).map_err(|e| protocol(&e.to_string()))?;
    let mut kept = match cbor::decode_canonical(card)
        .map_err(|e| protocol(&e.to_string()))?
        .get("attestations")
    {
        Some(cbor::Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
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
        404 => Ok(None),
        429 => Err(CoreError::RateLimited { retry_after: None }),
        _ => Err(refused("server_error")),
    }
}

/// Now, less the clock skew a server allows: a phone's clock ahead of the
/// server's must not make the certificate not yet valid there.
fn issued() -> u64 {
    now().saturating_sub(300)
}

fn derive(secret: &Secret<'_>, kdf: Kdf) -> Result<Keys, CoreError> {
    // The secret is borrowed, so the work cannot move to another thread:
    // block in place, which the core's multi-threaded runtime allows.
    tokio::task::block_in_place(|| Keys::derive(secret, kdf))
        .map_err(|e| protocol(&format!("deriving: {e}")))
}

fn bytes(reply: &Value, key: &str) -> Result<Vec<u8>, CoreError> {
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

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    fn a_name_a_server_could_not_read_is_refused_before_anything_is_asked() {
        assert!(check_name("Pixel 9").is_ok());
        for name in ["", " Pixel", "Pixel ", "Pixel\u{200b}", &"x".repeat(65)] {
            assert!(check_name(name).is_err(), "{name:?}");
        }
    }
}
