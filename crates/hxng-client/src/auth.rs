//! Proving an identity to a server before the WebSocket upgrade
//! (hxd-ng's `docs/hotline-ng-auth.md` §6.2): a challenge, the server's
//! signature on it for the host addressed, the device's login proof, and
//! the one-use token the upgrade then presents (§7.1).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hl_identity::proof::{canonical_host, LoginProof, ServerChallenge};
use hl_identity::{DeviceKey, PublicKey};
use serde_json::{json, Value};

use crate::driver::{platform_tls, Error, Refusal};
use crate::{ErrorReply, Token};

/// What a server's clock may differ from this one's by: hxd-ng's default
/// `[identity] clock_skew`.
const CLOCK_SKEW: u64 = 300;

/// A device as it proves itself: its key, the certificate the identity
/// signed for it, and the identity's card.
pub struct Device {
    pub key: DeviceKey,
    pub cert: Vec<u8>,
    pub card: Vec<u8>,
}

/// Prove `device` to the server whose ng endpoint is `url`, and hand back
/// the token its upgrade presents. With `create`, a server whose policy
/// allows it makes an account for an identity it has none for
/// (hotline-ng-identity.md §8.2). Each token is good for one upgrade, so
/// each new connection proves the device again; a resume needs none.
///
/// Refusals come back as [`Error::Refused`] with the server's code. A
/// server that does not sign its challenge for the host addressed is
/// refused here, before anything is signed for it (`wrong_host`).
pub async fn identity_token(
    url: &str,
    device: &Device,
    create: bool,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<Token, Error> {
    let (base, host) = base_of(url)?;
    // Our rustls config even for http: reqwest has no provider of its own.
    let tls = match tls {
        Some(t) => t,
        None => platform_tls()?,
    };
    // No redirects: one could carry the proof and the token to another
    // scheme or port. No proxies: the upgrade goes direct, so these do too.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .tls_backend_preconfigured(Arc::unwrap_or_clone(tls))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(base.starts_with("https:"))
        .build()
        .map_err(|e| Error::Connect(e.to_string()))?;

    let challenge = post(&http, &format!("{base}/identity/challenge"), None).await?;
    let (nonce, server_key) = vouched(&challenge, &host, now())?;
    let proof = LoginProof::sign(&device.key, &nonce, &server_key, &host, now())
        .map_err(|e| protocol(&e.to_string()))?;
    let ok = post(
        &http,
        &format!("{base}/identity/auth"),
        Some(json!({
            "card": URL_SAFE_NO_PAD.encode(&device.card),
            "device_cert": URL_SAFE_NO_PAD.encode(&device.cert),
            "proof": URL_SAFE_NO_PAD.encode(&proof),
            "downstream": "local",
            "create": create,
        })),
    )
    .await?;
    ok.get("token")
        .and_then(Value::as_str)
        .map(|t| Token::new(t.to_owned()))
        .ok_or_else(|| protocol("the auth reply carried no token"))
}

/// The challenge and server key a challenge reply carries, once the
/// server's own signature over them holds for `host`. Nothing is signed for
/// a server that has not shown it holds the key it names for this host:
/// one publishing another's key could hand on that server's challenge and
/// spend the answer there. Every refusal here is final.
fn vouched(reply: &Value, host: &str, now: u64) -> Result<([u8; 32], PublicKey), Error> {
    let bytes = |key: &str| -> Result<Vec<u8>, Error> {
        reply
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
            .ok_or_else(|| protocol(&format!("the challenge's {key} does not read")))
    };
    let exact = |key: &str| -> Result<[u8; 32], Error> {
        bytes(key)?
            .try_into()
            .map_err(|_| protocol(&format!("the challenge's {key} does not read")))
    };
    let (nonce, server_key) = (exact("challenge")?, exact("server_key")?);
    let signed = bytes("server_challenge").map_err(|_| {
        refused(
            "wrong_host",
            "the server did not sign its challenge for this host",
        )
    })?;
    let check = ServerChallenge::parse(&signed)
        .and_then(|sc| sc.check(&nonce, &server_key, host, now, CLOCK_SKEW));
    match check {
        Ok(()) => Ok((nonce, server_key)),
        // The phone's clock, most likely, not the server.
        Err(hl_identity::Error::Expired) => Err(refused(
            "clock_skew",
            "the server's challenge reads as expired: check this device's clock",
        )),
        Err(hl_identity::Error::HostMismatch) => Err(refused(
            "wrong_host",
            "the server signed its challenge for another host",
        )),
        Err(e) => Err(refused(
            "bad_challenge",
            &format!("the server's challenge does not hold: {e}"),
        )),
    }
}

/// The HTTP base an ng URL's server answers at, and the host it is
/// addressed as, in the form a proof is signed for.
fn base_of(url: &str) -> Result<(String, String), Error> {
    let (scheme, rest) = match url.split_once("://") {
        Some(("wss", rest)) => ("https", rest),
        Some(("ws", rest)) => ("http", rest),
        _ => {
            return Err(Error::Connect(format!(
                "{url} is not a ws:// or wss:// URL"
            )))
        }
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = canonical_host(authority)
        .ok_or_else(|| Error::Connect(format!("{authority} is not a host")))?;
    Ok((format!("{scheme}://{authority}"), host))
}

async fn post(http: &reqwest::Client, url: &str, body: Option<Value>) -> Result<Value, Error> {
    let req = http.post(url);
    let req = match body {
        Some(b) => req.json(&b),
        None => req,
    };
    let resp = req
        .send()
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;
    if status.is_success() {
        return serde_json::from_str(&text).map_err(|_| protocol("a reply that is not JSON"));
    }
    // A code it does not recognize is read by its status (§6.2).
    let reply: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let code = reply
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or(match status.as_u16() {
            400 => "bad_request",
            401 => "bad_proof",
            403 => "denied",
            404 => "not_available",
            421 => "wrong_host",
            429 => "rate_limited",
            _ => "server_error",
        });
    let mut refusal = ErrorReply {
        code: code.to_owned(),
        text: reply
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or(&text)
            .to_owned(),
        retry_after: reply.get("retry_after").and_then(Value::as_u64),
        rest: Default::default(),
    };
    // A server's own page, not a reason, if it is long: kept short.
    refusal.text = refusal.text.chars().take(200).collect();
    Err(Error::Refused(Box::new(Refusal {
        error: refusal,
        resumable: None,
    })))
}

fn refused(code: &str, text: &str) -> Error {
    Error::Refused(Box::new(Refusal {
        error: ErrorReply {
            code: code.into(),
            text: text.into(),
            retry_after: None,
            rest: Default::default(),
        },
        resumable: None,
    }))
}

fn protocol(what: &str) -> Error {
    Error::Connect(format!("identity: {what}"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ng_url_names_the_http_base_and_the_host_a_proof_is_for() {
        for (url, base, host) in [
            ("wss://hx.example/ng", "https://hx.example", "hx.example"),
            (
                "ws://127.0.0.1:5700/ng",
                "http://127.0.0.1:5700",
                "127.0.0.1:5700",
            ),
            (
                "wss://HX.Example:443/ng?x=1",
                "https://HX.Example:443",
                "hx.example",
            ),
            (
                "ws://hx.example:80/ng",
                "http://hx.example:80",
                "hx.example",
            ),
            (
                "wss://[2001:DB8::1]:5700/ng",
                "https://[2001:DB8::1]:5700",
                "[2001:db8::1]:5700",
            ),
        ] {
            assert_eq!(
                base_of(url).unwrap(),
                (base.to_owned(), host.to_owned()),
                "{url}"
            );
        }
        for bad in ["https://hx.example/ng", "wss://user@hx.example/ng"] {
            assert!(base_of(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nothing_is_signed_for_a_challenge_the_server_did_not_sign_for_this_host() {
        use hl_identity::ServerKey;
        let key = ServerKey::generate();
        let other = ServerKey::generate();
        let nonce = [7u8; 32];
        let now = 1_000_000;
        let b64 = |b: &[u8]| URL_SAFE_NO_PAD.encode(b);
        let reply = |signer: &ServerKey, host: &str, expires: u64, named: &ServerKey| {
            let mut r = json!({
                "challenge": b64(&nonce),
                "server_key": b64(&named.public()),
            });
            if !host.is_empty() {
                let signed = ServerChallenge::sign(signer, &nonce, host, expires, None).unwrap();
                r["server_challenge"] = json!(b64(&signed));
            }
            r
        };
        let cases = [
            ("vouched", reply(&key, "hx.example", now + 60, &key), None),
            (
                "unsigned",
                reply(&key, "", now + 60, &key),
                Some("wrong_host"),
            ),
            (
                "another host",
                reply(&key, "elsewhere.example", now + 60, &key),
                Some("wrong_host"),
            ),
            (
                "another key",
                reply(&other, "hx.example", now + 60, &key),
                Some("bad_challenge"),
            ),
            (
                "expired",
                reply(&key, "hx.example", now - 3600, &key),
                Some("clock_skew"),
            ),
        ];
        for (what, r, want) in cases {
            match (vouched(&r, "hx.example", now), want) {
                (Ok(_), None) => {}
                (Err(Error::Refused(e)), Some(code)) => assert_eq!(e.error.code, code, "{what}"),
                (got, _) => panic!("{what}: {:?}", got.map(|_| ())),
            }
        }
    }
}
