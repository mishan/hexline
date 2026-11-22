//! Device epochs from the holder's side (identity-registrar.md section
//! 4.10, identity-enrollment.md section 8): the floor this phone knows for
//! each identity it holds, and what an identity's registrars publish of
//! it. A certificate below its identity's floor is refused by servers that
//! know the floor, so every mint signs at the highest floor known.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use hl_identity::{
    DeviceCert, DeviceRevocation, Fingerprint, ListKind, PublicKey, Record, RegistrarKeys,
    SignedList,
};
use hxng_client::auth;
use hxng_client::reqwest::Url;

use crate::restore::{discovered, endpoint, registrar_base, Registrar};
use crate::CoreError;

/// The highest floor this process has learned for each identity. A mint
/// signs with its lock held, so a reset that raises the floor before it
/// posts is never signed under once it has begun.
static FLOORS: Mutex<BTreeMap<PublicKey, u64>> = Mutex::new(BTreeMap::new());

/// `mint` given `identity`'s floor, first raised to `known`, with the
/// lock held: what it signs is at a floor nothing has passed meanwhile.
/// A `known` below what was learned lowers nothing, and one past any
/// epoch a certificate may carry, as a damaged file could hand in, is
/// taken as the highest there is rather than leave nothing mintable.
pub(crate) fn at_floor<T>(identity: &PublicKey, known: u64, mint: impl FnOnce(u64) -> T) -> T {
    let mut floors = FLOORS.lock().unwrap_or_else(|e| e.into_inner());
    let floor = floors.entry(*identity).or_default();
    *floor = (*floor).max(known.min(hl_identity::cert::EPOCH_MAX));
    mint(*floor)
}

/// The highest device epoch this process has learned for the identity
/// whose card is `card`, 0 for none or for a card that does not read: for
/// the app to keep whatever a request it was read for came to.
#[uniffi::export]
pub fn held_floor(card: Vec<u8>) -> u64 {
    let Ok(card) = hl_identity::Card::parse(&card) else {
        return 0;
    };
    let floors = FLOORS.lock().unwrap_or_else(|e| e.into_inner());
    floors.get(&card.identity).copied().unwrap_or(0)
}

/// What an identity's registrars publish of its devices.
#[derive(Debug, Clone, Default)]
pub(crate) struct Published {
    /// The highest device epoch any of them publishes, 0 for none.
    pub(crate) epoch: u64,
    pub(crate) revocations: Vec<DeviceRevocation>,
}

impl Published {
    fn merge(&mut self, other: Published) {
        self.epoch = self.epoch.max(other.epoch);
        self.revocations.extend(other.revocations);
    }
}

/// Whether a request for `device`, renewing `prev` if it carries one, is
/// for a key that must not be certified again at `floor` (enrollment
/// section 8): one `prev` shows certified below it, one `listed` (this
/// phone's devices, each with the epoch it was certified at) shows
/// certified below it, one a revocation that stands names, or one that
/// signed a revocation below it. A reset may have been for a copied key,
/// so a key known from before it comes back only as a new one.
pub(crate) fn signed_out(
    device: &PublicKey,
    prev: Option<&DeviceCert>,
    floor: u64,
    listed: &[(PublicKey, u64)],
    published: &Published,
) -> bool {
    prev.is_some_and(|p| p.check_floor(floor).is_err())
        || listed.iter().any(|(d, e)| d == device && *e < floor)
        || published.revocations.iter().any(|r| {
            let below = r.check_signer_floor(floor).is_err();
            (r.device == *device && !below) || (r.signer.as_ref() == Some(device) && below)
        })
}

/// What `registrars` publish of `identity`, each reached at its base and
/// read alongside the others for up to `wait`: one that cannot be read in
/// that time is passed over, so the floor and the revocations are what
/// the rest say.
pub(crate) async fn published_at(
    registrars: &[String],
    identity: &PublicKey,
    wait: Duration,
) -> Published {
    let mut reads = tokio::task::JoinSet::new();
    for registrar in registrars {
        let (registrar, identity) = (registrar.clone(), *identity);
        reads.spawn(tokio::time::timeout(wait, async move {
            let base = registrar_base(&registrar)?;
            let http = auth::http_client(base.as_str(), None)?;
            let reg = discovered(&http, &base).await?;
            published(&http, &base, &reg, &identity).await
        }));
    }
    let mut all = Published::default();
    while let Some(read) = reads.join_next().await {
        if let Ok(Ok(Ok(p))) = read {
            all.merge(p);
        }
    }
    all
}

/// The registrars an identity's floor is read from: `kept`, where this
/// phone set it up or restored it, and each its card's attestations
/// name that `kept` is not, as a host reached over https.
pub(crate) fn registrars_of(kept: Option<&str>, card: &hl_identity::Card) -> Vec<String> {
    let kept_host = kept
        .and_then(|k| registrar_base(k).ok())
        .and_then(|b| b.host_str().map(str::to_owned));
    let mut out: Vec<String> = kept.map(str::to_owned).into_iter().collect();
    for a in card
        .attestations
        .iter()
        .filter(|a| a.identity == card.identity)
    {
        if kept_host.as_deref() != Some(a.registrar.as_str()) && !out.contains(&a.registrar) {
            out.push(a.registrar.clone());
        }
    }
    out
}

/// What `reg`'s per-identity records list says of `identity`, page after
/// page, each entry verified: its highest device epoch and the device
/// revocations.
pub(crate) async fn published(
    http: &hxng_client::reqwest::Client,
    base: &Url,
    reg: &Registrar,
    identity: &PublicKey,
) -> Result<Published, CoreError> {
    // A registrar serving pages without end is not followed for ever.
    const PAGES: usize = 64;
    let fingerprint = Fingerprint::of(identity);
    let keys = RegistrarKeys {
        host: &reg.host,
        keys: &reg.keys,
    };
    let records = endpoint(base, &reg.records)?;
    let mut out = Published::default();
    let mut since = None;
    for _ in 0..PAGES {
        let url = match since {
            None => format!("{records}/{fingerprint}"),
            Some(s) => format!("{records}/{fingerprint}?since={s}"),
        };
        let (status, body) = auth::get(http, &url).await?;
        if status == 429 || status == 503 {
            return Err(CoreError::RateLimited {
                retry_after: crate::restore::retry_after(&body),
            });
        }
        let list = (status == 200)
            .then(|| SignedList::parse(&body, ListKind::Records, keys).ok())
            .flatten()
            .filter(|l| l.fingerprint == Some(fingerprint.0) && l.since == since)
            .ok_or_else(|| CoreError::Protocol {
                detail: "the identity's records do not read".into(),
            })?;
        for (_, bytes) in &list.entries {
            match Record::parse(bytes, Some(keys)) {
                Ok(Record::DeviceEpoch(r)) if r.identity == *identity => {
                    out.epoch = out.epoch.max(r.epoch)
                }
                Ok(Record::RevokeDevice(r)) if r.identity == *identity => out.revocations.push(r),
                _ => {}
            }
        }
        if !list.more {
            return Ok(out);
        }
        // A page with `more` has an entry, and `parse` holds every seq
        // past `since`, so each page moves on.
        since = list.entries.last().map(|(seq, _)| *seq);
    }
    Err(CoreError::Protocol {
        detail: "the identity's records run on past what is read".into(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hl_identity::{DeviceEpoch, DeviceKey, IdentityKey, ServerKey};
    use serde_json::json;

    /// A registrar at 127.0.0.1 publishing `records` for whoever is asked
    /// about, `per_page` to a page, and answering anything else 404.
    pub(crate) async fn registrar_publishing(records: Vec<Vec<u8>>, per_page: usize) -> Url {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let key = ServerKey::from_seed(&[5; 32]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
                let (status, body) = if path == "/.well-known/hotline" {
                    let doc = json!({ "registrar": {
                        "host": "127.0.0.1",
                        "key": crate::restore::b64(&key.public()),
                        "endpoints": { "register": "/registrar/register" },
                    } });
                    (200, doc.to_string().into_bytes())
                } else if let Some(rest) = path.strip_prefix("/registrar/records/") {
                    let (fp, since) = match rest.split_once("?since=") {
                        Some((fp, s)) => (fp, Some(s.parse::<u64>().unwrap())),
                        None => (rest, None),
                    };
                    let from = since.map_or(0, |s| s as usize);
                    let page: Vec<_> = records
                        .iter()
                        .enumerate()
                        .skip(from)
                        .take(per_page)
                        .map(|(i, r)| (i as u64 + 1, r.clone()))
                        .collect();
                    let list = SignedList {
                        registrar: "127.0.0.1".into(),
                        issued: 1,
                        expires: u64::MAX / 2,
                        fingerprint: Some(Fingerprint::parse(fp).unwrap().0),
                        since,
                        more: from + page.len() < records.len(),
                        entries: page,
                    };
                    (200, list.sign(ListKind::Records, &key))
                } else {
                    (404, Vec::new())
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(&[reply.as_bytes(), &body].concat()).await;
            }
        });
        base
    }

    /// A registrar's address that takes every connection and never answers one.
    pub(crate) async fn silent() -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = l.accept().await {
                held.push(s);
            }
        });
        url
    }

    pub(crate) fn reset(id: &IdentityKey, epoch: u64) -> Vec<u8> {
        DeviceEpoch {
            identity: id.public(),
            epoch,
            time: 1_000,
        }
        .sign(id)
        .unwrap()
    }

    fn revocation(id: &IdentityKey, device: PublicKey) -> Vec<u8> {
        DeviceRevocation {
            identity: id.public(),
            device,
            time: 1_000,
            until: 2_000,
            reason: None,
            signer: None,
            signer_cert: None,
        }
        .sign(id)
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_floor_is_the_highest_any_registrar_reached_publishes_across_its_pages() {
        let id = IdentityKey::generate();
        let other = IdentityKey::generate();
        let lost = DeviceKey::generate().public();
        let records = vec![
            reset(&id, 2),
            revocation(&id, lost),
            reset(&id, 5),
            // Another identity's, served wrongly: it counts for nothing here.
            reset(&other, 9),
        ];
        let paged = registrar_publishing(records, 1).await.to_string();
        let lower = registrar_publishing(vec![reset(&id, 3)], 8)
            .await
            .to_string();
        let gone = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let silent = silent().await;
        for (registrars, epoch, revoked) in [
            (vec![paged.clone(), lower.clone()], 5, 1),
            (vec![silent, paged.clone()], 5, 1),
            (vec![lower.clone()], 3, 0),
            (vec![gone.clone(), lower.clone()], 3, 0),
            (vec![gone], 0, 0),
        ] {
            let got = published_at(&registrars, &id.public(), Duration::from_secs(2)).await;
            assert_eq!(
                (got.epoch, got.revocations.len()),
                (epoch, revoked),
                "{registrars:?}"
            );
        }
    }

    #[test]
    fn a_key_known_from_below_the_floor_is_signed_out_and_a_new_one_is_not() {
        let id = IdentityKey::generate();
        let (device, manager) = (DeviceKey::generate(), DeviceKey::generate());
        let d = device.public();
        let cert_at = |key: &DeviceKey, epoch| {
            let mut c = DeviceCert::for_device(&id, key, 1_000, 1_000_000).unwrap();
            c.epoch = epoch;
            c.caps = Some(hl_identity::caps::LOGIN | hl_identity::caps::MANAGE);
            c
        };
        let by_manager = |epoch, of: PublicKey| {
            let r = DeviceRevocation {
                identity: id.public(),
                device: of,
                time: 2_000,
                until: 3_000,
                reason: None,
                signer: None,
                signer_cert: None,
            };
            let signed = r
                .sign_as_device(&manager, cert_at(&manager, epoch).sign(&id))
                .unwrap();
            DeviceRevocation::parse(&signed).unwrap()
        };
        let by_identity = DeviceRevocation::parse(&revocation(&id, d)).unwrap();
        let published = |revocations| Published {
            epoch: 0,
            revocations,
        };
        let (old, now) = (cert_at(&device, 1), cert_at(&device, 2));
        let none = Published::default();
        for (what, prev, listed, records, out) in [
            ("a prev below the floor", Some(&old), vec![], &none, true),
            ("a prev at the floor", Some(&now), vec![], &none, false),
            ("listed below the floor", None, vec![(d, 1)], &none, true),
            ("listed at the floor", None, vec![(d, 2)], &none, false),
            (
                "another device listed",
                None,
                vec![([9; 32], 0)],
                &none,
                false,
            ),
            (
                "revoked by the identity",
                None,
                vec![],
                &published(vec![by_identity.clone()]),
                true,
            ),
            (
                "revoked by a device at the floor",
                None,
                vec![],
                &published(vec![by_manager(2, d)]),
                true,
            ),
            (
                "revoked by a device below it, which is void",
                None,
                vec![],
                &published(vec![by_manager(1, d)]),
                false,
            ),
            (
                "nothing known of it",
                None,
                vec![],
                &published(vec![by_manager(2, [9; 32])]),
                false,
            ),
        ] {
            assert_eq!(signed_out(&d, prev, 2, &listed, records), out, "{what}");
        }
        let signer = manager.public();
        for (epoch, out) in [(1, true), (2, false)] {
            let records = published(vec![by_manager(epoch, [9; 32])]);
            assert_eq!(
                signed_out(&signer, None, 2, &[], &records),
                out,
                "a signer at epoch {epoch}"
            );
        }
    }

    #[test]
    fn a_floor_rises_and_is_never_lowered_by_a_stale_one() {
        let id = IdentityKey::generate().public();
        let max = hl_identity::cert::EPOCH_MAX;
        for (known, floor) in [(0, 0), (3, 3), (1, 3), (5, 5), (u64::MAX, max), (5, max)] {
            assert_eq!(at_floor(&id, known, |f| f), floor, "{known}");
        }
    }

    #[test]
    fn the_floor_is_read_where_the_phone_keeps_it_and_where_the_card_is_attested() {
        let id = IdentityKey::generate();
        let reg = ServerKey::from_seed(&[3; 32]);
        let att = |registrar: &str| {
            hl_identity::cbor::decode_canonical(
                &hl_identity::Attestation {
                    identity: id.public(),
                    registrar: registrar.into(),
                    registrar_key: reg.public(),
                    handle: "alice".into(),
                    registered: 1,
                    issued: 1,
                    expires: u64::MAX / 2,
                    level: None,
                }
                .sign(&reg),
            )
            .unwrap()
        };
        let card = hl_identity::Card::new(&id, "Alice", 10)
            .sign(&id, vec![att("reg.example"), att("other.example")])
            .unwrap();
        let card = hl_identity::Card::parse(&card).unwrap();
        for (kept, want) in [
            (None, vec!["reg.example", "other.example"]),
            (
                Some("https://reg.example:8443"),
                vec!["https://reg.example:8443", "other.example"],
            ),
            (
                Some("third.example"),
                vec!["third.example", "reg.example", "other.example"],
            ),
        ] {
            assert_eq!(registrars_of(kept, &card), want, "{kept:?}");
        }
    }
}
