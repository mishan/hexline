//! Moving a held identity to the successor its card commits to: the
//! successor code read against the card, a new successor and recovery
//! code written down for the new key, its card and this phone's device
//! under it, and the rotation record, signed once by the old key and kept,
//! to be sent as the same bytes however often it is sent.

use std::sync::{Arc, Mutex};

use hl_identity::{
    Card, DeviceKey, Fingerprint, IdentityKey, ListKind, Record, RegistrarKeys, Rotation,
    SignedList, SuccessorCode,
};
use hxng_client::auth;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::holder::{refused, seed32, Codes, HolderMinted};
use crate::restore::{b64, certify, discovered, endpoint, issued, registrar_base};
use crate::CoreError;

/// A rotation being made: the successor key K1, read from the code the
/// person wrote down, the old key's card, the codes K1's own card commits
/// to and its recovery is sealed by, and once signed the record. The
/// old key's seed is asked for once, to sign, and never kept.
#[derive(uniffi::Object)]
pub struct RotationSetup {
    state: Mutex<Rotating>,
}

struct Rotating {
    /// The old key's card, as stored.
    card0: Card,
    successor: Zeroizing<[u8; 32]>,
    mended: bool,
    codes: Codes,
    card1: Vec<u8>,
    /// K1's card's commitment, which the record names as `next`: the
    /// registrar holds it as K1's, and refuses a later rotation of K1 to
    /// any other key.
    next: [u8; 32],
    /// This phone's device under K1, once minted.
    device: Option<(Zeroizing<[u8; 32]>, Vec<u8>)>,
    record: Option<Vec<u8>>,
}

#[uniffi::export]
impl RotationSetup {
    /// The rotation of the identity whose card is `card` to the successor
    /// `typed_successor` names: read against the card's commitment, which
    /// outranks the code's check symbols, and mended if one symbol was
    /// misread. Refused `not_committed` for a card that commits to none,
    /// `wrong_successor` for a code no single symbol makes the committed
    /// one, `bad_card` for a card that does not read.
    #[uniffi::constructor]
    pub fn new(card: Vec<u8>, typed_successor: Vec<u8>) -> Result<Arc<Self>, CoreError> {
        let typed = Zeroizing::new(typed_successor);
        let card0 = Card::parse(&card).map_err(|_| refused("bad_card"))?;
        let commitment = card0.successor.ok_or_else(|| refused("not_committed"))?;
        let typed = std::str::from_utf8(&typed).map_err(|_| refused("wrong_successor"))?;
        let code = SuccessorCode::parse_for(typed, &commitment)
            .ok_or_else(|| refused("wrong_successor"))?;
        let mended = seed_symbols(typed) != seed_symbols(&code.display());
        let next = SuccessorCode::generate();
        let k1 = code.key();
        let card1 = successor_card(&k1, &card0, &next)?;
        Ok(Arc::new(RotationSetup {
            state: Mutex::new(Rotating {
                card0,
                successor: k1.seed(),
                mended,
                next: next.commitment(),
                codes: Codes::new(Some(next)),
                card1,
                device: None,
                record: None,
            }),
        }))
    }

    /// A rotation kept unfinished, after the process ended: K1's seed, the
    /// old key's card, K1's card as stored (its commitment stands, so no
    /// new successor code is shown), this phone's device under K1 and the
    /// record as signed, which is never signed again. The recovery code is
    /// new. Refused `wrong_identity` for a seed or a record that is not the
    /// cards' (a record's `next` is K1's card's commitment), `no_next` for
    /// a record that names no `next`, signed before rotations named one,
    /// `not_committed` for a card that commits to no successor,
    /// `wrong_successor` for an old card that commits to another than K1,
    /// `bad_device` for a device that is not K1's or not a holder's own.
    #[uniffi::constructor]
    pub fn resume(
        successor_seed: Vec<u8>,
        card0: Vec<u8>,
        card1: Vec<u8>,
        device_seed: Vec<u8>,
        device_cert: Vec<u8>,
        record: Vec<u8>,
    ) -> Result<Arc<Self>, CoreError> {
        let seed = seed32(successor_seed)?;
        let device = seed32(device_seed)?;
        let k1 = IdentityKey::from_seed(&seed);
        let card0 = Card::parse(&card0).map_err(|_| refused("bad_card"))?;
        let parsed = Card::parse(&card1).map_err(|_| refused("bad_card"))?;
        let rotation = Rotation::parse(&record).map_err(|_| refused("wrong_identity"))?;
        if parsed.identity != k1.public()
            || rotation.identity != card0.identity
            || rotation.successor != k1.public()
        {
            return Err(refused("wrong_identity"));
        }
        match card0.successor {
            None => return Err(refused("not_committed")),
            Some(c) if c != rotation.commitment() => return Err(refused("wrong_successor")),
            Some(_) => {}
        }
        let next = parsed.successor.ok_or_else(|| refused("not_committed"))?;
        match rotation.next {
            None => return Err(refused("no_next")),
            Some(n) if n != next => return Err(refused("wrong_identity")),
            Some(_) => {}
        }
        let info =
            crate::identity::cert_for_device(device_cert.clone(), card1.clone(), device.to_vec())
                .map_err(|_| refused("bad_device"))?;
        if !(info.can_login && info.can_message && info.can_manage) || info.can_vouch {
            return Err(refused("bad_device"));
        }
        // The process before may have signed in this second, and at the
        // record's time, whatever the clock says now.
        crate::backup::signed_at(crate::restore::now().max(rotation.time));
        Ok(Arc::new(RotationSetup {
            state: Mutex::new(Rotating {
                card0,
                successor: seed,
                mended: false,
                next,
                codes: Codes::new(None),
                card1,
                device: Some((device, device_cert)),
                record: Some(record),
            }),
        }))
    }

    /// Whether the code was read with a symbol other than the one typed.
    pub fn mended(&self) -> bool {
        self.lock().mended
    }

    pub fn successor_fingerprint(&self) -> String {
        IdentityKey::from_seed(&self.lock().successor)
            .fingerprint()
            .to_string()
    }

    /// The code of the successor K1's card commits to, to show once: none
    /// once typed back, or for a resumed rotation.
    pub fn next_successor_code(&self) -> Option<Vec<u8>> {
        self.lock().codes.successor_code()
    }

    pub fn confirm_next_successor(&self, typed: Vec<u8>) -> bool {
        self.lock().codes.confirm_successor(typed)
    }

    /// K1's recovery code, to show once: none once typed back.
    pub fn recovery_code(&self) -> Option<Vec<u8>> {
        self.lock().codes.recovery_code()
    }

    pub fn confirm_recovery(&self, typed: Vec<u8>) -> bool {
        self.lock().codes.confirm_recovery(typed)
    }

    /// K1's seed, for the app to hold and then wipe, once both codes are
    /// typed back: `unconfirmed` before.
    pub fn successor_seed(&self) -> Result<Vec<u8>, CoreError> {
        let s = self.confirmed()?;
        Ok(s.successor.to_vec())
    }

    /// This phone's device under K1, a holder's own; the rotation keeps it.
    pub fn mint(&self, device_name: String) -> Result<HolderMinted, CoreError> {
        let mut s = self.confirmed()?;
        let k1 = IdentityKey::from_seed(&s.successor);
        let device = DeviceKey::generate();
        let cert = certify(&k1, &device, &device_name)?;
        s.device = Some((device.seed(), cert.clone()));
        Ok(HolderMinted {
            device_seed: device.seed().to_vec(),
            cert,
        })
    }

    /// K1's card, once both codes are typed back: `unconfirmed` before, as
    /// it commits to a successor nobody may have written down.
    pub fn successor_card(&self) -> Result<Vec<u8>, CoreError> {
        Ok(self.confirmed()?.card1.clone())
    }

    /// The record, signed by the old key, whose seed is `identity_seed`, and
    /// acknowledged by K1; signed once, and the same bytes after. Refused
    /// `wrong_identity` for a seed that is not the old card's,
    /// `unconfirmed` before both codes are typed back, and `unminted`
    /// before [`RotationSetup::mint`], as a record kept with no device
    /// could not be resumed.
    pub fn sign(&self, identity_seed: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let seed = seed32(identity_seed)?;
        let mut s = self.confirmed()?;
        let k0 = IdentityKey::from_seed(&seed);
        if k0.public() != s.card0.identity {
            return Err(refused("wrong_identity"));
        }
        if s.device.is_none() {
            return Err(refused("unminted"));
        }
        if let Some(record) = &s.record {
            return Ok(record.clone());
        }
        let k1 = IdentityKey::from_seed(&s.successor);
        let record = Rotation {
            identity: k0.public(),
            successor: k1.public(),
            time: crate::backup::signing_time(),
            next: Some(s.next),
        }
        .sign(&k0, &k1)
        .map_err(|e| CoreError::Protocol {
            detail: format!("the rotation does not sign: {e}"),
        })?;
        s.record = Some(record.clone());
        Ok(record)
    }
}

impl RotationSetup {
    fn lock(&self) -> std::sync::MutexGuard<'_, Rotating> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn confirmed(&self) -> Result<std::sync::MutexGuard<'_, Rotating>, CoreError> {
        let s = self.lock();
        s.codes.confirmed()?;
        Ok(s)
    }
}

/// A registrar's answer to a rotation record (registrar §6.2).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Posted {
    /// Published there, now or by an earlier post of the same record.
    Published,
    /// Held for the registrar's delay: posted again, as the same bytes,
    /// at or after `until`, when that post publishes it.
    Pending { until: u64 },
    /// Another rotation of the identity is held there, and this one is
    /// not taken while it is: until `until`, where the registrar says
    /// (one older than `rotation_pending` does not).
    PendingElsewhere { until: Option<u64> },
    /// Another rotation to the same successor was published there
    /// first, naming `next` (as a fingerprint, or none) for the
    /// successor's commitment rather than this record's: another phone
    /// holding the same successor code, or whoever holds both the old key
    /// and that code. The identity is the successor's now, held to a
    /// commitment this phone did not make.
    Superseded { next: Option<String> },
    /// The identity was rotated there to `successor` (a fingerprint), a
    /// key other than this record's: whoever holds the old key, or
    /// another phone with a successor code of its own, moved it first.
    RotatedAway { successor: String },
    /// Frozen there by its operator, which cancels a held rotation:
    /// posted again once the freeze is lifted (registrar §8.2).
    Frozen,
    /// Refused there as `code`, which posting the same bytes again does
    /// not change: `successor_mismatch` (the successor holds another
    /// commitment there), `revoked` (the identity was revoked, naming no
    /// successor), or
    /// `not_registered` (the registrar attests no such identity).
    Refused { code: String },
}

/// What a post of a rotation came to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PostOutcome {
    Answered {
        answer: Posted,
    },
    /// No answer that changes what is kept: the same bytes are posted
    /// again later, after the longer of the backoff for posts that changed
    /// nothing and the `retry_after` seconds a `rate_limited` answer asked
    /// for, which is held to a day.
    Unanswered {
        retry_after: Option<u64>,
    },
}

impl From<Result<Posted, CoreError>> for PostOutcome {
    fn from(posted: Result<Posted, CoreError>) -> PostOutcome {
        match posted {
            Ok(answer) => PostOutcome::Answered { answer },
            Err(CoreError::RateLimited { retry_after }) => PostOutcome::Unanswered { retry_after },
            Err(_) => PostOutcome::Unanswered { retry_after: None },
        }
    }
}

/// What a registrar before `rotation_pending` answered a second rotation
/// with, as a `bad_request` (registrar §6.2).
const PENDING_TEXT: &str = "a rotation for this identity is already pending";

/// Posts `record`, a rotation as signed, to `registrar`'s records. Any
/// other answer is unanswered, and the same bytes may be posted again
/// later: a registrar not reached, `rate_limited` with its `retry_after`,
/// or a `bad_request`, among them §5.4's successor that is revoked,
/// frozen or rotating itself, which hxd tells apart by its text alone.
#[uniffi::export(async_runtime = "tokio")]
pub async fn post_rotation(registrar: String, record: Vec<u8>) -> PostOutcome {
    post(registrar, record).await.into()
}

async fn post(registrar: String, record: Vec<u8>) -> Result<Posted, CoreError> {
    let rotation = Rotation::parse(&record).map_err(|_| refused("bad_record"))?;
    crate::connection::RUNTIME
        .spawn(async move {
            let base = registrar_base(&registrar)?;
            let http = auth::http_client(base.as_str(), None)?;
            let reg = discovered(&http, &base).await?;
            let records = endpoint(&base, &reg.records)?;
            match auth::post(&http, &records, Some(json!({ "record": b64(&record) }))).await {
                Ok(reply) if reply["published"] == true => Ok(Posted::Published),
                Ok(reply) => match reply["pending_until"].as_u64() {
                    Some(until) => Ok(Posted::Pending { until }),
                    None => Err(protocol("a rotation neither published nor pending")),
                },
                Err(hxng_client::driver::Error::Refused(r))
                    if r.error.code == "rotation_pending" =>
                {
                    match r.error.rest.get("pending_until").and_then(Value::as_u64) {
                        Some(until) => Ok(Posted::PendingElsewhere { until: Some(until) }),
                        None => Err(protocol("a rotation pending with no time")),
                    }
                }
                Err(hxng_client::driver::Error::Refused(r))
                    if r.error.code == "bad_request" && r.error.text == PENDING_TEXT =>
                {
                    Ok(Posted::PendingElsewhere { until: None })
                }
                Err(e) => match CoreError::from(e) {
                    CoreError::Refused {
                        code, successor, ..
                    } if code == "revoked"
                        && successor == Some(Fingerprint::of(&rotation.successor).to_string()) =>
                    {
                        let published = published(&http, &reg, &records, &rotation).await?;
                        // hxd answers a repost of this record from its
                        // records, before `revoked`; a registrar that does
                        // not is answered by its bytes here.
                        if published.1 == record || published.0.next == rotation.next {
                            Ok(Posted::Published)
                        } else {
                            Ok(Posted::Superseded {
                                next: published.0.next.map(|n| Fingerprint(n).to_string()),
                            })
                        }
                    }
                    CoreError::Refused {
                        code,
                        successor: Some(successor),
                        ..
                    } if code == "revoked" => Ok(Posted::RotatedAway { successor }),
                    CoreError::Refused { code, .. } if code == "frozen" => Ok(Posted::Frozen),
                    CoreError::Refused { code, .. }
                        if matches!(
                            code.as_str(),
                            "successor_mismatch" | "revoked" | "not_registered"
                        ) =>
                    {
                        Ok(Posted::Refused { code })
                    }
                    e => Err(e),
                },
            }
        })
        .await
        .unwrap_or_else(|_| Err(protocol("the rotation's post stopped")))
}

/// The rotation of `rotation`'s identity to its successor that the
/// registrar published, as its records list for the identity carries it,
/// and its bytes: page after page, each past the last seq seen, until the
/// list ends.
async fn published(
    http: &hxng_client::reqwest::Client,
    reg: &crate::restore::Registrar,
    records: &str,
    rotation: &Rotation,
) -> Result<(Rotation, Vec<u8>), CoreError> {
    // A registrar serving pages without end is not followed for ever.
    const PAGES: usize = 64;
    let fingerprint = Fingerprint::of(&rotation.identity);
    let keys = RegistrarKeys {
        host: &reg.host,
        keys: &reg.keys,
    };
    let mut url = format!("{records}/{fingerprint}");
    for _ in 0..PAGES {
        let (status, body) = auth::get(http, &url).await?;
        if status == 429 {
            return Err(CoreError::RateLimited {
                retry_after: crate::restore::retry_after(&body),
            });
        }
        let list = (status == 200)
            .then(|| SignedList::parse(&body, ListKind::Records, keys).ok())
            .flatten()
            .filter(|l| l.fingerprint == Some(fingerprint.0))
            .ok_or_else(|| protocol("the identity's records do not read"))?;
        let last = list.entries.last().map(|(seq, _)| *seq);
        let found = list.entries.into_iter().find_map(|(_, bytes)| {
            match Record::parse(&bytes, Some(keys)) {
                Ok(Record::Rotate(r))
                    if r.identity == rotation.identity && r.successor == rotation.successor =>
                {
                    Some((r, bytes))
                }
                _ => None,
            }
        });
        match (found, last) {
            (Some(found), _) => return Ok(found),
            (None, Some(last)) if list.more => {
                url = format!("{records}/{fingerprint}?since={last}")
            }
            _ => break,
        }
    }
    Err(protocol("rotated, with no rotation in its records"))
}

fn protocol(detail: &str) -> CoreError {
    CoreError::Protocol {
        detail: detail.into(),
    }
}

/// K1's card: the old card's name, committing to `next`, unattested until
/// a registrar reissues K1's handles.
fn successor_card(
    k1: &IdentityKey,
    card0: &Card,
    next: &SuccessorCode,
) -> Result<Vec<u8>, CoreError> {
    let mut card = Card::new(k1, card0.name.clone(), issued());
    card.successor = Some(next.commitment());
    card.sign(k1, Vec::new()).map_err(|_| refused("bad_card"))
}

/// A successor code's symbols as hl-identity reads them, less its two
/// check symbols: what was typed for the seed.
fn seed_symbols(code: &str) -> Zeroizing<String> {
    let mut read = Zeroizing::new(String::with_capacity(code.len()));
    for c in code.chars().filter(|c| !matches!(c, ' ' | '-')) {
        read.push(match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        });
    }
    read.pop();
    read.pop();
    read
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::{caps, DeviceCert, RecoveryCode};

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

    /// K0 and its card committing to `successor`'s key.
    fn held(successor: &SuccessorCode) -> (IdentityKey, Vec<u8>) {
        let k0 = IdentityKey::generate();
        let mut card = Card::new(&k0, "Alice", issued());
        card.successor = Some(successor.commitment());
        let card = card.sign(&k0, Vec::new()).unwrap();
        (k0, card)
    }

    /// `code` with the symbol at `at` taken for `c`.
    fn replaced(code: &str, at: usize, c: char) -> String {
        let mut symbols: Vec<char> = code.chars().collect();
        symbols[at] = c;
        symbols.into_iter().collect()
    }

    /// `code` with the symbol at `at` taken for another.
    fn misread(code: &str, at: usize) -> String {
        let was = code.chars().nth(at).unwrap();
        replaced(code, at, if was == '0' { '1' } else { '0' })
    }

    /// Both codes typed back, and this phone's device minted.
    fn ready(r: &RotationSetup) -> HolderMinted {
        assert!(r.confirm_next_successor(r.next_successor_code().unwrap()));
        assert!(r.confirm_recovery(r.recovery_code().unwrap()));
        r.mint("Pixel".into()).unwrap()
    }

    #[test]
    fn the_successor_code_is_read_against_the_cards_commitment() {
        let s1 = SuccessorCode::generate();
        let (k0, card) = held(&s1);
        let typed = s1.display().to_string();
        let uncommitted = Card::new(&k0, "Alice", issued())
            .sign(&k0, Vec::new())
            .unwrap();
        let other = SuccessorCode::generate().display().to_string();
        let last = typed.chars().count() - 1;
        let lowered = typed.to_lowercase().replace('-', "").replace('0', "o");
        for (what, card, typed, want) in [
            ("as written", &card, typed.clone(), Ok(false)),
            ("lowercase, run together", &card, lowered, Ok(false)),
            (
                "a check symbol wrong",
                &card,
                misread(&typed, last),
                Ok(false),
            ),
            (
                "a two-byte check symbol",
                &card,
                replaced(&typed, last, '\u{e9}'),
                Ok(false),
            ),
            (
                "a three-byte check symbol",
                &card,
                replaced(&typed, last, '\u{ff21}'),
                Ok(false),
            ),
            ("a seed symbol misread", &card, misread(&typed, 3), Ok(true)),
            (
                "no commitment",
                &uncommitted,
                typed.clone(),
                Err("not_committed"),
            ),
            ("another key's code", &card, other, Err("wrong_successor")),
            (
                "two symbols misread",
                &card,
                misread(&misread(&typed, 3), 10),
                Err("wrong_successor"),
            ),
        ] {
            match (RotationSetup::new(card.clone(), typed.into_bytes()), want) {
                (Ok(r), Ok(mended)) => {
                    assert_eq!(r.mended(), mended, "{what}");
                    assert_eq!(
                        r.successor_fingerprint(),
                        s1.key().fingerprint().to_string(),
                        "{what}"
                    );
                }
                (got, Err(code)) => assert_eq!(refused_as(got), code, "{what}"),
                (Err(e), Ok(_)) => panic!("{what}: {e:?}"),
            }
        }
    }

    #[test]
    fn nothing_is_handed_out_until_both_new_codes_are_typed_back() {
        let s1 = SuccessorCode::generate();
        let (k0, card) = held(&s1);
        let r = RotationSetup::new(card, s1.display().as_bytes().to_vec()).unwrap();
        let k0_seed = k0.seed().to_vec();
        assert_eq!(refused_as(r.successor_seed()), "unconfirmed");
        assert_eq!(refused_as(r.successor_card()), "unconfirmed");
        assert_eq!(refused_as(r.mint("Pixel".into())), "unconfirmed");
        assert_eq!(refused_as(r.sign(k0_seed.clone())), "unconfirmed");
        let s2 = SuccessorCode::parse(&text(r.next_successor_code())).unwrap();
        assert!(r.confirm_next_successor(s2.display().as_bytes().to_vec()));
        assert_eq!(refused_as(r.successor_seed()), "unconfirmed", "S2 alone");
        assert!(r.confirm_recovery(r.recovery_code().unwrap()));

        assert_eq!(r.successor_seed().unwrap(), s1.key().seed().to_vec());
        let k1_card = Card::parse(&r.successor_card().unwrap()).unwrap();
        assert_eq!(k1_card.identity, s1.key().public());
        assert_eq!(k1_card.name, "Alice");
        assert_eq!(k1_card.successor, Some(s2.commitment()));
        assert!(k1_card.attestations.is_empty());
        for other in [k0.public(), s1.key().public()] {
            assert_ne!(s2.key().public(), other, "S2 is a key of its own");
        }
        assert_eq!(refused_as(r.sign(k0_seed.clone())), "unminted");
        let minted = r.mint("Pixel".into()).unwrap();
        let info = crate::identity::cert_for_device(
            minted.cert.clone(),
            r.successor_card().unwrap(),
            minted.device_seed,
        )
        .unwrap();
        assert_eq!(info.fingerprint, r.successor_fingerprint());
        let cert = DeviceCert::parse(&minted.cert).unwrap();
        assert_eq!(cert.caps, Some(caps::LOGIN | caps::MESSAGE | caps::MANAGE));
        r.sign(k0_seed).unwrap();
    }

    #[test]
    fn the_record_is_signed_once_by_the_cards_key_and_acknowledged_by_the_successor() {
        let s1 = SuccessorCode::generate();
        let (k0, card) = held(&s1);
        let r = RotationSetup::new(card, s1.display().as_bytes().to_vec()).unwrap();
        ready(&r);
        let stranger = IdentityKey::generate();
        for seed in [stranger.seed().to_vec(), s1.key().seed().to_vec()] {
            assert_eq!(refused_as(r.sign(seed)), "wrong_identity");
        }
        let record = r.sign(k0.seed().to_vec()).unwrap();
        let rotation = Rotation::parse(&record).unwrap();
        assert_eq!(rotation.identity, k0.public());
        assert_eq!(rotation.successor, s1.key().public());
        let card1 = Card::parse(&r.successor_card().unwrap()).unwrap();
        assert_eq!(rotation.next, card1.successor, "K1's first commitment");
        assert_eq!(
            r.sign(k0.seed().to_vec()).unwrap(),
            record,
            "never re-signed"
        );
        assert_eq!(
            refused_as(r.sign(stranger.seed().to_vec())),
            "wrong_identity",
            "nor handed to another key"
        );
    }

    #[test]
    fn a_resumed_rotation_keeps_its_card_and_record_and_asks_a_new_recovery_code_alone() {
        let s1 = SuccessorCode::generate();
        let (k0, card0) = held(&s1);
        let first = RotationSetup::new(card0.clone(), s1.display().as_bytes().to_vec()).unwrap();
        let first_recovery = text(first.recovery_code());
        let minted = ready(&first);
        let record = first.sign(k0.seed().to_vec()).unwrap();
        let card1 = first.successor_card().unwrap();
        let resume = |seed: &[u8], card0: &[u8], card1: &[u8], cert: &[u8], record: &[u8]| {
            RotationSetup::resume(
                seed.to_vec(),
                card0.to_vec(),
                card1.to_vec(),
                minted.device_seed.clone(),
                cert.to_vec(),
                record.to_vec(),
            )
        };
        let k1 = s1.key();
        let k1_seed = k1.seed().to_vec();
        let r = resume(&k1_seed, &card0, &card1, &minted.cert, &record).unwrap();
        assert_eq!(r.next_successor_code(), None);
        let code = text(r.recovery_code());
        assert_ne!(code, first_recovery);
        assert!(RecoveryCode::parse(&code).is_some());
        assert!(r.confirm_recovery(code.into_bytes()));
        assert_eq!(r.successor_card().unwrap(), card1);
        assert_eq!(r.sign(k0.seed().to_vec()).unwrap(), record);

        let other = IdentityKey::generate();
        let elsewhere = Rotation {
            identity: k0.public(),
            successor: other.public(),
            time: 1,
            next: None,
        }
        .sign(&k0, &other)
        .unwrap();
        let other_next = Rotation {
            identity: k0.public(),
            successor: k1.public(),
            time: 1,
            next: Some([7; 32]),
        }
        .sign(&k0, &k1)
        .unwrap();
        let no_next = Rotation {
            identity: k0.public(),
            successor: k1.public(),
            time: 1,
            next: None,
        }
        .sign(&k0, &k1)
        .unwrap();
        let (_, others_card0) = held(&s1);
        let committing = |successor| {
            let mut card = Card::new(&k0, "Alice", issued());
            card.successor = successor;
            card.sign(&k0, Vec::new()).unwrap()
        };
        let (misdirected, uncommitted0) = (committing(Some([7; 32])), committing(None));
        // Committed, and with this device certified by it, so only the
        // card's identity tells it apart.
        let mut others_card1 = Card::new(&other, "Alice", issued());
        others_card1.successor = Some([7; 32]);
        let others_card1 = others_card1.sign(&other, Vec::new()).unwrap();
        let uncommitted = Card::new(&k1, "Alice", issued())
            .sign(&k1, Vec::new())
            .unwrap();
        let theirs = certify(&k1, &DeviceKey::generate(), "Pixel").unwrap();
        let device = DeviceKey::from_seed(&minted.device_seed.clone().try_into().unwrap());
        let vouching =
            DeviceCert::for_keys(&k1, device.public(), device.public_enc(), issued(), 86_400)
                .unwrap()
                .sign(&k1);
        let others_cert = certify(&other, &device, "Pixel").unwrap();
        for (what, seed, card0, card1, cert, record, code) in [
            (
                "another seed",
                other.seed().to_vec(),
                &card0,
                &card1,
                &minted.cert,
                &record,
                "wrong_identity",
            ),
            (
                "another old card",
                k1_seed.clone(),
                &others_card0,
                &card1,
                &minted.cert,
                &record,
                "wrong_identity",
            ),
            (
                "an old card committing to another",
                k1_seed.clone(),
                &misdirected,
                &card1,
                &minted.cert,
                &record,
                "wrong_successor",
            ),
            (
                "an old card committing to none",
                k1_seed.clone(),
                &uncommitted0,
                &card1,
                &minted.cert,
                &record,
                "not_committed",
            ),
            (
                "another new card",
                k1_seed.clone(),
                &card0,
                &others_card1,
                &others_cert,
                &record,
                "wrong_identity",
            ),
            (
                "another successor",
                k1_seed.clone(),
                &card0,
                &card1,
                &minted.cert,
                &elsewhere,
                "wrong_identity",
            ),
            (
                "a record naming another next",
                k1_seed.clone(),
                &card0,
                &card1,
                &minted.cert,
                &other_next,
                "wrong_identity",
            ),
            (
                "a record naming no next",
                k1_seed.clone(),
                &card0,
                &card1,
                &minted.cert,
                &no_next,
                "no_next",
            ),
            (
                "no commitment",
                k1_seed.clone(),
                &card0,
                &uncommitted,
                &minted.cert,
                &record,
                "not_committed",
            ),
            (
                "another device",
                k1_seed.clone(),
                &card0,
                &card1,
                &theirs,
                &record,
                "bad_device",
            ),
            (
                "a vouching device",
                k1_seed.clone(),
                &card0,
                &card1,
                &vouching,
                &record,
                "bad_device",
            ),
        ] {
            assert_eq!(
                refused_as(resume(&seed, card0, card1, cert, record)),
                code,
                "{what}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_registrar_limiting_the_records_read_after_revoked_asks_to_be_waited_for() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (k0, k1) = (IdentityKey::generate(), IdentityKey::generate());
        let record = Rotation {
            identity: k0.public(),
            successor: k1.public(),
            time: 1,
            next: Some([7; 32]),
        }
        .sign(&k0, &k1)
        .unwrap();
        let successor = k1.fingerprint().to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Discovery, then the post answered `revoked` naming K1, then the
        // records list asked for too often.
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (status, body) = if head.starts_with("GET /.well-known/hotline") {
                    (
                        200,
                        json!({ "registrar": { "host": "127.0.0.1",
                            "endpoints": { "register": "/registrar/register" } } }),
                    )
                } else if head.starts_with("POST /registrar/records") {
                    (403, json!({ "error": "revoked", "successor": successor }))
                } else {
                    (429, json!({ "error": "rate_limited", "retry_after": 7 }))
                };
                let body = body.to_string();
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        assert_eq!(
            post_rotation(format!("http://127.0.0.1:{port}"), record).await,
            PostOutcome::Unanswered {
                retry_after: Some(7)
            }
        );
    }

    #[test]
    fn a_post_is_unanswered_but_where_a_registrar_answered_and_waits_only_where_it_asked() {
        let refused = |code: &str| CoreError::Refused {
            code: code.into(),
            detail: String::new(),
            successor: None,
        };
        let unanswered = |retry_after| PostOutcome::Unanswered { retry_after };
        for (posted, want) in [
            (
                Ok(Posted::Frozen),
                PostOutcome::Answered {
                    answer: Posted::Frozen,
                },
            ),
            (
                Err(CoreError::RateLimited {
                    retry_after: Some(7),
                }),
                unanswered(Some(7)),
            ),
            (
                Err(CoreError::RateLimited { retry_after: None }),
                unanswered(None),
            ),
            (
                Err(CoreError::Connect {
                    detail: "unreachable".into(),
                }),
                unanswered(None),
            ),
            (Err(refused("bad_request")), unanswered(None)),
            (Err(refused("bad_record")), unanswered(None)),
            (
                Err(CoreError::Protocol {
                    detail: "neither".into(),
                }),
                unanswered(None),
            ),
        ] {
            let what = format!("{posted:?}");
            assert_eq!(PostOutcome::from(posted), want, "{what}");
        }
    }

    #[test]
    fn a_resumed_rotation_signs_nothing_at_a_time_the_process_before_may_have() {
        // Built by hand: nothing here signs before the resume does.
        let s1 = SuccessorCode::generate();
        let (k0, card0) = held(&s1);
        let k1 = s1.key();
        let s2 = SuccessorCode::generate();
        let card1 = successor_card(&k1, &Card::parse(&card0).unwrap(), &s2).unwrap();
        let device = DeviceKey::generate();
        let cert = certify(&k1, &device, "Pixel").unwrap();
        // Ahead by more than any other test moves the shared clock.
        for time in [1, crate::restore::now() + 10_000] {
            let record = Rotation {
                identity: k0.public(),
                successor: k1.public(),
                time,
                next: Some(s2.commitment()),
            }
            .sign(&k0, &k1)
            .unwrap();
            let before = crate::restore::now().max(time);
            RotationSetup::resume(
                k1.seed().to_vec(),
                card0.clone(),
                card1.clone(),
                device.seed().to_vec(),
                cert.clone(),
                record,
            )
            .unwrap();
            assert!(crate::backup::signing_time() > before, "record at {time}");
        }
    }
}
