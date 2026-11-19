//! Moving a held identity to the successor its card commits to: the
//! successor code read against the card, a new successor and recovery
//! code written down for the new key, its card and this phone's device
//! under it, and the rotation record, signed once by the old key and kept,
//! to be sent as the same bytes however often it is sent.

use std::sync::{Arc, Mutex};

use hl_identity::{Card, DeviceKey, IdentityKey, Rotation, SuccessorCode};
use zeroize::Zeroizing;

use crate::holder::{refused, seed32, Codes, HolderMinted};
use crate::restore::{certify, issued};
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
    /// cards', `not_committed` for a card that commits to no successor,
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
        if parsed.successor.is_none() {
            return Err(refused("not_committed"));
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
            next: None,
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

    #[test]
    fn a_resumed_rotation_signs_nothing_at_a_time_the_process_before_may_have() {
        // Built by hand: nothing here signs before the resume does.
        let s1 = SuccessorCode::generate();
        let (k0, card0) = held(&s1);
        let k1 = s1.key();
        let card1 = successor_card(
            &k1,
            &Card::parse(&card0).unwrap(),
            &SuccessorCode::generate(),
        )
        .unwrap();
        let device = DeviceKey::generate();
        let cert = certify(&k1, &device, "Pixel").unwrap();
        // Ahead by more than any other test moves the shared clock.
        for time in [1, crate::restore::now() + 10_000] {
            let record = Rotation {
                identity: k0.public(),
                successor: k1.public(),
                time,
                next: None,
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
