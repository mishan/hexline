//! What a phone holding its identity key does with it (design §2.1, the
//! holder): the seed is the app's to keep behind a key that asks for the
//! person each time, and comes here only for the one operation it was
//! unwrapped for.

use hl_identity::{Card, DeviceKey, Fingerprint, IdentityKey};
use zeroize::Zeroizing;

use crate::restore::{certify, now};
use crate::CoreError;

/// An identity key just made, with the card it signed for itself: its
/// seed, for the app to wrap at once and then wipe.
#[derive(uniffi::Record)]
pub struct NewIdentity {
    pub seed: Vec<u8>,
    pub card: Vec<u8>,
    pub fingerprint: String,
}

/// A new identity key named `name`, and its card.
#[uniffi::export]
pub fn new_identity(name: String) -> Result<NewIdentity, CoreError> {
    let key = IdentityKey::generate();
    let card = Card::new(&key, name, now())
        .sign(&key, Vec::new())
        .map_err(|_| refused("bad_name"))?;
    Ok(NewIdentity {
        seed: key.seed().to_vec(),
        card,
        fingerprint: key.fingerprint().to_string(),
    })
}

/// A device this phone's own identity certified for itself: its seed, for
/// the app to wrap under the device key's store and then wipe, and its
/// certificate.
#[derive(uniffi::Record)]
pub struct HolderMinted {
    pub device_seed: Vec<u8>,
    pub cert: Vec<u8>,
}

/// A new device for the identity whose seed is `identity_seed`, named
/// `device_name`, certified by it as a holder's own: to log in, message and
/// manage, never to vouch (design §2.3). `card` must be that identity's,
/// so a seed paired with another's card is refused rather than minted for.
#[uniffi::export]
pub fn holder_mint(
    identity_seed: Vec<u8>,
    card: Vec<u8>,
    device_name: String,
) -> Result<HolderMinted, CoreError> {
    let seed = Zeroizing::new(identity_seed);
    let seed: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| refused("bad_seed"))?;
    let id = IdentityKey::from_seed(seed);
    let card = Card::parse(&card).map_err(|_| refused("bad_card"))?;
    if Fingerprint::of(&card.identity) != id.fingerprint() {
        return Err(refused("wrong_identity"));
    }
    let device = DeviceKey::generate();
    let cert = certify(&id, &device, &device_name)?;
    Ok(HolderMinted {
        device_seed: device.seed().to_vec(),
        cert,
    })
}

fn refused(code: &str) -> CoreError {
    CoreError::Refused {
        code: code.into(),
        detail: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::{caps, DeviceCert};

    #[test]
    fn a_holder_mints_its_own_device_to_log_in_message_and_manage_and_never_vouch() {
        let made = new_identity("Alice".into()).unwrap();
        let minted = holder_mint(made.seed.clone(), made.card.clone(), "Hexline".into()).unwrap();
        let info =
            crate::identity::cert_for_device(minted.cert.clone(), made.card, minted.device_seed)
                .unwrap();
        assert_eq!(info.fingerprint, made.fingerprint);
        let cert = DeviceCert::parse(&minted.cert).unwrap();
        assert_eq!(cert.caps, Some(caps::LOGIN | caps::MESSAGE | caps::MANAGE));
        assert_eq!(cert.name.as_deref(), Some("Hexline"));
    }

    #[test]
    fn a_seed_is_minted_for_only_with_its_own_card() {
        let alice = new_identity("Alice".into()).unwrap();
        let bob = new_identity("Bob".into()).unwrap();
        for (seed, card, code) in [
            (alice.seed.clone(), bob.card.clone(), "wrong_identity"),
            (alice.seed[..31].to_vec(), alice.card.clone(), "bad_seed"),
            (alice.seed.clone(), b"not a card".to_vec(), "bad_card"),
        ] {
            match holder_mint(seed, card, "Hexline".into()) {
                Err(CoreError::Refused { code: c, .. }) => assert_eq!(c, code),
                other => panic!("{code}: {:?}", other.map(|_| ())),
            }
        }
    }
}
