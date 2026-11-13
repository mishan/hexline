//! A device's keys as the app keeps them: made here, from the system's
//! randomness, and their certificate and card read here, so the app never
//! parses CBOR or checks a signature itself.

use hl_identity::{caps, Card, DeviceCert, DeviceKey, Fingerprint};

use crate::CoreError;

/// A device key just made: its seed, for the app to wrap at once and then
/// wipe, and its two public keys, which a certificate names. The seed
/// crosses the FFI this once, and again each time the app hands it back
/// to log in; neither crossing's buffers are wiped.
#[derive(uniffi::Record)]
pub struct NewDevice {
    pub seed: Vec<u8>,
    pub public: Vec<u8>,
    pub public_enc: Vec<u8>,
}

/// A new device key.
#[uniffi::export]
pub fn new_device() -> NewDevice {
    let key = DeviceKey::generate();
    NewDevice {
        seed: key.seed().to_vec(),
        public: key.public().to_vec(),
        public_enc: key.public_enc().to_vec(),
    }
}

/// What a device certificate and its identity's card say, once both hold.
#[derive(Debug, PartialEq, uniffi::Record)]
pub struct CertInfo {
    /// The identity that signed both.
    pub fingerprint: String,
    /// The device's two public keys, as the certificate names them.
    pub device: Vec<u8>,
    pub device_enc: Vec<u8>,
    pub issued: u64,
    pub expires: u64,
    /// When to renew it: with a third of its life left (design §2.1).
    pub renew_after: u64,
    pub can_login: bool,
    pub can_message: bool,
    pub can_vouch: bool,
    pub can_manage: bool,
    pub name: Option<String>,
}

/// Read `cert` and `card` as a device would keep them: the certificate
/// for the key `seed` makes, its signing and its encryption key alike, and
/// the card the same identity's.
#[uniffi::export]
pub fn cert_for_device(cert: Vec<u8>, card: Vec<u8>, seed: Vec<u8>) -> Result<CertInfo, CoreError> {
    let seed = zeroize::Zeroizing::new(seed);
    let seed: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| refused("a device seed is 32 bytes"))?;
    let key = DeviceKey::from_seed(seed);
    cert_info(cert, card, key.public().to_vec(), key.public_enc().to_vec())
}

/// [`cert_for_device`] against a device's public keys, so what was kept can
/// be read again without unwrapping its seed.
#[uniffi::export]
pub fn cert_info(
    cert: Vec<u8>,
    card: Vec<u8>,
    device: Vec<u8>,
    device_enc: Vec<u8>,
) -> Result<CertInfo, CoreError> {
    let c = DeviceCert::parse(&cert)
        .map_err(|e| refused(&format!("the device certificate does not read: {e}")))?;
    // A certificate for this device's signing key with another's
    // encryption key would seal its messages to someone else.
    if c.device.as_slice() != device || c.device_enc.as_slice() != device_enc {
        return Err(refused("the certificate is for another device's key"));
    }
    if c.expires <= c.issued {
        return Err(refused("the certificate is never valid"));
    }
    let k = Card::parse(&card).map_err(|e| refused(&format!("the card does not read: {e}")))?;
    if k.identity != c.identity {
        return Err(refused("the card is another identity's"));
    }
    Ok(CertInfo {
        fingerprint: Fingerprint::of(&c.identity).to_string(),
        device,
        device_enc,
        issued: c.issued,
        expires: c.expires,
        renew_after: c.expires - (c.expires - c.issued) / 3,
        can_login: c.allows(caps::LOGIN),
        can_message: c.allows(caps::MESSAGE),
        can_vouch: c.allows(caps::VOUCH),
        can_manage: c.allows(caps::MANAGE),
        name: c.name,
    })
}

fn refused(detail: &str) -> CoreError {
    CoreError::Protocol {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::IdentityKey;

    fn card(id: &IdentityKey) -> Vec<u8> {
        Card::new(id, "Alice", 900).sign(id, Vec::new()).unwrap()
    }

    #[test]
    fn a_certificate_is_read_for_the_keys_it_names_and_its_identitys_card() {
        let id = IdentityKey::generate();
        let device = new_device();
        let key = DeviceKey::from_seed(&device.seed.clone().try_into().unwrap());
        let other = DeviceKey::generate();
        let sign = |enc: [u8; 32], issued, lifetime, caps| {
            let mut c = DeviceCert::for_keys(&id, key.public(), enc, issued, lifetime).unwrap();
            c.caps = caps;
            c.sign(&id)
        };
        let good = sign(key.public_enc(), 900, 300, Some(caps::WEB));

        let info = cert_for_device(good.clone(), card(&id), device.seed.clone()).unwrap();
        assert_eq!(
            info,
            CertInfo {
                fingerprint: Fingerprint::of(&id.public()).to_string(),
                device: device.public.clone(),
                device_enc: device.public_enc.clone(),
                issued: 900,
                expires: 1200,
                renew_after: 1100,
                can_login: true,
                can_message: true,
                can_vouch: false,
                can_manage: false,
                name: None,
            }
        );
        assert_eq!(
            cert_info(
                good.clone(),
                card(&id),
                device.public.clone(),
                device.public_enc.clone()
            )
            .unwrap(),
            info
        );

        let mut tampered = good.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let refusals = [
            (
                "another device's key",
                good.clone(),
                card(&id),
                other.seed().to_vec(),
            ),
            (
                "another encryption key",
                sign(other.public_enc(), 900, 300, None),
                card(&id),
                device.seed.clone(),
            ),
            (
                "a signature that does not hold",
                tampered,
                card(&id),
                device.seed.clone(),
            ),
            (
                "never valid",
                sign(key.public_enc(), 900, 0, None),
                card(&id),
                device.seed.clone(),
            ),
            (
                "another identity's card",
                good.clone(),
                card(&IdentityKey::generate()),
                device.seed.clone(),
            ),
            (
                "not a certificate",
                b"junk".to_vec(),
                card(&id),
                device.seed.clone(),
            ),
            ("a short seed", good, card(&id), vec![1; 31]),
        ];
        for (what, cert, card, seed) in refusals {
            assert!(cert_for_device(cert, card, seed).is_err(), "{what}");
        }
    }
}
