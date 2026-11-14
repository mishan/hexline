//! What the app's secrets and files are named by: a hash of what they are
//! for, never text a person typed made into a file name. The names must
//! not change, or what was kept under them is lost.

use sha2::{Digest, Sha256};

/// The first 12 bytes of `bytes`' SHA-256, in lowercase hex.
#[uniffi::export]
pub fn short_hash(bytes: Vec<u8>) -> String {
    hex12(&bytes)
}

/// [`short_hash`] of `parts`, each as its UTF-8 length (four bytes,
/// big-endian) and then its bytes, so no two lists of parts run together
/// into the same input.
#[uniffi::export]
pub fn parts_hash(parts: Vec<String>) -> String {
    let mut input = Vec::new();
    for part in &parts {
        let len = u32::try_from(part.len()).expect("a name's part is not 4 GiB");
        input.extend_from_slice(&len.to_be_bytes());
        input.extend_from_slice(part.as_bytes());
    }
    hex12(&input)
}

fn hex12(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..12]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names the app kept things under before these functions existed,
    /// as its own code derived them.
    #[test]
    fn names_are_the_ones_already_kept_under() {
        let parts = |p: &[&str]| parts_hash(p.iter().map(|s| s.to_string()).collect());
        assert_eq!(
            parts(&["wss://a.example/ng", "login", "alice"]),
            "c1024e74d2a56a9d07b135d8"
        );
        assert_eq!(
            parts(&["wss://a.example/ng", "guest"]),
            "01dee48b4e419032f18e6f40"
        );
        assert_eq!(
            parts(&["wss://\u{e4}.example/ng", "identity", "hl1xyz"]),
            "6a7488a07ae3f2d4d5c30382"
        );
        assert_eq!(
            short_hash(b"wss://a.example/ng\nalice".to_vec()),
            "d988dadc3324c7a5638381c7"
        );
        assert_eq!(short_hash(vec![1, 2, 3]), "039058c6f2c0cb492c533b0a");
    }
}
