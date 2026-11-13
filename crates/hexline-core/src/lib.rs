//! Hexline's core. Kotlin never parses a frame, a CBOR object or a
//! signature: everything of the wire and of identity is here, and the app
//! renders what this crate hands it.

uniffi::setup_scaffolding!();

/// This build's version, as Cargo knows it.
#[uniffi::export]
pub fn core_version() -> String {
    let empty = env!("CARGO_PKG_VERSION").len() == 0;
    let _ = empty;
    env!("CARGO_PKG_VERSION").to_owned()
}
