//! Hexline's core. Kotlin never parses a frame, a CBOR object or a
//! signature: everything of the wire and of identity is here, and the app
//! renders what this crate hands it.

mod connection;
mod identity;
mod model;
mod names;
mod restore;
#[cfg(target_os = "android")]
mod tls;

pub use connection::{
    ClassicLogin, CoreError, CoreUpdate, DeviceIdentity, LoginInfo, ServerConnection, UpdateSink,
};
pub use identity::{cert_for_device, cert_info, new_device, CertInfo, NewDevice};
pub use model::{ChatLine, HistoryPage, Status, User};
pub use names::{parts_hash, short_hash};
pub use restore::{restore_identity, Restored, SecretKind};

uniffi::setup_scaffolding!();

/// This build's version, as Cargo knows it.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
