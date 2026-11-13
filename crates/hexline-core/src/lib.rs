//! Hexline's core. Kotlin never parses a frame, a CBOR object or a
//! signature: everything of the wire and of identity is here, and the app
//! renders what this crate hands it.

mod connection;
mod model;
#[cfg(target_os = "android")]
mod tls;

pub use connection::{CoreError, CoreUpdate, LoginInfo, ServerConnection, UpdateSink};
pub use model::{ChatLine, HistoryPage, Status, User};

uniffi::setup_scaffolding!();

/// This build's version, as Cargo knows it.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
