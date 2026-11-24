//! Hexline's core. Kotlin never parses a frame, a CBOR object or a
//! signature: everything of the wire and of identity is here, and the app
//! renders what this crate hands it.

mod backup;
mod connection;
mod enroll;
mod epoch;
mod holder;
mod holder_session;
mod identity;
mod kept_rotation;
mod model;
mod names;
mod reset;
mod restore;
mod rotation;
mod rotation_notice;
#[cfg(target_os = "android")]
mod tls;

#[cfg(feature = "live-tests")]
pub use backup::before_reserving;
pub use backup::{backup_delete, backup_passphrase, min_passphrase, RecoveryCodeSetup};
pub use connection::{
    ClassicLogin, CoreError, CoreUpdate, DeviceIdentity, LoginInfo, ServerConnection, UpdateSink,
};
pub use enroll::{card_name, enrollment_code, newer_card, renewal_due, Enrolled, Enrollee};
pub use epoch::{held_floor, WholeRead};
pub use holder::{
    check_device_name, check_holder_registrar, held_renewal, holder_mint, holder_renew,
    new_identity, HeldRenewal, HolderCommitted, HolderMinted, HolderSetup, NewIdentity,
};
pub use holder_session::{
    certify_end, device_fingerprint_of, device_standing, open_holder_session, revoke_device,
    Certified, CertifyEnd, DeviceStanding, DeviceStandings, HolderKept, HolderRequest,
    HolderSession, ListedDevice, Qr, RevokeReason,
};
pub use identity::{
    cert_for_device, cert_info, cert_time, new_device, CertInfo, CertTime, NewDevice,
};
pub use kept_rotation::{
    decode_rotation, encode_rotation, rotation_due, rotation_posted, rotations_next_due,
    KeptRotation, RegistrarState, RotationRegistrar, RotationState,
};
pub use model::{ChatLine, HistoryPage, Status, User};
pub use names::{parts_hash, short_hash};
pub use reset::{reset_devices, retry_reset, DevicesReset, NotYet, NotYetReset, ResetRetried};
pub use restore::{restore_identity, restore_identity_to_hold, HeldRestore, Restored, SecretKind};
pub use rotation::{post_rotation, PostOutcome, Posted, RotationSetup};
pub use rotation_notice::{rotation_notice, RotationNotice, RotationNoticeKind};

uniffi::setup_scaffolding!();

/// This build's version, as Cargo knows it.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
