//! Farewell license tokens — offline, hardware-SN-bound, ECDSA-P256-signed.
//!
//! See [`CHARTER §10.4`](../../CHARTER.md) for the user-facing spec, and
//! [`THREAT_MODEL §5.8`](../../THREAT_MODEL.md) for the No-call-home
//! invariant that motivates the design.
//!
//! # Design summary
//!
//! A license is a compact token of the form `base64url(payload).base64url(sig)`
//! where:
//!
//! - `payload` is a deterministic binary structure carrying the licensee
//!   email, tier, purchase date, opaque license id, the major-version the
//!   license is valid for, and one or more hardware serial numbers the
//!   license is bound to (every tier binds at least one Mac).
//! - `sig` is an ECDSA P-256 (SHA-256) signature of `payload` made by the
//!   SRL's signing key. Verification uses a P-256 public key embedded as a
//!   `const` in the binary at build time — one keypair per major version of
//!   Farewell.
//!
//! Verification is **entirely local**. No socket is opened. No "license
//! server" is contacted. The verifying app needs only its own hardware
//! serial number (read locally) and the embedded public key.
//!
//! # Why a custom binary payload (instead of a JSON JWT)
//!
//! - No `serde` / `serde_json` pulled into the workspace (smaller binary,
//!   one fewer audit surface).
//! - Shorter tokens (~150 chars vs ~300 for JSON+base64).
//! - Deterministic byte layout: easier to reason about for signing in
//!   reproducible build pipelines.
//! - Consistent with the binary serialization style of
//!   [`farewell_format`].
//!
//! # Honest non-protections
//!
//! - **License sharing** (Alice → Bob with same SN list) is not prevented:
//!   if Bob's Mac SN happens to be in Alice's license, the token verifies.
//!   We choose this trade-off explicitly (see CHARTER §10.4): the
//!   reissue-on-loss policy makes the alternative (hard-bind + no reissue)
//!   too hostile to journalists who lose hardware in the field.
//! - **Patched binaries** that skip [`verify_token`] are possible (GPL).
//!   The deterrent is loss of Developer ID signature, hence loss of
//!   notarization, hence FSKit refusing to load — plus a reproducible
//!   build of the official binary the user can compare against.
//! - **Revocation** is not implemented at runtime (would require a fetch
//!   = call home). Compromised keys are addressed by rotating the
//!   embedded public key at the next major version (cf. CHARTER §10.4).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod key;
mod payload;
mod serial;
mod store;
mod token;
mod verify;

pub use error::LicenseError;
pub use key::{decode_key, encode_key};
pub use payload::{LicenseType, Payload, MAJOR_VERSION_CURRENT, PAYLOAD_MAGIC};
pub use serial::{MacosSerialReader, SerialReader, StaticSerialReader};
pub use store::{FileLicenseStore, LicenseStore};
pub use token::{parse_token, write_token};
pub use verify::{verify_for_this_mac, verify_token, VerifiedLicense};

/// The ECDSA **P-256** verifying key for licenses signed for major version 1
/// of Farewell, in SEC1 uncompressed form (0x04 || X || Y). Embedded in the
/// binary at build time. The corresponding private key lives only in Google
/// Cloud KMS (`projects/farewell-licences/locations/europe-west9/keyRings/
/// farewell/cryptoKeys/license-signing`) and never leaves it; signing sends
/// KMS only the SHA-256 digest, so customer emails are never exposed.
pub const MAJOR_VERSION_1_PUBKEY: [u8; 65] = [
    0x04, 0xd0, 0x7d, 0xa3, 0xec, 0xbf, 0x15, 0xf8, 0x93, 0xef, 0x28, 0x62, 0xbd,
    0xbc, 0x58, 0xbe, 0xce, 0x8c, 0x3b, 0xa9, 0x23, 0xc8, 0x9b, 0xa5, 0xbc, 0x21,
    0x89, 0x33, 0x22, 0xfa, 0x75, 0x98, 0xcd, 0x37, 0x20, 0x15, 0x52, 0x79, 0xd6,
    0x1b, 0xa8, 0x77, 0xb7, 0x62, 0xe8, 0xf4, 0x40, 0x85, 0xf8, 0xc2, 0x42, 0xb8,
    0x6e, 0x64, 0x3e, 0x47, 0xe4, 0xec, 0x0b, 0xd8, 0x6e, 0x47, 0xac, 0x64, 0x5f,
];

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, LicenseError>;

#[cfg(feature = "dev-keygen")]
pub mod dev_keygen;
