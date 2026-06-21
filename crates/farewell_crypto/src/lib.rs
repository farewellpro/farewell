//! Farewell cryptographic primitives.
//!
//! This crate exposes the cryptographic building blocks used by Farewell.
//! All operations are constant-time where applicable and use audited
//! upstream implementations (RustCrypto, dalek-cryptography).
//!
//! # Notes
//!
//! - Post-quantum primitives are implemented via `libcrux` (formally verified):
//!   ML-DSA-87 (`sign`) signs the vault metadata at rest (one-shot, FIPS 204);
//!   ML-KEM-1024 (`kem`) is implemented but reserved for the future P2P
//!   transfer — not wired into the at-rest path (see ARCHITECTURE §3.2).
//! - Argon2id: shipping builds use `kdf::PRODUCTION_PARAMS` (1 GiB, ~2 s);
//!   `kdf::DEV_PARAMS` is selected only under `cfg(test)` / the
//!   `farewell_format/dev-kdf` feature for fast tests (see
//!   `farewell_format` `KDF_PARAMS`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kem;
pub mod rng;
pub mod sign;

mod error;

pub use error::CryptoError;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, CryptoError>;
