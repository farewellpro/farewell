//! Binary self-attestation: verify own integrity at startup, and verify
//! release multi-signatures before install.
//!
//! # Status: stub (v0.1)
//!
//! Production design (ARCHITECTURE.md §13): the app hashes its own binary
//! at launch, compares to a value compiled in, and refuses to run on
//! mismatch. Each release is signed by ≥ 3 maintainers (Ed25519 + ML-DSA)
//! and recorded in a Sigstore-style transparency log.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Result of a self-attestation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationResult {
    /// Binary matches expected hash.
    Ok,
    /// Binary differs from expected hash. App must refuse to proceed.
    Mismatch,
    /// No expected hash compiled in; build was not done in attestable mode.
    NotApplicable,
}

/// Stub: return `NotApplicable` in dev builds.
pub fn self_attest() -> AttestationResult {
    // TODO(Phase 1): hash `std::env::current_exe()` and compare to
    // compile-time `option_env!("FAREWELL_EXPECTED_BIN_HASH")`.
    AttestationResult::NotApplicable
}
