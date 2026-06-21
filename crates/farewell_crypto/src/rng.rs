//! Cryptographically secure RNG wrapper.
//!
//! Uses the OS-provided CSPRNG via `rand::rngs::OsRng`. We deliberately
//! avoid any userspace-only PRNG for cryptographic material: a deterministic
//! `seed → bytes` API would defeat the purpose of forward secrecy.

use rand_core::{OsRng, RngCore};

use crate::{CryptoError, Result};

/// Fill `dst` with cryptographically secure random bytes.
pub fn fill(dst: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(dst)
        .map_err(|_| CryptoError::Rng)
}

/// Allocate a `Vec<u8>` of `len` bytes of fresh randomness.
pub fn bytes(len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    fill(&mut v)?;
    Ok(v)
}
