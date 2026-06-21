//! Argon2id key derivation.
//!
//! Parameters chosen per ARCHITECTURE.md §3.1 for production, with a
//! reduced profile for development.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::{CryptoError, Result};

/// Output length of a derived key in bytes.
pub const KEY_LEN: usize = 32;

/// Derived key, zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; KEY_LEN]);

impl DerivedKey {
    /// Borrow the raw bytes. Caller must not retain a copy.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Argon2id parameters in (memory_kib, iterations, parallelism, output_len).
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost (number of iterations).
    pub iterations: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
}

/// Production parameters (per ARCHITECTURE.md §3.1).
///
/// 1 GiB memory, 4 iterations, 4 lanes — tuned for ~2s on Apple Silicon M2.
/// Decreasing any of these without a documented threat-model amendment is
/// a vulnerability, not an optimization.
pub const PRODUCTION_PARAMS: KdfParams = KdfParams {
    memory_kib: 1024 * 1024,
    iterations: 4,
    parallelism: 4,
};

/// Development parameters. Reduced cost for fast tests. **Never** ship.
pub const DEV_PARAMS: KdfParams = KdfParams {
    memory_kib: 32 * 1024, // 32 MiB
    iterations: 2,
    parallelism: 1,
};

/// Derive a key from a passphrase and a salt using Argon2id.
///
/// `salt` MUST be at least 16 bytes and unique per vault — 32 random
/// bytes generated at setup and stored as the vault's sole plaintext
/// field (offset 0, indistinguishable from random).
pub fn derive(
    passphrase: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<DerivedKey> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(format!("invalid Argon2 params: {e}")))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| {
            // Zeroize any partial output before propagating.
            out.zeroize();
            CryptoError::Kdf(format!("argon2 failed: {e}"))
        })?;

    Ok(DerivedKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_derive_is_deterministic() {
        let salt = [0x42u8; 32];
        let a = derive(b"correct horse battery staple", &salt, &DEV_PARAMS).unwrap();
        let b = derive(b"correct horse battery staple", &salt, &DEV_PARAMS).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn dev_derive_changes_with_salt() {
        let pass = b"correct horse battery staple";
        let a = derive(pass, &[0x01u8; 32], &DEV_PARAMS).unwrap();
        let b = derive(pass, &[0x02u8; 32], &DEV_PARAMS).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn dev_derive_changes_with_passphrase() {
        let salt = [0x42u8; 32];
        let a = derive(b"alpha", &salt, &DEV_PARAMS).unwrap();
        let b = derive(b"beta", &salt, &DEV_PARAMS).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn salt_too_short_fails() {
        let result = derive(b"pass", &[0u8; 4], &DEV_PARAMS);
        assert!(result.is_err());
    }
}
