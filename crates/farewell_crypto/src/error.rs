use thiserror::Error;

/// Errors returned by the crypto layer.
///
/// Variants intentionally avoid revealing which step failed during unlock
/// flows: callers must not propagate granular failure causes to the user.
/// A wrong passphrase, a wrong hardware key challenge, and a corrupted
/// header all surface as `CryptoError::Decrypt` to the outside world.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD decryption failed (wrong key, modified ciphertext, or invalid tag).
    #[error("decryption failed")]
    Decrypt,

    /// KDF failed (parameter rejection, allocation failure).
    #[error("key derivation failed: {0}")]
    Kdf(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    Signature,

    /// Key encapsulation/decapsulation failed.
    #[error("KEM operation failed")]
    Kem,

    /// CSPRNG returned an error (extremely rare, usually fatal).
    #[error("RNG failure")]
    Rng,

    /// Input has wrong length for the expected primitive.
    #[error("invalid length: expected {expected}, got {got}")]
    InvalidLength {
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes received.
        got: usize,
    },
}
