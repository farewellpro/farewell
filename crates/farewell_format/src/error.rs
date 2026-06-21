use thiserror::Error;

/// Errors at the format layer.
#[derive(Debug, Error)]
pub enum FormatError {
    /// File too small for the declared layout.
    #[error("vault file too small: {0} bytes")]
    TooSmall(u64),

    /// Magic bytes do not match `FRWL`.
    #[error("not a Farewell vault (magic mismatch)")]
    NotAVault,

    /// Format version is not supported by this build.
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u16),

    /// Underlying cryptographic operation failed.
    /// Notably surfaces wrong-passphrase as a generic decrypt failure.
    #[error("crypto error")]
    Crypto(#[from] farewell_crypto::CryptoError),

    /// I/O error from the underlying file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Manifest could not be parsed (corruption, post-decrypt).
    #[error("manifest parse error: {0}")]
    Manifest(String),

    /// Requested chunk index does not exist.
    #[error("invalid chunk index: {0}")]
    InvalidChunk(u32),

    /// Vault is full: no free chunks available to store the requested data.
    #[error("vault is full")]
    Full,

    /// Requested file name was not found in the manifest.
    #[error("file not found: {0}")]
    FileNotFound(String),

    /// File name violates manifest constraints (too long, empty, control chars).
    #[error("invalid file name")]
    InvalidName,

    /// Manifest exceeded the single-chunk size limit (~64 KiB).
    #[error("manifest too large to fit in a single chunk")]
    ManifestOverflow,

    /// The vault has reached its wipe threshold and its slots have been
    /// zeroized. No further unlock attempts will ever succeed; the
    /// contents are unrecoverable. By design.
    #[error("vault wiped — wipe threshold reached, contents unrecoverable")]
    Wiped,

    /// The vault's header signature does not verify. The immutable parts
    /// of the header (magic, version, algorithm IDs, salt, total chunks,
    /// wipe threshold, embedded ML-DSA verifying key) have been altered
    /// since vault creation, or a different vault's data has been spliced
    /// in. The app refuses to open the vault.
    #[error("vault header signature invalid — file has been tampered with or substituted")]
    HeaderSignatureInvalid,

    /// The mounted level's manifest counter is below the value the caller
    /// expected. This indicates a rollback attack: an older snapshot of
    /// the vault file has been substituted in place of the latest one.
    /// Refuse to proceed and warn the user.
    #[error(
        "counter rollback detected: expected ≥ {expected}, found {actual} \
         (file may have been replaced with an older snapshot)"
    )]
    CounterRollback {
        /// The minimum counter value the caller required.
        expected: u64,
        /// The counter actually found in the mounted manifest.
        actual: u64,
    },

    /// The matching KDF decrypted the slot's outer layer, so the
    /// passphrase is correct, but the slot is hardware-protected (`K >= 1`)
    /// and no authenticator was supplied. Distinct from a generic decrypt
    /// failure so callers can tell "wrong passphrase" from "needs a key"
    /// and skip the remaining (hardened) KDF candidate — opening with no
    /// authenticator stops here instead of doing a slow wasted derive.
    #[error("vault requires a hardware key but none was provided")]
    HardwareKeyRequired,

    /// Another process holds an exclusive lock on the vault file.
    /// Mounting from two processes at the same time is unsafe (the
    /// in-memory manifest would diverge from disk under concurrent
    /// writes), so we refuse rather than risk corruption.
    ///
    /// In practice: close the other `farewell` invocation, or unmount
    /// the vault from the macOS app, before retrying.
    #[error("vault is already open in another process (advisory lock held)")]
    AlreadyLocked,
}
