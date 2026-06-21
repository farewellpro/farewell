//! Error types for license operations.

use thiserror::Error;

/// Errors that can occur during license parsing, verification, or storage.
#[derive(Debug, Error)]
pub enum LicenseError {
    /// Token does not contain exactly one `.` separator.
    #[error("malformed token: expected 'payload.signature', got {0}")]
    MalformedToken(String),

    /// Base64url decoding failed on the payload or signature segment.
    #[error("base64url decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Payload bytes do not start with the expected magic.
    #[error("payload magic mismatch: expected FLW1, got {0:?}")]
    BadMagic([u8; 4]),

    /// Payload version field is not supported by this build.
    #[error("payload version {got} not supported (this build understands version {expected})")]
    PayloadVersion {
        /// Version found in the token.
        got: u8,
        /// Version this build can parse.
        expected: u8,
    },

    /// Payload bytes are shorter than expected for the declared structure.
    #[error("payload truncated: needed {needed} more bytes, got 0")]
    Truncated {
        /// Number of additional bytes that would have been read.
        needed: usize,
    },

    /// `license_type` field decoded to an unknown variant.
    #[error("unknown license type discriminant {0}")]
    UnknownLicenseType(u8),

    /// Email string is not valid UTF-8.
    #[error("email field is not valid UTF-8")]
    EmailNotUtf8,

    /// Hardware serial number string is not valid ASCII.
    #[error("serial number contains non-ASCII bytes")]
    SerialNotAscii,

    /// Signature bytes are not a valid DER-encoded ECDSA signature. (The
    /// `usize` is the offending byte length, for diagnostics.)
    #[error("malformed ECDSA signature ({0} bytes)")]
    SignatureLength(usize),

    /// Public key is not a valid P-256 point in SEC1 form (65-byte
    /// uncompressed or 33-byte compressed).
    #[error("invalid P-256 public key ({0} bytes)")]
    PublicKeyLength(usize),

    /// ECDSA P-256 signature verification failed.
    #[error("signature does not match payload (wrong key, tampered, or wrong major version)")]
    InvalidSignature,

    /// The license is signed for a different major version of Farewell.
    #[error("license is for major version {license}, but this build is major version {build}")]
    MajorVersionMismatch {
        /// Major version embedded in the license.
        license: u32,
        /// Major version of the running binary.
        build: u32,
    },

    /// The license carries no bound serial numbers. Every tier must bind
    /// at least one Mac, so an unbound license is treated as invalid (it
    /// would otherwise unlock on any machine).
    #[error("license is not bound to any Mac (invalid: every license must name at least one serial)")]
    UnboundLicense,

    /// This Mac's hardware serial number is not in the license's bound list.
    #[error(
        "this Mac (serial {this_mac}) is not authorized by this license. Authorized: {authorized:?}. \
         See https://farewell.pro/license-policy to request a free re-issue."
    )]
    SerialNotAuthorized {
        /// Hardware serial number of the Mac that ran the check.
        this_mac: String,
        /// Serial numbers the license is bound to.
        authorized: Vec<String>,
    },

    /// Looked up the hardware serial number via `system_profiler` and got
    /// neither an error nor a recognizable serial — likely a Hackintosh,
    /// a stripped-down VM, or a permission denial.
    #[error("could not read this Mac's hardware serial number: {0}")]
    SerialReadFailed(String),

    /// I/O error while reading or writing a license file on disk.
    #[error("license file I/O error: {0}")]
    Io(#[from] std::io::Error),
}
