//! BLAKE3 hashing and keyed MAC.

/// Output size of a BLAKE3 hash in bytes.
pub const HASH_LEN: usize = 32;

/// BLAKE3 hash output.
pub type Hash = [u8; HASH_LEN];

/// Compute the BLAKE3 hash of `data`.
pub fn hash(data: &[u8]) -> Hash {
    let mut out = [0u8; HASH_LEN];
    let h = blake3::hash(data);
    out.copy_from_slice(h.as_bytes());
    out
}

/// Compute a keyed BLAKE3 MAC over `data` with `key`.
pub fn mac(key: &[u8; HASH_LEN], data: &[u8]) -> Hash {
    let mut out = [0u8; HASH_LEN];
    let h = blake3::keyed_hash(key, data);
    out.copy_from_slice(h.as_bytes());
    out
}

/// Derive a sub-key from an input key and a context string using BLAKE3's
/// key derivation mode. The `context` string MUST be application-globally
/// unique and constant — never user-controlled.
pub fn derive_key(context: &'static str, input_key: &[u8]) -> Hash {
    blake3::derive_key(context, input_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // BLAKE3 hash of empty input.
        let h = hash(b"");
        assert_eq!(
            hex::encode(h),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn derive_is_deterministic() {
        let a = derive_key("farewell test context v1", b"input material");
        let b = derive_key("farewell test context v1", b"input material");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_changes_with_context() {
        let a = derive_key("farewell test context v1", b"input material");
        let b = derive_key("farewell test context v2", b"input material");
        assert_ne!(a, b);
    }
}
