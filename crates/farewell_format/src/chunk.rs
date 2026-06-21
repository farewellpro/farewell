//! Fixed-size encrypted chunks.
//!
//! Every chunk on disk is exactly [`CHUNK_STORED_LEN`] bytes, regardless
//! of the plaintext payload. Smaller payloads are padded to
//! [`CHUNK_PLAINTEXT_LEN`] with zero bytes (the encrypted form is then
//! indistinguishable from a payload that genuinely had those zeros, since
//! the ciphertext is AEAD-randomized).
//!
//! v0.1 uses a fixed 64 KiB plaintext size.

use byteorder::{ByteOrder, LittleEndian};
use farewell_crypto::{
    aead::{self, AeadKey, NONCE_LEN, TAG_LEN},
    hash, rng,
};

use crate::{FormatError, Result};

/// Plaintext capacity per chunk in bytes.
pub const CHUNK_PLAINTEXT_LEN: usize = 64 * 1024;

/// Stored chunk size on disk = nonce + (plaintext + 4-byte real-length tag) + AEAD tag.
pub const CHUNK_STORED_LEN: usize = NONCE_LEN + CHUNK_PLAINTEXT_LEN + 4 + TAG_LEN;

/// Index of a chunk within the chunks region.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkIndex(pub u32);

impl ChunkIndex {
    /// Byte offset of this chunk in the vault file given the chunks region
    /// base offset.
    pub fn offset_in_region(self) -> u64 {
        (self.0 as u64) * (CHUNK_STORED_LEN as u64)
    }
}

/// Encrypt a plaintext payload into a fixed-size chunk.
///
/// `chunk_key` is the per-chunk key (derived from the master key and the
/// chunk index via BLAKE3 derive_key).
///
/// The real length of `plaintext` is stored encrypted alongside the data
/// so that retrieval knows how many trailing zero-padding bytes to drop.
pub fn encrypt_chunk(
    chunk_key: &AeadKey,
    index: ChunkIndex,
    plaintext: &[u8],
) -> Result<[u8; CHUNK_STORED_LEN]> {
    if plaintext.len() > CHUNK_PLAINTEXT_LEN {
        return Err(FormatError::Manifest(format!(
            "chunk payload too large: {} > {}",
            plaintext.len(),
            CHUNK_PLAINTEXT_LEN
        )));
    }

    // Pad to fixed plaintext size with zeros, then prepend a length tag.
    let mut padded = vec![0u8; CHUNK_PLAINTEXT_LEN + 4];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    LittleEndian::write_u32(&mut padded[CHUNK_PLAINTEXT_LEN..], plaintext.len() as u32);

    // Nonce: random 12 bytes. With GCM-SIV, even an accidental repeat does
    // not catastrophically leak.
    let mut nonce = [0u8; NONCE_LEN];
    rng::fill(&mut nonce)?;

    // AAD binds the chunk to its index, preventing chunk-shuffling attacks.
    let aad = chunk_aad(index);
    let ct = aead::encrypt(chunk_key, &nonce, &aad, &padded)?;

    debug_assert_eq!(ct.len(), CHUNK_PLAINTEXT_LEN + 4 + TAG_LEN);

    let mut stored = [0u8; CHUNK_STORED_LEN];
    stored[..NONCE_LEN].copy_from_slice(&nonce);
    stored[NONCE_LEN..].copy_from_slice(&ct);
    Ok(stored)
}

/// Decrypt a stored chunk back to its variable-length plaintext.
pub fn decrypt_chunk(
    chunk_key: &AeadKey,
    index: ChunkIndex,
    stored: &[u8; CHUNK_STORED_LEN],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&stored[..NONCE_LEN]);
    let aad = chunk_aad(index);
    let pt = aead::decrypt(chunk_key, &nonce, &aad, &stored[NONCE_LEN..])?;
    if pt.len() != CHUNK_PLAINTEXT_LEN + 4 {
        return Err(FormatError::Manifest("chunk plaintext length mismatch".into()));
    }
    let real_len = LittleEndian::read_u32(&pt[CHUNK_PLAINTEXT_LEN..]) as usize;
    if real_len > CHUNK_PLAINTEXT_LEN {
        return Err(FormatError::Manifest("chunk declared length out of range".into()));
    }
    Ok(pt[..real_len].to_vec())
}

/// Generate a random chunk-shaped block of bytes for unused slots so they
/// are indistinguishable from real chunks. Used for cryptographic shred
/// of deleted chunks and for padding the chunks region at vault creation.
pub fn random_chunk() -> Result<[u8; CHUNK_STORED_LEN]> {
    let mut block = [0u8; CHUNK_STORED_LEN];
    rng::fill(&mut block)?;
    Ok(block)
}

/// Derive the per-chunk AEAD key from the master key and chunk index.
///
/// Two chunks with the same content under the same master key yield
/// different per-chunk keys, which combined with random nonces gives
/// fresh ciphertext for each.
pub fn derive_chunk_key(master_key: &[u8; aead::KEY_LEN], index: ChunkIndex) -> AeadKey {
    let mut input = [0u8; aead::KEY_LEN + 4];
    input[..aead::KEY_LEN].copy_from_slice(master_key);
    LittleEndian::write_u32(&mut input[aead::KEY_LEN..], index.0);
    let k = hash::derive_key("farewell.chunk.key.v1", &input);
    AeadKey::from_bytes(k)
}

fn chunk_aad(index: ChunkIndex) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(b"chk1");
    LittleEndian::write_u32(&mut aad[4..], index.0);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let mk = [0xCDu8; aead::KEY_LEN];
        let idx = ChunkIndex(7);
        let key = derive_chunk_key(&mk, idx);

        let payload = b"my-source-list.txt content";
        let stored = encrypt_chunk(&key, idx, payload).unwrap();
        assert_eq!(stored.len(), CHUNK_STORED_LEN);

        let recovered = decrypt_chunk(&key, idx, &stored).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn wrong_index_fails() {
        // Chunk encrypted at index 1 must not decrypt at index 2 (AAD-bound).
        let mk = [0xCDu8; aead::KEY_LEN];
        let k1 = derive_chunk_key(&mk, ChunkIndex(1));
        let k2 = derive_chunk_key(&mk, ChunkIndex(2));

        let stored = encrypt_chunk(&k1, ChunkIndex(1), b"hi").unwrap();
        assert!(decrypt_chunk(&k2, ChunkIndex(2), &stored).is_err());
        // Also fails if we use the right index but wrong key.
        assert!(decrypt_chunk(&k2, ChunkIndex(1), &stored).is_err());
    }

    #[test]
    fn full_chunk_works() {
        let mk = [0u8; aead::KEY_LEN];
        let idx = ChunkIndex(0);
        let key = derive_chunk_key(&mk, idx);
        let payload = vec![0xAAu8; CHUNK_PLAINTEXT_LEN];
        let stored = encrypt_chunk(&key, idx, &payload).unwrap();
        let pt = decrypt_chunk(&key, idx, &stored).unwrap();
        assert_eq!(pt, payload);
    }

    #[test]
    fn too_large_payload_fails() {
        let mk = [0u8; aead::KEY_LEN];
        let key = derive_chunk_key(&mk, ChunkIndex(0));
        let payload = vec![0u8; CHUNK_PLAINTEXT_LEN + 1];
        assert!(encrypt_chunk(&key, ChunkIndex(0), &payload).is_err());
    }

    #[test]
    fn empty_payload_works() {
        let mk = [0u8; aead::KEY_LEN];
        let key = derive_chunk_key(&mk, ChunkIndex(0));
        let stored = encrypt_chunk(&key, ChunkIndex(0), b"").unwrap();
        let pt = decrypt_chunk(&key, ChunkIndex(0), &stored).unwrap();
        assert_eq!(pt, b"");
    }
}
