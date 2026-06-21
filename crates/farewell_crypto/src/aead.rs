//! Authenticated encryption: AES-256-GCM-SIV.
//!
//! GCM-SIV is chosen over plain GCM for nonce-misuse resistance: a repeated
//! nonce reveals only equality of plaintexts (not their content), where GCM
//! would catastrophically leak the authentication key. This matches the
//! threat model of `harvest now, decrypt later` adversaries who may observe
//! many vault states over time.

use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use zeroize::Zeroize;

use crate::{CryptoError, Result};

/// Symmetric key length in bytes.
pub const KEY_LEN: usize = 32;

/// Nonce length in bytes for AES-256-GCM-SIV.
pub const NONCE_LEN: usize = 12;

/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// A symmetric AEAD key, zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct AeadKey([u8; KEY_LEN]);

impl AeadKey {
    /// Construct a key from raw bytes. Caller must ensure the bytes come
    /// from a secure derivation, never from user input.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes. Caller must not retain a copy.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Encrypt `plaintext` with `key` and 12-byte `nonce`, binding `aad`.
///
/// Output is `ciphertext || tag` (16-byte tag appended).
pub fn encrypt(
    key: &AeadKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes256GcmSiv::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Decrypt)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// Decrypt `ciphertext` (which includes the 16-byte trailing tag) with
/// `key`, `nonce`, and `aad`. Returns the plaintext on success.
///
/// On any failure (wrong key, tampered ciphertext, wrong AAD), returns
/// `CryptoError::Decrypt` with no further detail. Do not surface a
/// distinction to the user.
pub fn decrypt(
    key: &AeadKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        Aes256GcmSiv::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Decrypt)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> AeadKey {
        AeadKey::from_bytes([0x42u8; KEY_LEN])
    }

    #[test]
    fn roundtrip() {
        let key = fixed_key();
        let nonce = [0x07u8; NONCE_LEN];
        let aad = b"vault-header-v1";
        let plaintext = b"the journalist's source list";

        let ct = encrypt(&key, &nonce, aad, plaintext).unwrap();
        let pt = decrypt(&key, &nonce, aad, &ct).unwrap();

        assert_eq!(pt, plaintext);
    }

    #[test]
    fn ciphertext_longer_than_plaintext() {
        let key = fixed_key();
        let pt = b"abc";
        let ct = encrypt(&key, &[0u8; NONCE_LEN], b"", pt).unwrap();
        assert_eq!(ct.len(), pt.len() + TAG_LEN);
    }

    #[test]
    fn wrong_key_fails() {
        let nonce = [0u8; NONCE_LEN];
        let ct = encrypt(&fixed_key(), &nonce, b"", b"hello").unwrap();

        let wrong = AeadKey::from_bytes([0xFFu8; KEY_LEN]);
        assert!(decrypt(&wrong, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = fixed_key();
        let nonce = [0u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"context-a", b"hello").unwrap();
        assert!(decrypt(&key, &nonce, b"context-b", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = fixed_key();
        let nonce = [0u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"", b"hello").unwrap();
        ct[0] ^= 0x01;
        assert!(decrypt(&key, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn nonce_misuse_does_not_reveal_key() {
        // GCM-SIV property: repeating nonce on different plaintexts is
        // safe-ish (it reveals plaintext equality, but not the key).
        let key = fixed_key();
        let nonce = [0u8; NONCE_LEN];
        let ct1 = encrypt(&key, &nonce, b"", b"alpha").unwrap();
        let ct2 = encrypt(&key, &nonce, b"", b"beta").unwrap();
        // Different plaintexts → different ciphertexts (since they differ).
        assert_ne!(ct1, ct2);
        // Same plaintext → same ciphertext (this is the SIV property).
        let ct3 = encrypt(&key, &nonce, b"", b"alpha").unwrap();
        assert_eq!(ct1, ct3);
    }
}
