//! Digital signatures: Ed25519 (classical) and ML-DSA-87 (post-quantum).
//!
//! v0.10 — ML-DSA-87 is provided by `libcrux-ml-dsa`, formally verified
//! via hax + F* (Cryspen).
//!
//! Per ARCHITECTURE.md §3.2, releases and vault headers are signed with
//! both primitives concurrently. Verification accepts only if both are
//! valid. The hybrid composition lives outside this module — this file
//! just exposes solid single-algorithm primitives.

use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey,
    Verifier as EdVerifier, VerifyingKey as EdVerifyingKey,
};
use libcrux_ml_dsa::{
    ml_dsa_87::{self, MLDSA87Signature, MLDSA87VerificationKey},
    KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE,
};
use rand_core::OsRng;
use zeroize::Zeroize;

use crate::{rng, CryptoError, Result};

/// Ed25519 public key length in bytes.
pub const ED25519_PK_LEN: usize = 32;
/// Ed25519 secret key length in bytes.
pub const ED25519_SK_LEN: usize = 32;
/// Ed25519 signature length in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// ML-DSA-87 verifying (public) key length in bytes (FIPS 204 §6, Table 2).
pub const MLDSA_PK_LEN: usize = 2592;
/// ML-DSA-87 signing key — canonical 32-byte seed `ξ`.
///
/// libcrux's full expanded signing key is 4896 bytes; we persist only
/// the FIPS 204 seed and regenerate the expanded form on demand. This
/// gives compact at-rest storage and matches what a mainteneur would
/// commit to long-term cold storage.
pub const MLDSA_SK_SEED_LEN: usize = KEY_GENERATION_RANDOMNESS_SIZE;
/// ML-DSA-87 signature length in bytes.
pub const MLDSA_SIG_LEN: usize = 4627;

/// Empty context byte string used by the high-level sign/verify API.
/// The FIPS 204 sign API takes a context parameter for domain
/// separation; in our default use case (header signing, release
/// signing) the context is the empty string. Callers needing domain
/// separation should call `mldsa_sign_with_context` directly.
const EMPTY_CONTEXT: &[u8] = b"";

// --- Ed25519 ---------------------------------------------------------------

/// Ed25519 signing key, zeroized on drop.
pub struct SigningKey(EdSigningKey);

impl SigningKey {
    /// Generate a fresh Ed25519 signing key from the OS CSPRNG.
    pub fn generate() -> Self {
        Self(EdSigningKey::generate(&mut OsRng))
    }

    /// Public verifying key for this signer.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIG_LEN] {
        self.0.sign(message).to_bytes()
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
    }
}

/// Ed25519 verifying (public) key.
#[derive(Clone)]
pub struct VerifyingKey(EdVerifyingKey);

impl VerifyingKey {
    /// Construct from raw 32-byte representation.
    pub fn from_bytes(bytes: &[u8; ED25519_PK_LEN]) -> Result<Self> {
        EdVerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::Signature)
    }

    /// Raw 32-byte representation.
    pub fn to_bytes(&self) -> [u8; ED25519_PK_LEN] {
        self.0.to_bytes()
    }

    /// Verify a signature against a message. Constant-time on success path.
    pub fn verify(&self, message: &[u8], signature: &[u8; ED25519_SIG_LEN]) -> Result<()> {
        let sig = EdSignature::from_bytes(signature);
        self.0
            .verify(message, &sig)
            .map_err(|_| CryptoError::Signature)
    }
}

// --- ML-DSA-87 (libcrux, formally verified) -------------------------------

/// ML-DSA-87 signing key. Persisted as the 32-byte FIPS 204 seed `ξ`;
/// the expanded keypair is regenerated lazily on each use.
///
/// The seed is held in a fixed-size array and zeroized on drop.
pub struct MlDsaSigningKey {
    seed: [u8; MLDSA_SK_SEED_LEN],
}

impl MlDsaSigningKey {
    fn keypair(&self) -> libcrux_ml_dsa::MLDSAKeyPair<2592, 4896> {
        ml_dsa_87::generate_key_pair(self.seed)
    }

    /// Derive the matching verifying key.
    pub fn verifying_key(&self) -> MlDsaVerifyingKey {
        let kp = self.keypair();
        MlDsaVerifyingKey(kp.verification_key)
    }

    /// Serialize to the canonical 32-byte FIPS 204 seed.
    pub fn to_bytes(&self) -> [u8; MLDSA_SK_SEED_LEN] {
        self.seed
    }

    /// Parse from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8; MLDSA_SK_SEED_LEN]) -> Result<Self> {
        Ok(Self { seed: *bytes })
    }
}

impl Drop for MlDsaSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// ML-DSA-87 verifying (public) key.
#[derive(Clone)]
pub struct MlDsaVerifyingKey(MLDSA87VerificationKey);

impl MlDsaVerifyingKey {
    /// Serialize the verifying key to its canonical byte form.
    pub fn to_bytes(&self) -> Box<[u8; MLDSA_PK_LEN]> {
        let mut out = Box::new([0u8; MLDSA_PK_LEN]);
        out.copy_from_slice(self.0.as_ref());
        out
    }

    /// Parse a verifying key from its canonical byte form.
    pub fn from_bytes(bytes: &[u8; MLDSA_PK_LEN]) -> Result<Self> {
        Ok(Self(MLDSA87VerificationKey::new(*bytes)))
    }
}

/// Generate an ML-DSA-87 keypair using the OS CSPRNG.
pub fn mldsa_generate() -> (MlDsaSigningKey, MlDsaVerifyingKey) {
    let mut seed = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    rng::fill(&mut seed).expect("OS CSPRNG must work");
    let kp = ml_dsa_87::generate_key_pair(seed);
    let sk = MlDsaSigningKey { seed };
    let vk = MlDsaVerifyingKey(kp.verification_key);
    // seed is moved into sk; nothing left to zeroize locally.
    (sk, vk)
}

/// Sign a message with an ML-DSA-87 signing key (empty context).
pub fn mldsa_sign(sk: &MlDsaSigningKey, message: &[u8]) -> Box<[u8; MLDSA_SIG_LEN]> {
    mldsa_sign_with_context(sk, message, EMPTY_CONTEXT)
}

/// Sign a message with an ML-DSA-87 signing key under a domain-separation
/// context (up to 255 bytes).
pub fn mldsa_sign_with_context(
    sk: &MlDsaSigningKey,
    message: &[u8],
    context: &[u8],
) -> Box<[u8; MLDSA_SIG_LEN]> {
    let kp = sk.keypair();
    let mut sign_seed = [0u8; SIGNING_RANDOMNESS_SIZE];
    rng::fill(&mut sign_seed).expect("OS CSPRNG must work");
    let sig: MLDSA87Signature = ml_dsa_87::sign(&kp.signing_key, message, context, sign_seed)
        .expect("sign should succeed with valid parameters");
    sign_seed.zeroize();
    let mut out = Box::new([0u8; MLDSA_SIG_LEN]);
    out.copy_from_slice(sig.as_ref());
    out
}

/// Verify an ML-DSA-87 signature against a message (empty context).
pub fn mldsa_verify(
    vk: &MlDsaVerifyingKey,
    message: &[u8],
    signature: &[u8; MLDSA_SIG_LEN],
) -> Result<()> {
    mldsa_verify_with_context(vk, message, EMPTY_CONTEXT, signature)
}

/// Verify an ML-DSA-87 signature against a message under a
/// domain-separation context.
pub fn mldsa_verify_with_context(
    vk: &MlDsaVerifyingKey,
    message: &[u8],
    context: &[u8],
    signature: &[u8; MLDSA_SIG_LEN],
) -> Result<()> {
    let sig = MLDSA87Signature::new(*signature);
    ml_dsa_87::verify(&vk.0, message, context, &sig).map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Ed25519 ---

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let msg = b"vault header v1 + counter=42";
        let sig = sk.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn ed25519_tampered_message_fails() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");
        assert!(vk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let sk1 = SigningKey::generate();
        let sk2 = SigningKey::generate();
        let sig = sk1.sign(b"hello");
        assert!(sk2.verifying_key().verify(b"hello", &sig).is_err());
    }

    #[test]
    fn ed25519_verifying_key_roundtrip() {
        let sk = SigningKey::generate();
        let vk = sk.verifying_key();
        let bytes = vk.to_bytes();
        let vk2 = VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk.to_bytes(), vk2.to_bytes());
    }

    // --- ML-DSA-87 ---

    #[test]
    fn mldsa_sign_verify_roundtrip() {
        let (sk, vk) = mldsa_generate();
        let msg = b"vault header v1 + counter=42";
        let sig = mldsa_sign(&sk, msg);
        assert!(mldsa_verify(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn mldsa_tampered_message_fails() {
        let (sk, vk) = mldsa_generate();
        let sig = mldsa_sign(&sk, b"original");
        assert!(mldsa_verify(&vk, b"tampered", &sig).is_err());
    }

    #[test]
    fn mldsa_wrong_key_fails() {
        let (sk1, _vk1) = mldsa_generate();
        let (_sk2, vk2) = mldsa_generate();
        let sig = mldsa_sign(&sk1, b"hello");
        assert!(mldsa_verify(&vk2, b"hello", &sig).is_err());
    }

    #[test]
    fn mldsa_verifying_key_byte_roundtrip() {
        let (_sk, vk) = mldsa_generate();
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), MLDSA_PK_LEN);
        let vk2 = MlDsaVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(*vk2.to_bytes(), *bytes);
    }

    #[test]
    fn mldsa_signing_key_byte_roundtrip_preserves_signatures() {
        let (sk, vk) = mldsa_generate();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), MLDSA_SK_SEED_LEN);
        let sk2 = MlDsaSigningKey::from_bytes(&bytes).unwrap();
        let sig = mldsa_sign(&sk2, b"after roundtrip");
        assert!(mldsa_verify(&vk, b"after roundtrip", &sig).is_ok());
    }

    #[test]
    fn mldsa_context_separation() {
        // Same message signed under different contexts must produce
        // different verifications. A sig with context A must NOT verify
        // under context B.
        let (sk, vk) = mldsa_generate();
        let msg = b"shared message";
        let sig_a = mldsa_sign_with_context(&sk, msg, b"context-A");
        assert!(mldsa_verify_with_context(&vk, msg, b"context-A", &sig_a).is_ok());
        assert!(mldsa_verify_with_context(&vk, msg, b"context-B", &sig_a).is_err());
    }
}
