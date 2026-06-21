//! Wrapped master-key slots — v0.4 (FIDO2 hardware-key wrapping).
//!
//! A vault always contains [`NUM_SLOTS`] slots, each [`SLOT_LEN`] bytes.
//! An active slot encrypts a fixed-shape inner payload under the
//! passphrase-derived key. That payload contains:
//!
//! - the number of enrolled hardware keys (0..=[`MAX_HW_KEYS_PER_LEVEL`]),
//! - one entry per HW key slot (credential ID + AEAD-wrapped Key-Wrapping
//!   Key under the combined `(passphrase + hmac-secret)` key),
//! - the AEAD wrap of the level's master key under the KWK.
//!
//! Inactive slots are filled with cryptographically random bytes,
//! statistically indistinguishable from active slots without the
//! passphrase. Within an active slot, HW slots that are not enrolled
//! are filled with random bytes too — the count `K` reveals enrollment
//! depth only to a holder of the passphrase.
//!
//! Format constants are versioned via `AAD`s; bumping the format
//! requires bumping the AAD strings to prevent cross-version replay.

use byteorder::{ByteOrder, LittleEndian};
use farewell_crypto::{
    aead::{self, AeadKey, NONCE_LEN, TAG_LEN},
    hash, rng,
};
use farewell_fido2::{Authenticator, Fido2Error, HMAC_OUTPUT_LEN, HMAC_SALT_LEN, MAX_CRED_ID_LEN};
use zeroize::Zeroize;

use crate::{FormatError, Result};

/// Number of master-key slots in a vault.
///
/// A Farewell vault is a single-domain encrypted container: exactly one
/// passphrase opens exactly one content tree, which uses the whole
/// capacity. (Hidden/decoy volumes were removed in v0.6 — see
/// ARCHITECTURE; this is intentionally not a multi-slot format.)
pub const NUM_SLOTS: usize = 1;

/// Size of one slot in bytes.
pub const SLOT_LEN: usize = 4096;

/// Length of the master key in bytes.
pub const MASTER_KEY_LEN: usize = aead::KEY_LEN;

/// Length of the shared metadata key in bytes (v0.5).
///
/// Every active slot carries an identical copy of this key inside its
/// AEAD-protected inner payload. It decrypts the single shared metadata
/// blob (version, total_chunks, ML-DSA verifying key + signature). It is
/// the same value across all real levels, so any level that unlocks can
/// read the vault metadata — yet it never appears in cleartext on disk.
pub const METADATA_KEY_LEN: usize = aead::KEY_LEN;

/// Length of the Key-Wrapping Key in bytes.
pub const KWK_LEN: usize = aead::KEY_LEN;

/// Maximum number of hardware keys enrolled per level.
pub const MAX_HW_KEYS_PER_LEVEL: usize = 3;

/// Layout constants for the inner (encrypted) payload of an active slot.
mod layout {
    use super::{METADATA_KEY_LEN, MAX_CRED_ID_LEN, MAX_HW_KEYS_PER_LEVEL};
    use farewell_crypto::aead::{NONCE_LEN, TAG_LEN};

    pub const CRED_LEN_FIELD: usize = 2; // u16 LE
    pub const HW_SLOT_LEN: usize = CRED_LEN_FIELD + MAX_CRED_ID_LEN + NONCE_LEN + 32 + TAG_LEN;
    //                              =2          +256              +12       +32 +16  = 318
    pub const NUM_HW_KEYS_FIELD: usize = 1;
    pub const MASTER_WRAP_PAYLOAD_LEN: usize = 32 + 4; // master_key || len_tag
    pub const MASTER_WRAP_LEN: usize = NONCE_LEN + MASTER_WRAP_PAYLOAD_LEN + TAG_LEN;
    //                                 =12        +36                       +16  = 64
    /// Offset of the master-key wrap within the inner plaintext.
    pub const MASTER_WRAP_OFFSET: usize =
        NUM_HW_KEYS_FIELD + MAX_HW_KEYS_PER_LEVEL * HW_SLOT_LEN;
    /// Offset of the shared metadata key, right after the master wrap (v0.5).
    pub const METADATA_KEY_OFFSET: usize = MASTER_WRAP_OFFSET + MASTER_WRAP_LEN;

    /// Per-key human-readable label length, UTF-8, zero-padded (v0.6). Fixed
    /// size so the label length is not observable from the (AEAD'd) inner.
    pub const LABEL_LEN: usize = 48;
    /// Offset of the labels block (one [`LABEL_LEN`] entry per HW key), right
    /// after the metadata key (v0.6).
    pub const LABELS_OFFSET: usize = METADATA_KEY_OFFSET + METADATA_KEY_LEN;
    pub const LABELS_BLOCK_LEN: usize = MAX_HW_KEYS_PER_LEVEL * LABEL_LEN;
    pub const INNER_PLAINTEXT_LEN: usize = LABELS_OFFSET + LABELS_BLOCK_LEN;
    //                  =1 +3*318 +64 +32 +3*48 = 1195
    pub const INNER_CIPHERTEXT_LEN: usize = INNER_PLAINTEXT_LEN + TAG_LEN;
}

const SLOT_AAD: &[u8] = b"farewell.slot.v6";

/// Salt domain string presented to the FIDO2 hmac-secret extension.
///
/// The actual salt mixed into the authenticator is BLAKE3.derive_key of
/// this domain over the vault salt, so the same authenticator can
/// safely host credentials for multiple vaults.
const FIDO_SALT_DOMAIN: &str = "farewell.fido.salt.v5";

/// Domain string used to derive KWK in passphrase-only (K=0) mode.
const NO_HW_KWK_DOMAIN: &str = "farewell.kwk.no_hw.v5";

/// Domain string used to derive `combine(passphrase_key, hw_output)`.
const COMBINE_DOMAIN: &str = "farewell.combine.v5";

/// Index of a slot (0, 1, or 2).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SlotIndex(pub u8);

impl SlotIndex {
    /// Construct from a numeric value, validating range.
    pub fn new(n: u8) -> Result<Self> {
        if (n as usize) >= NUM_SLOTS {
            return Err(FormatError::Manifest(format!("slot index {n} out of range")));
        }
        Ok(Self(n))
    }
}

/// Successful unwrap of a slot: gives the master key. (HW credentials
/// are consumed internally; callers do not need them.)
#[derive(Debug, Clone)]
pub struct UnwrappedSlot {
    /// Per-level master key.
    pub master_key: [u8; MASTER_KEY_LEN],
    /// Shared metadata key (identical across all real levels). Decrypts
    /// the vault's single encrypted metadata blob (v0.5).
    pub metadata_key: [u8; METADATA_KEY_LEN],
    /// Index of the slot this unwrap matched (0..NUM_SLOTS). Determines
    /// the level's disjoint chunk stripe (`chunk % NUM_SLOTS == slot`),
    /// the load-bearing property that makes cross-level corruption
    /// impossible. Set by [`WrappedSlot::try_unwrap_all`]; left 0 by
    /// the single-slot [`WrappedSlot::try_unwrap`].
    pub slot: u8,
    /// Number of hardware-key credentials enrolled in this slot (0 =
    /// passphrase-only). Read from the slot's `K` field at unwrap time;
    /// lets callers report how many keys open the vault, and cap further
    /// enrollment at [`MAX_HW_KEYS_PER_LEVEL`].
    pub num_hw_keys: usize,
}

/// Compute the `hmac-secret` salt presented to the authenticator from the
/// vault salt. Domain-separated by [`FIDO_SALT_DOMAIN`] so the same
/// authenticator credential can host secrets for unrelated vaults safely.
pub fn fido_salt_from_vault_salt(vault_salt: &[u8]) -> [u8; HMAC_SALT_LEN] {
    let mut input = Vec::with_capacity(vault_salt.len() + 16);
    input.extend_from_slice(b"vault_salt:");
    input.extend_from_slice(vault_salt);
    let derived = blake3::derive_key(FIDO_SALT_DOMAIN, &input);
    let mut out = [0u8; HMAC_SALT_LEN];
    out.copy_from_slice(&derived);
    out
}

/// Combine the passphrase-derived key and the hmac-secret output into a
/// single Key-Wrapping-Key encryption key.
fn combine_key(passphrase_key: &[u8; 32], hw_output: &[u8; HMAC_OUTPUT_LEN]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(passphrase_key);
    input[32..].copy_from_slice(hw_output);
    let out = blake3::derive_key(COMBINE_DOMAIN, &input);
    input.zeroize();
    out
}

/// KWK derivation when no HW key is enrolled (`K = 0`).
fn no_hw_kwk(passphrase_key: &[u8; 32]) -> [u8; KWK_LEN] {
    hash::derive_key(NO_HW_KWK_DOMAIN, passphrase_key)
}

/// Specification of the enrolled hardware keys for one level at create time.
///
/// `None` (or `Vec::new()`) → passphrase-only mode (K=0).
/// Otherwise contains the credential IDs returned by enrollment plus
/// the `hmac-secret` output captured at enroll time. Both pieces are
/// consumed when building the slot.
#[derive(Debug, Default)]
pub struct LevelEnrollment {
    /// (credential_id, hmac_output, label) tuples. The label is a short
    /// human-readable name shown in the keys-management UI (v0.6); it is
    /// stored inside the AEAD'd inner so it never appears in cleartext.
    /// Length 0..=[`MAX_HW_KEYS_PER_LEVEL`].
    pub entries: Vec<(Vec<u8>, [u8; HMAC_OUTPUT_LEN], String)>,
}

impl LevelEnrollment {
    /// Build an empty enrollment (passphrase-only mode).
    pub fn passphrase_only() -> Self {
        Self::default()
    }

    /// Number of enrolled HW keys (K).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no HW key is enrolled.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Push another `(credential_id, hmac_output)` pair with an empty label.
    pub fn push(&mut self, credential_id: Vec<u8>, hmac_output: [u8; HMAC_OUTPUT_LEN]) -> Result<()> {
        self.push_labeled(credential_id, hmac_output, String::new())
    }

    /// Push another `(credential_id, hmac_output, label)` tuple. The label is
    /// truncated to fit [`layout::LABEL_LEN`] bytes when the slot is written.
    pub fn push_labeled(
        &mut self,
        credential_id: Vec<u8>,
        hmac_output: [u8; HMAC_OUTPUT_LEN],
        label: String,
    ) -> Result<()> {
        if credential_id.len() > MAX_CRED_ID_LEN {
            return Err(FormatError::Manifest(format!(
                "credential ID too long: {} > {}",
                credential_id.len(),
                MAX_CRED_ID_LEN
            )));
        }
        if self.entries.len() >= MAX_HW_KEYS_PER_LEVEL {
            return Err(FormatError::Manifest(format!(
                "too many HW keys: max {}",
                MAX_HW_KEYS_PER_LEVEL
            )));
        }
        self.entries.push((credential_id, hmac_output, label));
        Ok(())
    }
}

/// Encode a label string into a fixed [`layout::LABEL_LEN`]-byte field:
/// UTF-8, truncated on a char boundary, zero-padded.
fn encode_label(label: &str, out: &mut [u8]) {
    debug_assert_eq!(out.len(), layout::LABEL_LEN);
    out.fill(0);
    let bytes = label.as_bytes();
    let mut n = bytes.len().min(layout::LABEL_LEN);
    // Don't split a multi-byte char: back off to a char boundary.
    while n > 0 && !label.is_char_boundary(n) {
        n -= 1;
    }
    out[..n].copy_from_slice(&bytes[..n]);
}

/// Decode a fixed-width label field back into a string (NUL-trimmed, lossy
/// UTF-8 so a corrupt field never errors the unlock path).
fn decode_label(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// One slot.
pub struct WrappedSlot;

impl WrappedSlot {
    /// Build a slot containing a wrapped master key, with optional HW
    /// key enrollment.
    pub fn wrap(
        passphrase_key: &[u8; 32],
        master_key: &[u8; MASTER_KEY_LEN],
        metadata_key: &[u8; METADATA_KEY_LEN],
        enrollment: &LevelEnrollment,
    ) -> Result<[u8; SLOT_LEN]> {
        // ---- choose KWK ----
        let kwk: [u8; KWK_LEN] = if enrollment.is_empty() {
            no_hw_kwk(passphrase_key)
        } else {
            let mut k = [0u8; KWK_LEN];
            rng::fill(&mut k)?;
            k
        };

        // ---- build inner plaintext ----
        let mut inner = vec![0u8; layout::INNER_PLAINTEXT_LEN];
        inner[0] = enrollment.len() as u8;

        // HW key slots: 3 of them. Active ones first (or in any order,
        // but we pack at the start). Random fill the rest.
        let mut cursor = layout::NUM_HW_KEYS_FIELD;
        for i in 0..MAX_HW_KEYS_PER_LEVEL {
            let hw_slot_start = cursor;
            let hw_slot_end = cursor + layout::HW_SLOT_LEN;
            cursor = hw_slot_end;

            if i < enrollment.len() {
                let (cred_id, hw_output, _label) = &enrollment.entries[i];
                // [..2] credId_len, [2..258] credId, [258..270] nonce, [270..318] AEAD(KWK)
                LittleEndian::write_u16(
                    &mut inner[hw_slot_start..hw_slot_start + 2],
                    cred_id.len() as u16,
                );
                // Place credential, zero pad up to MAX_CRED_ID_LEN.
                let cred_dst = &mut inner[hw_slot_start + 2..hw_slot_start + 2 + MAX_CRED_ID_LEN];
                cred_dst[..cred_id.len()].copy_from_slice(cred_id);
                // Random-fill the unused tail so the credential length isn't
                // observable from inner-plaintext zero patterns (defense in
                // depth — the whole inner is AEAD'd anyway).
                rng::fill(&mut cred_dst[cred_id.len()..])?;

                let kwk_nonce_off = hw_slot_start + 2 + MAX_CRED_ID_LEN;
                let kwk_ct_off = kwk_nonce_off + NONCE_LEN;
                let mut kwk_nonce = [0u8; NONCE_LEN];
                rng::fill(&mut kwk_nonce)?;
                inner[kwk_nonce_off..kwk_nonce_off + NONCE_LEN].copy_from_slice(&kwk_nonce);

                let combine = combine_key(passphrase_key, hw_output);
                let combine_aead = AeadKey::from_bytes(combine);
                let aad = hw_slot_aad(i);
                let kwk_ct = aead::encrypt(&combine_aead, &kwk_nonce, aad, &kwk)?;
                inner[kwk_ct_off..kwk_ct_off + kwk_ct.len()].copy_from_slice(&kwk_ct);
                // Zeroize the combine key as soon as we're done with it.
                let mut combine_kill = combine;
                combine_kill.zeroize();
            } else {
                // Inactive HW slot: random bytes.
                rng::fill(&mut inner[hw_slot_start..hw_slot_end])?;
                // Force credId_len to a "random" value as well; we already
                // randomized it via the rng::fill above.
            }
        }

        // Master key wrap: AEAD(KWK, master_key||len_tag).
        let mut master_nonce = [0u8; NONCE_LEN];
        rng::fill(&mut master_nonce)?;
        let mut master_payload = [0u8; layout::MASTER_WRAP_PAYLOAD_LEN];
        master_payload[..MASTER_KEY_LEN].copy_from_slice(master_key);
        LittleEndian::write_u32(
            &mut master_payload[MASTER_KEY_LEN..],
            MASTER_KEY_LEN as u32,
        );
        let kwk_aead = AeadKey::from_bytes(kwk);
        let master_ct = aead::encrypt(
            &kwk_aead,
            &master_nonce,
            b"farewell.slot.master.v6",
            &master_payload,
        )?;
        master_payload.zeroize();

        inner[cursor..cursor + NONCE_LEN].copy_from_slice(&master_nonce);
        inner[cursor + NONCE_LEN..cursor + NONCE_LEN + master_ct.len()]
            .copy_from_slice(&master_ct);

        // Shared metadata key, identical across all real levels (v0.5).
        inner[layout::METADATA_KEY_OFFSET..layout::METADATA_KEY_OFFSET + METADATA_KEY_LEN]
            .copy_from_slice(metadata_key);

        // Per-key labels block (v0.6): one fixed-width field per HW key.
        // Active keys carry their (truncated) name; inactive slots are random
        // so the active count isn't observable from the inner plaintext.
        for i in 0..MAX_HW_KEYS_PER_LEVEL {
            let off = layout::LABELS_OFFSET + i * layout::LABEL_LEN;
            let field = &mut inner[off..off + layout::LABEL_LEN];
            if i < enrollment.len() {
                encode_label(&enrollment.entries[i].2, field);
            } else {
                rng::fill(field)?;
            }
        }

        // ---- AEAD-encrypt the inner under the passphrase key ----
        let mut outer_nonce = [0u8; NONCE_LEN];
        rng::fill(&mut outer_nonce)?;
        let pp_aead = AeadKey::from_bytes(*passphrase_key);
        let outer_ct = aead::encrypt(&pp_aead, &outer_nonce, SLOT_AAD, &inner)?;
        // Zeroize the inner plaintext now.
        inner.zeroize();

        // ---- assemble the slot ----
        let mut slot = [0u8; SLOT_LEN];
        slot[..NONCE_LEN].copy_from_slice(&outer_nonce);
        slot[NONCE_LEN..NONCE_LEN + outer_ct.len()].copy_from_slice(&outer_ct);
        // Pad with random bytes.
        rng::fill(&mut slot[NONCE_LEN + outer_ct.len()..])?;
        Ok(slot)
    }

    /// Try to unwrap a slot.
    ///
    /// If the inner payload reports `K = 0`, the slot is unwrapped using
    /// the passphrase-only KWK derivation; the authenticator is not
    /// touched.
    ///
    /// If `K ≥ 1`, the authenticator is queried with the K candidate
    /// credentials and a salt derived from the vault salt. The HMAC
    /// output is combined with the passphrase key to recover the KWK
    /// and ultimately the master key.
    pub fn try_unwrap<A: Authenticator>(
        slot: &[u8; SLOT_LEN],
        passphrase_key: &[u8; 32],
        vault_salt: &[u8],
        authenticator: Option<&mut A>,
    ) -> Result<UnwrappedSlot> {
        // ---- decrypt outer ----
        let mut outer_nonce = [0u8; NONCE_LEN];
        outer_nonce.copy_from_slice(&slot[..NONCE_LEN]);
        let outer_ct = &slot[NONCE_LEN..NONCE_LEN + layout::INNER_CIPHERTEXT_LEN];
        let pp_aead = AeadKey::from_bytes(*passphrase_key);
        let inner_plain = aead::decrypt(&pp_aead, &outer_nonce, SLOT_AAD, outer_ct)?;
        if inner_plain.len() != layout::INNER_PLAINTEXT_LEN {
            return Err(FormatError::Manifest("inner plaintext length mismatch".into()));
        }

        let k = inner_plain[0] as usize;
        if k > MAX_HW_KEYS_PER_LEVEL {
            return Err(FormatError::Manifest(format!(
                "invalid HW key count: {k}"
            )));
        }

        // Recover the KWK.
        let kwk: [u8; KWK_LEN] = if k == 0 {
            no_hw_kwk(passphrase_key)
        } else {
            let auth = authenticator.ok_or(FormatError::HardwareKeyRequired)?;
            unwrap_kwk_via_authenticator(passphrase_key, vault_salt, k, &inner_plain, auth)?
        };

        // Decrypt the master key wrap.
        let master_off = layout::NUM_HW_KEYS_FIELD + MAX_HW_KEYS_PER_LEVEL * layout::HW_SLOT_LEN;
        let mut master_nonce = [0u8; NONCE_LEN];
        master_nonce.copy_from_slice(&inner_plain[master_off..master_off + NONCE_LEN]);
        let master_ct =
            &inner_plain[master_off + NONCE_LEN..master_off + layout::MASTER_WRAP_LEN];
        let kwk_aead = AeadKey::from_bytes(kwk);
        let master_payload = aead::decrypt(
            &kwk_aead,
            &master_nonce,
            b"farewell.slot.master.v6",
            master_ct,
        )?;
        // We have to zero the KWK we held briefly — `kwk_aead` owns its
        // copy via AeadKey::from_bytes (zeroized on drop).
        let mut kwk_kill = kwk;
        kwk_kill.zeroize();

        if master_payload.len() != layout::MASTER_WRAP_PAYLOAD_LEN {
            return Err(FormatError::Manifest("master payload length mismatch".into()));
        }
        let declared = LittleEndian::read_u32(&master_payload[MASTER_KEY_LEN..]) as usize;
        if declared != MASTER_KEY_LEN {
            return Err(FormatError::Manifest("master length tag mismatch".into()));
        }
        let mut master_key = [0u8; MASTER_KEY_LEN];
        master_key.copy_from_slice(&master_payload[..MASTER_KEY_LEN]);

        // Extract the shared metadata key from the (authenticated) inner.
        let mut metadata_key = [0u8; METADATA_KEY_LEN];
        metadata_key.copy_from_slice(
            &inner_plain
                [layout::METADATA_KEY_OFFSET..layout::METADATA_KEY_OFFSET + METADATA_KEY_LEN],
        );

        // `slot` is filled in by try_unwrap_all (which knows the index);
        // a bare try_unwrap doesn't know its position.
        Ok(UnwrappedSlot {
            master_key,
            metadata_key,
            slot: 0,
            num_hw_keys: k,
        })
    }

    /// Try to unwrap every slot of a vault with the same wrap inputs,
    /// returning the unique successful unwrap (or `Err` if zero or
    /// multiple slots succeed).
    pub fn try_unwrap_all<A: Authenticator>(
        slots: &[[u8; SLOT_LEN]; NUM_SLOTS],
        passphrase_key: &[u8; 32],
        vault_salt: &[u8],
        mut authenticator: Option<&mut A>,
    ) -> Result<UnwrappedSlot> {
        let mut successes: Vec<UnwrappedSlot> = Vec::with_capacity(NUM_SLOTS);
        // A slot whose outer decrypted but which needs a hardware key we
        // weren't given (only possible when `authenticator` is None). We
        // remember it so a caller opening passphrase-only can be told the
        // passphrase was right but a key is required — distinct from a
        // wrong passphrase, which never decrypts any slot's outer.
        let mut needs_hw = false;
        for (idx, slot) in slots.iter().enumerate() {
            // Borrow the authenticator option as a re-usable &mut for each attempt.
            let auth_opt = authenticator.as_deref_mut();
            match WrappedSlot::try_unwrap(slot, passphrase_key, vault_salt, auth_opt) {
                Ok(mut u) => {
                    // Record which slot position matched — this drives the
                    // level's chunk stripe.
                    u.slot = idx as u8;
                    successes.push(u);
                }
                Err(FormatError::HardwareKeyRequired) => needs_hw = true,
                Err(_) => {}
            }
        }
        match successes.len() {
            1 => Ok(successes.pop().unwrap()),
            0 if needs_hw => Err(FormatError::HardwareKeyRequired),
            _ => Err(FormatError::Crypto(
                farewell_crypto::CryptoError::Decrypt,
            )),
        }
    }

    /// Fill a slot with indistinguishable random bytes.
    pub fn fill_indistinguishable() -> Result<[u8; SLOT_LEN]> {
        let mut slot = [0u8; SLOT_LEN];
        rng::fill(&mut slot)?;
        Ok(slot)
    }

    /// Decrypt a slot with `passphrase_key` and return `(K, credential_ids,
    /// labels)`. `Err` if the passphrase key is wrong (the outer AEAD fails) or
    /// the inner is malformed. Used to (a) confirm the right passphrase/KDF,
    /// (b) list the enrolled credentials so a present key can be challenged,
    /// and (c) show each key's name in the keys-management UI.
    pub fn read_enrollment(
        slot: &[u8; SLOT_LEN],
        passphrase_key: &[u8; 32],
    ) -> Result<(usize, Vec<Vec<u8>>, Vec<String>)> {
        let mut outer_nonce = [0u8; NONCE_LEN];
        outer_nonce.copy_from_slice(&slot[..NONCE_LEN]);
        let outer_ct = &slot[NONCE_LEN..NONCE_LEN + layout::INNER_CIPHERTEXT_LEN];
        let pp_aead = AeadKey::from_bytes(*passphrase_key);
        let inner = aead::decrypt(&pp_aead, &outer_nonce, SLOT_AAD, outer_ct)?;
        if inner.len() != layout::INNER_PLAINTEXT_LEN {
            return Err(FormatError::Manifest("inner plaintext length mismatch".into()));
        }
        let k = inner[0] as usize;
        if k > MAX_HW_KEYS_PER_LEVEL {
            return Err(FormatError::Manifest(format!("invalid HW key count: {k}")));
        }
        let mut creds = Vec::with_capacity(k);
        let mut labels = Vec::with_capacity(k);
        let mut cursor = layout::NUM_HW_KEYS_FIELD;
        for i in 0..k {
            let cred_len = LittleEndian::read_u16(&inner[cursor..cursor + 2]) as usize;
            if cred_len == 0 || cred_len > MAX_CRED_ID_LEN {
                return Err(FormatError::Manifest(format!(
                    "HW slot {i}: invalid credential length {cred_len}"
                )));
            }
            creds.push(inner[cursor + 2..cursor + 2 + cred_len].to_vec());
            let loff = layout::LABELS_OFFSET + i * layout::LABEL_LEN;
            labels.push(decode_label(&inner[loff..loff + layout::LABEL_LEN]));
            cursor += layout::HW_SLOT_LEN;
        }
        Ok((k, creds, labels))
    }

    /// Add one hardware-key credential to an existing slot, in place — the
    /// master key and every existing entry are preserved (the same KWK is
    /// re-wrapped for the new key). Returns the rebuilt slot bytes.
    ///
    /// `recover_hmac` is the hmac-secret output of a **present, already-enrolled**
    /// key, used to recover the KWK; pass `None` only when the slot has no
    /// hardware keys yet (`K==0`, the KWK is passphrase-derived). `new_cred` /
    /// `new_hmac` are the just-enrolled backup key's credential id and its
    /// hmac-secret output for this vault.
    pub fn add_credential(
        slot: &[u8; SLOT_LEN],
        passphrase_key: &[u8; 32],
        recover_hmac: Option<&[u8; HMAC_OUTPUT_LEN]>,
        new_cred: &[u8],
        new_hmac: &[u8; HMAC_OUTPUT_LEN],
        new_label: &str,
    ) -> Result<[u8; SLOT_LEN]> {
        if new_cred.is_empty() || new_cred.len() > MAX_CRED_ID_LEN {
            return Err(FormatError::Manifest("invalid new credential length".into()));
        }

        // ---- decrypt outer ----
        let mut outer_nonce = [0u8; NONCE_LEN];
        outer_nonce.copy_from_slice(&slot[..NONCE_LEN]);
        let outer_ct = &slot[NONCE_LEN..NONCE_LEN + layout::INNER_CIPHERTEXT_LEN];
        let pp_aead = AeadKey::from_bytes(*passphrase_key);
        let mut inner = aead::decrypt(&pp_aead, &outer_nonce, SLOT_AAD, outer_ct)?;
        if inner.len() != layout::INNER_PLAINTEXT_LEN {
            return Err(FormatError::Manifest("inner plaintext length mismatch".into()));
        }
        let k = inner[0] as usize;
        if k > MAX_HW_KEYS_PER_LEVEL {
            return Err(FormatError::Manifest(format!("invalid HW key count: {k}")));
        }
        if k >= MAX_HW_KEYS_PER_LEVEL {
            inner.zeroize();
            return Err(FormatError::Manifest(
                "no free hardware-key slot (vault already has the maximum)".into(),
            ));
        }

        // ---- recover the KWK ----
        let mut kwk: [u8; KWK_LEN] = if k == 0 {
            no_hw_kwk(passphrase_key)
        } else {
            let hmac = recover_hmac.ok_or_else(|| {
                FormatError::Manifest("a present enrolled key is required to add another".into())
            })?;
            recover_kwk_with_hmac(passphrase_key, k, &inner, hmac)?
        };

        // ---- write the new entry at index k ----
        let entry_start = layout::NUM_HW_KEYS_FIELD + k * layout::HW_SLOT_LEN;
        LittleEndian::write_u16(&mut inner[entry_start..entry_start + 2], new_cred.len() as u16);
        let cred_dst = &mut inner[entry_start + 2..entry_start + 2 + MAX_CRED_ID_LEN];
        cred_dst[..new_cred.len()].copy_from_slice(new_cred);
        rng::fill(&mut cred_dst[new_cred.len()..])?;

        let kwk_nonce_off = entry_start + 2 + MAX_CRED_ID_LEN;
        let kwk_ct_off = kwk_nonce_off + NONCE_LEN;
        let mut kwk_nonce = [0u8; NONCE_LEN];
        rng::fill(&mut kwk_nonce)?;
        inner[kwk_nonce_off..kwk_nonce_off + NONCE_LEN].copy_from_slice(&kwk_nonce);

        let mut combine = combine_key(passphrase_key, new_hmac);
        let combine_aead = AeadKey::from_bytes(combine);
        let aad = hw_slot_aad(k);
        let kwk_ct = aead::encrypt(&combine_aead, &kwk_nonce, aad, &kwk)?;
        inner[kwk_ct_off..kwk_ct_off + kwk_ct.len()].copy_from_slice(&kwk_ct);
        combine.zeroize();
        kwk.zeroize();

        // ---- write the new key's label at index k ----
        let loff = layout::LABELS_OFFSET + k * layout::LABEL_LEN;
        encode_label(new_label, &mut inner[loff..loff + layout::LABEL_LEN]);

        // ---- bump K and re-encrypt ----
        inner[0] = (k + 1) as u8;
        let mut new_nonce = [0u8; NONCE_LEN];
        rng::fill(&mut new_nonce)?;
        let new_ct = aead::encrypt(&pp_aead, &new_nonce, SLOT_AAD, &inner)?;
        inner.zeroize();

        let mut out = [0u8; SLOT_LEN];
        out[..NONCE_LEN].copy_from_slice(&new_nonce);
        out[NONCE_LEN..NONCE_LEN + new_ct.len()].copy_from_slice(&new_ct);
        rng::fill(&mut out[NONCE_LEN + new_ct.len()..])?;
        Ok(out)
    }

    /// Remove the hardware-key credential at `index` from a slot, **in place
    /// and with the passphrase alone** — no key needs to be present. Deleting
    /// an entry just drops that key's wrapped-KWK copy; the master wrap and the
    /// remaining entries' wraps are untouched, so the other keys still open the
    /// vault. This is what lets a user revoke a *lost or stolen* key with only
    /// the passphrase.
    ///
    /// Requires `K >= 2`: removing the **last** key would leave the master
    /// wrapped under a KWK no key can recover, so turning a vault back into
    /// passphrase-only is a separate operation (it must re-wrap the master and
    /// re-harden the KDF, which needs the key present). Returns the rebuilt slot.
    pub fn remove_credential(
        slot: &[u8; SLOT_LEN],
        passphrase_key: &[u8; 32],
        index: usize,
    ) -> Result<[u8; SLOT_LEN]> {
        // ---- decrypt outer ----
        let mut outer_nonce = [0u8; NONCE_LEN];
        outer_nonce.copy_from_slice(&slot[..NONCE_LEN]);
        let outer_ct = &slot[NONCE_LEN..NONCE_LEN + layout::INNER_CIPHERTEXT_LEN];
        let pp_aead = AeadKey::from_bytes(*passphrase_key);
        let mut inner = aead::decrypt(&pp_aead, &outer_nonce, SLOT_AAD, outer_ct)?;
        if inner.len() != layout::INNER_PLAINTEXT_LEN {
            return Err(FormatError::Manifest("inner plaintext length mismatch".into()));
        }
        let k = inner[0] as usize;
        if k > MAX_HW_KEYS_PER_LEVEL {
            inner.zeroize();
            return Err(FormatError::Manifest(format!("invalid HW key count: {k}")));
        }
        if index >= k {
            inner.zeroize();
            return Err(FormatError::Manifest(format!(
                "key index {index} out of range (K={k})"
            )));
        }
        if k <= 1 {
            inner.zeroize();
            return Err(FormatError::Manifest(
                "cannot remove the last hardware key here (would orphan the master)".into(),
            ));
        }

        // ---- shift later entries (and labels) down over `index` ----
        let hw0 = layout::NUM_HW_KEYS_FIELD;
        for i in index..k - 1 {
            let dst = hw0 + i * layout::HW_SLOT_LEN;
            let src = hw0 + (i + 1) * layout::HW_SLOT_LEN;
            inner.copy_within(src..src + layout::HW_SLOT_LEN, dst);
            let ldst = layout::LABELS_OFFSET + i * layout::LABEL_LEN;
            let lsrc = layout::LABELS_OFFSET + (i + 1) * layout::LABEL_LEN;
            inner.copy_within(lsrc..lsrc + layout::LABEL_LEN, ldst);
        }
        // Random-fill the now-vacated last entry + its label (indistinguishable).
        let vac = hw0 + (k - 1) * layout::HW_SLOT_LEN;
        rng::fill(&mut inner[vac..vac + layout::HW_SLOT_LEN])?;
        let vlab = layout::LABELS_OFFSET + (k - 1) * layout::LABEL_LEN;
        rng::fill(&mut inner[vlab..vlab + layout::LABEL_LEN])?;

        // ---- decrement K and re-encrypt ----
        inner[0] = (k - 1) as u8;
        let mut new_nonce = [0u8; NONCE_LEN];
        rng::fill(&mut new_nonce)?;
        let new_ct = aead::encrypt(&pp_aead, &new_nonce, SLOT_AAD, &inner)?;
        inner.zeroize();

        let mut out = [0u8; SLOT_LEN];
        out[..NONCE_LEN].copy_from_slice(&new_nonce);
        out[NONCE_LEN..NONCE_LEN + new_ct.len()].copy_from_slice(&new_ct);
        rng::fill(&mut out[NONCE_LEN + new_ct.len()..])?;
        Ok(out)
    }
}

/// Recover the KWK from an inner-plaintext slot using a present key's
/// hmac-secret output: try the `combine(passphrase_key, hmac)` key against each
/// of the `k` enrolled entries (it matches exactly one).
fn recover_kwk_with_hmac(
    passphrase_key: &[u8; 32],
    k: usize,
    inner: &[u8],
    hmac: &[u8; HMAC_OUTPUT_LEN],
) -> Result<[u8; KWK_LEN]> {
    let combine = combine_key(passphrase_key, hmac);
    let combine_aead = AeadKey::from_bytes(combine);
    let mut cursor = layout::NUM_HW_KEYS_FIELD;
    let mut result: Option<[u8; KWK_LEN]> = None;
    for i in 0..k {
        let kwk_nonce_off = cursor + 2 + MAX_CRED_ID_LEN;
        let kwk_ct_off = kwk_nonce_off + NONCE_LEN;
        let kwk_ct_end = kwk_ct_off + (KWK_LEN + TAG_LEN);
        let mut kwk_nonce = [0u8; NONCE_LEN];
        kwk_nonce.copy_from_slice(&inner[kwk_nonce_off..kwk_nonce_off + NONCE_LEN]);
        let aad = hw_slot_aad(i);
        if let Ok(pt) = aead::decrypt(&combine_aead, &kwk_nonce, aad, &inner[kwk_ct_off..kwk_ct_end])
        {
            if pt.len() == KWK_LEN {
                let mut kwk = [0u8; KWK_LEN];
                kwk.copy_from_slice(&pt);
                result = Some(kwk);
                break;
            }
        }
        cursor += layout::HW_SLOT_LEN;
    }
    let mut combine_kill = combine;
    combine_kill.zeroize();
    result.ok_or(FormatError::Crypto(farewell_crypto::CryptoError::Decrypt))
}

/// AAD for a hardware key's wrapped-KWK ciphertext.
///
/// Deliberately **position-independent** (v0.6): every active entry encrypts
/// the *same* KWK under its own distinct `combine(passphrase_key, hw_output)`
/// key, so binding the ciphertext to its slot index would buy no security
/// (there is nothing to "confuse" between entries holding identical plaintext)
/// — but it *would* prevent shifting entries down when a key is removed
/// without re-wrapping. A constant AAD lets [`WrappedSlot::remove_credential`]
/// compact the entries with the passphrase alone.
fn hw_slot_aad(_index: usize) -> &'static [u8] {
    b"farewell.slot.hwwrap.v6"
}

fn unwrap_kwk_via_authenticator<A: Authenticator>(
    passphrase_key: &[u8; 32],
    vault_salt: &[u8],
    k: usize,
    inner_plain: &[u8],
    authenticator: &mut A,
) -> Result<[u8; KWK_LEN]> {
    // Collect candidate credential IDs from the K active HW slots.
    let mut candidates: Vec<Vec<u8>> = Vec::with_capacity(k);
    let mut slot_offsets: Vec<usize> = Vec::with_capacity(k);
    let mut cursor = layout::NUM_HW_KEYS_FIELD;
    for i in 0..k {
        let cred_len_off = cursor;
        let cred_off = cursor + 2;
        let cred_len =
            LittleEndian::read_u16(&inner_plain[cred_len_off..cred_len_off + 2]) as usize;
        if cred_len == 0 || cred_len > MAX_CRED_ID_LEN {
            return Err(FormatError::Manifest(format!(
                "HW slot {i}: invalid credential length {cred_len}"
            )));
        }
        let cred = inner_plain[cred_off..cred_off + cred_len].to_vec();
        candidates.push(cred);
        slot_offsets.push(cursor);
        cursor += layout::HW_SLOT_LEN;
    }

    let salt = fido_salt_from_vault_salt(vault_salt);
    let (used_cred, hw_output) = authenticator
        .challenge_response(&candidates, &salt)
        .map_err(map_fido_error)?;

    // Find which slot this credential corresponds to.
    let matched = candidates
        .iter()
        .position(|c| c == &used_cred)
        .ok_or_else(|| {
            FormatError::Manifest("authenticator returned unknown credential".into())
        })?;

    // Decrypt KWK from slot `matched`.
    let hw_slot_start = slot_offsets[matched];
    let kwk_nonce_off = hw_slot_start + 2 + MAX_CRED_ID_LEN;
    let kwk_ct_off = kwk_nonce_off + NONCE_LEN;
    let kwk_ct_end = kwk_ct_off + (KWK_LEN + TAG_LEN);
    let mut kwk_nonce = [0u8; NONCE_LEN];
    kwk_nonce.copy_from_slice(&inner_plain[kwk_nonce_off..kwk_nonce_off + NONCE_LEN]);
    let kwk_ct = &inner_plain[kwk_ct_off..kwk_ct_end];

    let combine = combine_key(passphrase_key, &hw_output);
    let combine_aead = AeadKey::from_bytes(combine);
    let aad = hw_slot_aad(matched);
    let kwk_pt = aead::decrypt(&combine_aead, &kwk_nonce, aad, kwk_ct)?;
    // Zeroize combine key.
    let mut combine_kill = combine;
    combine_kill.zeroize();

    if kwk_pt.len() != KWK_LEN {
        return Err(FormatError::Manifest("KWK length mismatch".into()));
    }
    let mut kwk = [0u8; KWK_LEN];
    kwk.copy_from_slice(&kwk_pt);
    Ok(kwk)
}

fn map_fido_error(e: Fido2Error) -> FormatError {
    // Surface FIDO errors as opaque crypto errors at this layer so the
    // unlock failure path is uniform.
    match e {
        Fido2Error::NoMatchingCredential
        | Fido2Error::UserCancelled
        | Fido2Error::Protocol(_)
        | Fido2Error::CredentialTooLarge { .. } => {
            FormatError::Crypto(farewell_crypto::CryptoError::Decrypt)
        }
        Fido2Error::Transport(msg) => {
            FormatError::Manifest(format!("authenticator transport error: {msg}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use farewell_fido2::MockAuthenticator;

    fn pp_key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn md_key(byte: u8) -> [u8; METADATA_KEY_LEN] {
        [byte; METADATA_KEY_LEN]
    }

    #[test]
    fn k0_wrap_then_unwrap() {
        let pp = pp_key(0xAA);
        let mk = [0x77u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &LevelEnrollment::passphrase_only())
            .unwrap();
        let result = WrappedSlot::try_unwrap::<MockAuthenticator>(&slot, &pp, salt, None).unwrap();
        assert_eq!(result.master_key, mk);
        assert_eq!(result.metadata_key, md_key(0x5A));
    }

    #[test]
    fn k0_wrong_passphrase_fails() {
        let pp = pp_key(0xAA);
        let mk = [0x77u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &LevelEnrollment::passphrase_only())
            .unwrap();
        let bad = pp_key(0xBB);
        assert!(
            WrappedSlot::try_unwrap::<MockAuthenticator>(&slot, &bad, salt, None).is_err()
        );
    }

    #[test]
    fn k1_wrap_then_unwrap_with_correct_authenticator() {
        let pp = pp_key(0xCC);
        let mk = [0x55u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";

        let mut auth = MockAuthenticator::new("farewell.foundation");
        let cred = auth.enroll(b"vault1").unwrap();
        let fido_salt = fido_salt_from_vault_salt(salt);
        let (_, hw_output) = auth
            .challenge_response(&[cred.clone()], &fido_salt)
            .unwrap();

        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred, hw_output).unwrap();
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &enr).unwrap();

        let result = WrappedSlot::try_unwrap(&slot, &pp, salt, Some(&mut auth)).unwrap();
        assert_eq!(result.master_key, mk);
    }

    #[test]
    fn k1_wrong_passphrase_fails_even_with_correct_authenticator() {
        let pp = pp_key(0xCC);
        let mk = [0x55u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";

        let mut auth = MockAuthenticator::new("farewell.foundation");
        let cred = auth.enroll(b"vault1").unwrap();
        let fido_salt = fido_salt_from_vault_salt(salt);
        let (_, hw_output) = auth
            .challenge_response(&[cred.clone()], &fido_salt)
            .unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred, hw_output).unwrap();
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &enr).unwrap();

        let bad = pp_key(0xDD);
        assert!(WrappedSlot::try_unwrap(&slot, &bad, salt, Some(&mut auth)).is_err());
    }

    #[test]
    fn k1_correct_passphrase_but_wrong_authenticator_fails() {
        let pp = pp_key(0xCC);
        let mk = [0x55u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";

        let mut a = MockAuthenticator::new("farewell.foundation");
        let cred = a.enroll(b"vault1").unwrap();
        let fido_salt = fido_salt_from_vault_salt(salt);
        let (_, hw_output) = a.challenge_response(&[cred.clone()], &fido_salt).unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred, hw_output).unwrap();
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &enr).unwrap();

        // A fresh, unrelated authenticator (no enrolled cred): should fail.
        let mut b = MockAuthenticator::new("farewell.foundation");
        assert!(WrappedSlot::try_unwrap(&slot, &pp, salt, Some(&mut b)).is_err());
    }

    #[test]
    fn k1_without_authenticator_fails() {
        let pp = pp_key(0xCC);
        let mk = [0x55u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";

        let mut auth = MockAuthenticator::new("farewell.foundation");
        let cred = auth.enroll(b"vault1").unwrap();
        let fido_salt = fido_salt_from_vault_salt(salt);
        let (_, hw_output) = auth
            .challenge_response(&[cred.clone()], &fido_salt)
            .unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred, hw_output).unwrap();
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &enr).unwrap();

        // Correct passphrase, but no authenticator supplied.
        assert!(WrappedSlot::try_unwrap::<MockAuthenticator>(&slot, &pp, salt, None).is_err());
    }

    #[test]
    fn add_credential_lets_either_key_unlock() {
        let pp = pp_key(0xCC);
        let mk = [0x55u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let fido_salt = fido_salt_from_vault_salt(salt);

        // Key A: enrolled into the original 1-key slot.
        let mut auth_a = MockAuthenticator::new("farewell.foundation");
        let cred_a = auth_a.enroll(b"vaultA").unwrap();
        let (_, hmac_a) = auth_a.challenge_response(&[cred_a.clone()], &fido_salt).unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred_a.clone(), hmac_a).unwrap();
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &enr).unwrap();

        // Key B: the backup, enrolled on a separate authenticator.
        let mut auth_b = MockAuthenticator::new("farewell.foundation");
        let cred_b = auth_b.enroll(b"vaultB").unwrap();
        let (_, hmac_b) = auth_b.challenge_response(&[cred_b.clone()], &fido_salt).unwrap();

        // Add B to the slot, recovering the KWK via A's hmac.
        let slot2 =
            WrappedSlot::add_credential(&slot, &pp, Some(&hmac_a), &cred_b, &hmac_b, "Backup")
                .unwrap();

        // Either key now unlocks, recovering the SAME master key.
        let ra = WrappedSlot::try_unwrap(&slot2, &pp, salt, Some(&mut auth_a)).unwrap();
        let rb = WrappedSlot::try_unwrap(&slot2, &pp, salt, Some(&mut auth_b)).unwrap();
        assert_eq!(ra.master_key, mk);
        assert_eq!(rb.master_key, mk);

        // The enrollment now lists both credentials, and the new key's label.
        let (k, creds, labels) = WrappedSlot::read_enrollment(&slot2, &pp).unwrap();
        assert_eq!(k, 2);
        assert!(creds.contains(&cred_a) && creds.contains(&cred_b));
        assert_eq!(labels[1], "Backup");

        // A foreign key still can't unlock.
        let mut foreign = MockAuthenticator::new("farewell.foundation");
        let _ = foreign.enroll(b"other").unwrap();
        assert!(WrappedSlot::try_unwrap(&slot2, &pp, salt, Some(&mut foreign)).is_err());
    }

    #[test]
    fn add_credential_upgrades_passphrase_only_vault() {
        let pp = pp_key(0xAB);
        let mk = [0x33u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let fido_salt = fido_salt_from_vault_salt(salt);
        let slot =
            WrappedSlot::wrap(&pp, &mk, &md_key(0x11), &LevelEnrollment::passphrase_only()).unwrap();

        let mut auth = MockAuthenticator::new("farewell.foundation");
        let cred = auth.enroll(b"v").unwrap();
        let (_, hmac) = auth.challenge_response(&[cred.clone()], &fido_salt).unwrap();

        // K==0 → no recover hmac needed (KWK is passphrase-derived).
        let slot2 = WrappedSlot::add_credential(&slot, &pp, None, &cred, &hmac, "First").unwrap();

        // Now the key unlocks it; passphrase alone no longer does (K is now 1).
        let r = WrappedSlot::try_unwrap(&slot2, &pp, salt, Some(&mut auth)).unwrap();
        assert_eq!(r.master_key, mk);
        assert!(WrappedSlot::try_unwrap::<MockAuthenticator>(&slot2, &pp, salt, None).is_err());
    }

    #[test]
    fn wrap_round_trips_key_labels() {
        let pp = pp_key(0x55);
        let mk = [0x77u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let fido_salt = fido_salt_from_vault_salt(salt);
        let mut auth = MockAuthenticator::new("farewell.foundation");

        let mut enr = LevelEnrollment::passphrase_only();
        let c1 = auth.enroll(b"a").unwrap();
        let (_, h1) = auth.challenge_response(&[c1.clone()], &fido_salt).unwrap();
        enr.push_labeled(c1.clone(), h1, "Laptop".into()).unwrap();
        let c2 = auth.enroll(b"b").unwrap();
        let (_, h2) = auth.challenge_response(&[c2.clone()], &fido_salt).unwrap();
        enr.push_labeled(c2.clone(), h2, "Home safe".into()).unwrap();

        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x22), &enr).unwrap();
        let (k, creds, labels) = WrappedSlot::read_enrollment(&slot, &pp).unwrap();
        assert_eq!(k, 2);
        assert_eq!(creds[0], c1);
        assert_eq!(labels, vec!["Laptop".to_string(), "Home safe".to_string()]);
    }

    #[test]
    fn remove_credential_drops_one_key_passphrase_only() {
        let pp = pp_key(0x5A);
        let mk = [0x42u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let fido_salt = fido_salt_from_vault_salt(salt);

        // Enroll three keys A,B,C with names.
        let mut auth_a = MockAuthenticator::new("farewell.foundation");
        let mut auth_b = MockAuthenticator::new("farewell.foundation");
        let mut auth_c = MockAuthenticator::new("farewell.foundation");
        let ca = auth_a.enroll(b"v").unwrap();
        let cb = auth_b.enroll(b"v").unwrap();
        let cc = auth_c.enroll(b"v").unwrap();
        let (_, ha) = auth_a.challenge_response(&[ca.clone()], &fido_salt).unwrap();
        let (_, hb) = auth_b.challenge_response(&[cb.clone()], &fido_salt).unwrap();
        let (_, hc) = auth_c.challenge_response(&[cc.clone()], &fido_salt).unwrap();
        let mut enr = LevelEnrollment::passphrase_only();
        enr.push_labeled(ca.clone(), ha, "A".into()).unwrap();
        enr.push_labeled(cb.clone(), hb, "B".into()).unwrap();
        enr.push_labeled(cc.clone(), hc, "C".into()).unwrap();
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x33), &enr).unwrap();

        // Sanity: all three keys unlock the original slot.
        assert_eq!(WrappedSlot::try_unwrap(&slot, &pp, salt, Some(&mut auth_a)).unwrap().master_key, mk);
        assert_eq!(WrappedSlot::try_unwrap(&slot, &pp, salt, Some(&mut auth_b)).unwrap().master_key, mk);
        assert_eq!(WrappedSlot::try_unwrap(&slot, &pp, salt, Some(&mut auth_c)).unwrap().master_key, mk);

        // Remove the middle key (B) with the passphrase alone.
        let slot2 = WrappedSlot::remove_credential(&slot, &pp, 1).unwrap();

        // K is now 2, and the labels collapsed to [A, C].
        let (k, creds, labels) = WrappedSlot::read_enrollment(&slot2, &pp).unwrap();
        assert_eq!(k, 2);
        assert_eq!(labels, vec!["A".to_string(), "C".to_string()]);
        assert!(creds.contains(&ca) && creds.contains(&cc) && !creds.contains(&cb));

        // A and C still unlock the SAME master key; B no longer does.
        let ra = WrappedSlot::try_unwrap(&slot2, &pp, salt, Some(&mut auth_a)).unwrap();
        let rc = WrappedSlot::try_unwrap(&slot2, &pp, salt, Some(&mut auth_c)).unwrap();
        assert_eq!(ra.master_key, mk);
        assert_eq!(rc.master_key, mk);
        assert!(WrappedSlot::try_unwrap(&slot2, &pp, salt, Some(&mut auth_b)).is_err());

        // Removing down to the last key is refused here (needs the downgrade path).
        let slot3 = WrappedSlot::remove_credential(&slot2, &pp, 1).unwrap();
        assert!(WrappedSlot::remove_credential(&slot3, &pp, 0).is_err());
        // ...and an out-of-range index is refused.
        assert!(WrappedSlot::remove_credential(&slot2, &pp, 5).is_err());
    }

    #[test]
    fn label_truncation_respects_utf8_boundaries() {
        // 'é' is 2 bytes; 25 of them = 50 bytes > LABEL_LEN (48). Truncation
        // must back off to a char boundary (24 é = 48 bytes), never split one.
        let s = "é".repeat(25);
        let mut buf = [0u8; layout::LABEL_LEN];
        encode_label(&s, &mut buf);
        let back = decode_label(&buf);
        assert!(back.chars().all(|c| c == 'é')); // valid UTF-8, no split char
        assert_eq!(back.chars().count(), 24); // 24 × 2 bytes = 48
    }

    #[test]
    fn k2_either_authenticator_can_unlock() {
        let pp = pp_key(0xEE);
        let mk = [0x33u8; MASTER_KEY_LEN];
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let fido_salt = fido_salt_from_vault_salt(salt);

        let mut a = MockAuthenticator::new("farewell.foundation");
        let mut b = MockAuthenticator::new("farewell.foundation");
        let cred_a = a.enroll(b"v").unwrap();
        let cred_b = b.enroll(b"v").unwrap();
        let (_, ha) = a.challenge_response(&[cred_a.clone()], &fido_salt).unwrap();
        let (_, hb) = b.challenge_response(&[cred_b.clone()], &fido_salt).unwrap();

        let mut enr = LevelEnrollment::passphrase_only();
        enr.push(cred_a, ha).unwrap();
        enr.push(cred_b, hb).unwrap();
        let slot = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &enr).unwrap();

        // Either authenticator alone unlocks.
        let r_a = WrappedSlot::try_unwrap(&slot, &pp, salt, Some(&mut a)).unwrap();
        assert_eq!(r_a.master_key, mk);
        let r_b = WrappedSlot::try_unwrap(&slot, &pp, salt, Some(&mut b)).unwrap();
        assert_eq!(r_b.master_key, mk);
    }

    #[test]
    fn two_wraps_of_same_inputs_differ() {
        let pp = pp_key(0xAB);
        let mk = [0x77u8; MASTER_KEY_LEN];
        let s1 = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &LevelEnrollment::passphrase_only())
            .unwrap();
        let s2 = WrappedSlot::wrap(&pp, &mk, &md_key(0x5A), &LevelEnrollment::passphrase_only())
            .unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn random_slot_does_not_unwrap() {
        let slot = WrappedSlot::fill_indistinguishable().unwrap();
        let pp = pp_key(0x12);
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        assert!(
            WrappedSlot::try_unwrap::<MockAuthenticator>(&slot, &pp, salt, None).is_err()
        );
    }

    #[test]
    fn unwrap_all_finds_the_match() {
        let salt = b"vault-salt-32-bytes-long-fixed!!";
        let pp_a = pp_key(0xA1);
        let mk_a = [0x10u8; MASTER_KEY_LEN];

        let slots = [WrappedSlot::wrap(
            &pp_a,
            &mk_a,
            &md_key(0x5A),
            &LevelEnrollment::passphrase_only(),
        )
        .unwrap()];

        let u_a = WrappedSlot::try_unwrap_all::<MockAuthenticator>(&slots, &pp_a, salt, None)
            .unwrap();
        assert_eq!(u_a.master_key, mk_a);

        // A wrong passphrase never opens the slot.
        let pp_c = pp_key(0xC1);
        assert!(WrappedSlot::try_unwrap_all::<MockAuthenticator>(&slots, &pp_c, salt, None)
            .is_err());
    }
}
