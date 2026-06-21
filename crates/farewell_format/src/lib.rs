//! Farewell `.vault` file format.
//!
//! See ARCHITECTURE.md §4 for the conceptual layout.
//!
//! v0.3 (current) — overlapping-range hidden volumes:
//!
//! - Public header (4 KiB).
//! - Three wrapped master-key slots (4 KiB each), always present.
//!   Unused slots contain indistinguishable random ciphertext.
//! - Each slot wraps **only** a master key — no range, no level count,
//!   no hint about other levels. This is the load-bearing property of
//!   deniability: unwrapping one slot reveals nothing about the others.
//! - Each level conceptually owns the entire chunks region. Its manifest
//!   chunk position is derived deterministically from its master key.
//!   Allocation is randomized over the free chunks known to the level.
//! - Without protected mount, writes from one level may overwrite chunks
//!   of another level. Mitigation: [`Vault::open_protected`] in trusted
//!   environments. Intrinsic limitation of plausible deniability.
//!
//! Not yet implemented in v0.3:
//!
//! - No FIDO2 hardware key (passphrase only).
//! - No real post-quantum primitives (stubs in farewell_crypto).
//! - No P2P sync, no resizing, no migration.

// `deny`, not `forbid`: the [`lock`] module needs ONE `unsafe` block
// to call `libc::flock(2)` for cross-process exclusion. That block is
// annotated and audited in place. Same pattern as `farewell_keys` for
// its `mlock` syscalls. No other module in this crate may use unsafe.
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod chunk;
mod error;
mod lock;
mod manifest;
mod metadata;
mod slot;
mod vault;

#[cfg(test)]
mod proptest_ops;

pub use chunk::{ChunkIndex, CHUNK_PLAINTEXT_LEN, CHUNK_STORED_LEN};
pub use error::FormatError;
pub use manifest::{FileEntry, FileStat, Manifest};
pub use metadata::{
    fingerprint_from_vk, signed_metadata_message, Metadata, FORMAT_VERSION, METADATA_BLOB_LEN,
    MLDSA_VK_LEN, SALT_LEN,
};
pub use slot::{
    fido_salt_from_vault_salt, LevelEnrollment, SlotIndex, UnwrappedSlot, WrappedSlot,
    METADATA_KEY_LEN, MAX_HW_KEYS_PER_LEVEL, NUM_SLOTS, SLOT_LEN,
};
pub use vault::{
    enroll_hw_key, manifest_chunk_for_slot, migrate_vault, LevelSpec, MigrateCapacity,
    MigratePhase, MigrateReport, Vault, VaultBuilder,
};

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, FormatError>;
