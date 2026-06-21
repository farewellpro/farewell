//! Manifest: file tree stored in chunk 0 of the vault.
//!
//! The manifest maps file names to the list of chunk indices that hold
//! their content. v0.1 keeps the manifest in a single chunk, capping the
//! number/size of files (~thousands of entries comfortably).
//!
//! Serialization is a hand-rolled little-endian format. We avoid `serde`
//! because the bytes are cryptographic material: we want byte-exact
//! control and zero implicit complexity.
//!
//! ```text
//! [0..4]      magic = "MFST"
//! [4..6]      manifest version (u16 LE)
//! [6..8]      reserved
//! [8..16]     monotonic counter (u64 LE)
//! [16..20]    entry count (u32 LE)
//! [20..]      entries: for each entry
//!                 [..1]      name length (u8)
//!                 [..N]      name (UTF-8)
//!                 [..8]      file size in bytes (u64 LE)
//!                 [..4]      chunk count (u32 LE)
//!                 [..4*K]    chunk indices (u32 LE each)
//! ```

use byteorder::{ByteOrder, LittleEndian};

use crate::chunk::{ChunkIndex, CHUNK_PLAINTEXT_LEN};
use crate::{FormatError, Result};

const MANIFEST_MAGIC: [u8; 4] = *b"MFST";
// v2: adds the `child_slots` list (hidden levels this level has
// spawned). Stored encrypted inside the level's own manifest, so it is
// invisible to any other level — the asymmetry that lets a primary
// level track its decoys without a decoy ever learning the primary
// exists.
// v3: adds the `folders` list — explicit folder paths, so empty
// folders persist. Files encode their folder via a slash-separated
// name prefix (the manifest stays flat); `folders` adds the empty
// ones. Purely organizational metadata, encrypted with the rest.
// v4: adds the optional `owner` field (opt-in creator identity). The
// parser still accepts v3 (owner = None), so existing vaults open
// unchanged; we always WRITE v4.
const MANIFEST_VERSION: u16 = 0x0004;
const MANIFEST_VERSION_MIN: u16 = 0x0003;
const MAX_NAME_LEN: usize = 255;
const MAX_FOLDER_PATH_LEN: usize = 1024;
const MAX_OWNER_LEN: usize = 256;

/// One file entry in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Display name (UTF-8). Slashes are allowed; the manifest is flat.
    pub name: String,
    /// Plaintext size in bytes (real, not padded).
    pub size: u64,
    /// Chunks that hold this file's content, in order.
    pub chunks: Vec<ChunkIndex>,
}

/// Lightweight file metadata, suitable for `readdir` / `stat`
/// responses without exposing the internal chunk layout.
///
/// This is what a filesystem layer (FSKit, FUSE) sees when it asks
/// "what files are in this mount?" — no encrypted state, no chunk
/// indices, just the user-facing attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStat {
    /// File name as stored in the manifest.
    pub name: String,
    /// Plaintext size in bytes.
    pub size: u64,
}

impl From<&FileEntry> for FileStat {
    fn from(e: &FileEntry) -> Self {
        Self {
            name: e.name.clone(),
            size: e.size,
        }
    }
}

/// In-memory manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Monotonic counter, incremented on every commit.
    pub counter: u64,
    /// File entries, ordered by insertion (UI ordering responsibility).
    pub entries: Vec<FileEntry>,
    /// Slot indices of hidden levels this level has spawned. Lets the
    /// primary level remember which slots it already used so the next
    /// "add hidden level" picks a genuinely free slot — without any
    /// other level being able to see this list (it lives inside this
    /// level's AEAD-encrypted manifest).
    pub child_slots: Vec<u8>,
    /// Explicit folder paths (normalized, no leading/trailing slash),
    /// so empty folders persist. Non-empty folders are also implied by
    /// file-name prefixes; the UI shows the union.
    pub folders: Vec<String>,
    /// Optional license identity of the vault's CREATOR (opt-in, v4). Lives
    /// inside this AEAD-encrypted manifest, so it is only visible after unlock
    /// (deniability preserved) — it is NOT ML-DSA-signed, an attribution
    /// convenience that is OFF by default. `None` = not recorded.
    pub owner: Option<String>,
}

impl Manifest {
    /// Empty manifest, counter at zero.
    pub fn empty() -> Self {
        Self {
            counter: 0,
            entries: Vec::new(),
            child_slots: Vec::new(),
            folders: Vec::new(),
            owner: None,
        }
    }

    /// Record a freshly-spawned child level's slot index, advancing
    /// the counter.
    pub fn add_child_slot(&mut self, slot: u8) {
        if !self.child_slots.contains(&slot) {
            self.child_slots.push(slot);
            self.counter += 1;
        }
    }

    /// Lookup an entry by name.
    pub fn find(&self, name: &str) -> Option<&FileEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Insert or replace an entry, advancing the counter.
    pub fn upsert(&mut self, entry: FileEntry) {
        self.entries.retain(|e| e.name != entry.name);
        self.entries.push(entry);
        self.counter += 1;
    }

    /// Remove an entry by name. Returns the removed entry if found.
    pub fn remove(&mut self, name: &str) -> Option<FileEntry> {
        let pos = self.entries.iter().position(|e| e.name == name)?;
        let removed = self.entries.remove(pos);
        self.counter += 1;
        Some(removed)
    }

    /// Serialize into a `Vec<u8>`. Caller is responsible for ensuring the
    /// result fits in one chunk plaintext budget.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&MANIFEST_MAGIC);
        let mut tmp2 = [0u8; 2];
        LittleEndian::write_u16(&mut tmp2, MANIFEST_VERSION);
        out.extend_from_slice(&tmp2);
        out.extend_from_slice(&[0u8, 0u8]); // reserved
        let mut tmp8 = [0u8; 8];
        LittleEndian::write_u64(&mut tmp8, self.counter);
        out.extend_from_slice(&tmp8);
        let mut tmp4 = [0u8; 4];
        LittleEndian::write_u32(&mut tmp4, self.entries.len() as u32);
        out.extend_from_slice(&tmp4);

        for e in &self.entries {
            let name_bytes = e.name.as_bytes();
            if name_bytes.is_empty() || name_bytes.len() > MAX_NAME_LEN {
                return Err(FormatError::InvalidName);
            }
            if name_bytes.iter().any(|b| b.is_ascii_control()) {
                return Err(FormatError::InvalidName);
            }
            out.push(name_bytes.len() as u8);
            out.extend_from_slice(name_bytes);
            LittleEndian::write_u64(&mut tmp8, e.size);
            out.extend_from_slice(&tmp8);
            LittleEndian::write_u32(&mut tmp4, e.chunks.len() as u32);
            out.extend_from_slice(&tmp4);
            for c in &e.chunks {
                LittleEndian::write_u32(&mut tmp4, c.0);
                out.extend_from_slice(&tmp4);
            }
        }

        // child_slots (v2): u8 count + that many slot-index bytes.
        out.push(self.child_slots.len() as u8);
        out.extend_from_slice(&self.child_slots);

        // folders (v3): u16 count, then each: u16 len + UTF-8 path.
        LittleEndian::write_u16(&mut tmp2, self.folders.len() as u16);
        out.extend_from_slice(&tmp2);
        for f in &self.folders {
            let fb = f.as_bytes();
            if fb.is_empty() || fb.len() > MAX_FOLDER_PATH_LEN {
                return Err(FormatError::InvalidName);
            }
            if fb.iter().any(|b| b.is_ascii_control()) {
                return Err(FormatError::InvalidName);
            }
            LittleEndian::write_u16(&mut tmp2, fb.len() as u16);
            out.extend_from_slice(&tmp2);
            out.extend_from_slice(fb);
        }

        // owner (v4): u16 byte-length + UTF-8 (length 0 = not recorded).
        let owner_bytes = self.owner.as_deref().unwrap_or("").as_bytes();
        let olen = owner_bytes.len().min(MAX_OWNER_LEN);
        LittleEndian::write_u16(&mut tmp2, olen as u16);
        out.extend_from_slice(&tmp2);
        out.extend_from_slice(&owner_bytes[..olen]);

        if out.len() > CHUNK_PLAINTEXT_LEN {
            return Err(FormatError::ManifestOverflow);
        }
        Ok(out)
    }

    /// Parse a manifest from its serialized bytes.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let mut p = ManifestParser::new(buf);
        let magic = p.take(4)?;
        if magic != MANIFEST_MAGIC {
            return Err(FormatError::Manifest("bad manifest magic".into()));
        }
        let version = p.read_u16()?;
        if version < MANIFEST_VERSION_MIN || version > MANIFEST_VERSION {
            return Err(FormatError::Manifest(format!(
                "unsupported manifest version {version}"
            )));
        }
        let _reserved = p.take(2)?;
        let counter = p.read_u64()?;
        let entry_count = p.read_u32()? as usize;

        // SECURITY: never pre-allocate based on an attacker-controlled count.
        // A bogus count (corruption, or — defense in depth — a forged buffer)
        // must not trigger a multi-gigabyte allocation / OOM before we even
        // read the data. Cap the initial capacity at what the remaining bytes
        // could possibly hold; the read loop below still errors cleanly if the
        // real data runs short. Smallest possible entry: name_len(1) +
        // name(≥1) + size(8) + chunk_count(4) = 14 bytes.
        let mut entries = Vec::with_capacity(p.cap(entry_count, 14));
        for _ in 0..entry_count {
            let name_len = p.read_u8()? as usize;
            if name_len == 0 || name_len > MAX_NAME_LEN {
                return Err(FormatError::InvalidName);
            }
            let name_bytes = p.take(name_len)?.to_vec();
            let name = String::from_utf8(name_bytes)
                .map_err(|_| FormatError::Manifest("non-UTF8 name".into()))?;
            let size = p.read_u64()?;
            let chunk_count = p.read_u32()? as usize;
            // Each chunk is a 4-byte index.
            let mut chunks = Vec::with_capacity(p.cap(chunk_count, 4));
            for _ in 0..chunk_count {
                chunks.push(ChunkIndex(p.read_u32()?));
            }
            entries.push(FileEntry { name, size, chunks });
        }

        // child_slots (v2). Each is a single byte.
        let child_count = p.read_u8()? as usize;
        let mut child_slots = Vec::with_capacity(p.cap(child_count, 1));
        for _ in 0..child_count {
            child_slots.push(p.read_u8()?);
        }

        // folders (v3). Smallest folder record: len(2) + path(≥1) = 3 bytes.
        let folder_count = p.read_u16()? as usize;
        let mut folders = Vec::with_capacity(p.cap(folder_count, 3));
        for _ in 0..folder_count {
            let len = p.read_u16()? as usize;
            if len == 0 || len > MAX_FOLDER_PATH_LEN {
                return Err(FormatError::InvalidName);
            }
            let bytes = p.take(len)?.to_vec();
            let path = String::from_utf8(bytes)
                .map_err(|_| FormatError::Manifest("non-UTF8 folder".into()))?;
            folders.push(path);
        }

        // owner (v4+): u16 len + UTF-8 (0 = none). Absent in v3 → None. The
        // chunk is padded after the manifest, but the length prefix means we
        // never read into that padding.
        let owner = if version >= 0x0004 {
            let olen = p.read_u16()? as usize;
            if olen == 0 {
                None
            } else if olen > MAX_OWNER_LEN {
                return Err(FormatError::Manifest("owner too long".into()));
            } else {
                let bytes = p.take(olen)?.to_vec();
                Some(
                    String::from_utf8(bytes)
                        .map_err(|_| FormatError::Manifest("non-UTF8 owner".into()))?,
                )
            }
        } else {
            None
        };

        Ok(Self {
            counter,
            entries,
            child_slots,
            folders,
            owner,
        })
    }
}

struct ManifestParser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ManifestParser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// A safe initial `Vec::with_capacity` for a length field of `count`
    /// records, each at least `min_record_len` bytes: never reserve more than
    /// the bytes left in the buffer could actually hold. Prevents an
    /// untrusted/corrupt count from causing a huge allocation (OOM). The read
    /// loop still validates and errors if the real data is short.
    fn cap(&self, count: usize, min_record_len: usize) -> usize {
        let remaining = self.buf.len().saturating_sub(self.pos);
        count.min(remaining / min_record_len.max(1) + 1)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        // Overflow-safe bounds check (pos <= buf.len() is an invariant).
        if n > self.buf.len() - self.pos {
            return Err(FormatError::Manifest("truncated".into()));
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(LittleEndian::read_u16(self.take(2)?))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(LittleEndian::read_u32(self.take(4)?))
    }

    fn read_u64(&mut self) -> Result<u64> {
        Ok(LittleEndian::read_u64(self.take(8)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roundtrip() {
        let m = Manifest::empty();
        let bytes = m.serialize().unwrap();
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(parsed.counter, 0);
        assert!(parsed.entries.is_empty());
    }

    /// Regression for a fuzz-found OOM (RUSTSEC-style untrusted length): a tiny
    /// buffer declaring a huge `entry_count` must be rejected cleanly, not
    /// pre-allocate gigabytes. Found by `fuzz/fuzz_targets/manifest_parse.rs`.
    #[test]
    fn huge_entry_count_does_not_oom() {
        // Valid magic + version + reserved + counter, then a 4-byte entry_count
        // claiming ~1 billion entries, with no entry data following.
        let mut buf = Vec::new();
        buf.extend_from_slice(&MANIFEST_MAGIC);
        buf.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        buf.extend_from_slice(&[0u8, 0u8]); // reserved
        buf.extend_from_slice(&0u64.to_le_bytes()); // counter
        buf.extend_from_slice(&u32::MAX.to_le_bytes()); // entry_count = 4 billion
        // No entries follow → parser must error on the first missing byte
        // WITHOUT having reserved capacity for 4 billion entries.
        let err = Manifest::parse(&buf);
        assert!(err.is_err(), "huge count with no data must be rejected");
    }

    /// The exact byte sequence libFuzzer minimized for the OOM, kept as a
    /// permanent guard.
    #[test]
    fn fuzz_oom_artifact_is_handled() {
        let artifact = [
            77u8, 70, 83, 84, 3, 0, 0, 0, 0, 0, 0, 0, 77, 70, 83, 84, 1, 84, 1, 70, 70,
        ];
        // Must not panic or OOM; result may be Ok or Err depending on version.
        let _ = Manifest::parse(&artifact);
    }

    #[test]
    fn entries_roundtrip() {
        let mut m = Manifest::empty();
        m.upsert(FileEntry {
            name: "sources.txt".into(),
            size: 4242,
            chunks: vec![ChunkIndex(1), ChunkIndex(2), ChunkIndex(3)],
        });
        m.upsert(FileEntry {
            name: "draft-article.md".into(),
            size: 1024,
            chunks: vec![ChunkIndex(4)],
        });
        assert_eq!(m.counter, 2);

        let bytes = m.serialize().unwrap();
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(parsed.counter, 2);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "sources.txt");
        assert_eq!(parsed.entries[1].chunks, vec![ChunkIndex(4)]);
    }

    #[test]
    fn upsert_replaces_existing() {
        let mut m = Manifest::empty();
        m.upsert(FileEntry {
            name: "a".into(),
            size: 1,
            chunks: vec![ChunkIndex(1)],
        });
        m.upsert(FileEntry {
            name: "a".into(),
            size: 2,
            chunks: vec![ChunkIndex(2)],
        });
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].size, 2);
        assert_eq!(m.counter, 2);
    }

    #[test]
    fn remove_works() {
        let mut m = Manifest::empty();
        m.upsert(FileEntry {
            name: "x".into(),
            size: 1,
            chunks: vec![],
        });
        let removed = m.remove("x").unwrap();
        assert_eq!(removed.name, "x");
        assert!(m.find("x").is_none());
        assert_eq!(m.counter, 2);
    }

    #[test]
    fn rejects_control_chars() {
        let m = Manifest {
            counter: 0,
            entries: vec![FileEntry {
                name: "bad\nname".into(),
                size: 0,
                chunks: vec![],
            }],
            child_slots: vec![],
            folders: vec![],
            owner: None,
        };
        assert!(matches!(m.serialize(), Err(FormatError::InvalidName)));
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(Manifest::parse(b"MFST").is_err());
    }

    #[test]
    fn owner_round_trips() {
        let mut m = Manifest::empty();
        m.owner = Some("alice@example.org".into());
        let bytes = m.serialize().unwrap();
        let parsed = Manifest::parse(&bytes).unwrap();
        assert_eq!(parsed.owner.as_deref(), Some("alice@example.org"));
        // No owner → None round-trips too.
        let m2 = Manifest::empty();
        let p2 = Manifest::parse(&m2.serialize().unwrap()).unwrap();
        assert_eq!(p2.owner, None);
    }

    #[test]
    fn v3_manifest_parses_with_no_owner() {
        // A hand-built v3 manifest (no owner section) must still open, with
        // owner = None — existing vaults aren't orphaned.
        let mut buf = Vec::new();
        buf.extend_from_slice(&MANIFEST_MAGIC);
        buf.extend_from_slice(&0x0003u16.to_le_bytes()); // version 3
        buf.extend_from_slice(&[0u8, 0u8]); // reserved
        buf.extend_from_slice(&7u64.to_le_bytes()); // counter
        buf.extend_from_slice(&0u32.to_le_bytes()); // entry_count
        buf.push(0u8); // child_slots count
        buf.extend_from_slice(&0u16.to_le_bytes()); // folder_count
        // (no owner field — this is the whole point)
        let parsed = Manifest::parse(&buf).unwrap();
        assert_eq!(parsed.counter, 7);
        assert_eq!(parsed.owner, None);
    }
}
