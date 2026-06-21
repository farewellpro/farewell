# Architecture — Farewell

**Status:** Founding document. Technical specification of components, formats, and flows. Aligned with [THREAT_MODEL.md](THREAT_MODEL.md) and [CHARTER.md](CHARTER.md).

---

## 1. Overview

```
┌──────────────────────────────────────────────────────────────┐
│                            User                              │
└────────────────────────────────┬─────────────────────────────┘
                                 │ setup · unlock · in-app viewer · settings
                   ┌─────────────▼──────────────┐
                   │      Farewell App          │
                   │  - Swift (macOS, windowed) │
                   │  - in-app viewer (no mount)│
                   └─────────────┬──────────────┘
                                 │ FFI — farewell_mount C ABI (a function bridge,
                                 │       NOT a filesystem mount)
┌────────────────────────────────▼──────────────────────────────┐
│                     Farewell Core (Rust)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Vault format │  │ Crypto stack │  │ Key manager  │         │
│  │ (chunks,mfm) │  │ (AEAD/KDF/PQ)│  │ (mlock,zero) │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ FIDO2 client │  │ P2P (stub)   │  │ Self-check   │         │
│  │ (USB CTAP2)  │  │ (Noise XX)   │  │ (stub)       │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────┬─────────────────────────────┘
                                  ▼
                         ┌──────────────────┐
                         │   .vault file    │
                         │ (fixed-size,     │
                         │  AEAD encrypted, │
                         │  single-domain)  │
                         └──────────────────┘
```

---

## 2. Components

### 2.1 Farewell Core (Rust)

Pure Rust library, no dependency on UIs. Exposes a stable API consumed by the native app through the `farewell_mount` C ABI (FFI).

**Main modules:**

- `farewell_format` — serialization/deserialization of the `.vault` format.
- `farewell_crypto` — crypto primitives: AES-256-GCM-SIV, Argon2id and BLAKE3 (RustCrypto), X25519/Ed25519 (`dalek`), and ML-KEM-1024 / ML-DSA-87 (`libcrux`, formally verified).
- `farewell_keys` — in-memory key material (`mlock`, zeroize-on-drop).
- `farewell_mount` — C ABI (FFI) shim exposing the core to the native apps. *(Despite the name it is a function-call bridge, not a filesystem mount — see §7.)*
- `farewell_fido2` — FIDO2/CTAP2 `hmac-secret` client (`ctap-hid-fido2`).
- `farewell_passphrase` — passphrase generation/strength (EFF wordlist).
- `farewell_license` — offline license tokens (ECDSA P-256, serial-bound).
- `farewell_audio` — media decoding for the in-app viewer.
- `farewell_p2p` — planned P2P LAN transport (Noise XX); **stub, not wired**.
- `farewell_attest` — planned binary self-verification; **stub**.

### 2.2 Core ↔ app bridge (FFI)

There is **no filesystem mount** — exposing a vault as a mounted volume is an explicit non-goal (cf. CHARTER §5 and §7 below). The native apps call the Rust core directly through the `farewell_mount` **C ABI shim** — a function-call bridge, not an FSKit/FUSE/kext mount. Vault content is read on demand by the in-app viewer through the FFI surface (e.g. `farewell_read_range`, 64 KiB chunks); decrypted bytes stay in memory and never land on disk.

### 2.3 Farewell App

- **macOS**: native Swift, a **windowed app** (SwiftUI `WindowGroup`, regular Dock app). The main window is the file list + in-app viewer; a separate Settings window holds preferences. See §8.1.
- **Linux**: planned (Phase 2) — in-app viewer, no mount; not yet built.

The app talks to the Rust Core exclusively via the `farewell_mount` FFI; a future Linux app will reuse the same Core.

---

## 3. Cryptographic stack

### 3.1 Primitives and parameters

| Usage | Primitive | Parameters |
|---|---|---|
| KDF passphrase → key | Argon2id | m=1 GiB, t=4, p=4 (tuned for ~2s on Apple Silicon M2) |
| Symmetric AEAD (chunks) | AES-256-GCM-SIV | 96-bit random nonce (stored per chunk), 128-bit tag |
| Symmetric AEAD (metadata) | AES-256-GCM-SIV | 96-bit nonce, 128-bit tag |
| Key encapsulation (classical) | X25519 | Curve25519, 256-bit scalar |
| Key encapsulation (PQ) | ML-KEM-1024 | NIST FIPS 203, level 5 (AES-256 equivalent) |
| Signature (classical) | Ed25519 | RFC 8032 |
| Signature (PQ) | ML-DSA-87 | NIST FIPS 204, level 5 |
| Hash | BLAKE3 | 256-bit output |
| MAC | BLAKE3 keyed mode | 256-bit |
| CSPRNG | OS-provided (`getrandom`) | Audited per platform |

### 3.2 Hybridization

We hybridize classical + post-quantum **only where an asymmetric operation is actually involved** — adding a KEM where there is no public-key step would buy no security.

- **Signatures**: the vault metadata is stamped at creation with a **one-shot ML-DSA-87 (FIPS 204)** signature — a fresh keypair signs the fixed metadata (version, capacity, salt, verifying key), then the **signing key is destroyed**; no signing key persists anywhere (the verifying key + signature live inside the AEAD blob). *(The `SIG_ID` byte reserves a hybrid Ed25519+ML-DSA-87 id for crypto-agility, but v6 stores ML-DSA-87 only.)* Releases (future, §12) will use a **hybrid Ed25519 + ML-DSA-87** multi-maintainer signature, verified before install.
- **Key exchange (P2P transfer, §10)**: device-to-device transfer agrees a session key as `KDF(X25519_shared_secret ‖ ML-KEM-1024_shared_secret)` — an attacker must break X25519 **and** ML-KEM-1024 to recover it, defeating "harvest now, decrypt later" on the wire. *(Reserved for the P2P feature; the ML-KEM-1024 primitive is integrated but not yet wired.)*

**At rest there is deliberately no KEM.** A local vault is unlocked by a passphrase (and/or a FIDO2 key), so the master key is wrapped with a **symmetric** key — `Argon2id(passphrase)` and/or the FIDO2 `hmac-secret`, sealed with **AES-256-GCM-SIV** (see §4.1). This chain has no public-key step, so it is **already post-quantum-resistant**: 256-bit symmetric drops to ~128-bit under Grover (out of reach), and there is nothing for Shor to attack. Adding a KEM here would not raise the security floor (it still bottlenecks on the passphrase / hardware key); it would only introduce a device private key to protect — itself under the passphrase, i.e. circular — and more structured material to keep indistinguishable from random.

### 3.3 Constant-time

Critical crypto operations rely on audited implementations chosen for constant-time behaviour: `subtle` for secret comparisons, `dalek-cryptography` (X25519/Ed25519), `libcrux` (ML-KEM-1024 / ML-DSA-87, formally verified), and the RustCrypto AEAD/KDF/hash crates (`aes-gcm-siv`, `argon2`, `blake3`). No branch or memory access in our own code depends on secret bits.

*(Automated timing-regression tests, e.g. `dudect`, are a planned hardening — not yet in CI.)*

---

## 4. `.vault` format

### 4.1 Overview

The `.vault` file is a monolithic container of **fixed** size (chosen at setup, e.g., 1 GiB, 10 GiB, 100 GiB). All space is filled — unused space contains encrypted random padding indistinguable from real chunks.

The file is conceptually structured as (format v6, `FORMAT_VERSION 0x0006`):

```
┌─────────────────────────────────────────────────────────────────────┐
│ Salt (32 bytes) — the ONLY plaintext field, uniform random           │
│  - NO magic, NO version, NO algorithm IDs in the clear               │
│  - NO wipe region, NO attempt counter (see below)                    │
├─────────────────────────────────────────────────────────────────────┤
│ Wrapped master-key slot × 1 (single-domain)                         │
│  - AEAD(passphrase+HW ; master_key ‖ shared metadata_key)           │
│  - Fixed-size, indistinguishable from random without the passphrase  │
├─────────────────────────────────────────────────────────────────────┤
│ Encrypted metadata blob                                              │
│  - AEAD(metadata_key ; version, capacity, ML-DSA-87 vk + signature)  │
│  - Internal magic ("FRWL") checked ONLY after decryption             │
├─────────────────────────────────────────────────────────────────────┤
│ Chunks region (fixed size chosen at setup)                           │
│  - Each chunk: AEAD(content ‖ padding) under active master_key       │
│  - Manifests (file tree, monotonic counter) are themselves chunks    │
│  - Unused chunks = indistinguishable random padding                  │
└─────────────────────────────────────────────────────────────────────┘
```

**Indistinguishable from random.** The format carries **no plaintext header** — no magic, no version, no algorithm IDs, no verifying key in the clear. A vault is therefore not identifiable by a `grep`, which would otherwise undermine deniability at the level of *"do you even use Farewell?"*:

- The **only** plaintext is the 32-byte salt, which is uniform random by
  construction (a salt is supposed to look random). Everything else —
  slots, metadata blob, chunks — is AEAD ciphertext.
- The shared, non-secret metadata (format version, capacity, the
  one-shot ML-DSA-87 attestation) lives in a single AEAD blob, decrypted
  with a 32-byte `metadata_key` carried *identically* inside every active
  key slot. Any level that unlocks can read the metadata; none of it is
  observable on disk.
- **Opening** = derive a key from passphrase + salt, then try to decrypt
  each slot. The internal magic appears only *after* a successful AEAD
  decryption. A wrong passphrase and a non-Farewell file are
  indistinguishable (generic failure) — VeraCrypt's model.
- This is byte-level indistinguishability, modulo a residual *size*
  heuristic inherent to any fixed-layout container (file length ≡ a fixed
  offset plus a whole number of chunks).

**No auto-wipe, by design.** There is no failed-attempt counter and no
self-destruct. A wipe-after-N-failures defense and unconditional
indistinguishability are mutually exclusive (the counter must be updated
on the wrong-passphrase path, hence outside passphrase-gated encryption
and therefore detectable), and a wipe never stopped a disk-imaging
attacker who simply works on a copy. Defense against offline brute force
is therefore the per-guess cost of Argon2id × passphrase entropy, plus —
for the strong configuration — a FIDO2 hardware key whose `hmac-secret`
is required to unwrap the master key (a copy is then uncrackable without
the physical token). See THREAT_MODEL §5.4.

### 4.2 Single-domain layout

**A Farewell vault is single-domain: one passphrase opens one content
tree, which uses the whole capacity.** There are no hidden "decoy"
levels. See §6 for the rationale and the coercion model used instead.

The wrapped master-key slot region is still fixed-size and AEAD-encrypted,
so it remains indistinguishable from random without the passphrase. The
slot wrap contains **only the vault's master key** — no range, no count,
no structural marker. A wrong passphrase and a non-Farewell file are
indistinguishable (generic AEAD failure), exactly as in §4.1.

### 4.3 Chunks and manifests

Files are split into **fixed-size 64 KiB chunks** (`CHUNK_PLAINTEXT_LEN`). Each chunk is encrypted independently with AES-256-GCM-SIV under a per-chunk key derived from the master key (BLAKE3 `derive_key`).

A **manifest** (itself an encrypted chunk) lists the files: each entry holds the name (slashes allowed; the manifest is flat), the plaintext size, and the ordered chunk indices that hold the file's content.

Chunks are stored at deterministic offsets (`chunk_index × CHUNK_STORED_LEN`). Indistinguishability does not rely on hiding positions: every chunk — used or not — is fixed-size AEAD ciphertext, so the layout reveals nothing about which chunks hold data.

### 4.4 Padding and fixed size

At setup, the user chooses a size (e.g., 10 GiB). The `.vault` file is immediately created at this size, filled with encrypted random bytes (no sparse file — sparse = info leak).

Beyond this size, the vault refuses additions; the user must create a new vault and migrate. No dynamic resizing in v1.0 (cf. THREAT_MODEL §6: security > convenience).

### 4.5 Format versioning

The format version lives **inside the encrypted metadata blob** (`u16`), not in any plaintext header — so a vault's version is only knowable after it unlocks. Future format revisions remain readable by the current app unless a forced crypto-agility migration deprecates them (cf. THREAT_MODEL §11).

---

## 5. Key hierarchy

At rest the key-wrapping is **symmetric** — there is no KEM (see §3.2 for why).
A FIDO2 key is **optional**; when absent, the hardened Argon2id is the whole
brute-force defense.

```
                    Passphrase (user)
                            │
                            ▼
                    Argon2id (KDF, see §3.1)
                            │
                            ▼
              Passphrase-derived key (PK, 256-bit)
                            │
        ┌───────────────────┴──────────────────────┐
        │ passphrase-only           FIDO2 enrolled │
        ▼                                          ▼
  KWK = derive(PK)        KWK = combine(PK, FIDO2 hmac-secret response)
        │                                          │
        └───────────────────┬──────────────────────┘
                            ▼
        Key-wrapping key (KWK) — AES-256-GCM-SIV
                            │
                            ▼
              Master key  [unwrapped from the slot]
                            │
                            ▼
     Per-chunk keys (BLAKE3 derive_key from master + chunk_id)
                            │
                            ▼
            AES-256-GCM-SIV for each 64 KiB chunk
```

**Properties:**

- A passphrase-only vault opens with the passphrase alone — the hardened
  Argon2id (1 GiB) is the entire offline-brute-force defense.
- When a FIDO2 key is enrolled, **both** the passphrase and the physical key are
  required; a copied file is then uncrackable without the key regardless of KDF
  cost (so a lighter KDF is used in that mode — see §4 / THREAT_MODEL §5.4).
- The master key is never written to disk. While a vault is open it is unwrapped from the slot into an `mlock`'d, zeroize-on-drop buffer (`SecureBuffer`).
- On vault lock, key material is zeroized via the `zeroize` crate (volatile writes + a compiler fence — the `explicit_bzero` equivalent, so the wipe cannot be optimized away).
- Per-chunk keys are never persisted; recomputed at each access.

---

## 6. Single-domain model

### 6.1 The model

A vault has a **single key slot** (`NUM_SLOTS = 1`), one passphrase, and
one content tree that owns the whole capacity. There are **no hidden /
"decoy" volumes**, no multi-level secrecy, no protected mount, no
`add_hidden_level`. This is a deliberate design choice — see §6.2.

### 6.2 Why

- **Bounded value.** Because Farewell is open source and *documents* the
  hidden-volume capability, merely using it signals "this person may have
  a hidden volume" — so an unbounded coercer demands "the other passphrase
  too", regardless of whether one exists. Deniability helps only against a
  *bounded* adversary (legal process, a searcher who accepts a plausible
  decoy), and is further weakened by a multi-snapshot adversary who watches
  writes cluster at both ends of the file over time.
- **Complexity and false confidence.** Hidden volumes are the most
  intricate, footgun-prone feature a vault format can carry (placement, corruption,
  protected mount, behavioural tells). A user who *believes* they are
  deniable but leaks it is in **more** danger than one who knows they are
  not. A half-correct deniability layer is worse than none.
- **A simpler, more honest coercion defense exists** (§6.3).

### 6.3 The coercion model

For the border-crossing / transport scenario, Farewell relies on the
**mandatory hardware-key** path: create the vault with a YubiKey required
(passphrase **and** key both needed to open). Then, at a checkpoint, simply
**not carrying the key** makes "I cannot open it" *true and physically
verifiable* — no lie to maintain, no behavioural tell, no corruption risk.
The data stays protected as long as the key never meets the adversary.

Residual, openly stated: this covers **transport**, not in-place coercion
where the key is seized together with the device. We judge that residual
not worth the complexity and false-confidence cost of hidden volumes. (See
THREAT_MODEL §5.2.)

What deniability **remains** is byte-level: a `.vault` file is
unconditionally indistinguishable from random data (§4.1), so the bytes
never betray that you use Farewell or what the file contains — modulo the
surrounding context on your machine (THREAT_MODEL §6.9).

---

## 7. No filesystem integration (by design)

Farewell deliberately does **not** mount the vault as a volume — no FSKit, no FUSE, no kext, no `NSFileProvider`. A mount would hand decrypted content back to the operating system, where Spotlight/Tracker indexing, Quick Look thumbnails, Time Machine, swap, and "open with…" hand-off would each leak plaintext to disk and betray that a vault is in use. This is a permanent **non-goal** (cf. CHARTER §5).

The **only** path to content is the in-app viewer (§8.3): the app reads chunks through the `farewell_mount` FFI surface (`farewell_read_range`, 64 KiB at a time), decodes them in RAM, and never writes plaintext to disk nor hands a file URL to a system viewer. The name `farewell_mount` is historical — it is a C ABI **function bridge**, not a filesystem mount.

---

## 8. Farewell App

### 8.1 macOS app

Farewell is a **standard windowed macOS app** — a SwiftUI `WindowGroup` with an `AppKit` delegate (`NSApp.setActivationPolicy(.regular)`), i.e. a regular app with a Dock icon. It is not a menu-bar / status-item app.

The **main window** is a split view (`HSplitView`): the **file list** on the left, the **in-app viewer** on the right. A separate **Settings** window (SwiftUI `Settings` scene) holds preferences such as the auto-lock timeout (5-minute idle default). Vault content is reached **only** through the in-app viewer (§8.3) — never a filesystem mount.

A **Linux** app (in-app viewer, no mount) is a Phase 2 objective; it is not yet built.

### 8.2 Windows and flows

- **Main window** — file list + in-app viewer (`HSplitView`).
- **Create / setup flow** — vault size, passphrase, optional hardware key(s).
- **Unlock prompt** — passphrase + (if enrolled) hardware-key PIN and touch.
- **Settings** — auto-lock timeout and related preferences.
- **Fullscreen video** — a dedicated window for in-app video playback.

Pairing for P2P transfer is a Phase 2 addition (not yet present).

### 8.3 In-app viewer

The in-app viewer is the **only** path to vault content — there is no mount,
no export, no "open with…". Decrypted bytes are decoded **from RAM** and must
never be written to disk, nor handed to a system viewer (QuickLook, Preview,
QuickTime) or any file URL.

Per format:

- **PDF**: PDFKit (macOS) / Poppler-rs (Linux), no JavaScript, no interactive forms.
- **Images**: decoded in-process via `NSImage` (macOS) from the in-memory bytes — never a file URL.
- **Text/Markdown**: rendered in-app from the decrypted string (Swift `AttributedString(markdown:)` for Markdown); no external renderer, no file URL.
- **Audio**: **pure-Rust decode** via the `farewell_audio` crate (Symphonia,
  `#![forbid(unsafe_code)]`). The decrypted bytes are decoded to interleaved
  PCM in our own audited code and streamed into `AVAudioEngine`. No OS codec
  touches the file, no `AVAsset`, no temp file. Supported: MP3, AAC/M4A, ALAC,
  FLAC, Vorbis/Ogg, WAV, AIFF, CAF, PCM/ADPCM.
- **Video**: rendered from RAM via a custom `AVAssetResourceLoaderDelegate`
  (a private `farewellmem://` scheme that serves byte ranges out of memory),
  into a bare `AVPlayerLayer` with our own transport controls and our own
  fullscreen window — never AVKit, never QuickTime/Preview, never a file URL.

*(Planned: clipboard inhibition while the viewer is open on a sensitive file. Not yet implemented — text in the viewer currently supports native selection/copy.)*

#### Honest caveat: video decode uses the OS codec (VideoToolbox)

We are deliberately transparent about an asymmetry between audio and video:

- **Audio** is decoded **entirely in our own pure-Rust code** (Symphonia). The
  trust boundary for audio playback is just Farewell.
- **Video** is *fed* from RAM, but the actual H.264/HEVC decoding is performed
  by **Apple's VideoToolbox**, the system media stack behind `AVPlayer`. There
  is no production-grade, pure-Rust video decoder we could ship without pulling
  in a large C dependency (e.g. ffmpeg), which would *enlarge* the attack
  surface rather than shrink it. So video decoding runs **in-process, on bytes
  we hand it from memory** — but the codec itself is Apple's, not ours.

What this means concretely:

- We have **empirically verified** that this playback path writes **nothing to
  disk**: a reproducible audit (`scripts/verify-no-disk-spill.swift`) plays a
  generated clip through the exact in-app path and confirms the decrypted bytes
  never appear in any temp/cache file and no file is left open. VideoToolbox
  decodes in RAM via the resource-loader callbacks; it is not handed a path.
- The residual trust assumption is therefore **the correctness of Apple's
  in-process codec**, not a disk-spill or a hand-off to an external app. A
  malicious or buggy codec parsing attacker-controlled video is a real (and
  industry-wide) attack surface; we mitigate it only insofar as the OS
  sandboxes its own media services.
- **Audio does not carry this caveat.** If you need the strongest possible
  guarantee for a given sensitive recording, prefer an audio format.

A future option (post-1.0) is to move video decode into a tightly sandboxed
helper process so a codec compromise cannot reach the rest of the address
space; this is tracked, not yet implemented.

### 8.4 Hardware-key PIN handling

Farewell adopts **strict Option A** for the CTAP2 PIN:

- **No persistence.** The PIN is never written to disk, nor stored in macOS Keychain, Linux Secret Service, or any configuration store.
- **Prompted at every initial vault unlock.** On lock (manual or auto-lock), the PIN is zeroized in memory (`SecureBuffer`); the user must re-enter it at the next unlock.
- **In-memory cache during the unlocked session only.** While the vault is unlocked, the PIN remains in `SecureBuffer` so that subsequent CTAP2 operations (add file, etc.) do not re-prompt.
- **Per-operation touch only.** PIN handling and user-presence are managed by the CTAP2 client (`ctap-hid-fido2`); the session-cached PIN avoids re-prompting, and each operation requires only the physical touch.

**Unlock flow:**

1. User opens Farewell and clicks "Unlock".
2. A sheet appears with the passphrase field and, if the vault uses a hardware key, a PIN field.
3. User fills, confirms.
4. App shows "Touch your hardware key" with animation. **A single touch** is required per high-level operation: the PIN is validated cryptographically without touching the key (silent ECDH+AES-CBC exchange), and only the user-presence step of the actual crypto operation (`makeCredential` or `getAssertion` with `up: true`) requires physical contact. Some CTAP2 libraries print a prompt before each underlying command, which may suggest multiple touches; in practice the YubiKey blinks only once.
5. Success → vault unlocked; content is read through the in-app viewer.

**Error UX:**

| Situation | Display |
|---|---|
| No key plugged in | "Plug in your hardware key" + USB animation |
| Wrong PIN | "YubiKey check failed — wrong PIN, or it wasn't touched in time." |
| Wrong key (credential not enrolled) | "This key is not enrolled for this vault." |
| No touch within 30 s | "Timeout, try again." |
| 8 consecutive wrong PINs | YubiKey locked. Full reset required (loses all credentials). Onboarding stresses enrolling ≥ 2 keys. |

**No PIN on the key:** if a key has no CTAP2 PIN set, no PIN field is shown for it.

---

## 9. Secure deletion

### 9.1 Mechanism

Deletion of a file in the vault triggers:

1. **Identification of chunks** belonging to the file via the manifest.
2. **Cryptographic overwrite** of each chunk: generation of new indistinguishable random ciphertext (CSPRNG → AEAD with dummy key), immediate write in place of the deleted chunk.
3. **Manifest update**: removal of the file entry, manifest chunk re-written.
4. **Durable flush** of the `.vault` file. On macOS this is `fcntl(F_FULLFSYNC)`, **not** a plain `fsync`: `fsync` does not flush the drive's internal write cache, so a "secure overwrite" could otherwise sit in volatile cache and never reach the platters/flash. The same durable flush is applied on `truncate_file` (shrinking frees + shreds chunks) and `delete_folder`. On non-Apple targets it degrades to `fsync` (the strongest portable primitive); if a filesystem rejects `F_FULLFSYNC` it also degrades to `fsync`.

#### Source originals (files imported from the user's disk)

The optional "Shred originals" step erases the *plaintext source file* the user imported. This is medium-aware (detected via IOKit `Device Characteristics → Medium Type`):

- **Rotational (HDD):** N-pass random overwrite (1/3/7, user-selectable; 1 is sufficient), each forced durable with `F_FULLFSYNC`. The original bytes are physically destroyed.
- **Solid state / unknown (SSD/flash):** overwrite + `F_FULLFSYNC` + a whole-file `F_PUNCHHOLE` (a TRIM/unmap hint) before `unlink`, but with **no guarantee** — wear-leveling can leave the original cells intact. The UI says so plainly. The real protection is never to have written the plaintext at all (keep content inside the vault / in-app viewer).

### 9.2 Guarantees

- No recovery window.
- No versioning.
- If the process is killed during shred, the manifest is updated last — so either the file is entirely present, or it is entirely deleted.

### 9.3 Limitations

- On SSDs with wear leveling, overwrite does not guarantee physical destruction of the original cells (cf. THREAT_MODEL §6.3). But since the chunk is encrypted, without the master key the old content remains unreadable — and the durable flush + cryptographic-shred design means the *only* recoverable artifact would be old ciphertext on an un-erased flash page, useless without the key.
- On magnetic disks, the in-place overwrite + durable flush is sufficient.
- The honest, unconditional guarantee on any medium is therefore **cryptographic**, not physical: delete removes the chunk's recoverability under the master key. Physical erasure is achieved on HDDs and best-effort on SSDs.

---

## 10. P2P LAN

> **Status: planned — not implemented.** `farewell_p2p` is a stub; the protocol, pairing, and sync described below are the intended design, not shipped behaviour.

### 10.1 Protocol

**Noise XX pattern** (Noise Protocol Framework) for the mutual handshake. TCP transport on LAN, restricted to `fe80::/10`, RFC1918, or link-local.

### 10.2 Pairing

1. Device A (initiator) generates a **single-use token** (32 random bytes, base32-encoded, ~52 human characters).
2. A displays the token to the user.
3. The user transmits the token to device B **out-of-band** (Signal, encrypted email, paper).
4. B enters the token. Noise handshake starts, derives a session key.
5. Fingerprint verification displayed on both devices — the user compares.
6. Token consumed, will never be accepted again.

### 10.3 Sync semantics

P2P LAN does not automatically "sync" the vault. Instead, it allows:

- **Manual file transfer** between two Farewell instances belonging to the same user.
- **Persistent pairing verification** (no need to re-pair after the first setup).

No continuous sync of `.vault` state. The user initiates each transfer.

### 10.4 Restrictions

- Active refusal of any globally routable IP (verification of source/destination IP octets).
- Refusal of SOCKS proxy, HTTP proxy, VPN whose exit is not LAN.
- No P2P relay via Internet, ever.

---

## 11. Memory protection

### 11.1 Sensitive allocations

In-memory crypto keys live in a Rust struct **`SecureBuffer`**:

- `mlock()` to keep the pages out of swap (macOS and Linux; best-effort).
- Zeroize-on-drop via the `zeroize` crate (volatile writes + a compiler fence — the `explicit_bzero` equivalent, so the wipe cannot be optimized away).

*Planned hardening (not yet implemented): guard pages and `mprotect(PROT_NONE)` when a buffer is idle (`SecureBuffer::with_guard`).*

### 11.2 Platform memory protections

Farewell does not rely on any undocumented hardware memory-encryption behaviour. Whatever protection the platform provides is a bonus; the guarantees we actually control are the software ones above (`mlock` + zeroize-on-drop).

### 11.3 Swap and hibernation

- `mlock` keeps live key pages out of swap in the first place; on lock they are zeroized.
- What no user-space program can control: a hibernation image (`sleepimage`), kernel page copies, or CPU registers / stack spills. User recommendation: disable disk hibernation (`pmset -a hibernatemode 0` on macOS) or use encrypted swap (Linux: LUKS swap).

---

## 12. Self-check and attestation

### 12.1 Binary self-check

**Status: planned — `farewell_attest` is a stub.** Intended design: at startup the app hashes its own binary and compares it to a value compiled in; a mismatch refuses to start with a user alert ("The binary has been modified. Re-download from a verified source.").

### 12.2 Reproducible builds

Documented, deterministic, tested build pipeline for the Rust core:

- Pinned Rust toolchain (`rust-toolchain.toml`, exact version).
- Dependencies pinned via `Cargo.lock`.
- `SOURCE_DATE_EPOCH` + identical build flags.
- CI rebuilds the `farewell` CLI twice and fails if the two binaries differ — on Linux x86_64 and macOS arm64 (`scripts/verify-reproducible.sh`).

Verification: anyone can run `scripts/verify-reproducible.sh` to reproduce the hash. *(Per-release published hash manifests are planned with the first tagged release. The signed GUI `.app`/`.dmg` is not bit-reproducible — code signing and notarization make the bundle non-deterministic; reproducibility covers the Rust core.)*

### 12.3 Multi-signature

**Status: planned — a future, multi-maintainer objective.** Today releases are signed with a single Apple Developer ID. The intended model: each release signed by **≥ 3 independent maintainers**:

- Ed25519 + ML-DSA-87 signature by each maintainer.
- Maintainers' public keys distributed in the binary and verifiable out-of-band.
- The app refuses binaries with < 3 signatures or unknown signatures.

### 12.4 Transparency log

**Status: planned.** Intended: all releases recorded in an append-only log (Sigstore Rekor model):

- Inclusion proof required for a release to be accepted.
- The app verifies the inclusion proof at install (if an opt-in network connection is authorized).

---

## 13. Build and release pipeline

> **Target pipeline.** Multi-maintainer signatures and the transparency log are future objectives (§12.3–12.4). Today: a reproducible Rust core (§12.2) plus a single Developer-ID-signed, notarized macOS build (Apple silicon).

```
   Source (GitHub / Codeberg)
        │
        ▼
   CI build (reproducible, deterministic)
        │
        ▼
   Artifacts — today: macOS arm64 (Apple silicon).  Planned: Linux x86_64 / arm64
        │
        ▼
   Signature by maintainer 1 (Ed25519 + ML-DSA-87)
   Signature by maintainer 2 (Ed25519 + ML-DSA-87)
   Signature by maintainer 3 (Ed25519 + ML-DSA-87)
        │
        ▼
   Inclusion in Transparency Log (Sigstore-style)
        │
        ▼
   Publication on official site + mirrors
        │
        ▼
   User downloads, verifies signatures, verifies inclusion proof, installs
```

---

## 14. Open questions and assumptions to validate

Pending technical decisions, to be resolved in Phase 0:

1. **Chunk size**: shipped at a fixed 64 KiB. Whether to offer a larger (e.g. 1 MiB) profile for very large vaults remains to benchmark.
2. **GTK vs. Tauri for Linux**: GTK = native but GNOME-centric burden; Tauri = wider cross-DE but web-tech burden. To decide at prototyping.
3. **Linux distro strategy**: which distros do we officially support? Ubuntu LTS + Fedora + Debian stable + Arch? Snap/Flatpak or not?

---

## 15. Crypto-agility and migration

### 15.1 Why

Cryptographic primitives age. The on-disk metadata already carries
per-algorithm IDs (AEAD/KDF/KEM/SIG) and a `FORMAT_VERSION`, so the format can
*express* a new algorithm — but moving an existing vault to it needs a
migration. The engine provides that mechanism so a future format bump won't be stuck.
It is also useful today as **key rotation** and **capacity change**: the engine writes
the *current* format (v6), so a same-version migration is simply a re-encrypt; a future
format (v7) would only change the destination's algorithm IDs.

### 15.2 Side-by-side, verified, atomic

`migrate_vault` (core) opens the source **read-only** and is intrinsically
crash-safe:

1. Build a **new** vault file (fresh salt + keys) at a temporary path.
2. Recreate folders; **stream** every file across in 64 KiB windows (never a
   whole file in RAM), hashing the source bytes (BLAKE3).
3. Re-read the destination and **verify** every file's hash, the file set, and
   the folder set. Any mismatch → `Err`; the caller deletes the temp; the
   source is untouched.
4. Carry the anti-rollback counter forward (`new ≥ old + 1`).
5. `F_FULLFSYNC` the destination, then the caller performs the swap.

The app's swap: same folder → rename the old to `<name>.bak` (kept until the
user deletes it), move the verified temp into place, reopen. Different
folder/drive → write the new file there, keep the original. A leftover
`.<name>.migrating` from an interrupted run is detected on open and offered for
discard; the source is always intact, so the user is never locked out.

### 15.3 Disk-space handling

Because `VaultBuilder` pre-allocates the **entire** capacity up front, the new
vault file is full-size immediately, so a side-by-side migration needs ≈ 2× the
vault size on the destination while both exist for the verify step. This is
handled, not hidden:

- **`MigrateCapacity`**: `Same` (preserve headroom), `ShrinkToFit` (only as big
  as the contents + ~25%/1 MiB margin, never larger than the source — turns an
  almost-empty 100 GB vault into a few MB), or `Exact(n)`.
- **Destination choice**: the same folder (atomic in-place swap) or another
  folder/drive (escape hatch when the source volume can't hold 2×).
- **Hard pre-flight**: the app estimates the destination size and compares it to
  the destination volume's free space (`volumeAvailableCapacityForImportantUsage`);
  if it won't fit, the migration **refuses to start** with an actionable
  message (shrink, or pick another drive). A migration that cannot finish is
  never begun.

### 15.4 Surfaces

Core `migrate_vault`; FFI `farewell_migrate`; CLI
`farewell migrate <src> <dest> [--shrink | --chunks N]`; and an app wizard
(capacity + destination + a live space pre-flight) that runs on the dedicated
HID run-loop thread behind the existing progress overlay.

---

**End of document.**
