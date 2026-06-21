# Threat Model — Farewell

**Status:** Founding document. To be validated before any detailed architecture work. Absolute reference for subsequent design tradeoffs.

---

## 1. Preamble

This document defines precisely what Farewell protects, what it does not protect, and against whom. In case of conflict between a proposed feature and this threat model, the threat model wins: either the feature is dropped, or the threat model is explicitly amended through traceable public discussion.

**Guiding principle.** A product claiming *nation-state grade* security must be honest about its limits. Over-promising on security is more dangerous than a modest but kept guarantee. A declared but unmet guarantee destroys trust in all the others; an honestly declared limit reinforces the credibility of what is guaranteed.

---

## 2. Canonical personas

Design is decided as a function of the following personas. If a feature serves other uses without harming these, all the better; if it conflicts, it is rejected.

### 2.1 Primary persona — Maya, investigative journalist

Maya, 34, independent journalist based in a European capital. Works on cross-border corruption cases involving state actors. Travels regularly through hostile jurisdictions. Owns a MacBook Pro and a ThinkPad running Qubes OS. Not a developer. Already uses Signal, Tor, OnionShare daily.

**Assets she protects:**
- Source identities: interview notes, raw recordings, meeting metadata
- Documents received from sources: PDFs, leaks, photos
- Unpublished article drafts
- Archived communications: Signal exports, sensitive emails

**Threat scenarios:**
- *Border.* Arriving in Istanbul; her devices are confiscated for 4 hours for "inspection."
- *Targeted burglary.* Her apartment is visited, the laptop stolen and possibly returned.
- *Legal compulsion.* A judge in a transit country orders her to provide the password.
- *Long-term surveillance.* Her network traffic is observed by a global passive adversary for months.
- *Targeted attack.* Commercial spyware (NSO, FinFisher, Intellexa) attempts to install.

### 2.2 Secondary persona — Karim, internal source

Karim, 41, employee of a public administration. Wants to transmit internal documents to Maya proving a misappropriation. No technical skills. Will use Farewell only to prepare a USB transfer that Maya will collect in person.

**Assets he protects:**
- His own identity — the mere fact that he *has* prepared a vault must be plausibly deniable
- The documents until transfer

**Scenarios:**
- *Discovery of the vault* on his work laptop during an internal audit or by a colleague
- *Seizure* of his work equipment

### 2.3 Tertiary persona — Lena, exile

Lena, exiled from an authoritarian regime, lives in Europe. Coordinates with activists who stayed behind. Her family back home may be threatened to coerce her into cooperation.

**Assets she protects:**
- Contact list (real identities ↔ operational pseudonyms)
- Action plans, event calendars
- Collected testimonies

**Scenarios:**
- *Return trip* to her country of origin
- *Family coercion.* A relative is arrested to force her cooperation

### 2.4 Out of persona

Farewell is **not** designed for:
- The general user who simply wants to encrypt vacation photos (FileVault is sufficient, and is less demanding on discipline).
- The enterprise wanting to manage shared multi-user access with audit logs (different need, requires incompatible tradeoffs).

Farewell is a cryptographic tool. Like any strong cryptographic tool, it has dual uses. The publisher does not pass judgment on individual use — this neutrality is the precondition of the product's usefulness for the personas it serves. This position is shared by Tor Project and Signal Foundation.

---

## 3. Protected assets and priorities

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| File content | Critical | Critical | Low (loss acceptable) |
| Filenames and structure | Critical | High | Low |
| Fact that the file *is* a Farewell vault | Critical | n/a | n/a |
| Master keys | Critical | Critical | None (no recovery) |
| Access metadata (timestamps, frequency) | High | Medium | Low |
| Telemetry, usage logs | None (do not exist) | n/a | n/a |
| Actual size of stored data | Critical | n/a | n/a |

**Assumed asymmetry.** Confidentiality and integrity always trump availability. In case of tradeoff, availability is lost. No feature will be added that increases availability at the price of either of the other two.

---

## 4. Adversary model

Adversaries are described by their capabilities, not their identity. Capabilities evolve; identities are contingent.

### 4.1 In-scope adversary — "Hostile State-Level Actor"

**Assumed capabilities:**

- **Classical cryptanalysis.** Significant but not unlimited compute resources. No ability to break AES-256-GCM-SIV by direct cryptanalysis on human timescales.
- **Future quantum cryptanalysis.** Plausible capability within 5 to 15 years. Justifies the post-quantum posture: 256-bit symmetric encryption at rest (already quantum-safe) plus an ML-DSA-87 attestation, with PQ-hybrid key exchange reserved for the wire (future P2P).
- **Physical access.** Device seizure, bit-for-bit disk imaging, forensic lab analysis, image retention for years for later cryptanalysis ("harvest now, decrypt later").
- **Legal compulsion.** Ability to obtain an order forcing the user to cooperate, to conduct searches, to issue a National Security Letter to a service or distribution provider.
- **Network capability.** Global passive interception (timing/volume correlation on the Internet), local active interception (MITM on LAN, hotspots).
- **Targeted compromise.** Ability to run spyware on the target's device if she commits an operational error or if a 0-day vulnerability is exploitable at time T.
- **Supply chain.** Ability to compromise a point in a software distribution chain, but not all mirrors simultaneously if reproducible builds are community-verifiable.
- **Hardware cryptography.** Assumed reliable for standard elements (AES-NI, Apple Silicon Secure Enclave, TPM 2.0) with a residual uncertainty margin. No blind trust.

### 4.2 **Out-of-scope** adversary — "Omniscient Adversary"

Farewell does not protect against:

- An adversary already executing code on the system **before** the vault is unlocked (rootkit, evil maid on firmware, active spyware).
- An adversary physically observing the user (camera in the room, over-the-shoulder, video surveillance of keyboard input).
- An adversary with a hardware keylogger (TEMPEST, USB key sniffer physically implanted).
- An adversary capable of breaking AES-256 by direct cryptanalysis (exotic hypothesis today; if it materialized, the entire ecosystem would collapse with it).
- Prolonged torture of the user. No technical solution resists unlimited physical coercion.

These limits are communicated **explicitly** to the user in documentation and at the point of relevance in the app (e.g.: warning at unlock on a system whose boot integrity is not verified).

---

## 5. In-scope surface

### 5.1 Confidentiality at rest

Encryption at rest of content, filenames, folder structure, and internal metadata. The `.vault` file is indistinguishable from random noise to anyone without the passphrase (and, for hardware-key vaults, the FIDO2 key as well). Random encrypted padding makes the actual data size undetectable at the container level.

### 5.2 Deniability (byte-level)

**No hidden volumes.** A Farewell vault is single-domain — there are no
hidden "decoy" volumes. The reasons, and the coercion model used instead,
are in ARCHITECTURE §6; in short: the deniability hidden volumes would buy
is *bounded* (an open-source tool that documented the feature would signal
its own capability, so an unbounded coercer demands "the other passphrase
too" regardless), they are the most footgun-prone feature a vault format
can carry, and a half-correct deniability layer that gives **false
confidence** is more dangerous than none.

What deniability **remains** is byte-level and unconditional: a `.vault`
file has no magic, no plaintext header, and no wipe region — without the
passphrase it is byte-for-byte indistinguishable from random data (§6.9).
So the bytes never betray that the file is a Farewell vault, nor its
content — modulo the surrounding context on the machine (§6.9).

The coercion scenario is instead served by the mandatory-hardware-key path
(§5.4): not carrying the key makes "I cannot open it" *true and verifiable*.

### 5.3 Multi-factor authentication

A vault may be created **hardware-key-mandatory**: unlocking then requires
**simultaneously** the passphrase AND the FIDO2 hardware key. No fallback.
No "I lost my key."

The hardware key participates in the cryptographic derivation — it is not just a software gate. Without it, the FIDO2 challenge-response operations cannot produce the cryptographic material needed to decrypt the master key wrapping.

### 5.4 Anti-coercion

- **No auto-wipe — by design.** A wipe-after-N-failures is **mutually exclusive with unconditional indistinguishability** and provides little real protection. The reasoning, in full:
  - A wipe needs an attempt counter that survives — and is updated by — *wrong*-passphrase attempts. Such state lives outside the passphrase-gated encryption (a wrong guess cannot decrypt anything), so it is at least faintly detectable, breaking the "looks like pure random" guarantee. (This is exactly why VeraCrypt has no auto-wipe.)
  - Worse, the wipe never stopped the adversary it appeared to: anyone who can read the file can **copy it and brute-force the copy**, restoring the original between guesses, so the counter never advances. The wipe only ever inconvenienced a *naive on-device* attacker who guesses against the original file by hand — a narrow case not worth a permanent deniability tell.
  - The honest consequence: **defense against offline brute force is the per-guess cost of Argon2id × passphrase entropy** (so the product enforces a strong-passphrase policy — see the passphrase-strength bullet below), **plus, for the strong configuration, a FIDO2 hardware key** whose `hmac-secret` is required to unwrap the master key. With a hardware key enrolled, a copy of the file is uncrackable without the physical token, regardless of passphrase guessing — this is the genuine anti-brute-force defense, not a wipe. **Because of this, hardware-key vaults use a LIGHT KDF** (the expensive Argon2id is the *substitute* for hardware; it is redundant once the key carries the resistance, and a multi-second KDF would make the touch flow unusable). Residual trade-off: an attacker who brute-forces such a vault's slot outer-AEAD could recover the *passphrase* (and confirm it is a Farewell vault), but still cannot open it without the key; a strong/generated passphrase keeps even that infeasible. The KDF profile is not stored on disk (deniability); open tries the light profile first, then the hardened one.
- **Mandatory hardware key as the coercion defense.** A vault created with a required YubiKey cannot be opened by passphrase alone. For the border-crossing / transport scenario, the user simply **does not carry the key**: "I cannot open it" is then *true and physically verifiable*, with no lie to maintain, no behavioural tell, and no corruption risk. The data stays protected as long as the key never meets the adversary. This covers transport; it does not cover in-place coercion where the key is seized with the device (openly stated residual). Farewell offers no hidden volumes for this scenario (see §5.2 and ARCHITECTURE §6).
- **Strict no-recovery (by construction).** No backdoor, no security questions, no reset. Supports the legal defense "I cannot, even if I wanted to" (5th Amendment US and equivalents). This is the strongest *non-coercive* guarantee in the product.
- **Passphrase strength policy.** Because the passphrase is the whole offline-brute-force defense (no wipe, plus an optional hardware key), creation enforces a hard floor: the passphrase must reach the maximum **zxcvbn score (4/4)** — a guessability estimate, not naive composition rules (which NIST SP 800-63B discourages). The recommended path is a **generated EFF-diceware passphrase** (10 words ≈ 129 bits) the user must record. A custom passphrase is accepted only if it clears the floor. The same estimator/generator (`farewell_passphrase`) is shared by the core, the CLI, and the app. Trade-off acknowledged: a strong passphrase the user *forgets* is, under strict no-recovery, permanent loss — hence the generated-and-write-it-down default.

*Design note: a **cryptographic time-lock** mechanism (Verifiable Delay Functions) was considered and dropped. On review of the threat model, it provides no useful attacker/legitimate asymmetry — an adversary who coerces the user for N days waits the same N days as them, at a lower marginal cost. The mechanisms above (mandatory hardware key + no recovery) cover the anti-coercion scenarios relevant to the §2 personas.*

### 5.5 Anti-forensic

- No versioning. What is deleted is deleted. No internal snapshot, ever, even opt-in.
- No cleartext trace outside the memory of an actively unlocked process.
- Names of opened files are never persisted in system "Recents," indexed by Spotlight, or cached in Finder thumbnails.
- On vault lock, key material is zeroized (`zeroize` crate, volatile writes); keys are `mlock`'d while open so they never reach swap. GUI buffers are cleared.

### 5.6 Integrity

Authenticated encryption (AES-256-GCM-SIV or constant-time equivalent) for each chunk: any unauthorized modification is detected on decryption with probability ≥ 1 - 2⁻¹²⁸.

Post-quantum **ML-DSA-87** signature (formally verified via libcrux / hax + F\*) on the vault's canonical metadata. A **one-shot** signature created at vault creation, stored **inside the encrypted metadata blob** (format v6). An ML-DSA keypair is generated, the VK is stored, the signature covers the canonical metadata (version, algorithm IDs, capacity, salt, and the VK itself), and the signing key is destroyed immediately (no re-signing possible). The signed message binds the salt, so a signature cannot be lifted onto another vault.

Because the metadata is now AEAD-encrypted (no plaintext header), tamper detection works in two layers: (1) the AEAD tag on the metadata blob already rejects any modification without the metadata key; (2) the ML-DSA signature adds destroyed-key immutability *even against a passphrase holder*, who could otherwise re-encrypt the blob but cannot forge a fresh signature. **Detection therefore happens at open, after the passphrase unwraps a slot** — by design: there is no plaintext header that could let detection (or a metadata readout) happen *before* the passphrase, since a pre-authentication readout would itself be a deniability leak. The `BLAKE3(VK)` fingerprint is a stable user-visible substitution detector, shown post-unlock. Limits: no signed monotonic counter (the manifest counter lives in the encrypted manifest chunk, see §5.6); no Ed25519 hybrid alongside the ML-DSA-87 signature.

### 5.7 Software anti-tampering

- **Reproducible builds (shipped).** Every build of the Rust core is bit-for-bit verifiable by any third party from the published sources. (The signed `.app` is not bit-reproducible — code signing is non-deterministic.)
- **Multi-signature (planned, Phase 3+).** Releases to be signed by ≥ 3 geographically and legally independent maintainers; today a single Developer ID signs.
- **Transparency log (planned).** Releases recorded in an append-only public log (Sigstore / Rekor style), with client-verifiable inclusion proof.
- **Self-check (planned).** `farewell_attest` (a stub) is to make the app refuse to run if its binary was modified post-install.

### 5.8 Network — "No call home" invariant

The app **contacts no server** operated by Denis Florent Media Group SRL or any third party, under any circumstances. This invariant is absolute and verifiable:

- **No telemetry**, even anonymized.
- **No crash reporting** — crashes are handled locally.
- **No analytics, ping, or heartbeat.**
- **No online license verification** — licenses are ECDSA P-256 tokens (KMS-signed) verified locally with the public key embedded in the binary.
- **No update check, even opt-in.** Users manually visit the official site to check for new versions; no in-app mechanism triggers any network request.
- **Opt-in P2P LAN (Phase 2)** — explicit exception, strictly limited to local LAN: single-use token pairing shared out-of-band, end-to-end Noise XX, restriction to `fe80::/10`, RFC1918, and link-local ranges. Active refusal of any globally routable IP. Disabled by default, requires explicit user opt-in **and** separate enabling of network entitlements in a distinct build.

**Verification**: no path in the app opens a network socket (other than the opt-in P2P build) — verifiable by inspection of the open source. The macOS build currently uses the **hardened runtime** (not the App Sandbox), so "no socket" is a property of the code, not yet OS-enforced. Making it OS-enforced — shipping under the App Sandbox with the `com.apple.security.network.*` entitlements omitted, so the sandbox blocks any socket regardless of code — is a planned hardening.

### 5.9 Elimination of disk traces of decrypted content

Guarantee: when the user consults content via the **primary path** (in-app viewer, cf. CHARTER §4.6), no persistent disk trace of plaintext remains after the vault is locked.

The in-app viewer keeps decrypted bytes exclusively inside the Farewell process for the session's duration. These bytes are never materialized as a file on the host filesystem, never exposed to QuickLook (no thumbnail cache), to Spotlight (no indexing), to Time Machine (no backup), nor to any third-party app (no "Recent Items" entry, no auto-save by external editor).

At vault lock, the Farewell process zeroizes its in-memory plaintext buffers, releases mapped memory, closes the `.vault` file descriptor, and releases the flock. (`SecureBuffer`'s `mlock`+zeroize currently covers key material; extending it to content buffers is a planned hardening — see §5.10.)

**Honestly acknowledged residual limits:**

- **Memory swap**: under heavy memory pressure, pages containing plaintext may be swapped to disk before lock. Planned mitigation: `mlock` of plaintext buffers (RAM cost proportional to open file sizes). We do not rely on any undocumented hardware memory-encryption behaviour.
- **Crash dump of Farewell itself**: if the Farewell process crashes while holding decrypted bytes, the dump in `/Library/Logs/DiagnosticReports/` may contain them. User mitigation: disable "Share with App Developers" in System Settings → Privacy.

**Explicit export** (CHARTER §4.7) falls outside this guarantee by construction: the user has consented to materializing a plaintext copy outside Farewell's perimeter; the resulting traces are those of any plaintext file on macOS. No filesystem mount is offered by Farewell — that is an explicit non-goal documented in CHARTER §5.

### 5.10 Plaintext-in-RAM surface (streaming, mlock, Secure Enclave)

The exposure of decrypted content in RAM during rendering is a real leak surface (swap to disk, debugger dump, crash report capturing memory). The naive reflex of "re-encrypting RAM content with a key that also lives in RAM" is security theater: an attacker who reads RAM reads both the ciphertext and the key. Farewell addresses this surface with five complementary defence layers — three shipped, two planned — each effective against a distinct attack class.

**1. Streaming decryption.** The in-app viewer never decrypts an entire file. At any instant, only the data strictly required for the current rendering (one PDF page, one audio segment, one video window) exists in cleartext. The core's `read_range` API is the primitive that makes this natural: read a byte window, render, zeroize, move to the next. Plaintext surface divided by 10-1000× depending on the file.

**2. `mlock` of active buffers (planned).** The intent is to mark the plaintext pages currently being displayed unpageable via `mlock(2)`, so they cannot reach swap or the sleepimage (hibernation). Today `farewell_keys::SecureBuffer` (`mlock`+zeroize) covers key material; extending it to content buffers is planned.

**3. Hardened Runtime + hardening entitlements.** The signed binary refuses debugger attach (no `com.apple.security.get-task-allow`), enforces library validation (`disable-library-validation: false`), forbids JIT and executable-memory allocation. A non-root attacker cannot `lldb attach` or `task_for_pid` the Farewell process.

**4. Crash-dump disablement.** No signal handler that dumps memory; no opt-in to Apple Analytics submission. A Farewell crash produces a log message but no core dump usable for plaintext exfiltration.

**5. (Phase 1.x) Master key in the Secure Enclave.** On Apple Silicon, the Argon2id-derived master key is wrapped into the Secure Enclave immediately after derivation, then zeroized in RAM. All subsequent crypto operations route through the SE. A RAM dump reveals neither the master key nor any means to decrypt the vault's AEAD chunks. Limit: the SE has bounded crypto bandwidth; for large files we derive a short-lived **session key** symmetric in RAM (mlock'd) used for high-throughput decryption, re-derived periodically.

**Honestly acknowledged residual surface.** Layers 1, 3 and 4 are shipped (streaming, hardened runtime, no crash dumps); layers 2 (content `mlock`) and 5 (Secure Enclave) are planned. With all five in place, an attacker who read Farewell's RAM at a given instant would observe: (a) the plaintext window currently being rendered (typically 50 KB–5 MB, zeroized as soon as it leaves the screen — and, once layer 2 ships, `mlock`'d so never on disk), (b) the vault chunks in AEAD-encrypted form, (c) once layer 5 ships, on Apple Silicon only an opaque Secure-Enclave handle. Even today — the master key is never written to disk and the chunks stay AEAD-encrypted — this compares favourably to VeraCrypt (entire volume decrypted in kernel-mapped memory), Cryptomator (no SE), and Signal Desktop (Electron, plaintext liberal in RAM).

---

## 6. **Out-of-scope** surface

This section is as important as the previous one. It distinguishes an honest product from one that over-promises.

### 6.1 OS compromise pre-unlock

If an attacker has code executing on the system (rootkit, persistent malware, evil maid on firmware or bootloader) **before** the user unlocks the vault, Farewell can guarantee nothing. A passphrase typed on a compromised system is known to the attacker.

**User-side mitigation:** use Farewell on an OS with verified boot integrity (Secure Boot + reproducible build of the OS, ideally Tails or Qubes for critical cases).

**Product-side mitigation:** explicit documentation and in-app warning on sensitive operations.

### 6.2 User compromise

- Unlimited physical coercion (torture).
- Social manipulation (the user accepts to install a fake Farewell under pressure or by deception).
- Direct visual observation of keyboard input.

### 6.3 Advanced hardware side-channels

- TEMPEST (electromagnetic emissions captured at distance).
- Power analysis on electrical consumption.
- Acoustic cryptanalysis on keyboard or component noise.

These attacks require privileged, long-term, costly physical access. Countering them demands a Faraday environment + isolated power — outside the software perimeter of a consumer product, even nation-state.

### 6.4 Usage metadata outside the vault

If the user opens a file extracted from the vault with Pages, Pages may create a thumbnail, index the content, save an autosave in `~/Library/Containers/`, write to `~/Library/Preferences/`. Farewell does not control third-party apps that touch extracted files.

The user is responsible for understanding that **taking a file out of the vault = leaving Farewell's guarantees**.

**Product mitigation:** explicit documentation + in-app viewer/editor mode (App Quarantine view) that makes a file visible without ever writing it in cleartext outside the Farewell perimeter.

### 6.5 Availability

Farewell guarantees **no availability**:

- Passphrase loss = permanent loss.
- Hardware key loss or destruction = permanent loss.
- `.vault` file corruption (dead disk sector, bit flip) = permanent loss of the affected chunk, possibly the whole depending on location.
- No automatic backup. The user manages out-of-band backups, knowing the copy is also encrypted and subject to the same no-recovery.

### 6.6 Post-mortem forensic audit

Without the passphrase (and, where enrolled, the hardware key), **no forensic analysis** can recover the content: the file is indistinguishable from random and the master key is unwrappable only with the correct secrets. This is the desired property, not a defect. (There is no auto-wipe; see §5.4.)

### 6.7 Network metadata outside LAN

If the user enables P2P LAN, the fact that two devices on the same network speak Farewell is observable by an attacker controlling the network (compromised router). The content remains encrypted, but the existence of the traffic is observable.

Possible future mitigation (post-v1.0): constant padding + noise to decorrelate real activity from silence.

### 6.8 OS compromise by its vendor

On macOS, Apple can technically push an update compromising Secure Enclave (e.g., under NSL coercion). We accept this residual risk and document: Farewell is exactly as reliable as the OS that runs it.

On Linux, the user trusts the distro, kernel, drivers. Farewell cannot guarantee the integrity of the base.

### 6.9 Linkability outside the vault

**Updated for the v6 format.** A `.vault` file no longer has any "format signature": there is no magic, no plaintext header, and no wipe region — without the passphrase it is **unconditionally** byte-for-byte indistinguishable from random data (the lone plaintext field is the salt, which *is* random). So the file *itself* never betrays that you use Farewell, nor its content. One caveat remains:

- **Context still links.** The installed Farewell app, a `.vault` extension, shell history, a residual size heuristic (file length ≡ a fixed offset plus a whole number of chunks), or several such files in one directory all establish *that* you use the tool and that the files share an owner — independently of the bytes inside. Deniability protects the **content** (and the fact that the bytes are a Farewell vault at all); it cannot erase the surrounding context on your machine. Operational discipline (naming, placement, removable media) remains the user's responsibility.

---

## 7. Trust assumptions

Farewell assumes the following elements honest and uncompromised. If one assumption fails, the corresponding guarantees fail.

| Element | Required trust | Justification |
|---|---|---|
| AES-256 (classical cryptanalysis) | Total | No significant progress in 26 years |
| Argon2id | High | Best-in-class KDF, monitor benchmarks |
| ML-KEM-1024 (NIST PQC) | High | `libcrux-ml-kem` formally verified implementation (hax + F\*, Cryspen). NIST FIPS 203. |
| ML-DSA-87 (NIST PQC) | High | `libcrux-ml-dsa` formally verified implementation. NIST FIPS 204. |
| Curve25519 / Ed25519 | High | Widely audited, large-scale deployment |
| macOS Secure Enclave | High | Audited by third parties, but proprietary to Apple |
| TPM 2.0 (Linux) | High | Open standard, multiple implementations |
| FIDO2 open-source firmware key (Nitrokey, SoloKey) | High | Verifiable firmware |
| FIDO2 closed firmware key (YubiKey) | Moderate | Closed firmware, audited by third parties |
| Host operating system | **Conditional** | The user is responsible for their OS |
| Hardware CPU (AES-NI, Apple Silicon) | Moderate | Residual risk of undetected backdoor |
| OS video codec (VideoToolbox) | Moderate | **Video only.** H.264/HEVC decode is done by Apple's in-process codec on bytes fed from RAM (no disk spill — verified by `scripts/verify-no-disk-spill.swift`). No production-grade pure-Rust video decoder exists without a large C dependency that would enlarge the attack surface. **Audio is exempt**: decoded entirely in pure-Rust (`farewell_audio`, Symphonia). |

---

## 8. Accepted failure modes

We document what we accept losing in certain scenarios. All are made explicit to the user at setup, with acknowledgment required before the first piece of data is stored.

| Scenario | Accepted consequence |
|---|---|
| User forgets passphrase | Total permanent loss |
| User loses hardware key | Total permanent loss |
| Disk failure (corrupted vault) | Total or partial loss |
| Weak passphrase + attacker has a copy | Offline brute force may succeed (no auto-wipe; use a strong passphrase and/or a hardware key) |
| OS compromised before unlock | Loss of all confidentiality |
| Apple revokes app signature | App will not launch on macOS until update |
| Critical post-release bug | Emergency release + public advisory |

---

## 9. Formal cryptographic guarantees

### 9.1 Confidentiality

> Without the passphrase (and, for hardware-key vaults, the FIDO2 key), an adversary cannot distinguish the content of a Farewell vault from random noise of the same size, under the cryptographic assumption of **AES-256-GCM-SIV** (the passphrase stretched by Argon2id, and/or the FIDO2 `hmac-secret`).
>
> At rest the key-wrapping is **symmetric** — there is no public-key step — so confidentiality is already post-quantum-safe (256-bit symmetric drops to ~128-bit under Grover, out of reach; nothing for Shor to attack). The X25519+ML-KEM-1024 hybrid is reserved for the future P2P transfer (§5.8), not used at rest.

### 9.2 Deniability (byte-level)

> Without the passphrase, a `.vault` file is computationally indistinguishable from uniform random data of the same length (no magic, no plaintext header, no wipe region; the lone plaintext field is the salt, which is random by construction). There are no hidden volumes (§5.2) and no multi-level secrecy claim.

### 9.3 Integrity

> Any modification of an encrypted chunk without the key is detected with probability ≥ 1 - 2⁻¹²⁸ via the AEAD.

### 9.4 Anti-rollback

> The manifest contains a monotonic counter, AEAD-protected by a key derived from the master key. Incremented on every write (`add_file` / `delete_file`). Surfaced to the user by the CLI on every read or write (`farewell add` / `farewell list` etc. print `Manifest counter: N`). The user can pass `--expect-counter N` at mount to require the counter be ≥ N, otherwise refusal with `CounterRollback`. **Acknowledged, publicly declared limit**: without persistent external state (a value the user records themselves or compares across devices), an attacker who can replace the entire file with an earlier copy cannot be cryptographically detected — the manifest's AEAD is valid for the old file too. This is an **intrinsic** limit of a stand-alone file format. Cryptographic internal mitigations proposed in the literature (chained signed counters, blockchain anchoring, TPM-backed counters) are no more effective without that external state. An ML-DSA signature over the counter would buy **nothing**: the attacker already holds everything to produce a coherent older file (including its internal signature). The correct defense is UX: the app exposes the counter, the user records it, and compares it via `--expect-counter`.

### 9.5 Anti-replay (P2P LAN)

> *(Phase 2 — P2P not yet implemented.)* Any message replayed in a P2P LAN session is detected via nonce + per-session signed counter.

---

## 10. Assumed limits and public declarations

The following limits are declared publicly and prominently in the documentation, on the site, and in the app at relevant moments.

1. **"Farewell does not protect against torture."**
2. **"Farewell does not protect against a compromised OS."**
3. **"Farewell never recovers a forgotten passphrase."**
4. **"Farewell stores nothing outside your device without your explicit action."**
5. **"Farewell is open-source GPL v3, publicly audited, sold one-shot from €49, self-funded without VC or debt."**

These sentences are the *narrative guardrails* of the product. All product communication must be reconcilable with them.

---

## 11. Revision process

This threat model is revised:

- At each major release (1.0, 2.0, etc.).
- At each external audit (annual or ad-hoc).
- At each significant security incident (critical CVE, maintainer compromise).
- At each evolution of the cryptographic state of the art (e.g., publication of a practical attack on ML-KEM, quantum breakthrough).

Any modification must be discussed publicly via RFC in the repo (cf. CHARTER §8.5), and validated publicly before integration.

The complete revision history is kept in the repository in cleartext and signed.

---

## 12. Crypto-agility and format migration

If a cryptographic primitive used by Farewell is compromised (e.g., practical attack published against ML-KEM-1024, relevant quantum breakthrough on AES-256, weakness found in Argon2id), a migration release is triggered according to the following process.

### 12.1 Response procedure

1. **Emergency evaluation (24-72h).** The publisher issues a signed advisory evaluating the criticality of the attack, its applicability to the Farewell format, the expected practical exploitation timeline, and any transitional mitigations.

2. **Migration release.** A new version integrating the replacement primitives (e.g., ML-KEM-2048 or NIST successor) is published according to the standard process (reproducible builds + multi-signature).

3. **Full re-encryption on next open.** When unlocking a vault with the migrated version, the user is informed that a full re-encryption will occur. The operation may take several hours on large vaults. Re-encryption is **atomic at the file level**: interruption (sector failure, process kill) = clean restart from the last consistent point, never a partially migrated or corrupted intermediate state.

4. **Force-migration with deadline.** After a delay determined by criticality (typically 6 to 24 months depending on urgency), Farewell versions after the migration release refuse to open vaults in the old format. The user must have migrated, or lose access.

5. **Limited and deliberate backwards compatibility.** Farewell does not indefinitely maintain the ability to read old formats. This decision is deliberate: an old format left readable is an entry point for historical cryptanalysis ("harvest now, decrypt later" becomes "decrypt now"). The absence of fallback is a security guarantee, not a design flaw.

### 12.2 Accepted consequences

- A user who does not open their vault for years may end up with an unreadable file after a format migration intervened in the meantime.
- Product documentation and advisories make this explicit.
- A long-inactivity warning is displayed in the app if an installed version detects that a vault in obsolete format has just been opened outside the migration window.

### 12.3 Anticipation and preparation

To limit the impact of forced migrations:

- Each Farewell release publishes the format(s) it can still read and the one(s) it writes.
- The publisher publishes a forward-looking deprecation calendar as soon as it is known (typically 12-18 months ahead for non-urgent migrations).
- An in-app notification warns at open if a migration is scheduled within 6 months.

---

**End of document.**
