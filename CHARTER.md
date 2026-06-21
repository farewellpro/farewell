# Charter — Farewell

**Status:** Founding document. Defines the mission, scope, principles, and governance of the project. Aligned with [THREAT_MODEL.md](THREAT_MODEL.md).

---

## 1. Mission

Farewell gives people whose safety depends on their data — journalists, sources, dissidents — a software vault that keeps its promises under state-level threat.

The product exists because current tools fail at least one of the three conditions below:

- They use cryptography that will not survive the decade (no post-quantum).
- They impose so heavy a usage discipline that they are in practice misused or abandoned (cf. VeraCrypt on macOS).
- They are not really auditable (missing or imperfect reproducible builds, opaque governance).

Farewell aims to fix all three simultaneously.

---

## 2. Vision

At a 5-year horizon, Farewell is the de facto standard for encrypted storage among people at high risk, occupying the role Signal occupies in messaging: a tool whose mention is immediately understood as a serious choice, and whose cryptographic guarantees are publicly verifiable.

The goal is not the mass market. The goal is **qualitative adoption** — the right people use the right tool and know why.

---

## 3. Personas and users

Per [THREAT_MODEL.md](THREAT_MODEL.md) §2, the canonical personas are:

- **Maya** — investigative journalist, primary arbitration persona.
- **Karim** — non-technical source preparing a sensitive transfer.
- **Lena** — exile coordinating with activists in a hostile jurisdiction.

The product is explicitly **not** designed for the general public seeking to encrypt vacation photos (FileVault is enough) nor for enterprises seeking multi-user sharing with audit logs (architecturally incompatible). These non-targets are not a defect: they are scope decisions that make the guarantees for the real personas possible.

---

## 4. Scope (in-scope)

Farewell commits to providing:

1. **Encryption at rest** of a monolithic, opaque, single-domain `.vault` container, indistinguishable from random noise without the passphrase (and, for hardware-key vaults, the FIDO2 key).
2. **Byte-level deniability**: no magic, no plaintext header, no wipe region — the file never betrays that it is a Farewell vault. (A vault is single-domain; there are no hidden/decoy volumes — see ARCHITECTURE §6.)
3. **Strict multi-factor authentication**: passphrase + hardware key(s) FIDO2 enrolled at setup.
4. **Anti-coercion via the mandatory hardware key**: at a border, not carrying the key makes "I cannot open it" true and verifiable; plus anti-rollback (counter exposed out-of-band) and strict no-recovery. (No auto-wipe — it is incompatible with unconditional indistinguishability.)
5. **Post-quantum posture + crypto-agility**: content is sealed with AES-256-GCM-SIV + Argon2id (symmetric, already quantum-safe at rest) plus a one-shot ML-DSA-87 attestation; the metadata records algorithm IDs and a forced-migration path. The X25519+ML-KEM-1024 and Ed25519+ML-DSA-87 hybrids are implemented and held in reserve for future device-to-device transfer and release signing respectively (not used at rest).
6. **In-app viewer (the ONLY content access path)**: native integrated viewing and reading for PDF, images, text, markdown, audio, video — decrypted bytes never leave the Farewell process. Absolute guarantee that no OS cache (QuickLook, Spotlight, Time Machine) and no third-party app can create a disk trace of sensitive content. No filesystem mount is offered, in any build. The plaintext-in-RAM surface is minimized by streaming decryption + `mlock` of active buffers + Hardened Runtime (Phase 1) + Master key in the Secure Enclave (Phase 1.x). Cf. THREAT_MODEL §5.9, §5.10 and CHARTER §5.
7. **Controlled import / export**: drag-drop for import (with optional secure-shred of source file), explicit export with warning dialog listing each OS-cache leak vector, direct inter-Farewell P2P (Phase 2) for device-to-device transfer without touching disk in cleartext.
8. **Opt-in P2P LAN** for synchronization between devices of the same user, with pairing via out-of-band shared single-use token. *(Phase 2 — not yet implemented.)*
9. **Reproducible builds** for the Rust core (shipped). **Multi-signature** (≥ 3 independent maintainers) and a **Sigstore-style transparency log** for releases are planned objectives (cf. §11.3).
10. **Supported platforms:** macOS (priority) and Linux. No Windows in v1.0. Mobile is out of scope for v1.0 and evaluated afterwards.
11. **Documentation in English**, additional languages in Phase 3+.

---

## 5. Non-goals (explicit out-of-scope)

Farewell will **never** do:

- **Passphrase recovery.** No backdoor, no security questions, no reset. Loss is permanent, and that is the principal guarantee.
- **Cloud sync.** No server hosts user data, ever. P2P LAN is the only exception, and it stays on the local network.
- **Multi-user with audit logs.** Architecturally incompatible with the other guarantees (audit logs are seizable). Organizations that need this must choose another tool.
- **Third-party companion apps (Pages, Office).** Sensitive content stays in the in-app viewer. Taking a file out = leaving the guarantees.
- **Search inside the vault.** Manual navigation only. No index = no attack surface via access patterns.
- **Versioning, snapshot, undelete.** Deletion = irrecoverable. No exploitation window in time.
- **Silent auto-update.** Updates verified explicitly by the user, never in the background.
- **Telemetry, automatic crash reports, A/B tests, analytics.** Nothing leaves the app without a conscious action.
- **App Store distribution.** Apple can block/withdraw; the sandbox restricts filesystem access. Direct distribution + reproducible builds only.
- **Full-disk / block-level encryption.** This flagship VeraCrypt feature (encrypting an entire USB stick or partition with XTS-AES) requires a kernel kext on macOS and a kernel module on Linux. Incompatible with our "no kext, no SIP disable, no admin privileges for mount" commitment (ARCHITECTURE §7.1) — this is a major security downgrade, not a missing feature. For FDE, use **FileVault** (macOS), **LUKS** (Linux), or **BitLocker** (Windows): audited, OS-integrated, no third party. Farewell complements those at the **file** level: a `.vault` on a normally-formatted USB stick (exFAT, APFS) provides the same cryptographic guarantees as VeraCrypt FDE, plus cross-OS portability with no driver, no macOS "Disk Not Readable" nagging, and all our other features (hybrid PQC, FIDO2 hmac-secret, fingerprint, anti-rollback). The only thing we lose is the illusion of "disk-level deniability" that VeraCrypt claims to offer — illusion largely hollow, since a forensic analyst recognizes a VeraCrypt disk instantly by its entropy and header structure.
- **Filesystem mount (FSKit, FUSE, kext, or equivalent).** No path where decrypted content is exposed to the host OS as a volume manipulable by third-party apps. This option was considered then refused because it degrades the product's central guarantee: as soon as content transits Finder + Preview + QuickLook + Spotlight + Time Machine + third-party apps, macOS creates disk traces that Farewell cannot fully neutralize (persistent QuickLook thumbnails, Spotlight index, Time Machine snapshots, app Recent Items, auto-save, crash dumps). VeraCrypt and Cryptomator have lived with these leaks for 20 years; Farewell explicitly refuses to inherit them. The **only** content access path is the in-app viewer (CHARTER §4.6). This choice is public, permanent, and constitutive of the product's promise.

These non-goals are **public and permanent**. Any feature proposal that violates them is rejected without extended discussion.

---

## 6. Guiding principles

The following principles decide tradeoffs when the threat model alone does not suffice.

### 6.1 Confidentiality > integrity > availability

In case of conflict, availability is lost. Never the reverse. Loss of data is an acceptable failure; leakage of data is an unacceptable failure.

### 6.2 Honesty before marketing

All product communication must reconcile with the five public declarations of the threat model:

1. *"Farewell does not protect against torture."*
2. *"Farewell does not protect against a compromised OS."*
3. *"Farewell never recovers a forgotten passphrase."*
4. *"Farewell stores nothing outside your device without your explicit action."*
5. *"Farewell is open-source GPL v3, publicly audited, sold one-shot from €49, self-funded without VC or debt."*

### 6.3 Friction that serves the user, not friction that punishes

Each heavy step in the product (30-min setup, frequent re-auth, no recovery) is a *protection*. Documentation and the app explain why at each friction point. The user must exit each step knowing what they have just gained.

### 6.4 Audit before feature

No feature ships unless its code has been audited by at least one maintainer independent of the author. Non-essential features wait until the audit debt is cleared.

### 6.5 Complexity is the enemy of security

At equal feature scope, we always choose the solution with less code surface. At equal code surface, we choose the more formally verifiable solution. The project actively refuses growth by feature accumulation.

### 6.6 Independence from any single vendor

No single vendor can bring down Farewell. No blocking dependency on Apple, on a cloud provider, on a proprietary CI infrastructure, on a third-party service. The project must be able to continue if any provider disappears or turns hostile.

### 6.7 Documentation as first-class

Each feature ships with its documentation. Ambiguous sentences in documentation are bugs. Advisories are published in plain text before the release that fixes them.

---

## 7. Values and public commitments

### 7.1 Fully open source

Full source code under **GPL v3**. No commercial version, no dual licensing, no paid features. The distributed code is exactly the auditable code.

### 7.2 Guaranteed reproducible builds

Every published build of the **Rust core** is bit-for-bit reproducible by any third party from the published sources. The build pipeline is documented, deterministic, and re-checked in CI on every push and release tag.

Mechanism: `rust-toolchain.toml` pins the exact rustc/cargo version; `.cargo/config.toml` together with `scripts/verify-reproducible.sh` set `SOURCE_DATE_EPOCH`, `RUSTFLAGS` with `--remap-path-prefix`, and `CARGO_INCREMENTAL=0`; the script builds the binary twice in distinct `target/` directories and compares the SHA-256 hashes. The GitHub Actions workflow `.github/workflows/reproducible-build.yml` re-runs this check on Linux x86_64 and macOS arm64 on every push and every release tag. The `docs/REPRODUCIBLE_BUILDS.md` document explains how a third party reproduces the operation locally. Acknowledged limits (made explicit in that doc): cross-architecture reproducibility is not guaranteed (Linux x86_64 ≠ macOS arm64, expected); trusting-trust of the rustc compiler itself (pre-built binary via rustup) is out of scope for this version; and the signed/notarized macOS `.app` bundle is not bit-reproducible (code signing is non-deterministic) — reproducibility covers the Rust core.

### 7.3 No ethical neutrality beyond the product

The publisher does not pass judgment on individual use of the tool. But it publicly opposes legislation requiring cryptographic backdoors, and funds/supports strategic litigation as appropriate.

### 7.4 Operational transparency

The SRL's annual accounts relevant to transparency (product revenue, audit/dev/infra expenses) are published yearly. Governance, maintainers, and their countries of residence are public. Potential conflicts of interest are declared.

---

## 8. Governance and structure

### 8.1 Publishing entity

Farewell is published by **Denis Florent Media Group SRL**, a commercial company under Romanian law, for-profit, operating under EU regime (GDPR, intra-community VAT).

This decision breaks with the "Foundation" model initially envisaged. Reasons assumed:

- **Economic sustainability**: sales (cf. §10) directly fund development, annual audits and maintenance, without depending on unpredictable grant cycles.
- **Decision velocity**: tight structure necessary to iterate against state-level adversaries.
- **Independence from any single grant**: no dominant funder that could be captured.

Honest trade-off vs Foundation: governance diversity is weaker. Compensated by §8.3.

### 8.2 Jurisdiction choice — Romania

For an encryption tool, the publisher's jurisdiction is a material trust criterion. The choice is made explicit here rather than diluted in a "Legal" page.

**Romanian strengths:**

- **Constitutional jurisprudence favoring privacy**: the Constitutional Court invalidated in 2009 the Romanian transposition of directive 2006/24/CE (data retention), 5 years before the CJEU in 2014. European landmark, reaffirmed in 2011 and 2017.
- **No mandatory key-disclosure law.**
- **Outside intelligence alliances** Five/Nine/Fourteen Eyes.
- **EU member** (GDPR, CJEU, single market) and peripheral NATO member (less bilateral US pressure).
- **Industrial precedent**: Bitdefender (founded 2001) demonstrates that a Romanian security company can reach worldwide reputation.

**Honestly acknowledged weaknesses:**

- **Unfavorable Western tech stereotype**. Mitigation: transparency + Cure53/NCC audits.
- **Perceived corruption** (Transparency Intl 2023: 46/100, vs Germany 78). Relevant for trust in the judicial system if compelled disclosure were attempted.
- **Press Freedom RSF 2024 rank 49**. Relevant for the protection of user-sources.

**Why not Switzerland**: ideal privacy jurisdiction in theory, but incorporation and operational cost 5-10× higher. Reevaluable if Farewell reaches a scale that allows it.

### 8.3 Trust model in the absence of multi-maintainer

The "≥ 3 independent maintainers sign each release" model planned for the Foundation is inapplicable to an SRL with initially reduced team. To avoid weakening the trust chain, it is replaced by:

- **Reproducible builds** (cf. §7.2): recompilation from source verifies the sold binary bit-for-bit. Cornerstone that makes the publisher non-load-bearing for security.
- **Source GPL-3.0 fully public** (cf. §10.1): no proprietary blob.
- **Annual external audit** by recognized firm (Cure53, NCC Group, Trail of Bits — cf. §11.1), public report.
- **Permanent bug bounty** (cf. §11.2).
- **Multi-signature releases — Phase 3+ objective**: transition to ≥ 3 external co-signers contractually engaged when Farewell reaches financial maturity allowing compensation.

No multi-maintainer claim not delivered. Sustainability comes through verifiability of code and binary, not through jurisdictional diversity of signers.

### 8.4 Advisory board

Advisory board of 5-7 people (cryptography, operational security, human rights, investigative journalism, international law). Non-binding but published opinions. To be constituted in Phase 1.

### 8.5 Public discussion of structural decisions

Decisions affecting product security, threat model, file format, or public commitments → **public RFCs** in the GitHub repository. Comment period ≥ 30 days, final decision publicly documented. Commercial decisions (pricing, marketing, operations) remain SRL discretionary.

---

## 9. Funding

### 9.1 Economic model

**Primary revenue: one-shot product sales** (cf. §10 Distribution).

- **Single**: €49 — 1 Mac, v1.x lifetime updates.
- **Duo**: €69 — 2 Macs.
- **Quintet**: €129 — 5 Macs.
- **Major version upgrade**: a reduced fee on the next major version.

**At-risk grant program**: free **Grant** licenses for journalists, dissidents and whistleblowers, issued as signed redeem codes — distributed directly or via verified partnerships (RSF, EFF, Frontline Defenders, Access Now). A Grant is serial-bound to one Mac like any other license.

**Acknowledged exclusions:**

- **No direct state grants**, to preserve independence from any government.
- **No venture capital funding**: no VCs, no fundraising rounds, no investor-imposed growth pressure.
- **No bank debt**: self-funding by sales only.
- **No reselling of user data**: impossible by construction, we collect none (cf. THREAT_MODEL §5.8).
- **No freemium**: no degraded free version. The only free access is compiling from source (GPL) and the at-risk grant program.

### 9.2 Target budget

Estimates for an SRL model with initially very small team (1-2 FTE), to be refined with the first real sales figures.

| Phase | Target annual expenses | Sources |
|---|---|---|
| Phase 0 (M0-M3, pre-launch) | ~€50-80k | SRL initial capital |
| Phase 1 (M3-M9, private alpha) | ~€80-120k | Capital + possible early-access sales |
| Phase 2 (M9-M15, beta + 1.0) | ~€150-200k | 1.0 sales |
| Steady-state post-1.0 | ~€150-250k/year | Sales only |

Main line items: 1 FTE maintainer (€60-90k), 1 annual external audit Cure53/NCC/Trail of Bits (€40-80k depending on scope), Apple Developer + infra + tooling (~€5k), legal + accounting (~€10k), minimal marketing (~€10-20k).

**Viability floor**: on the order of a few thousand one-time sales per year across the Single / Duo / Quintet plans — the exact figure depends on the mix. Reachable in year 2 with a proper press launch.

### 9.3 Operational independence

Self-funding by sales ensures no single actor (grant funder, investor, bank, government) holds leverage over product decisions. The only operational dependencies are Apple (Developer Program, notarization — mitigable via self-signed Developer ID + reproducible builds in case of political revocation, the app stays functional unnotarized in local dev mode), an SEPA bank, and an EU payment processor (Stripe, Paddle, Mollie — substitutable). None accesses user data: by construction (cf. THREAT_MODEL §5.8) we collect none beyond what's strictly necessary for billing.

---

## 10. Distribution and license

### 10.1 License

- **Code**: GPL v3.
- **Documentation**: CC BY-SA 4.0.
- **"Farewell" trademark**: registered by the SRL, regulated use to prevent fork-based usurpation.

### 10.2 Distribution channels

- **Official site** (`farewell.pro` or equivalent) with direct downloads.
- **Geographically distributed mirrors** (official mirrors sponsored by universities, sibling projects).
- **Linux package managers** (apt, dnf) with signed repositories once 1.0 is stable.
- **No macOS App Store** (cf. non-goals §5).
- **No official Homebrew tap** in v1.0 (the community may maintain one, but without endorsement).

### 10.3 Update mechanism — no automatic check

No in-app mechanism for update verification or download is included, **even opt-in**. This commitment materializes the "No call home" invariant from THREAT_MODEL §5.8:

- Users manually visit the official site to check for a new version.
- Release announcements go through external channels they choose (optional newsletter, RSS feed, specialized press, EFF/RSF for critical CVEs).
- Any update install is done manually after inspection of the signature and transparency log.
- The app prominently displays its current version, so users know when to check.

Acknowledged trade-off: users may remain on a vulnerable version longer than with automatic checks. Mitigation: critical CVE announcements are relayed by partner NGOs (EFF, RSF, Frontline Defenders), to which at-risk users are by construction connected.

### 10.4 License enforcement

Farewell licenses are **bound to the hardware serial number** of each authorized Mac. The serial number (visible in Apple menu → About this Mac) is embedded in the ECDSA P-256-signed license payload; at launch, the app verifies locally that the Mac's SN matches. Everything happens offline, consistent with the No-call-home invariant (cf. THREAT_MODEL §5.8).

**After purchase:**

- The buyer reaches a **token-gated management page** (a 60-minute link tied to the purchase email) and enters their Mac serial number(s) there — one for Single, up to two for Duo, up to five for Quintet. The license is generated on the spot.
- **At-risk Grant**: issued as a **signed redeem code**; the recipient redeems it and binds it to their Mac's serial after installation. Rationale: at-risk users cannot guarantee which Mac they will use (mobility, seizures, emergency loans).

**Public commitment to free reissuance:**

The publisher publicly commits to **reissue a license at no cost**, on proof of Stripe purchase, in the following cases:

- Mac stolen, lost, or physically destroyed.
- Logic board replaced by Apple Service (the hardware SN has changed).
- Sale of the original Mac and purchase of a replacement Mac.
- SN entry error at checkout (verifiable).

Procedure: email to `hello@farewell.pro` with Stripe order number + SN to revoke + new SN. Response within 24 business hours. No quota, no trick questions.

**What is NOT covered by reissuance:**

- Acquisition of an additional Mac beyond the plan limit (upgrade to a larger plan, or an additional purchase).
- Attempt to transfer the license to a third party (license is bound to the purchase email).
- Hackintosh or absent / invalid SN (compile from GPL source).

This posture reconciles technical enforcement (real device limit) with respect for the mobility of the target audience: a journalist can lose their Mac and obtain a reissuance within 24 hours, without administrative drama.

---

## 11. Audit and transparency

### 11.1 External audits

- **Annual full audit** by independent firm (Trail of Bits, NCC Group, Cure53, or equivalent).
- **Ad-hoc audit** on each major release or cryptographic change.
- Audit reports published in full, redacted only for still-unpatched vulnerabilities.

### 11.2 Bug bounty

- Public program, significantly funded (€10k-€50k per critical vulnerability based on impact).
- Hall of Fame for contributors.
- Responsible disclosure with standard 90-day delay, documented exceptions.

### 11.3 Release transparency log

- All releases recorded in an append-only Sigstore/Rekor-style log.
- Inclusion proof verifiable client-side.
- Allows detection of "you received a different release than others" attacks.

---

## 12. Stakeholders

### 12.1 Users

Personas defined in the threat model. Voice in public RFCs, regular surveys via untraceable channels (onion-service form).

### 12.2 Maintainers

See §8.2.

### 12.3 Auditors

Independent security firms, paid by the SRL out of product revenue (cf. §9.2), operationally independent from maintainers. Annual rotation to avoid trust drift.

### 12.4 Contributor community

Non-maintainer open-source contributors. Clear contribution process, active mentoring to facilitate entry. Strict Code of Conduct.

### 12.5 Paying customers

Buyers (Single, Duo, Quintet) and Grant recipients. Voice in public RFCs (cf. §8.5), no veto right on the roadmap. Payment buys neither influence nor privileged access — only the signed binary and v1.x lifetime updates (cf. §9.1).

### 12.6 Strategic allies

Tor Project, Signal Foundation, EFF, Reporters Without Borders, Access Now, La Quadrature du Net. Occasional collaborations (advocacy, joint advisories, user training).

---

## 13. Acknowledged risks

We publicly document the risks we have identified without having solved them.

### 13.1 Single-founder risk

The publishing SRL has one majority shareholder. In case of death, incapacity, or compromise, product continuity depends on three cumulative mechanisms: 1/ a succession plan prepared from Phase 1 (will with technical instructions, signing keys deposited with notary with documented transfer procedure); 2/ the GPL-3.0 license which allows the community to fork and maintain independently; 3/ reproducible builds which make the sold binary verifiable without the publisher. Primary mitigation: prepare 1/ explicitly before the 1.0 release.

### 13.2 Cryptographic fracture risk

ML-KEM or ML-DSA could be compromised within a few years. Mitigation: at rest, confidentiality rests on symmetric AES-256 (unaffected by a public-key break); the metadata records algorithm IDs and the engine supports a forced migration to replacement primitives. Where an asymmetric step is actually used (future P2P transfer, release signing), classical+PQ hybrids (X25519+ML-KEM, Ed25519+ML-DSA) require *both* to fall.

### 13.3 Compromised-maintainer risk

A maintainer could be coerced or turned. Current mitigation: reproducible builds (the published binary is verifiable without trusting the publisher) and GPL-3.0 fork-ability. Planned (Phase 3+, cf. §8.3): a release-signing quorum of ≥3 independent maintainers across jurisdictions, plus a transparency log.

### 13.4 Hostile-fork risk

A state actor could fork Farewell, add a backdoor, and distribute a seemingly legitimate version. Mitigation: trademark + reproducible builds + verifiable signatures + user education on official sources.

### 13.5 Malicious-use risk

Like any strong cryptographic tool, Farewell can be used by harmful actors. The publisher accepts this opportunity cost: utility to legitimate personas outweighs marginal hostile use (cf. Tor, Signal arguments).

### 13.6 Operational-complexity risk for users

The product remains demanding (30-min setup, frequent re-auth, no recovery). Some target users will not maintain the discipline. Mitigation: carefully crafted pedagogical onboarding, reassuring Signal-like voice, accessible documentation.

### 13.7 Post-1.0 stagnation risk

Once 1.0 is shipped, the project may lose momentum. Mitigation: a roadmap beyond 1.0 (future PQC migrations, possible mobile read-only, etc.), multi-year publisher commitment.

---

## 14. Structural decisions (references)

All design decisions made in the design phase are documented in:

- [THREAT_MODEL.md](THREAT_MODEL.md) — whom we protect, against what, against what not.
- [ARCHITECTURE.md](ARCHITECTURE.md) — components, technical stack, flows.

Any modification of a structural decision goes through a public RFC.

---

**End of document.**
