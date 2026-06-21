# Farewell

> An encrypted file vault for people whose threat model includes a state-level adversary.

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Status: pre-1.0](https://img.shields.io/badge/Status-pre--1.0-orange.svg)](#status)
[![Reproducible builds](https://img.shields.io/badge/Reproducible-yes-brightgreen.svg)](docs/REPRODUCIBLE_BUILDS.md)

---

## Status

**Pre-1.0, but available.** The macOS app is built, notarized, and on sale (v0.22); the Rust core (`crates/`) is feature-rich and tested. It remains pre-1.0 — actively evolving toward a 1.0 backed by external audits.

| Component | Status |
|---|---|
| macOS app (windowed, in-app viewer) | **shipping** — v0.22, notarized, on sale |
| Vault format (Rust core, v6) | read/write/truncate, indistinguishable from random, POSIX-shaped FFI |
| Encryption at rest | AES-256-GCM-SIV + Argon2id (1 GiB) + BLAKE3 |
| Post-quantum integrity | one-shot ML-DSA-87 attestation in encrypted metadata (libcrux, formally verified) |
| FIDO2 hardware-key auth (YubiKey real device) | end-to-end validated; up to 3 keys per vault |
| Anti-rollback (out-of-band counter) | `--expect-counter` enforced |
| License tokens (offline, serial-bound) | ECDSA P-256, KMS-signed, no call home |
| Reproducible builds + CI | Rust core: Linux x86_64 + macOS arm64 |
| Linux app (in-app viewer, no mount) | Phase 2 (post-1.0 macOS) |
| Filesystem mount (FSKit, FUSE, kext, ...) | **explicit non-goal**, never — cf. CHARTER §5 |

## What it is

A **VeraCrypt-class encrypted container** with three guarantees that no current product combines:

1. **Post-quantum by design.** Content is sealed with AES-256-GCM-SIV + Argon2id (1 GiB) — symmetric, already beyond quantum reach — and each vault carries a one-shot **ML-DSA-87** (FIPS 204) integrity attestation, via [libcrux](https://github.com/cryspen/libcrux) (Cryspen / INRIA), formally verified through `hax` → F\*. An X25519 + ML-KEM-1024 hybrid is implemented and held in reserve for future device-to-device transfer (not used at rest).
2. **No call home.** The app contacts no server — no telemetry, no crash reporting, no license server, no update check (licenses verify offline). The only networking component (P2P LAN) is an unwired stub. *The macOS build currently uses the hardened runtime; making "no socket" OS-enforced via the App Sandbox (omitting the `com.apple.security.network.client` entitlement) is a planned hardening.* See [`THREAT_MODEL §5.8`](THREAT_MODEL.md).
3. **Reproducible builds.** Anyone can recompile from source and verify, byte-for-byte, that the binary they download matches. Documented in [`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md).

Plus standard but well-executed:

- **Single-domain vault, indistinguishable from random.** No magic, no plaintext header — without the passphrase the file is byte-for-byte uniform random. (A vault is single-domain; there are no hidden/decoy volumes — see [`ARCHITECTURE §6`](ARCHITECTURE.md).)
- **Strict multi-factor**: passphrase + one or more FIDO2 hardware keys (YubiKey hmac-secret tested on real hardware). The **coercion defense** is the mandatory key: at a border, not carrying it makes "I cannot open it" true and verifiable.
- **No auto-wipe**: a wipe is incompatible with unconditional indistinguishability and never stopped a copy-attacker. Offline-bruteforce defense is Argon2id × passphrase entropy + the hardware key.
- **Anti-rollback** via out-of-band manifest counter; the `--expect-counter` flag refuses to mount an older snapshot.
- **Per-major-version license keys**: ECDSA P-256 tokens (signed in Google Cloud KMS) bound to Mac hardware serial numbers, verified locally, free re-issue on lost / replaced Mac.

## Trust model

Farewell is **GPL-3.0-or-later**. Its trust does not rest on trusting Denis Florent Media Group SRL (the publisher) — it rests on:

- **The source is open.** Read it. Audit it. Compile it yourself.
- **The binary is reproducible.** What you download equals what the source produces, bit-for-bit.
- **No call home.** The app makes no network calls (no telemetry, license, or update traffic; the P2P transport is an unwired stub). OS-level enforcement via the App Sandbox is a planned hardening.
- **External audits** by recognized firms (Cure53 / NCC Group / Trail of Bits class) are scheduled before 1.0; reports will be public.
- **Multi-signature releases** are a Phase 3+ objective; until then, the trust chain is publisher + reproducible builds + audit + GPL fork-ability.

The publisher's jurisdiction (Romania) is documented in [`CHARTER §8.2`](CHARTER.md): an EU member with privacy-favouring constitutional jurisprudence, no mandatory key-disclosure law, and outside the Five/Nine/Fourteen Eyes alliances.

## Build from source

Minimum supported Rust is 1.85; the build uses the exact toolchain pinned in `rust-toolchain.toml`.

```bash
git clone https://github.com/farewellpro/farewell.git
cd farewell
cargo build --release --workspace
cargo test --workspace
```

For a reproducible build matching the binaries that will ship at 1.0:

```bash
./scripts/verify-reproducible.sh
```

See [`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md) for the full details (pinned toolchain, `SOURCE_DATE_EPOCH`, `--remap-path-prefix`).

## Try the CLI

The current CLI (`farewell`) is a development tool, not the end-user product (which is the macOS app with its in-app viewer — no filesystem mount, by deliberate design, cf. CHARTER §5). It exercises the core:

```bash
cargo run -p farewell-cli -- init my.vault --size 10
cargo run -p farewell-cli -- add my.vault notes.txt --from /tmp/secret.txt
cargo run -p farewell-cli -- list my.vault
cargo run -p farewell-cli -- read my.vault notes.txt --to -
cargo run -p farewell-cli -- info my.vault
```

License-related commands (the production ECDSA P-256 verifying key is embedded in the binary):

```bash
cargo run -p farewell-cli -- activate my-license.flw
cargo run -p farewell-cli -- license-status
```

## Founding documents

| Doc | Document | Purpose |
|---|---|---|
| Threat model | [THREAT_MODEL.md](THREAT_MODEL.md) | Personas, adversary, scope, invariants |
| Charter | [CHARTER.md](CHARTER.md) | Mission, governance, financing, licensing |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md) | Format, crypto stack, components |

## Security disclosure

See [`SECURITY.md`](SECURITY.md). Vulnerabilities reach us at `security@farewell.pro` (please mark reports `[SECURITY]`). We follow 90-day responsible disclosure.

## License

- **Code**: GPL-3.0-or-later. The full text is in [`LICENSE`](LICENSE).
- **Documentation**: CC BY-SA 4.0.
- **"Farewell" name and logo**: trademark of Denis Florent Media Group SRL. Forks may use the code under GPL but must choose a different name.

You can sell GPL software — see [FSF on selling free software](https://www.gnu.org/philosophy/selling.html). The publisher's commercial offering (signed binary + notarization + support + updates) starts at €49 one-time (Single, 1 Mac), with Duo (2 Macs, €69) and Quintet (5 Macs, €129); at-risk users (journalists, dissidents, whistleblowers) can receive free Grant licenses. See [`CHARTER §9`](CHARTER.md).

## Contributing

Project is currently pre-1.0 and not actively soliciting external code contributions — the threat model and architecture are still being refined. Bug reports, security findings, and threat-model critiques are welcome via the issue tracker (once the repo is public). A `CONTRIBUTING.md` with full process will land at 1.0.

---

*Farewell is published by [Denis Florent Media Group SRL](https://farewell.pro), a Romanian commercial entity. There is no foundation, no VC funding, no data collection. The publisher is funded by paid licenses and by you choosing the signed binary over recompiling yourself.*
