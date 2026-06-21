# Reproducible builds — verification guide

This document explains how to independently verify that the `farewell`
binary you downloaded matches the official one published by the
publisher (Denis Florent Media Group SRL). This is the load-bearing trust step described in
[CHARTER §7.2](../CHARTER.md) and [THREAT_MODEL §5.7](../THREAT_MODEL.md).

## Why reproducibility matters

Without reproducible builds, the only thing protecting you from a
malicious binary is "trust the publisher". With reproducible builds,
anyone can verify that the binary on the download page is *exactly*
what the published source produces. A maintainer turned hostile, a
compromised build server, or a state actor splicing in a backdoor —
all become detectable.

This is the same property that protects Bitcoin Core, Tor Browser,
Tails, and the Linux kernel. We aim for the same standard.

## How verification works

You take three inputs:

1. The source code at a specific git commit.
2. The pinned Rust toolchain version (in `rust-toolchain.toml`).
3. A deterministic build environment (paths, timestamps, flags).

You produce one output: a SHA-256 hash of the resulting binary.

If your hash equals the one published in the release advisory, you
have cryptographic proof that the binary was produced by the source.

## Prerequisites

- A POSIX shell (bash, zsh, dash).
- `cargo` and `rustc` reachable on `$PATH`. The pinned toolchain is
  installed automatically by `rustup` on first use of `cargo`.
- `sha256sum` (Linux) or `shasum` (macOS). The script detects either.

## Running the check

From the source root:

```sh
./scripts/verify-reproducible.sh
```

This will:

1. Sync the pinned toolchain via `rustup`.
2. Set a fixed `SOURCE_DATE_EPOCH` (2025-01-01 UTC).
3. Set `RUSTFLAGS` with `--remap-path-prefix` to strip absolute paths.
4. Build the `farewell` CLI binary **twice** in two separate
   `target/` directories.
5. Compare the SHA-256 of both binaries.
6. Exit `0` if they match; exit `1` if they differ.

Expected output on success:

```
[verify-reproducible] Build #1 → /tmp/farewell-repro-a-xxxxxx
[verify-reproducible] Build #2 → /tmp/farewell-repro-b-xxxxxx
[verify-reproducible] Binary #1: <hash>
[verify-reproducible] Binary #2: <hash>
[verify-reproducible]
[verify-reproducible] REPRODUCIBLE ✓
[verify-reproducible] Hash:         <hash>
```

## Comparing to an official release

For a tagged release:

```sh
git checkout v1.0.0
./scripts/verify-reproducible.sh
```

The printed hash should match the one in the release advisory at
`https://farewell.pro/releases/v1.0.0` and the corresponding
detached signature should also verify.

## What's covered (and what's not)

### Covered

- The `farewell` CLI binary produced by `cargo build --release --bin farewell`.
- Same host architecture: a Linux x86_64 build is reproducible from
  any Linux x86_64 machine; a macOS arm64 build from any Apple Silicon
  Mac.
- Same rustc version (pinned via `rust-toolchain.toml`).

### Not yet covered

- **Cross-architecture reproducibility.** A Linux x86_64 build and a
  macOS arm64 build produce different binaries (different machine
  code). Each target is reproducible *within* its arch but not across.
- **Independent rebuild from sources, no rustup.** The toolchain
  itself is downloaded as pre-built binaries from `static.rust-lang.org`.
  Achieving end-to-end source reproducibility down to the compiler
  ("trusting trust") requires a bootstrapped rustc, out of scope for
  this version.
- **Cargo dependencies.** `Cargo.lock` pins each dependency to a
  specific version and source-hash, but the `cargo` registry itself
  is a trust root.

These gaps are documented openly per CHARTER §6.2 ("Honesty before
marketing").

## What to do if verification fails

If `verify-reproducible.sh` exits 1 with two different hashes:

1. **Don't panic.** Most failures are environment leakage, not a
   compromised binary.
2. Check for stray modifications in `Cargo.lock`, `Cargo.toml`, or
   workspace files (`git status`, `git diff`).
3. Make sure `SOURCE_DATE_EPOCH` is honored by your rustc (run
   `rustc --version`; minimum supported version is in
   `rust-toolchain.toml`).
4. Run `cmp -l target_a/release/farewell target_b/release/farewell | head`
   to see byte-level differences. If they cluster in a known region
   (debug info, BuildID), that's a bug in this script and we want to
   hear about it.
5. If the binaries differ in a way that looks like a real
   non-deterministic codegen issue, file a bug at
   [issues](https://github.com/farewellpro/farewell/issues).

## CI mirror

The same script runs on every push to `main` and on every release
tag, in two configurations:

- Linux x86_64 (Ubuntu 24.04 runner)
- macOS arm64 (macOS 15 runner)

The CI logs and the resulting hashes are public. A divergence between
your local hash and the CI hash on the same commit is a strong signal
that one of the build environments is compromised. Investigate; do
not ignore.
