#!/usr/bin/env bash
#
# Build the Farewell CLI binary twice with identical, deterministic
# settings and verify that the two outputs are byte-for-byte identical.
#
# This is the reference reproducibility check. A maintainer running
# this script on their own machine, after pulling the source at a
# tagged commit, should obtain the same hash as the one published in
# the release advisory.
#
# Usage: scripts/verify-reproducible.sh
#
# Exit codes:
#   0  builds are bit-identical (reproducible)
#   1  builds differ (NOT reproducible) — investigation required
#   2  prerequisite missing (Rust, sha256sum, etc.)

set -euo pipefail

# Resolve the workspace root (parent of this script's directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$WORKSPACE"

err() { printf '[verify-reproducible] %s\n' "$*" >&2; }
info() { printf '[verify-reproducible] %s\n' "$*"; }

# --- Prerequisites ---------------------------------------------------------

command -v cargo >/dev/null  || { err "cargo not found"; exit 2; }
command -v rustc >/dev/null  || { err "rustc not found"; exit 2; }
if command -v sha256sum >/dev/null; then
    HASH=sha256sum
elif command -v shasum >/dev/null; then
    HASH="shasum -a 256"
else
    err "neither sha256sum nor shasum available"
    exit 2
fi

EXPECTED_RUSTC="$(awk -F'"' '/channel/ {print $2}' rust-toolchain.toml)"
ACTUAL_RUSTC="$(rustc --version | awk '{print $2}')"
if [ "$EXPECTED_RUSTC" != "$ACTUAL_RUSTC" ]; then
    err "rustc version mismatch: rust-toolchain.toml says $EXPECTED_RUSTC, installed $ACTUAL_RUSTC"
    err "rustup will normally auto-install the pinned version. Run \`cargo --version\` once to trigger it."
    exit 2
fi

# --- Deterministic environment --------------------------------------------

# SOURCE_DATE_EPOCH (Reproducible Builds standard) controls any embedded
# timestamps. We freeze it at a project-known constant so successive
# builds at different real wall-clock times still match.
export SOURCE_DATE_EPOCH=1735689600  # 2025-01-01 00:00 UTC, arbitrary stable

# Strip absolute paths from debuginfo:
# - source tree → "."
# - cargo home (~/.cargo/registry/...)  → "/cargo-home"
CARGO_HOME_REAL="${CARGO_HOME:-$HOME/.cargo}"
PATH_REMAP=(
    "--remap-path-prefix=${WORKSPACE}=."
    "--remap-path-prefix=${CARGO_HOME_REAL}=/cargo-home"
)

# Force single-threaded codegen to make ordering of work deterministic
# beyond what the release profile already does. We do this here, not in
# Cargo.toml, so that normal `cargo build` stays fast for devs.
export CARGO_BUILD_JOBS=1

# Determinism for rustc itself.
export RUSTFLAGS="${PATH_REMAP[*]}"
export CARGO_INCREMENTAL=0  # never use incremental; it's path-tagged
export RUST_BACKTRACE=0

# --- Build twice from scratch ---------------------------------------------

TARGET_A="$(mktemp -d -t farewell-repro-a-XXXXXX)"
TARGET_B="$(mktemp -d -t farewell-repro-b-XXXXXX)"
trap 'rm -rf "$TARGET_A" "$TARGET_B"' EXIT

info "Build #1 → $TARGET_A"
CARGO_TARGET_DIR="$TARGET_A" cargo build --release --bin farewell --quiet

info "Build #2 → $TARGET_B"
CARGO_TARGET_DIR="$TARGET_B" cargo build --release --bin farewell --quiet

BIN_A="$TARGET_A/release/farewell"
BIN_B="$TARGET_B/release/farewell"

HASH_A="$($HASH "$BIN_A" | awk '{print $1}')"
HASH_B="$($HASH "$BIN_B" | awk '{print $1}')"

info "Binary #1: $HASH_A"
info "Binary #2: $HASH_B"

if [ "$HASH_A" = "$HASH_B" ]; then
    # Publish the verified binary + its hash at the standard build location,
    # so callers/CI can archive the artifact that was actually verified. The
    # two builds are byte-identical, so either copy is canonical. (The temp
    # build dirs are removed by the EXIT trap; this copy survives.)
    mkdir -p "$WORKSPACE/target/release"
    cp "$BIN_A" "$WORKSPACE/target/release/farewell"
    printf '%s  farewell\n' "$HASH_A" > "$WORKSPACE/target/release/farewell.sha256"

    info ""
    info "REPRODUCIBLE ✓"
    info "Hash:         $HASH_A"
    info "Source date:  $SOURCE_DATE_EPOCH"
    info "Rustc:        $ACTUAL_RUSTC"
    info "Verified binary: target/release/farewell (+ farewell.sha256)"
    info ""
    info "Record this hash in the release advisory or compare it to the"
    info "value published by the publisher."
    exit 0
fi

err ""
err "NOT REPRODUCIBLE — binaries differ"
err "Hash #1: $HASH_A"
err "Hash #2: $HASH_B"
err ""
err "Run \`cmp -l \"$BIN_A\" \"$BIN_B\" | head\` to see byte differences."
err "Investigate environment leakage: paths, timestamps, /tmp residue,"
err "compiler bug, or non-determinism in a dependency."
exit 1
