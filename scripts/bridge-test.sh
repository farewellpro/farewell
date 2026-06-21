#!/usr/bin/env bash
#
# bridge-test.sh — build both halves of the Rust ↔ Swift bridge and
# run the smoke executable. Exits 0 on success, non-zero on any
# build/link/runtime failure.
#
# Usage:
#   ./scripts/bridge-test.sh           # release build (default)
#   ./scripts/bridge-test.sh debug     # debug build
#
# Pre-requisites on the dev machine:
#   - Rust 1.85+ (per rust-toolchain.toml)
#   - Xcode 15+ with Swift 5.9+ (we develop on Xcode 26 / Swift 6.x)
#   - macOS only (the smoke target builds for the host arch).

set -euo pipefail

PROFILE="${1:-release}"

case "$PROFILE" in
    release|debug) ;;
    *)
        echo "ERROR: unknown profile '$PROFILE' (expected: release|debug)" >&2
        exit 2
        ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "==> [1/3] Building Rust staticlib (libfarewell_mount.a) [$PROFILE]"
if [[ "$PROFILE" == "release" ]]; then
    cargo build -p farewell_mount --release
else
    cargo build -p farewell_mount
fi

if [[ ! -f "target/$PROFILE/libfarewell_mount.a" ]]; then
    echo "ERROR: expected target/$PROFILE/libfarewell_mount.a not found" >&2
    exit 1
fi

echo "==> [2/3] Building Swift smoke executable"
cd swift
if [[ "$PROFILE" == "release" ]]; then
    swift build -c release
    exe="./.build/release/FarewellHelloBridge"
else
    swift build
    exe="./.build/debug/FarewellHelloBridge"
fi

echo "==> [3/3] Running smoke test"
"$exe"
echo
echo "bridge-test.sh: OK"
