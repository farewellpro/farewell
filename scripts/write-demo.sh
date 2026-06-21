#!/usr/bin/env bash
#
# write-demo.sh — end-to-end demo of the v0.18 Phase B FFI surface.
#
# 1. Build the Rust staticlib (libfarewell_mount.a) in release mode.
# 2. Build the Swift FarewellWriteDemo executable.
# 3. Create a fresh demo vault via the Rust CLI (empty, no files).
# 4. Run FarewellWriteDemo: it creates a file, writes, truncates,
#    renames, deletes — all via the FFI, with read-back verification
#    at each step.
#
# Exits 0 if every step in the demo printed its success line.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DEMO_DIR="$(mktemp -d -t farewell-write-demo.XXXXXX)"
trap 'rm -rf "$DEMO_DIR"' EXIT

VAULT="$DEMO_DIR/demo.vault"
PASSPHRASE="alpha"

echo "==> [1/3] Building Rust staticlib (release)"
cargo build -p farewell_mount --release

echo "==> [2/3] Building Swift FarewellWriteDemo (release)"
( cd swift && swift build -c release )

echo "==> [3/3] Provisioning empty vault and running the demo"
printf "%s\n%s\n" "$PASSPHRASE" "$PASSPHRASE" \
    | cargo run --quiet -p farewell-cli -- \
        init "$VAULT" --size 1 --levels 1 --wipe-threshold 10 --passphrase-stdin \
        > /dev/null

./swift/.build/release/FarewellWriteDemo "$VAULT" "$PASSPHRASE"

echo
echo "write-demo.sh: OK"
