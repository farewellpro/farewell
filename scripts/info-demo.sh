#!/usr/bin/env bash
#
# info-demo.sh — end-to-end demo of the v0.18 Phase C FFI surface
# (readdir + info accessors).
#
# 1. Build the Rust staticlib (libfarewell_mount.a) in release mode.
# 2. Build the Swift FarewellInfoDemo executable.
# 3. Create a fresh demo vault via the Rust CLI and populate it with
#    two files of different sizes.
# 4. Run FarewellInfoDemo: prints total chunks, counter, fingerprint,
#    and a per-file listing — all retrieved through the FFI.
#
# Exits 0 if every step prints its success line.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DEMO_DIR="$(mktemp -d -t farewell-info-demo.XXXXXX)"
trap 'rm -rf "$DEMO_DIR"' EXIT

VAULT="$DEMO_DIR/demo.vault"
PASSPHRASE="alpha"

echo "==> [1/3] Building Rust staticlib (release)"
cargo build -p farewell_mount --release

echo "==> [2/3] Building Swift FarewellInfoDemo (release)"
( cd swift && swift build -c release )

echo "==> [3/3] Provisioning vault with two files, then running info demo"
printf "%s\n%s\n" "$PASSPHRASE" "$PASSPHRASE" \
    | cargo run --quiet -p farewell-cli -- \
        init "$VAULT" --size 1 --levels 1 --wipe-threshold 10 --passphrase-stdin \
        > /dev/null

# Populate.
echo -n "short payload" > "$DEMO_DIR/a.txt"
printf "%s\n" "$PASSPHRASE" \
    | cargo run --quiet -p farewell-cli -- \
        add "$VAULT" "a.txt" --from "$DEMO_DIR/a.txt" --passphrase-stdin \
        > /dev/null

dd if=/dev/urandom of="$DEMO_DIR/blob.bin" bs=1024 count=4 2>/dev/null
printf "%s\n" "$PASSPHRASE" \
    | cargo run --quiet -p farewell-cli -- \
        add "$VAULT" "blob.bin" --from "$DEMO_DIR/blob.bin" --passphrase-stdin \
        > /dev/null

./swift/.build/release/FarewellInfoDemo "$VAULT" "$PASSPHRASE"

echo
echo "info-demo.sh: OK"
