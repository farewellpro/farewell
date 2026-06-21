#!/usr/bin/env bash
#
# read-demo.sh — end-to-end demo of the v0.18 FFI surface.
#
# 1. Build the Rust staticlib (libfarewell_mount.a) in release mode.
# 2. Build the Swift FarewellReadDemo executable.
# 3. Create a fresh demo vault via the Rust CLI.
# 4. Add a known file into it.
# 5. Open the vault from Swift, stat + read the file, print it.
#
# Exits 0 if the bytes read by Swift match what the CLI wrote.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DEMO_DIR="$(mktemp -d -t farewell-read-demo.XXXXXX)"
trap 'rm -rf "$DEMO_DIR"' EXIT

VAULT="$DEMO_DIR/demo.vault"
PAYLOAD="$DEMO_DIR/payload.txt"
PASSPHRASE="alpha"
NAME="hello.txt"
CONTENT="hello from the Swift side, via the v0.18 FFI."

echo "==> [1/4] Building Rust staticlib (release)"
cargo build -p farewell_mount --release

echo "==> [2/4] Building Swift FarewellReadDemo (release)"
( cd swift && swift build -c release )

echo "==> [3/4] Creating a fresh demo vault via the Rust CLI"
printf "%s\n%s\n" "$PASSPHRASE" "$PASSPHRASE" \
    | cargo run --quiet -p farewell-cli -- \
        init "$VAULT" --size 1 --levels 1 --wipe-threshold 10 --passphrase-stdin \
        > /dev/null

printf "%s" "$CONTENT" > "$PAYLOAD"
printf "%s\n" "$PASSPHRASE" \
    | cargo run --quiet -p farewell-cli -- \
        add "$VAULT" "$NAME" --from "$PAYLOAD" --passphrase-stdin \
        > /dev/null

echo "==> [4/4] Reading it back from Swift via the FFI"
output="$(./swift/.build/release/FarewellReadDemo "$VAULT" "$PASSPHRASE" "$NAME")"
echo "$output"

# Verify the Swift side printed exactly what the CLI wrote.
if ! echo "$output" | grep -Fq "content     : $CONTENT"; then
    echo
    echo "ERROR: Swift output did not contain the expected content line." >&2
    echo "       Expected: 'content     : $CONTENT'" >&2
    exit 1
fi

echo
echo "read-demo.sh: OK"
