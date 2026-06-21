#!/usr/bin/env bash
#
# make-icns.sh — build a macOS .icns from a single 1024x1024 PNG.
#
# Generates every size Apple expects (16…512 + @2x) into a temporary
# .iconset, then runs `iconutil` to produce the .icns. macOS only; uses
# the always-present `sips` and `iconutil`.
#
# Usage:
#   ./scripts/make-icns.sh <src-1024.png> <out.icns>

set -euo pipefail

src="${1:?usage: make-icns.sh <src.png> <out.icns>}"
out="${2:?usage: make-icns.sh <src.png> <out.icns>}"

if [[ ! -f "$src" ]]; then
    echo "make-icns: source not found: $src" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
set="$work/AppIcon.iconset"
mkdir -p "$set"

# name:size pairs for the iconset (Retina @2x are the doubled pixel sizes).
gen() { sips -z "$2" "$2" "$src" --out "$set/$1" >/dev/null; }
gen "icon_16x16.png"        16
gen "icon_16x16@2x.png"     32
gen "icon_32x32.png"        32
gen "icon_32x32@2x.png"     64
gen "icon_128x128.png"     128
gen "icon_128x128@2x.png"  256
gen "icon_256x256.png"     256
gen "icon_256x256@2x.png"  512
gen "icon_512x512.png"     512
gen "icon_512x512@2x.png" 1024

iconutil -c icns "$set" -o "$out"
echo "make-icns: wrote $out"
