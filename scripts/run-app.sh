#!/usr/bin/env bash
#
# run-app.sh — build and launch the SwiftUI Farewell app on a demo vault.
#
# Creates a fresh vault, populates it with a handful of files of
# different types, builds the app, launches it. The window opens
# at the file-browser view (vault auto-unlocked via argv).
#
# Usage:
#   ./scripts/run-app.sh
#
# To re-run without recreating the vault, point the existing one:
#   ./swift/.build/release/FarewellApp /tmp/farewell-app-demo/demo.vault alpha

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

DEMO_DIR="/tmp/farewell-app-demo"
VAULT="$DEMO_DIR/demo.vault"
# A strong demo passphrase (passes the zxcvbn 4/4 policy; the old weak
# "alpha" is now rejected at creation — v0.5 has no auto-wipe, so the
# passphrase is the whole defense and must be strong).
PASSPHRASE="reburial-almost-carpenter-dizziness-renewably-gurgle"

if [[ ! -f "$VAULT" ]]; then
    echo "==> Provisioning a fresh demo vault at $VAULT"
    rm -rf "$DEMO_DIR"
    mkdir "$DEMO_DIR"
    printf "%s\n%s\n" "$PASSPHRASE" "$PASSPHRASE" \
        | cargo run --quiet -p farewell-cli -- \
            init "$VAULT" --size 1 \
                          --passphrase-stdin \
        > /dev/null

    # --- real fixtures so the viewers actually show something ---

    # notes.md, todo.txt — plain text/markdown
    printf "# Source meeting 2026-06-04\n\nMet with **K.** at the café.\n\n- confirmed the documents\n- next contact via Signal only\n" \
        > "$DEMO_DIR/notes.md"
    printf -- "- check passphrase rotation\n- review fingerprint\n- export nothing\n" \
        > "$DEMO_DIR/todo.txt"

    # demo.pdf — a real, minimal, valid one-page PDF (computed offsets).
    python3 - "$DEMO_DIR/demo.pdf" <<'PY'
import sys
objs = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 320 160] "
    b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
]
stream = b"BT /F1 22 Tf 30 90 Td (Farewell PDF demo) Tj ET"
objs.append(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream))
objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
out = b"%PDF-1.4\n"
offsets = []
for i, body in enumerate(objs, start=1):
    offsets.append(len(out))
    out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
xref = len(out)
out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
for off in offsets:
    out += b"%010d 00000 n \n" % off
out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
open(sys.argv[1], "wb").write(out)
PY

    # demo.png — a real 64x64 PNG gradient (pure stdlib zlib).
    python3 - "$DEMO_DIR/demo.png" <<'PY'
import sys, zlib, struct
W = H = 64
raw = bytearray()
for y in range(H):
    raw.append(0)  # filter byte: none
    for x in range(W):
        raw += bytes([(x * 4) & 255, (y * 4) & 255, 128])
def chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))
png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
png += chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
PY

    # tone.wav — a 3-second 440 Hz stereo tone (pure stdlib `wave`), so
    # the audio viewer has something to play.
    python3 - "$DEMO_DIR/tone.wav" <<'PY'
import sys, wave, struct, math
sr, secs, freq = 44100, 3, 440.0
frames = bytearray()
for i in range(sr * secs):
    v = int(0.3 * 32767 * math.sin(2 * math.pi * freq * i / sr))
    frames += struct.pack("<hh", v, v)  # stereo
w = wave.open(sys.argv[1], "wb")
w.setnchannels(2); w.setsampwidth(2); w.setframerate(sr)
w.writeframes(bytes(frames)); w.close()
PY

    for pair in \
        "notes.md:$DEMO_DIR/notes.md" \
        "todo.txt:$DEMO_DIR/todo.txt" \
        "report.pdf:$DEMO_DIR/demo.pdf" \
        "photo.png:$DEMO_DIR/demo.png" \
        "tone.wav:$DEMO_DIR/tone.wav"
    do
        name="${pair%%:*}"
        src="${pair#*:}"
        printf "%s\n" "$PASSPHRASE" \
            | cargo run --quiet -p farewell-cli -- \
                add "$VAULT" "$name" --from "$src" --passphrase-stdin \
            > /dev/null
    done
    echo "    populated with notes.md, todo.txt, report.pdf, photo.png, tone.wav"
fi

echo "==> Building Rust staticlib (release)"
cargo build -p farewell_mount --release

echo "==> Building Swift FarewellApp (release)"
( cd swift && swift build -c release --product FarewellApp )

# macOS will not reliably grant a GUI window to a bare executable run
# from the command line — it needs a proper .app bundle with an
# Info.plist. Pre-1.0 we synthesize a minimal bundle around the binary
# SwiftPM produced; the production app will be a real, signed bundle.
echo "==> Packaging a minimal .app bundle"
APP_BUNDLE="$DEMO_DIR/FarewellApp.app"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
cp ./swift/.build/release/FarewellApp "$APP_BUNDLE/Contents/MacOS/FarewellApp"

# Localizations: copy each <lang>.lproj into the bundle's Resources so
# SwiftUI's LocalizedStringKey lookups (Bundle.main) find translations.
if compgen -G "swift/Resources/Localizations/*.lproj" >/dev/null; then
    cp -R swift/Resources/Localizations/*.lproj "$APP_BUNDLE/Contents/Resources/"
fi

# App icon: use a finished AppIcon.icns if present, else build one from the
# 1024x1024 AppIcon.png. Absent either, the bundle just ships without an icon.
HAS_ICON=0
if [[ -f swift/Resources/AppIcon.icns ]]; then
    cp swift/Resources/AppIcon.icns "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
    HAS_ICON=1
elif [[ -f swift/Resources/AppIcon.png ]]; then
    ./scripts/make-icns.sh swift/Resources/AppIcon.png \
        "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
    HAS_ICON=1
fi

cat > "$APP_BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>               <string>Farewell</string>
    <key>CFBundleDisplayName</key>        <string>Farewell</string>
    <key>CFBundleDevelopmentRegion</key>  <string>en</string>
    <key>CFBundleLocalizations</key>
    <array>
        <string>en</string>
        <string>fr</string>
        <string>es</string>
        <string>ar</string>
        <string>ru</string>
        <string>fa</string>
        <string>zh-Hans</string>
        <string>zh-Hant</string>
    </array>
    <key>CFBundleIdentifier</key>         <string>app.farewell.dev</string>
    <key>CFBundleVersion</key>            <string>0.22</string>
    <key>CFBundleShortVersionString</key> <string>0.22</string>
    <key>CFBundleExecutable</key>         <string>FarewellApp</string>
    <key>CFBundleIconFile</key>           <string>AppIcon</string>
    <key>NSHumanReadableCopyright</key>   <string>© Denis Florent Media Group SRL</string>
    <key>CFBundlePackageType</key>        <string>APPL</string>
    <key>LSMinimumSystemVersion</key>     <string>15.0</string>
    <key>NSHighResolutionCapable</key>    <true/>
    <key>NSPrincipalClass</key>           <string>NSApplication</string>
</dict>
</plist>
PLIST

# Ad-hoc sign so macOS lets us launch the dev bundle.
codesign --force --sign - "$APP_BUNDLE" >/dev/null 2>&1 || true

# Launch the binary DIRECTLY from inside the bundle (not via `open`).
# Two things are true at once this way:
#   1. Because the executable lives inside a .app structure with an
#      Info.plist, macOS grants it regular-app GUI privileges and a
#      focusable window — the thing a bare `swift build` binary lacks.
#   2. Because we exec it directly (rather than through LaunchServices
#      `open`), argv and the environment pass through normally, so the
#      app's dev auto-unlock (reading argv) works.
#
# Set FAREWELL_NO_VAULT=1 to launch with NO argv — lands on the
# Open/Create screen instead of auto-opening the demo vault. Use this to
# test vault creation, including the "Also require a YubiKey" toggle.
echo "==> Launching Farewell"
if [[ "${FAREWELL_NO_VAULT:-0}" == "1" ]]; then
    echo "    (no auto-open — starting at the Open/Create screen)"
    exec "$APP_BUNDLE/Contents/MacOS/FarewellApp"
else
    echo "    (vault: $VAULT)"
    exec "$APP_BUNDLE/Contents/MacOS/FarewellApp" "$VAULT" "$PASSPHRASE"
fi
