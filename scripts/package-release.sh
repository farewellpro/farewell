#!/usr/bin/env bash
#
# package-release.sh — build, Developer ID-sign, notarize, and package Farewell
# into a distributable, notarized .dmg. Produces dist/Farewell-<version>.dmg.
#
# This is the PRODUCTION counterpart to run-app.sh (which makes a throwaway,
# ad-hoc-signed dev bundle). Full pipeline:
#   build → bundle → sign (hardened runtime) → notarize app → staple →
#   build dmg → notarize dmg → staple dmg → verify.
#
# Prereqs:
#   - Xcode, and a "Developer ID Application" identity in the keychain.
#   - A stored notarytool credential profile (default "farewell-notary"),
#     created once with:
#       xcrun notarytool store-credentials farewell-notary \
#         --apple-id <you@example.com> --team-id <TEAMID> --password <app-pw>
#
# Usage:
#   scripts/package-release.sh                 # full pipeline, profile farewell-notary
#   scripts/package-release.sh --no-notarize   # build + sign only (no Apple round-trip)
#   NOTARY_PROFILE=other scripts/package-release.sh

set -euo pipefail
cd "$(dirname "$0")/.."

APP_NAME="Farewell"
BUNDLE_ID="app.farewell"
VERSION="0.22"
MIN_MACOS="15.0"
DIST="dist"
APP="$DIST/$APP_NAME.app"
DMG="$DIST/${APP_NAME}-${VERSION}.dmg"
NOTARY_PROFILE="${NOTARY_PROFILE:-farewell-notary}"

NOTARIZE=1
[[ "${1:-}" == "--no-notarize" ]] && NOTARIZE=0

# Auto-detect the Developer ID Application signing identity (the full
# "Developer ID Application: NAME (TEAMID)" string codesign wants).
IDENTITY=$(security find-identity -v -p codesigning \
    | grep "Developer ID Application" | head -1 \
    | sed -E 's/^[[:space:]]*[0-9]+\)[[:space:]]+[0-9A-Fa-f]+[[:space:]]+"(.*)"$/\1/')
if [[ -z "${IDENTITY:-}" ]]; then
    echo "ERROR: no 'Developer ID Application' identity found in the keychain." >&2
    echo "Create one in Xcode → Settings → Accounts → Manage Certificates → +." >&2
    exit 1
fi
echo "==> Signing identity: $IDENTITY"

echo "==> Building Rust staticlib (release)"
cargo build -p farewell_mount --release

echo "==> Building Swift app (release)"
( cd swift && swift build -c release --product FarewellApp )

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp swift/.build/release/FarewellApp "$APP/Contents/MacOS/$APP_NAME"

# Localizations: copy each <lang>.lproj into Resources so SwiftUI's
# LocalizedStringKey lookups (Bundle.main) find translations.
if compgen -G "swift/Resources/Localizations/*.lproj" >/dev/null; then
    cp -R swift/Resources/Localizations/*.lproj "$APP/Contents/Resources/"
fi

# App icon: prefer a finished .icns, else synthesize from the 1024px PNG.
if [[ -f swift/Resources/AppIcon.icns ]]; then
    cp swift/Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
elif [[ -f swift/Resources/AppIcon.png ]]; then
    ./scripts/make-icns.sh swift/Resources/AppIcon.png "$APP/Contents/Resources/AppIcon.icns"
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>               <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>        <string>${APP_NAME}</string>
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
    <key>CFBundleIdentifier</key>         <string>${BUNDLE_ID}</string>
    <key>CFBundleVersion</key>            <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key> <string>${VERSION}</string>
    <key>CFBundleExecutable</key>         <string>${APP_NAME}</string>
    <key>CFBundleIconFile</key>           <string>AppIcon</string>
    <key>NSHumanReadableCopyright</key>   <string>© Denis Florent Media Group SRL</string>
    <key>CFBundlePackageType</key>        <string>APPL</string>
    <key>LSMinimumSystemVersion</key>     <string>${MIN_MACOS}</string>
    <key>NSHighResolutionCapable</key>    <true/>
    <key>NSPrincipalClass</key>           <string>NSApplication</string>
</dict>
</plist>
PLIST

# Sign with the hardened runtime (--options runtime) and a secure Apple
# timestamp (--timestamp) — both required for notarization. The bundle has no
# nested frameworks or helpers, so signing the bundle covers its one executable.
echo "==> Signing (Developer ID + hardened runtime)"
codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP"
codesign --verify --strict --verbose=2 "$APP"

if [[ "$NOTARIZE" -eq 0 ]]; then
    echo ""
    echo "DONE (signed, NOT notarized) → $APP"
    exit 0
fi

# ---- Notarize the app ----
echo "==> Notarizing the app (uploading to Apple; usually 1–5 min)…"
ditto -c -k --keepParent "$APP" "$DIST/$APP_NAME.zip"
xcrun notarytool submit "$DIST/$APP_NAME.zip" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP"
rm -f "$DIST/$APP_NAME.zip"

# ---- Build the DMG (with the Farewell volume icon), notarize, staple ----
echo "==> Building the disk image (with the Farewell volume icon)"
STAGING="$DIST/dmg-staging"
RWDMG="$DIST/.${APP_NAME}-rw.dmg"
rm -rf "$STAGING" "$RWDMG" "$DMG"
mkdir -p "$STAGING"
cp -R "$APP" "$STAGING/$APP_NAME.app"
ln -s /Applications "$STAGING/Applications"
# A custom volume icon (the app icon) shows on BOTH the .dmg file and the
# mounted volume. It needs the read-write image flagged with kHasCustomIcon
# (SetFile -a C), so build UDRW first, flag it, then compress to UDZO.
if [[ -f "$APP/Contents/Resources/AppIcon.icns" ]]; then
    cp "$APP/Contents/Resources/AppIcon.icns" "$STAGING/.VolumeIcon.icns"
fi
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGING" -fs HFS+ -format UDRW -ov "$RWDMG" >/dev/null
ATTACH=$(hdiutil attach "$RWDMG" -readwrite -noverify -nobrowse)
DEV=$(echo "$ATTACH" | grep -Eo '^/dev/disk[0-9]+' | head -1)
MNT=$(echo "$ATTACH" | grep -Eo '/Volumes/.*$' | head -1)
[[ -f "$STAGING/.VolumeIcon.icns" && -x /usr/bin/SetFile ]] && /usr/bin/SetFile -a C "$MNT" || true
sync
hdiutil detach "$DEV" >/dev/null
hdiutil convert "$RWDMG" -format UDZO -o "$DMG" -ov >/dev/null
rm -rf "$STAGING" "$RWDMG"

echo "==> Notarizing the disk image…"
xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG"
xcrun stapler validate "$DMG"

echo ""
echo "DONE → $DMG  (notarized + stapled, ready to distribute)"
