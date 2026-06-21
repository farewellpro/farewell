# App resources

## App icon

Drop the macOS app icon here as **`AppIcon.png`** — a single square
**1024×1024** PNG, already finished as it should appear (macOS does **not**
auto-round app icons, so include the rounded-square shape + transparent margin
yourself if you want the standard Dock look).

The build (`scripts/run-app.sh`) converts it to `AppIcon.icns` (all required
sizes, via `sips` + `iconutil`), copies it into the app bundle's
`Contents/Resources/`, and references it from `Info.plist`
(`CFBundleIconFile`).

If you already have a finished `.icns`, drop it as **`AppIcon.icns`** instead
and it is used as-is (no conversion).
