#!/bin/bash
# Assemble Netwatch.app from the sources in this folder.
# Re-run after editing netwatch.py so the app picks up the change.
set -e
cd "$(dirname "$0")"
APP="Netwatch.app/Contents"
rm -rf Netwatch.app
mkdir -p "$APP/MacOS" "$APP/Resources"
cp netwatch.py dashboard.html requirements.txt "$APP/Resources/"
cp app_src/launcher.sh "$APP/MacOS/Netwatch"

cat > "$APP/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Netwatch</string>
    <key>CFBundleDisplayName</key><string>Netwatch</string>
    <key>CFBundleIdentifier</key><string>local.netwatch.launcher</string>
    <key>CFBundleExecutable</key><string>Netwatch</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>10.13</string>
</dict>
</plist>
PLIST

chmod +x "$APP/MacOS/Netwatch"
echo "built Netwatch.app"
