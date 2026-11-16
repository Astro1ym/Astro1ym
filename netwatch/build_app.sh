#!/bin/bash
# Assemble Netwatch.app from the sources in this folder.
# Re-run after editing netwatch.py so the app picks up the change.
set -e
cd "$(dirname "$0")"
APP="Netwatch.app/Contents"
rm -rf Netwatch.app
mkdir -p "$APP/MacOS" "$APP/Resources"
cp netwatch.py requirements.txt app_src/run.command "$APP/Resources/"

cat > "$APP/MacOS/Netwatch" <<'SH'
#!/bin/bash
# The dashboard is a terminal UI, so the app just opens it in Terminal.
open -a Terminal "$(cd "$(dirname "$0")/../Resources" && pwd)/run.command"
SH

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
    <key>LSMinimumSystemVersion</key><string>10.13</string>
</dict>
</plist>
PLIST

chmod +x "$APP/MacOS/Netwatch" "$APP/Resources/run.command"
echo "built Netwatch.app"
