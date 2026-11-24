#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 PATH_TO_OUTPUT.pkg [PATH_TO_UPDATE.zip]" >&2
    exit 2
fi
output_dir=$(dirname "$1")
mkdir -p "$output_dir"
output="$(cd "$output_dir" && pwd)/$(basename "$1")"
source_dir="$(cd "$(dirname "$0")" && pwd)"
work=$(mktemp -d /private/tmp/qosmos-installer.XXXXXXXX)
trap 'rm -rf "$work"' EXIT

/bin/bash "$source_dir/fetch-python.sh" "$work"

mkdir -p "$work/components" "$work/apps"
QOSMOS_PYTHON_DIR="$work/python" QOSMOS_BUILD_DIR="$work/build" "$source_dir/build.sh"
app="$work/build/Qosmos VPN.app"
info="$app/Contents/Info.plist"
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$info")
minimum=$(/usr/libexec/PlistBuddy -c 'Print LSMinimumSystemVersion' "$info")
[[ "$version" =~ ^[0-9]+(\.[0-9]+)*$ && "$minimum" =~ ^[0-9]+(\.[0-9]+)*$ ]]

# Keep Installer from relocating a copy that was previously opened from another folder.
mv "$app" "$work/apps/"
app="$work/apps/Qosmos VPN.app"
if [[ $# == 2 ]]; then
    /usr/bin/ditto -c -k --keepParent "$app" "$2"
    # Exercise the same archive validation that runs in an installed copy of Qosmos.
    mkdir "$work/check-update"
    cp "$2" "$work/check-update/update.zip"
    cp "$source_dir/update_installer.py" "$work/check-update/"
    digest=$(/usr/bin/shasum -a 256 "$2" | /usr/bin/awk '{print $1}')
    "$app/Contents/Resources/python/bin/python3" -I -B "$work/check-update/update_installer.py" \
        prepare "$app" "$version" "$digest"
fi
pkgbuild --analyze --root "$work/apps" "$work/app-properties.plist"
if ! /usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$work/app-properties.plist" 2>/dev/null; then
    /usr/libexec/PlistBuddy -c 'Add :0:BundleIsRelocatable bool false' "$work/app-properties.plist"
fi
pkgbuild --root "$work/apps" --component-plist "$work/app-properties.plist" \
    --install-location /Applications --identifier local.vlessvpn.mac.pkg \
    --version "$version" "$work/components/Qosmos App.pkg"
cp "$app/Contents/Resources/Qosmos Tunnel.pkg" "$work/components/"
cat > "$work/Distribution" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Qosmos VPN $version</title>
    <options customize="never" require-scripts="true" hostArchitectures="arm64"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <volume-check><allowed-os-versions><os-version min="$minimum"/></allowed-os-versions></volume-check>
    <choices-outline>
        <line choice="qosmos-app"/>
        <line choice="qosmos-tunnel"/>
    </choices-outline>
    <choice id="qosmos-app" visible="false"><pkg-ref id="local.vlessvpn.mac.pkg"/></choice>
    <choice id="qosmos-tunnel" visible="false"><pkg-ref id="local.vlessvpn.tunnel.pkg"/></choice>
    <pkg-ref id="local.vlessvpn.mac.pkg">Qosmos App.pkg</pkg-ref>
    <pkg-ref id="local.vlessvpn.tunnel.pkg">Qosmos Tunnel.pkg</pkg-ref>
</installer-gui-script>
EOF
productbuild --distribution "$work/Distribution" --package-path "$work/components" "$work/Qosmos VPN.pkg"
mv "$work/Qosmos VPN.pkg" "$output"
printf '%s\n' "$output"
