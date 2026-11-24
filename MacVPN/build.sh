#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
source_dir="$PWD"
engines="${QOSMOS_ENGINE_DIR:-$source_dir/../.vless-local}"
build="${QOSMOS_BUILD_DIR:-$source_dir/build}"
module_cache="$build/module-cache"
swift_target=arm64-apple-macos13.0
variant="${QOSMOS_APP_VARIANT:-qosmos}"
case "$variant" in
    qosmos) app_name="Qosmos VPN"; executable="VLESSVPN" ;;
    vezde) app_name="Vezde VPN"; executable="VezdeVPN" ;;
    *) printf 'Unknown application variant: %s\n' "$variant" >&2; exit 1 ;;
esac
app="$build/$app_name.app"
resources="$app/Contents/Resources"
iconset="$build/AppIcon.iconset"
mkdir -p "$app/Contents/MacOS" "$resources/en.lproj" "$module_cache" "$iconset"

install -m 0644 "$source_dir/backend.py" "$resources/backend.py"
for file in server_setup.py server-setup-entry.sh server-setup-exit.sh update_installer.py; do
    install -m 0644 "$source_dir/$file" "$resources/$file"
done
install -m 0644 "$source_dir/Info.plist" "$app/Contents/Info.plist"
if [[ "$variant" = vezde ]]; then
    plist="$app/Contents/Info.plist"
    plutil -replace CFBundleDisplayName -string "$app_name" "$plist"
    plutil -replace CFBundleName -string "$app_name" "$plist"
    plutil -replace CFBundleExecutable -string "$executable" "$plist"
    plutil -replace CFBundleIdentifier -string local.vezdevpn.mac "$plist"
    read -r app_version build_number < "$source_dir/../VezdeVPN/version"
    [[ "$app_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$build_number" =~ ^[1-9][0-9]*$ ]]
    plutil -replace CFBundleShortVersionString -string "$app_version" "$plist"
    plutil -replace CFBundleVersion -string "$build_number" "$plist"
    if [[ -n "${QOSMOS_UPDATE_SOURCE:-}" ]]; then
        plutil -replace QosmosUpdateSource -string "$QOSMOS_UPDATE_SOURCE" "$plist"
    else
        plutil -remove QosmosUpdateSource "$plist"
    fi
elif [[ -n "${QOSMOS_UPDATE_SOURCE:-}" ]]; then
    plutil -replace QosmosUpdateSource -string "$QOSMOS_UPDATE_SOURCE" "$app/Contents/Info.plist"
fi
if [[ -n "${QOSMOS_VOX_API_URL:-}" ]]; then
    plutil -insert QosmosVoxAPIURL -string "$QOSMOS_VOX_API_URL" "$app/Contents/Info.plist"
fi
if [[ -n "${QOSMOS_DIRECT_SITES:-}" ]]; then
    plutil -insert QosmosDirectSites -string "$QOSMOS_DIRECT_SITES" "$app/Contents/Info.plist"
fi
install -m 0644 "$source_dir/en.lproj/Localizable.strings" "$resources/en.lproj/Localizable.strings"
install -m 0644 "$source_dir/tun-template.json" "$resources/mac-vpn.json"
install -m 0644 "$source_dir/ru-direct-domains.LICENSE" "$resources/ru-direct-domains.LICENSE"
install -m 0755 "$engines/xray-test" "$resources/xray"
install -m 0755 "$engines/sing-box" "$resources/sing-box"
for license in xray-LICENSE sing-box-LICENSE; do
    if [[ -f "$engines/$license" ]]; then
        install -m 0644 "$engines/$license" "$resources/$license"
    fi
done
xcrun swift -module-cache-path "$module_cache" "$source_dir/Icon.swift" "$build/app-icon.png" "$variant"
for size in 16 32 128 256 512; do
    double=$((size * 2))
    base=$(printf 'icon_%sx%s' "$size" "$size")
    sips -z "$size" "$size" "$build/app-icon.png" --out "$iconset/$base.png" >/dev/null
    sips -z "$double" "$double" "$build/app-icon.png" --out "$iconset/$base@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$resources/AppIcon.icns"
package_root=$(mktemp -d "$build/tunnel-package.XXXXXXXX")
trap 'rm -rf "$package_root"' EXIT
service_dir="$package_root/Library/Application Support/QosmosVPN"
mkdir -p "$service_dir" "$package_root/Library/LaunchDaemons"
install -m 0644 "$source_dir/local.vlessvpn.tunnel.plist" "$package_root/Library/LaunchDaemons/"
install -m 0644 "$source_dir/tun-template.json" "$service_dir/tun-template.json"
install -m 0644 "$source_dir/ru-direct-domains.json" "$service_dir/ru-direct-domains.json"
install -m 0755 "$engines/sing-box" "$service_dir/sing-box"
xcrun swiftc -target "$swift_target" -O -module-cache-path "$module_cache" \
    "$source_dir/TunnelService.swift" "$source_dir/KillSwitch.swift" "$source_dir/SplitTunnel.swift" \
    -o "$service_dir/tunnel-service"
codesign --force --sign - "$service_dir/tunnel-service" "$service_dir/sing-box"
COPYFILE_DISABLE=1 pkgbuild --root "$package_root" --scripts "$source_dir/tunnel-installer" \
    --install-location / --ownership recommended --identifier local.vlessvpn.tunnel.pkg --version 12 \
    "$resources/Qosmos Tunnel.pkg"
xcrun swiftc -target "$swift_target" -parse-as-library -O -module-cache-path "$module_cache" \
    "$source_dir/VlessVPN.swift" "$source_dir/AppSettings.swift" "$source_dir/ServerSetup.swift" \
    "$source_dir/VoxSubscription.swift" "$source_dir/VezdeDashboard.swift" "$source_dir/VezdeAccountView.swift" \
    -o "$app/Contents/MacOS/$executable"
codesign --force --sign - "$app/Contents/Resources/xray" "$app/Contents/Resources/sing-box"
if [[ -n "${QOSMOS_PYTHON_DIR:-}" ]]; then
    test -x "$QOSMOS_PYTHON_DIR/bin/python3"
    ditto --norsrc "$QOSMOS_PYTHON_DIR" "$resources/python"
    # Older Qosmos updaters only accept regular files and directories in the ZIP.
    # Materialize Python's file aliases before signing the bundle.
    /usr/bin/python3 - "$resources/python" <<'PY'
from pathlib import Path
import shutil
import sys

runtime = Path(sys.argv[1]).resolve()
for path in runtime.rglob("*"):
    if path.is_symlink():
        target = path.resolve(strict=True)
        if not target.is_file() or runtime not in target.parents:
            raise SystemExit(f"Unexpected Python runtime link: {path.relative_to(runtime)}")
        path.unlink()
        shutil.copy2(target, path)
PY
    find "$resources/python" -type f \( -name '*.so' -o -name '*.dylib' -o -name 'python3.*' \
        -o -name python3 -o -name python \) -print0 |
        while IFS= read -r -d '' executable; do
            if file -b "$executable" | /usr/bin/grep -q '^Mach-O'; then
                codesign --force --sign - "$executable"
            fi
        done
fi
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"
printf '%s\n' "$app"
