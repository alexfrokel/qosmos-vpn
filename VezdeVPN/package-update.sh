#!/bin/bash
set -euo pipefail
umask 077

app_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
output_dir="${1:-$app_dir/build/update}"
mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
work="$(mktemp -d /private/tmp/vezde-update.XXXXXXXX)"
trap 'rm -rf "$work"' EXIT

/bin/bash "$app_dir/../MacVPN/fetch-python.sh" "$work"
QOSMOS_PYTHON_DIR="$work/python" VEZDE_BUILD_DIR="$work/build" /bin/bash "$app_dir/build.sh"
app="$work/build/Vezde VPN.app"
version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app/Contents/Info.plist")
archive="Vezde-VPN-macOS-arm64.zip"
/usr/bin/ditto -c -k --keepParent "$app" "$work/$archive"

digest=$(/usr/bin/shasum -a 256 "$work/$archive" | /usr/bin/awk '{print $1}')
mkdir "$work/check"
cp "$work/$archive" "$work/check/update.zip"
cp "$app_dir/../MacVPN/update_installer.py" "$work/check/"
"$app/Contents/Resources/python/bin/python3" -I -B "$work/check/update_installer.py" \
    prepare "$app" "$version" "$digest"

/usr/bin/python3 -I - "$work/vezde-update.json" "$version" "$digest" <<'PY'
import json
from pathlib import Path
import sys

path, version, digest = sys.argv[1:]
manifest = {
    "version": version,
    "url": f"https://github.com/alexfrokel/qosmos-vpn/releases/download/vezde-v{version}/Vezde-VPN-macOS-arm64.zip",
    "sha256": digest,
}
Path(path).write_text(json.dumps(manifest, indent=2) + "\n")
PY
mv -f "$work/$archive" "$work/vezde-update.json" "$output_dir/"
printf '%s\n' "$output_dir/$archive" "$output_dir/vezde-update.json"
