#!/bin/bash
set -euo pipefail
[ "$#" -eq 1 ] || { echo "Usage: $0 ENGINE_DIRECTORY" >&2; exit 2; }
mkdir -p "$1"
target="$(cd "$1" && pwd)"
work=$(mktemp -d "${TMPDIR:-/tmp}/qosmos-engines.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
cd "$work"

download() {
    local url="$1" filename="$2" checksum="$3"
    /usr/bin/curl -fLsS --retry 3 --proto '=https' "$url" -o "$filename"
    printf '%s  %s\n' "$checksum" "$filename" | /usr/bin/shasum -a 256 -c -
}

download https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-macos-arm64-v8a.zip \
    xray.zip 233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26
download https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-darwin-arm64.tar.gz \
    sing-box.tar.gz 0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838
/usr/bin/unzip -q xray.zip -d xray-files
mkdir sing-box-files
/usr/bin/tar -xzf sing-box.tar.gz -C sing-box-files --strip-components 1
install -m 0755 xray-files/xray "$target/xray-test"
install -m 0755 sing-box-files/sing-box "$target/sing-box"
install -m 0644 xray-files/LICENSE "$target/xray-LICENSE"
install -m 0644 sing-box-files/LICENSE "$target/sing-box-LICENSE"
