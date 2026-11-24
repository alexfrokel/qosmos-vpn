#!/bin/bash
set -euo pipefail

[ "$#" -eq 1 ] || { echo "Usage: $0 ENGINE_DIRECTORY" >&2; exit 2; }
mkdir -p "$1"
target="$(cd "$1" && pwd)"
if ! command -v go >/dev/null; then
    echo "Go 1.25 or newer is required to build the AmneziaWG engine." >&2
    exit 1
fi
revision=16724484cfa00d9b2c14d8280dc055564e2e12ba
archive_hash=c60f2d95ce84711c542db8c6921f24216d712e226916e24e8ce557464c6b3d27
source_url="https://codeload.github.com/amnezia-vpn/amnezia-box/tar.gz/$revision"
work=$(mktemp -d /private/tmp/vezde-amnezia-build.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
cd "$work"
/usr/bin/curl --proto '=https' -fLsS --retry 3 "$source_url" -o source.tar.gz
printf '%s  %s\n' "$archive_hash" source.tar.gz | /usr/bin/shasum -a 256 -c -
/usr/bin/tar -xzf source.tar.gz
cd "amnezia-box-$revision"
GOOS=darwin GOARCH=arm64 GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 MACOSX_DEPLOYMENT_TARGET=13.0 \
    go build -trimpath -mod=readonly -tags with_awg,with_gvisor -ldflags '-s -w' -o "$work/amnezia-box" ./cmd/sing-box
/usr/bin/install -m 0644 LICENSE "$target/amnezia-box-LICENSE"
printf '%s\n' "$source_url" > "$target/amnezia-box-SOURCE.txt"
/usr/bin/install -m 0755 "$work/amnezia-box" "$target/amnezia-box"
