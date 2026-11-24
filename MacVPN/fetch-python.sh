#!/bin/bash
set -euo pipefail

destination="$1"
mkdir -p "$destination"
archive="$(mktemp "$destination/python-runtime.XXXXXXXX")"
trap 'rm -f "$archive"' EXIT

python_url='https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.13.18%2B20261026-aarch64-apple-darwin-install_only_stripped.tar.gz'
python_hash=8392b6ea51d94391befb2c31ebe75463f045d0b69dfcf5e1bb3234e1f5fa3405
/usr/bin/curl -fLsS --retry 3 --proto '=https' "$python_url" -o "$archive"
printf '%s  %s\n' "$python_hash" "$archive" | /usr/bin/shasum -a 256 -c -
/usr/bin/tar -xzf "$archive" -C "$destination"
