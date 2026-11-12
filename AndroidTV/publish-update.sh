#!/bin/bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"

if [[ $# != 1 ]]; then
    printf 'Использование: ./publish-update.sh ПУТЬ_К_КЛЮЧУ_КАТАЛОГА\n' >&2
    exit 2
fi
key=$1
sdk="${ANDROID_HOME:-$PWD/.build/tools/android-sdk}"
export JAVA_HOME="${JAVA_HOME:-$PWD/.build/tools/jdk/Contents/Home}"
tools="$sdk/build-tools/35.0.0"
apk="$PWD/dist/Qosmos-TV-Personal.apk"
"$tools/apksigner" verify "$apk"
unzip -p "$apk" res/raw/catalog_key.txt | cmp -s - "$key"
metadata=$("$tools/aapt2" dump badging "$apk")
version=$(awk -F"'" '/^package:/ {print $6; exit}' <<< "$metadata")
code=$(awk -F"'" '/^package:/ {print $4; exit}' <<< "$metadata")
work=$(mktemp -d "${TMPDIR:-/tmp}/qosmos-tv-update.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
node catalog/encrypt-update.mjs "$apk" "$key" "$version" "$code" "$work"
gh release create "tv-v$version" "$work/update.json" "$work/Qosmos-TV.apk.enc" \
    --repo alexfrokel/qosmos-tv-catalog --latest --title "Qosmos TV $version" \
    --notes 'Encrypted update for the personal Qosmos TV build.'
