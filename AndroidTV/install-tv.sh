#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"

if [[ $# != 1 ]]; then
    printf 'Использование: bash install-tv.sh IP:ПОРТ\n' >&2
    exit 2
fi

sdk="${ANDROID_HOME:-$PWD/.build/tools/android-sdk}"
adb="${ADB:-$sdk/platform-tools/adb}"
serial=$1
"$adb" connect "$serial"
"$adb" -s "$serial" get-state | grep -qx device
"$adb" -s "$serial" install -r dist/Qosmos-TV.apk
ADB="$adb" /bin/bash enroll-catalog.sh "$serial"
