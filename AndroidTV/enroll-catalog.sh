#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")"

if [[ $# != 1 ]]; then
    printf 'Использование: bash enroll-catalog.sh АДРЕС_ТЕЛЕВИЗОРА\n' >&2
    exit 2
fi

serial=$1
sdk="${ANDROID_HOME:-$PWD/.build/tools/android-sdk}"
adb="${ADB:-$sdk/platform-tools/adb}"
repo=alexfrokel/qosmos-tv-configs
[[ "$(gh repo view "$repo" --json visibility --jq .visibility)" == PRIVATE ]]
"$adb" -s "$serial" get-state | grep -qx device
challenge=$(/usr/bin/openssl rand -hex 16)
"$adb" -s "$serial" shell am start -W --activity-single-top \
    -n com.alexfrokel.qosmos.tv/.MainActivity --es qosmos.catalog.enroll "$challenge" >/dev/null

record=
for attempt in {1..15}; do
    record=$("$adb" -s "$serial" logcat -d -s QosmosTVCatalog:I | awk -v key="$challenge" '$NF && $(NF-2) == key { print $(NF-1), $NF }')
    [[ -n "$record" ]] && break
    sleep 1
done
if [[ -z "$record" ]]; then
    printf 'Телевизор не вернул открытый ключ. Проверь, что установлена версия Qosmos TV 0.2.0 или новее.\n' >&2
    exit 1
fi

read -r id public_key <<< "$record"
path=$(/usr/bin/python3 - "$id" "$public_key" <<'PY'
import base64
import hashlib
import sys

id, key = sys.argv[1:]
der = base64.b64decode(key, validate=True)
digest = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip('=')
if id != digest or len(der) > 512:
    raise SystemExit('Открытый ключ телевизора не прошёл проверку.')
print(f'devices/{digest}.der')
PY
)

if ! gh api "repos/$repo/contents/$path" --silent 2>/dev/null; then
    gh api --method PUT "repos/$repo/contents/$path" \
        -f message='Authorize Qosmos TV device' -f content="$public_key" --silent
fi
printf 'Телевизор %s привязан. Ждём публикации каталога.\n' "${id:0:8}"
for attempt in {1..12}; do
    if /usr/bin/curl -fsS --connect-timeout 4 --max-time 6 \
        "https://raw.githubusercontent.com/alexfrokel/qosmos-tv-catalog/main/catalog.json?refresh=$(date +%s)" |
        /usr/bin/python3 -c 'import json,sys; sys.exit(sys.argv[1] not in json.load(sys.stdin)["devices"])' "$id"; then
        "$adb" -s "$serial" shell am start -W --activity-single-top \
            -n com.alexfrokel.qosmos.tv/.MainActivity --ez qosmos.catalog.refresh true >/dev/null
        printf 'Каталог открыт на телевизоре. Выбери профиль пультом.\n'
        exit 0
    fi
    sleep 5
done
printf 'GitHub ещё собирает каталог. Когда сборка завершится, нажми «Обновить каталог».\n'
