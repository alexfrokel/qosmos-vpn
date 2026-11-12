#!/bin/bash
set -euo pipefail
umask 077
project="$(cd -- "$(dirname -- "$0")" && pwd)"
if [[ $# -ne 2 && ! ( $# -eq 3 && "${2:-}" == --profile ) ]]; then
    printf '%s\n' 'Использование: send-profile.sh АДРЕС_ТЕЛЕВИЗОРА /путь/к/профилю.txt' \
        '          или: send-profile.sh АДРЕС_ТЕЛЕВИЗОРА --profile "Имя профиля в Qosmos"' >&2
    exit 2
fi
adb="${ADB:-${ANDROID_HOME:-$project/.build/tools/android-sdk}/platform-tools/adb}"
device="$1"
file="$2"
if [[ $# -eq 3 ]]; then
    file=$(mktemp "${TMPDIR:-/tmp}/qosmos-tv-profile.XXXXXXXX")
    trap 'rm -f "$file"' EXIT
    /usr/bin/python3 -I -B - "$3" "$file" <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import quote, urlencode

path = Path.home() / "Library/Application Support/VLESS VPN/profiles.json"
try:
    profiles = [item["profile"] for item in json.loads(path.read_text())]
except (OSError, ValueError, KeyError):
    raise SystemExit("Не удалось прочитать профили Qosmos для Mac.") from None
matches = [profile for profile in profiles if profile["name"] == sys.argv[1]]
if len(matches) != 1:
    raise SystemExit("Укажите точное имя одного профиля Qosmos.")
profile = matches[0]
if (profile["security"] != "reality" or profile.get("sshUser") or profile.get("cloudflareHost")
        or profile.get("network") not in ("raw", "tcp")):
    raise SystemExit("Android TV поддерживает прямые профили VLESS + REALITY по TCP.")
host = profile["host"]
if ":" in host:
    host = f"[{host}]"
query = urlencode({
    "type": "tcp", "security": "reality", "encryption": profile["encryption"],
    "sni": profile["sni"], "pbk": profile["key"], "sid": profile["shortID"],
    "fp": profile["fingerprint"], "flow": profile["flow"], "spx": profile["spider"],
})
link = f'vless://{profile["user"]}@{host}:{profile["port"]}?{query}#{quote(profile["name"])}'
Path(sys.argv[2]).write_text(link + "\n")
PY
fi
size=$(wc -c < "$file")
if (( size < 1 || size > 262144 )); then
    echo "Файл должен содержать от 1 байта до 256 КБ." >&2
    exit 1
fi
"$adb" -s "$device" shell -T 'run-as com.alexfrokel.qosmos.tv sh -c '"'"'
    set -e
    umask 077
    mkdir -p files
    temp=$(mktemp files/import.XXXXXXXX)
    trap "rm -f -- \"$temp\"" EXIT
    cat > "$temp"
    mv -f "$temp" files/import-pending.txt
'"'"'' < "$file"
echo "Профиль отправлен. На телевизоре откройте Qosmos VPN → Импорт с Mac → Добавить."
