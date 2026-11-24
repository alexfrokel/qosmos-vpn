#!/bin/bash
set -euo pipefail
app_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
export QOSMOS_APP_VARIANT=vezde
export QOSMOS_BUILD_DIR="${VEZDE_BUILD_DIR:-$app_dir/build}"
export QOSMOS_UPDATE_SOURCE="${VEZDE_UPDATE_SOURCE:-https://raw.githubusercontent.com/alexfrokel/qosmos-vpn/refs/heads/codex/vox-integration/VezdeVPN/updates/vezde-update.json}"
export QOSMOS_VOX_API_URL="${VEZDE_VOX_API_URL:-http://127.0.0.1:8765}"
exec /bin/bash "$app_dir/../MacVPN/build.sh"
