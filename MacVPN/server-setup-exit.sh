set -Eeuo pipefail
umask 077
fail() { printf 'QOSMOS_FAIL %s\n' "$1"; exit 1; }
trap 'fail server' ERR

dir=/opt/qosmos-xray
unit_name=qosmos-xray.service
if [[ "${single_ssh:-0}" = 1 ]]; then
    dir=/opt/qosmos-xray-ssh
    unit_name=qosmos-xray-ssh.service
fi
unit=/etc/systemd/system/$unit_name
if [[ "$action" = rollback ]]; then
    if [[ -f "$dir/owner" && "$(cat "$dir/owner")" = "$run_id" ]]; then
        systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
        rm -f -- "$unit"
        rm -rf -- "$dir"
        systemctl daemon-reload
    fi
    printf 'QOSMOS_OK\n'
    exit
fi

. /etc/os-release
case "${ID:-}" in
    debian) minimum=12 ;;
    ubuntu) minimum=22.04 ;;
    *) fail os ;;
esac
dpkg --compare-versions "${VERSION_ID:-0}" ge "$minimum" || fail os
[[ "$(ps -p 1 -o comm=)" = systemd ]] || fail os
[[ ! -e "$dir" && ! -L "$dir" && ! -e "$unit" && ! -L "$unit" ]] || fail existing
! systemctl cat "$unit_name" >/dev/null 2>&1 || fail existing
command -v ss >/dev/null || fail tools
[[ -z "$(ss -H -ltn "sport = :$vpn_port")" ]] || fail port
case "$(uname -m)" in
    x86_64) asset=Xray-linux-64.zip; hash=b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82 ;;
    aarch64) asset=Xray-linux-arm64-v8a.zip; hash=64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be ;;
    *) fail arch ;;
esac
if [[ "$action" = check ]]; then printf 'QOSMOS_OK\n'; exit; fi

if ! command -v curl >/dev/null || ! command -v unzip >/dev/null || [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get -qq -o Acquire::Retries=1 -o Acquire::http::Timeout=10 update >&2 &&
        apt-get -qq -o DPkg::Lock::Timeout=10 install -y curl unzip ca-certificates >&2 || fail apt
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
curl -fLsS --proto '=https' --connect-timeout 10 --max-time 80 \
    "https://github.com/XTLS/Xray-core/releases/download/v26.11.9/$asset" -o "$work/xray.zip" || fail download
printf '%s  %s\n' "$hash" "$work/xray.zip" | sha256sum -c - >&2 || fail digest
unzip -p "$work/xray.zip" xray > "$work/xray"
chmod 755 "$work/xray"
printf '%s\n' "$xray_config" > "$work/config.json"
"$work/xray" run -test -c "$work/config.json" >&2 || fail config

mkdir -m 0755 "$dir" || fail existing
printf '%s\n' "$run_id" > "$dir/owner"
install -m 0755 "$work/xray" "$dir/xray"
install -m 0600 "$work/config.json" "$dir/config.json"
cat > "$unit" <<UNIT
[Unit]
Description=Qosmos VPN (VLESS Reality)
After=network-online.target
Wants=network-online.target

[Service]
DynamicUser=yes
LoadCredential=config.json:$dir/config.json
ExecStart=$dir/xray run -c %d/config.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
systemctl daemon-reload
systemctl enable --now "$unit_name" >&2 || fail service
for _ in {1..15}; do
    if systemctl is-active --quiet "$unit_name" &&
        [[ -n "$(ss -H -ltnp "sport = :$vpn_port" | grep -F '"xray"')" ]]; then
        printf 'QOSMOS_OK\n'
        exit
    fi
    sleep .2
done
fail service
