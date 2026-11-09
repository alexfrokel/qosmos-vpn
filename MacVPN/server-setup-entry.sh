set -Eeuo pipefail
umask 077
fail() { printf 'QOSMOS_FAIL %s\n' "$1"; exit 1; }
trap 'fail server' ERR

dir=/var/lib/qosmos-relay
user=qosmos-relay
sock=/etc/systemd/system/qosmos-relay.socket
unit=/etc/systemd/system/qosmos-relay.service
if [[ "${single_ssh:-0}" = 1 ]]; then
    dir=/var/lib/qosmos-local
    user=qosmos-local
fi
if [[ "$action" = rollback ]]; then
    if [[ -f "$dir/owner" && "$(cat "$dir/owner")" = "$run_id" ]]; then
        if [[ "${single_ssh:-0}" != 1 ]]; then
            systemctl disable --now qosmos-relay.socket >/dev/null 2>&1 || true
            systemctl stop qosmos-relay.service >/dev/null 2>&1 || true
            rm -f -- "$sock" "$unit"
            systemctl daemon-reload
        fi
        if getent passwd "$user" >/dev/null; then userdel "$user"; fi
        if getent group "$user" >/dev/null; then groupdel "$user"; fi
        rm -rf -- "$dir"
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
[[ ! -e "$dir" && ! -L "$dir" ]] || fail existing
! getent passwd "$user" >/dev/null && ! getent group "$user" >/dev/null || fail existing
command -v useradd >/dev/null || fail tools
if [[ "${single_ssh:-0}" != 1 ]]; then
    for path in "$sock" "$unit"; do
        [[ ! -e "$path" && ! -L "$path" ]] || fail existing
        ! systemctl cat "${path##*/}" >/dev/null 2>&1 || fail existing
    done
    command -v ss >/dev/null || fail tools
    proxy=/usr/lib/systemd/systemd-socket-proxyd
    [[ -x "$proxy" ]] || proxy=/lib/systemd/systemd-socket-proxyd
    [[ -x "$proxy" ]] || fail tools
    [[ -z "$(ss -H -ltn "sport = :$relay_port")" ]] || fail relay_port
fi
if [[ "$action" = check ]]; then printf 'QOSMOS_OK\n'; exit; fi
if [[ "${single_ssh:-0}" = 1 ]]; then
    timeout 5 bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1"' _ "$vpn_port" || fail service
else
    timeout 7 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$exit_host" "$vpn_port" || fail path
fi

mkdir -m 0755 "$dir" || fail existing
printf '%s\n' "$run_id" > "$dir/owner"
useradd --system --user-group --no-create-home --home-dir "$dir" --shell /usr/sbin/nologin "$user"
install -d -m 0700 -o "$user" -g "$user" "$dir/.ssh"
printf 'restrict,port-forwarding,permitopen="127.0.0.1:%s",permitlisten="qosmos-disabled.invalid:1",command="/bin/false" %s\n' \
    "$relay_port" "$runtime_key" > "$dir/.ssh/authorized_keys"
chown "$user:$user" "$dir/.ssh/authorized_keys"
if [[ "${single_ssh:-0}" = 1 ]]; then printf 'QOSMOS_OK\n'; exit; fi
cat > "$sock" <<UNIT
[Unit]
Description=Qosmos VPN SSH relay socket

[Socket]
ListenStream=127.0.0.1:$relay_port

[Install]
WantedBy=sockets.target
UNIT
cat > "$unit" <<UNIT
[Unit]
Description=Qosmos VPN SSH relay
Requires=qosmos-relay.socket
After=qosmos-relay.socket

[Service]
DynamicUser=yes
ExecStart=$proxy $exit_host:$vpn_port
NoNewPrivileges=yes
UNIT
chmod 0644 "$sock" "$unit"
systemctl daemon-reload
systemctl enable --now qosmos-relay.socket >&2 && systemctl is-active --quiet qosmos-relay.socket || fail service
printf 'QOSMOS_OK\n'
