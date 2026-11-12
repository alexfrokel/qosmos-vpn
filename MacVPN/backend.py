#!/usr/bin/env python3
import fcntl
import ipaddress
import json
import os
import re
import shlex
import select
import shutil
import stat
import struct
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

RESOURCES = Path(__file__).resolve().parent
XRAY = RESOURCES / "xray"
SING_BOX = RESOURCES / "sing-box"
CHECK_URL = "https://api.ipify.org/"
FALLBACK_CHECK_URL = "https://1.1.1.1/cdn-cgi/trace"
HEALTH_CHECK_INTERVAL = 20
HEALTH_CHECK_FAILURE_LIMIT = 3
wake_requested = False
TUN_IPV4 = "198.18.10.1"
SERVICE = Path("/Library/Application Support/QosmosVPN")
SERVICE_SOCKET = SERVICE / "tunnel.sock"
SERVICE_READY = SERVICE / "tunnel-dns-v3"
SPLIT_SERVICE_READY = SERVICE / "tunnel-split-v5"
RU_SPLIT_SERVICE_READY = SERVICE / "tunnel-split-ru-v10"
CLOUDFLARE_SERVICE_READY = SERVICE / "tunnel-cloudflare-v7"
VPN_SITES_SERVICE_READY = SERVICE / "tunnel-vpn-sites-v8"
EXTENDED_SPLIT_SERVICE_READY = SERVICE / "tunnel-split-v9"
MAX_SPLIT_SITES = 20
PREVIOUS_SERVICE_READY = SERVICE / "kill-switch-v2"
AUTHORIZE = """on run argv
    return do shell script (item 1 of argv) with administrator privileges
end run
"""
STOP_TERMINAL = """actual=$(/bin/ps -ww -p "$1" -o lstart= -o uid= -o command=) || exit 1
[ "$actual" = "$2" ] || exit 1
/bin/kill -TERM "$1"
"""


class ProfileError(ValueError):
    pass


class HTTPSProbeError(ProfileError):
    pass


def parse_link(link, fallback):
    try:
        url = urlsplit(link)
        fields = parse_qs(url.query, keep_blank_values=True)
        if url.scheme != "vless" or any(len(values) != 1 for values in fields.values()):
            raise ProfileError("Нужна корректная ссылка vless://.")
        query = {key: values[0] for key, values in fields.items()}
        profile = {
            "name": unquote(url.fragment).strip() or fallback or url.hostname,
            "host": url.hostname,
            "port": url.port or 443,
            "user": unquote(url.username or ""),
            "flow": query.get("flow", ""),
            "encryption": query.get("encryption", "none"),
            "network": query.get("type", "tcp"),
            "security": query.get("security", ""),
            "sni": query.get("sni", ""),
            "fingerprint": query.get("fp", "chrome"),
            "key": query.get("pbk", ""),
            "shortID": query.get("sid", ""),
            "spider": query.get("spx", ""),
        }
        if "cfHost" in query:
            profile["cloudflareHost"] = query["cfHost"]
        if "sshUser" in query:
            profile["sshUser"] = query["sshUser"]
        if "sshPort" in query:
            profile["sshPort"] = int(query["sshPort"])
    except ValueError as error:
        if isinstance(error, ProfileError):
            raise
        raise ProfileError("Не удалось разобрать ссылку VLESS.") from error
    return validate(profile)


def validate(profile):
    local_ssh = profile.get("security") == "ssh" and profile.get("sshUser") == "qosmos-local"
    if (profile.get("security") != "reality" and not local_ssh) or profile.get("network") not in ("tcp", "raw"):
        raise ProfileError("Поддерживаются профили VLESS Reality с транспортом TCP (RAW).")
    if profile.get("flow") not in ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
        raise ProfileError("Этот режим VLESS flow пока не поддерживается.")
    if profile.get("encryption") != "none":
        raise ProfileError("Этот профиль использует дополнительное шифрование VLESS.")
    host = profile.get("host")
    if not isinstance(host, str) or not host or not re.fullmatch(r"[A-Za-z0-9_.:-]+", host):
        raise ProfileError("Укажите IPv4, IPv6 или имя сервера.")
    if type(profile.get("port")) is not int or not 1 <= profile["port"] <= 65535:
        raise ProfileError("Порт сервера должен быть от 1 до 65535.")
    cloudflare_host = profile.get("cloudflareHost")
    if cloudflare_host is not None and (
        not isinstance(cloudflare_host, str) or len(cloudflare_host) > 253
        or not re.fullmatch(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", cloudflare_host)
    ):
        raise ProfileError("Укажите полное доменное имя входа Cloudflare.")
    ssh_user = profile.get("sshUser")
    ssh_port = profile.get("sshPort")
    identity = profile.get("sshIdentity")
    if ssh_port is not None and (ssh_user is None or type(ssh_port) is not int or not 1 <= ssh_port <= 65535):
        raise ProfileError("Некорректный порт SSH.")
    if identity is not None and (ssh_user is None or not isinstance(identity, str)
                                 or not re.fullmatch(r"[a-f0-9]{32}", identity)):
        raise ProfileError("Некорректный идентификатор ключа SSH.")
    if ssh_user is not None:
        try:
            ssh_endpoint = ipaddress.IPv4Address(host)
        except ValueError as error:
            raise ProfileError("Для входа через SSH нужен публичный IPv4.") from error
        if (not ssh_endpoint.is_global or ssh_endpoint.is_multicast or cloudflare_host is not None
                or not isinstance(ssh_user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", ssh_user)
                or (not local_ssh and not profile.get("sni"))):
            raise ProfileError("Для входа через SSH укажите пользователя и имя SNI Reality.")
    if local_ssh and (not identity or profile.get("flow")):
        raise ProfileError("Для этого профиля требуется ключ SSH, созданный мастером Qosmos.")
    try:
        uuid.UUID(profile.get("user", ""))
    except (ValueError, TypeError, AttributeError) as error:
        raise ProfileError("В профиле отсутствует действительный UUID.") from error
    if not local_ssh and not re.fullmatch(r"[A-Za-z0-9_-]{43}", profile.get("key", "")):
        raise ProfileError("В профиле отсутствует корректный открытый ключ Reality.")
    short_id = profile.get("shortID", "")
    if not re.fullmatch(r"(?:[a-fA-F0-9]{2}){0,8}", short_id):
        raise ProfileError("Некорректный Short ID Reality.")
    sni = profile.get("sni", "")
    if sni and not re.fullmatch(r"[A-Za-z0-9_.:-]+", sni):
        raise ProfileError("Некорректное имя SNI.")
    profile["name"] = str(profile.get("name") or host).strip()[:90] or host
    return profile


def from_xray_json(source, fallback):
    try:
        document = json.loads(source)
        outbounds = document["outbounds"] if "outbounds" in document else [document]
        profiles = []
        for outbound in outbounds:
            if outbound.get("protocol") != "vless":
                continue
            settings = outbound["settings"]
            stream = outbound["streamSettings"]
            reality = stream.get("realitySettings", {})
            servers = settings.get("vnext") or [{
                "address": settings["address"], "port": settings["port"], "users": [settings],
            }]
            for server in servers:
                for user in server["users"]:
                    profiles.append(validate({
                        "name": outbound.get("tag") or fallback,
                        "host": server["address"], "port": server["port"],
                        "user": user["id"], "flow": user.get("flow", ""),
                        "encryption": user.get("encryption", "none"),
                        "network": stream.get("network", "tcp"), "security": stream.get("security", ""),
                        "sni": reality.get("serverName", ""), "fingerprint": reality.get("fingerprint", "chrome"),
                        "key": reality.get("password") or reality.get("publicKey", ""),
                        "shortID": reality.get("shortId", ""), "spider": reality.get("spiderX", ""),
                    }))
    except (ValueError, TypeError, AttributeError, KeyError) as error:
        if isinstance(error, ProfileError):
            raise
        raise ProfileError("Не удалось прочитать клиентский JSON Xray.") from error
    if not profiles:
        raise ProfileError("В файле нет клиентских профилей VLESS Reality.")
    return profiles


def parse_profiles(source, fallback):
    source = source.lstrip("\ufeff").strip()
    if source.startswith("{"):
        return from_xray_json(source, fallback)
    links = [line.strip() for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not links:
        raise ProfileError("В файле нет профилей.")
    return [parse_link(link, fallback) for link in links]


def configs(profile, endpoint, port):
    stream_settings = {"network": "raw", "security": "none"}
    if profile["security"] == "reality":
        stream_settings.update(security="reality", realitySettings={
            "serverName": profile["sni"] or profile["host"],
            "fingerprint": profile["fingerprint"], "password": profile["key"],
            "shortId": profile["shortID"], "spiderX": profile["spider"],
        })
    xray = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"udp": True},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": str(endpoint), "port": profile["port"],
                "users": [{
                    "id": profile["user"], "flow": profile["flow"], "encryption": profile["encryption"],
                }],
            }]},
            "streamSettings": stream_settings,
        }],
    }
    tun = json.loads((RESOURCES / "mac-vpn.json").read_text())
    tun["outbounds"][0]["server_port"] = port
    inbound = tun["inbounds"][0]
    excluded = ipaddress.ip_network(endpoint)
    routes = []
    for route_prefix in inbound["route_address"]:
        network = ipaddress.ip_network(route_prefix)
        if network.version == excluded.version and excluded.subnet_of(network):
            routes.extend(str(prefix) for prefix in network.address_exclude(excluded))
        else:
            routes.append(route_prefix)
    # Keep these prefixes separate to outrank any existing /1 VPN routes.
    inbound["route_address"] = routes
    return xray, tun


def say(kind, message, **details):
    print(json.dumps({"kind": kind, "message": message, **details}, ensure_ascii=False), flush=True)


def port_ready(port, proxy, attempts=40):
    for _ in range(attempts):
        if proxy.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return
        except OSError:
            time.sleep(0.05)
    raise ProfileError("Xray не смог открыть локальный прокси.")


def probe(proxy_port=None):
    proxy_args = ["--noproxy", "*"] if proxy_port is None else [
        "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{proxy_port}",
    ]
    for url in (CHECK_URL, FALLBACK_CHECK_URL):
        result = subprocess.run(
            ["/usr/bin/curl", "-q", "-4fsS", *proxy_args, "--connect-timeout", "4", "--max-time", "7", url],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            continue
        address = result.stdout.strip()
        if url == FALLBACK_CHECK_URL:
            address = next((line[3:] for line in address.splitlines() if line.startswith("ip=")), "")
        try:
            return ipaddress.IPv4Address(address)
        except ValueError:
            continue
    return None


def tunnel_exists():
    interfaces = subprocess.check_output(["/sbin/ifconfig"], text=True)
    return re.search(r"(?m)^\s*inet " + re.escape(TUN_IPV4) + r"\s", interfaces) is not None


def stop_proxy(proxy):
    if proxy.poll() is None:
        proxy.terminate()
        try:
            proxy.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.wait()


def local_ports(count):
    with ExitStack() as reserved:
        listeners = [reserved.enter_context(socket.socket()) for _ in range(count)]
        for listener in listeners:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in listeners]


def cloudflare_bridge(xray, hostname, endpoint, interface, bridge_port, http_port, password):
    vless = xray["outbounds"][0]["settings"]["vnext"][0]
    vless.update(address="127.0.0.1", port=bridge_port)
    xray["inbounds"].append({
        "listen": "127.0.0.1", "port": http_port, "protocol": "http", "tag": "cloudflare-connect",
        "settings": {"accounts": [{"user": "qosmos", "pass": password}]},
    })
    xray["outbounds"].append({
        "protocol": "freedom", "tag": "cloudflare-edge",
        "settings": {"redirect": f"{endpoint}:443"},
        "streamSettings": {"sockopt": {"interface": interface}},
    })
    xray["routing"] = {"rules": [{
        "type": "field", "inboundTag": ["cloudflare-connect"], "outboundTag": "cloudflare-edge",
    }]}
    proxy = f"http://qosmos:{password}@127.0.0.1:{http_port}"
    environment = {**os.environ, "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "NO_PROXY": ""}
    for name in ("https_proxy", "http_proxy", "no_proxy"):
        environment.pop(name, None)
    executable = next((path for path in (
        RESOURCES / "cloudflared", Path("/opt/homebrew/bin/cloudflared"), Path("/usr/local/bin/cloudflared"),
    ) if path.is_file() and os.access(path, os.X_OK)), None)
    if executable is None:
        raise ProfileError("Для этого профиля установите cloudflared на Mac: brew install cloudflared.")
    return [executable, "access", "tcp", "--hostname", hostname, "--url", f"127.0.0.1:{bridge_port}"], environment


def run_admin(arguments, failure, include_error=False):
    result = subprocess.run(
        ["/usr/bin/osascript", "-e", AUTHORIZE, shlex.join(arguments)], capture_output=True, text=True,
    )
    if result.returncode != 0:
        if "-128" in result.stderr:
            raise InterruptedError
        if include_error:
            error = result.stderr.replace("\r", "\n").strip()
            error = re.sub(r"^\d+:\d+: execution error: ", "", error)
            error = re.sub(r"\s+\(\d+\)$", "", error)
            if error and error != "The command exited with a non-zero status.":
                failure = f"{failure} {error[:350]}"
        raise ProfileError(failure)
    return result.stdout


def prepare_service(allow_install, split=False, direct_ru=False, cloudflare=False, vpn_sites=False, extended_split=False):
    required = RU_SPLIT_SERVICE_READY if direct_ru else (SPLIT_SERVICE_READY if split else SERVICE_READY)
    if cloudflare:
        required = CLOUDFLARE_SERVICE_READY
    if vpn_sites:
        required = VPN_SITES_SERVICE_READY
    if extended_split:
        required = EXTENDED_SPLIT_SERVICE_READY
    if direct_ru:
        required = RU_SPLIT_SERVICE_READY
    if not required.is_file():
        if not allow_install:
            raise ProfileError("Для автоподключения один раз подключитесь вручную и установите службу Qosmos VPN.")
        say("progress", "macOS запросит пароль для установки или обновления службы Qosmos VPN.")
        with tempfile.TemporaryDirectory(prefix="qosmos-install-", dir="/private/tmp") as temporary:
            package = Path(temporary) / "Qosmos Tunnel.pkg"
            shutil.copyfile(RESOURCES / package.name, package)
            run_admin(
                ["/usr/sbin/installer", "-pkg", str(package), "-target", "/"],
                "Не удалось установить системную службу Qosmos VPN.",
                include_error=True,
            )
    try:
        info = SERVICE_SOCKET.lstat()
        if info.st_uid != 0 or not stat.S_ISSOCK(info.st_mode):
            raise OSError
    except OSError as error:
        raise ProfileError("Системная служба Qosmos VPN недоступна. Проверьте «Объекты входа и расширения» в macOS.") from error


def service_request(payload, accepted, timeout=10):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect(str(SERVICE_SOCKET))
        connection.sendall(payload)
        response = connection.recv(1)
        if response not in accepted:
            raise OSError("Invalid response from tunnel service")
        return connection, response
    except BaseException:
        connection.close()
        raise


def protection_blocked():
    if not (SERVICE_READY.is_file() or PREVIOUS_SERVICE_READY.is_file()):
        return False
    connection, response = service_request(b"\x01", (b"\x01", b"\x02"), timeout=2)
    connection.close()
    return response == b"\x02"


def release_protection():
    connection, _ = service_request(b"\x02", (b"\x01",))
    connection.close()


def start_tunnel(endpoint, port, server_port, protect, direct_sites, direct_ru, cloudflare=False, vpn_sites=()):
    try:
        opcode = 5 if direct_ru else (4 if direct_sites else 3)
        if cloudflare:
            opcode = 6
        if vpn_sites:
            opcode = 7
        request = struct.pack("!BB16sHHB", opcode, endpoint.version, endpoint.packed, port, server_port, protect)
        if opcode in (4, 5, 6):
            if cloudflare:
                request += bytes([direct_ru])
            payload = json.dumps(direct_sites).encode("ascii")
            request += struct.pack("!H", len(payload)) + payload
        if opcode == 7:
            payload = json.dumps(vpn_sites).encode("ascii")
            request += struct.pack("!BH", cloudflare, len(payload)) + payload
        timeout = 35 if max(len(direct_sites), len(vpn_sites)) > 8 else 10
        connection, response = service_request(request, (b"\x01", b"\x03", b"\x04"), timeout=timeout)
        if response != b"\x01":
            connection.close()
            if response == b"\x03":
                raise ProfileError("Не удалось направить DNS macOS в туннель VPN.")
            raise ProfileError("Не удалось настроить сайты напрямую. Проверьте адреса и подключение по Wi-Fi или Ethernet.")
        connection.settimeout(None)
        return connection
    except OSError as error:
        message = ("Не удалось запустить туннель с Kill Switch."
                   if protect else "Системная служба Qosmos VPN не смогла запустить туннель.")
        raise ProfileError(message) from error


def terminal_session():
    if not tunnel_exists():
        return None
    process_table = subprocess.check_output(
        ["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,command="], text=True,
    )
    processes = {}
    for row in process_table.splitlines():
        parts = row.split(maxsplit=3)
        if len(parts) == 4 and all(part.isdecimal() for part in parts[:3]):
            pid, parent, uid = map(int, parts[:3])
            processes[pid] = parent, uid, parts[3]

    for pid, (parent, uid, command) in processes.items():
        match = re.fullmatch(r"(.+/\.vless-local)/sing-box run -c (/.*/check-vless-[\w-]+/tun\.json)", command)
        if uid != 0 or not match:
            continue
        directory, config = map(Path, match.groups())
        try:
            if config.stat().st_uid != os.getuid():
                continue
        except OSError:
            continue
        for _ in range(3):
            ancestor = processes.get(parent)
            if ancestor is None:
                break
            parent, owner, invocation = ancestor
            if owner == os.getuid() and invocation.endswith(f" {directory / 'check-vless.py'} --vpn"):
                return pid, command
            if owner != 0 or invocation != f"/usr/bin/sudo {command}":
                break
    return None


def stop_terminal():
    session = terminal_session()
    if session is None:
        if tunnel_exists():
            raise ProfileError("Запущенный туннель не принадлежит нашему скрипту.")
        say("disconnected", "VPN уже отключён.")
        return
    pid, command = session
    snapshot = subprocess.check_output(
        ["/bin/ps", "-ww", "-p", str(pid), "-o", "lstart=", "-o", "uid=", "-o", "command="], text=True,
    ).rstrip("\n")
    if not snapshot.endswith(" 0 " + command):
        raise ProfileError("Сеанс VPN изменился. Повторите отключение.")
    try:
        run_admin(
            ["/bin/sh", "-c", STOP_TERMINAL, "stop", str(pid), snapshot],
            "Не удалось остановить VPN. Возможно, сеанс уже завершился.",
        )
    except InterruptedError as error:
        raise ProfileError("Отключение отменено.") from error
    for _ in range(40):
        if not tunnel_exists():
            say("disconnected", "VPN отключён.")
            return
        time.sleep(0.15)
    raise ProfileError("Системный интерфейс VPN ещё не закрылся. Повторите проверку.")


def parse_site_hosts(value, invalid):
    hosts = {}
    if len(value) > 8192:
        raise ProfileError(invalid)
    for item in re.split(r"[,\n]", value):
        item = item.strip()
        if not item:
            continue
        try:
            url = urlsplit(item if "://" in item else "https://" + item)
            if url.scheme not in ("http", "https") or url.username is not None or url.port not in (None, 80, 443):
                raise ValueError
            host = (url.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        except (ValueError, UnicodeError) as error:
            raise ProfileError(invalid) from error
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2 or labels[-1].isdigit()
                or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise ProfileError(invalid)
        hosts[host] = None
        if len(hosts) > MAX_SPLIT_SITES:
            raise ProfileError(invalid)
    return list(hosts)


def resolve_direct_sites(hosts, proxy_port=None):
    if urlsplit(CHECK_URL).hostname in hosts:
        raise ProfileError("Домен api.ipify.org нужен для проверки VPN и не может идти напрямую.")
    sites = []
    for host in hosts:
        try:
            if proxy_port is None:
                records = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
                answers = [record[4][0] for record in records]
            else:
                response = subprocess.check_output([
                    "/usr/bin/curl", "-q", "-fsS", "--max-time", "5", "--noproxy", "",
                    "--proxy", f"socks5h://127.0.0.1:{proxy_port}", "-H", "accept: application/dns-json",
                    f"https://cloudflare-dns.com/dns-query?name={host}&type=A",
                ])
                answers = [answer["data"] for answer in json.loads(response).get("Answer", []) if answer["type"] == 1]
            addresses = {ipaddress.IPv4Address(answer) for answer in answers}
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            addresses = set()
        addresses = sorted(str(address) for address in addresses if address.is_global and not address.is_multicast)[:8]
        if not addresses:
            raise ProfileError("Не удалось получить публичный IPv4 для сайта из списка «Сайты напрямую».")
        sites.append({"host": host, "addresses": addresses})
    return sites


def connect(profile, allow_install, protect, direct_sites, direct_ru=False, previous_entry_ip=None, vpn_sites=None):
    only_hosts = ()
    if vpn_sites is not None:
        only_hosts = parse_site_hosts(vpn_sites, "Укажите до 20 доменов для VPN через запятую.")
        if not only_hosts:
            raise ProfileError("Добавьте хотя бы один сайт в список «Выбранные сайты через VPN».")
        direct_sites = ""
        direct_ru = False
    direct_hosts = parse_site_hosts(direct_sites, "Укажите до 20 доменов сайтов напрямую, через запятую.")
    storage = Path.home() / "Library/Application Support/VLESS VPN"
    storage.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (storage / "connection.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ProfileError("VLESS VPN уже запускает или поддерживает подключение.") from error
        try:
            if tunnel_exists():
                raise ProfileError("Этот системный туннель уже запущен. Отключите его в приложении перед новым подключением.")
            prepare_service(allow_install, split=bool(direct_hosts), direct_ru=direct_ru,
                            cloudflare=bool(profile.get("cloudflareHost")), vpn_sites=bool(only_hosts),
                            extended_split=max(len(direct_hosts), len(only_hosts)) > 8)
            blocked = protection_blocked()
            endpoint = None
            if blocked and previous_entry_ip is not None:
                try:
                    endpoint = ipaddress.ip_address(previous_entry_ip)
                except ValueError:
                    pass
            site_cache = storage / "direct-sites-cache.json"
            sites = [] if only_hosts else None
            deferred_sites = []
            if blocked and sites is None:
                try:
                    cached = json.loads(site_cache.read_text())
                    if cached.get("input") == direct_sites:
                        sites = cached["sites"]
                except (OSError, ValueError, KeyError, AttributeError):
                    pass
            if sites is None:
                if blocked:
                    # The firewall only permits the VPS before the TUN is ready.
                    sites, deferred_sites = [], direct_hosts
                else:
                    sites = resolve_direct_sites(direct_hosts)
                    try:
                        site_cache.write_text(json.dumps({"input": direct_sites, "sites": sites}))
                    except OSError:
                        pass
            app_pid = os.getppid()
            has_connected = False
            retried_startup = False
            retry_delay = 0
            while os.getppid() == app_pid:
                try:
                    endpoint = run_connection(profile, protect, sites, direct_ru, app_pid, endpoint,
                                              only_hosts, deferred_sites)
                except (ProfileError, OSError, subprocess.SubprocessError) as error:
                    if not has_connected:
                        if retried_startup or not isinstance(error, HTTPSProbeError):
                            raise
                        retried_startup = True
                        retry_delay = 2
                        say("progress", "Повторяем проверку HTTPS через VPN…")
                    else:
                        retry_delay = min(max(retry_delay * 2, 5), 30)
                        say("reconnecting", "Восстанавливаем соединение с VPN…")
                else:
                    has_connected = True
                    retry_delay = 0
                time.sleep(retry_delay)
        except StopRequested:
            if SERVICE_READY.is_file() or PREVIOUS_SERVICE_READY.is_file():
                try:
                    # The service handles this after tearing down the tunnel socket.
                    release_protection()
                except OSError as error:
                    raise ProfileError(
                        "Не удалось снять Kill Switch. Нажмите «Вернуть доступ» в Qosmos."
                    ) from error
            raise


def start_xray(profile, endpoint, stack, cloudflare_interface=None):
    if profile["security"] == "ssh" and not endpoint.is_loopback:
        raise ProfileError("Локальный VPN для профиля SSH должен быть доступен только через SSH.")
    cloudflare_host = profile.get("cloudflareHost")
    ports = local_ports(3 if cloudflare_host else 1)
    port = ports[0]
    xray, _ = configs(profile, endpoint, port)
    temp = stack.enter_context(tempfile.TemporaryDirectory(prefix="qosmos-vpn-", dir="/private/tmp"))
    bridge = None
    if cloudflare_host:
        bridge_port, http_port = ports[1:]
        command, environment = cloudflare_bridge(
            xray, cloudflare_host, endpoint, cloudflare_interface, bridge_port, http_port, uuid.uuid4().hex,
        )
    xray_path = Path(temp) / "xray.json"
    xray_path.write_text(json.dumps(xray))
    proxy = subprocess.Popen(
        [XRAY, "run", "-c", xray_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    stack.callback(stop_proxy, proxy)
    port_ready(port, proxy)
    if cloudflare_host:
        port_ready(http_port, proxy)
        bridge = subprocess.Popen(command, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stack.callback(stop_proxy, bridge)
        port_ready(bridge_port, bridge)
    return port, proxy, bridge


def start_ssh(profile, stack):
    endpoint = ipaddress.IPv4Address(profile["host"])
    identity = profile.get("sshIdentity")
    key = (Path.home() / ".ssh" / "qosmos" / identity / "id_ed25519"
           if identity else Path.home() / ".ssh" / f"qosmos-{endpoint}-ed25519")
    if not key.is_file():
        raise ProfileError("Для этого профиля сначала установите ключ SSH для Qosmos.")
    bridge_port = local_ports(1)[0]
    trust = (["-o", f"UserKnownHostsFile=~/.ssh/qosmos/{identity}/known_hosts",
              "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no"]
             if identity else [])
    bridge = subprocess.Popen([
        "/usr/bin/ssh", "-F", "/dev/null", "-NT", "-p", str(profile.get("sshPort") or 22),
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=6", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
        *trust, "-i", str(key), "-L", f"127.0.0.1:{bridge_port}:127.0.0.1:{profile['port']}",
        f"{profile['sshUser']}@{endpoint}",
    ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stack.callback(stop_proxy, bridge)
    try:
        port_ready(bridge_port, bridge, attempts=140)
    except ProfileError as error:
        raise ProfileError("Не удалось открыть вход через SSH. Проверьте доступ к VPS и ключ SSH.") from error
    local_profile = dict(profile, port=bridge_port)
    port, proxy, _ = start_xray(local_profile, ipaddress.IPv4Address("127.0.0.1"), stack)
    upstream_ip = probe(port)
    if upstream_ip is None:
        if profile["security"] == "ssh":
            raise ProfileError("SSH подключился, но VPS не передал HTTPS. Проверьте интернет на VPS.")
        raise ProfileError("SSH подключился, но Reality не передал HTTPS. Проверьте настройки пересылки на VPS.")
    return endpoint, port, proxy, bridge, upstream_ip


def start_cloudflare(profile, stack, previous_endpoint=None):
    hostname = profile["cloudflareHost"].lower()
    cache = Path.home() / "Library/Application Support/VLESS VPN" / f"cloudflare-edge-{hostname}"
    try:
        preferred = [str(ipaddress.IPv4Address(cache.read_text().strip()))]
    except (OSError, ValueError):
        preferred = []
    if previous_endpoint is not None:
        addresses = [str(previous_endpoint)]
    else:
        try:
            addresses = preferred + socket.gethostbyname_ex(hostname)[2]
        except OSError:
            addresses = preferred
    if not addresses:
        raise ProfileError("Не удалось получить IPv4 входа Cloudflare. Проверьте DNS и подключение к интернету.")
    attempted = []
    for address in dict.fromkeys(addresses):
        endpoint = ipaddress.IPv4Address(address)
        if not endpoint.is_global or endpoint.is_multicast:
            continue
        route = subprocess.run(["/sbin/route", "-n", "get", address], capture_output=True, text=True)
        interface = re.search(r"(?m)^\s*interface:\s+(en[0-9]+)\s*$", route.stdout)
        if interface is None:
            continue
        attempted.append(address)
        with ExitStack() as attempt:
            port, proxy, bridge = start_xray(profile, endpoint, attempt, interface[1])
            for _ in range(2 if address in preferred else 1):
                upstream_ip = probe(port)
                if upstream_ip is not None:
                    try:
                        cache.write_text(address + "\n")
                    except OSError:
                        pass
                    stack.enter_context(attempt.pop_all())
                    return endpoint, port, proxy, bridge, upstream_ip
    if not attempted:
        raise ProfileError("Не найден прямой маршрут к Cloudflare через Wi-Fi или Ethernet.")
    raise ProfileError(f"Не прошла проверка HTTPS через Cloudflare ({', '.join(attempted)}).")


def monitor_connection(service, proxy, bridge, app_pid, upstream_ip, probe_port=None):
    global wake_requested
    next_check = time.monotonic() + HEALTH_CHECK_INTERVAL
    failures = 0
    while os.getppid() == app_pid and proxy.poll() is None and tunnel_exists():
        if wake_requested or (bridge is not None and bridge.poll() is not None):
            break
        if select.select([service], [], [], 1)[0]:
            break
        if time.monotonic() >= next_check:
            failures = 0 if probe(probe_port) == upstream_ip else failures + 1
            if failures >= HEALTH_CHECK_FAILURE_LIMIT:
                break
            next_check = time.monotonic() + (2 if failures else HEALTH_CHECK_INTERVAL)
    wake_requested = False


def run_connection(profile, protect, direct_sites, direct_ru, app_pid, previous_endpoint=None,
                   vpn_sites=(), deferred_sites=()):
    if tunnel_exists():
        raise ProfileError("Этот системный туннель уже запущен. Отключите его в приложении перед новым подключением.")
    cloudflare_host = profile.get("cloudflareHost")
    ssh_user = profile.get("sshUser")
    server_port = (profile.get("sshPort") or 22) if ssh_user else (443 if cloudflare_host else profile["port"])
    with ExitStack() as stack:
        if cloudflare_host:
            endpoint, port, proxy, bridge, upstream_ip = start_cloudflare(profile, stack, previous_endpoint)
        elif ssh_user:
            endpoint, port, proxy, bridge, upstream_ip = start_ssh(profile, stack)
        else:
            try:
                with socket.create_connection((str(previous_endpoint or profile["host"]), server_port), timeout=6) as server:
                    endpoint = ipaddress.ip_address(server.getpeername()[0].split("%")[0])
            except OSError as error:
                raise ProfileError("Сервер профиля недоступен. Проверьте адрес и подключение к интернету.") from error
            port, proxy, bridge = start_xray(profile, endpoint, stack)
            upstream_ip = probe(port)
            if upstream_ip is None:
                raise HTTPSProbeError("Xray запустился, но через VPN не ответили оба проверочных HTTPS-адреса.")
        if deferred_sites and not direct_sites:
            direct_sites.extend(resolve_direct_sites(deferred_sites, port))
        say("progress", "Запускаем системный туннель…")
        try:
            with start_tunnel(endpoint, port, server_port, protect, direct_sites, direct_ru,
                              cloudflare=bool(cloudflare_host), vpn_sites=vpn_sites) as service:
                for _ in range(40):
                    if tunnel_exists():
                        break
                    if select.select([service], [], [], 0.15)[0]:
                        raise ProfileError("Системный туннель остановился при запуске.")
                else:
                    raise ProfileError("macOS не подняла сетевой интерфейс VPN.")
                say("progress", "Проверяем выход в интернет через VPN…")
                observed_ip = None
                for _ in range(2):
                    current_ip = probe(port if vpn_sites else None)
                    if current_ip == upstream_ip:
                        break
                    if current_ip is not None:
                        observed_ip = current_ip
                else:
                    if observed_ip is None:
                        raise HTTPSProbeError("Туннель запустился, но через VPN не ответили оба проверочных HTTPS-адреса.")
                    raise ProfileError("Системный маршрут не совпал с выходом через VPS. Отключите другие VPN и повторите.")
                say("connected", str(upstream_ip), entryIP=str(endpoint))
                monitor_connection(service, proxy, bridge, app_pid, upstream_ip, port if vpn_sites else None)
                if os.getppid() == app_pid:
                    say("reconnecting", "Восстанавливаем соединение с VPN…")
        finally:
            stop_proxy(proxy)
            for _ in range(40):
                if not tunnel_exists():
                    break
                time.sleep(0.15)
    return endpoint


def self_test():
    profile = parse_profiles(sys.stdin.read(), "Проверка")[0]
    endpoint = ipaddress.ip_address(profile["host"])
    xray, tun = configs(profile, endpoint, 32145)
    assert not any(endpoint in ipaddress.ip_network(p) for p in tun["inbounds"][0]["route_address"])
    assert tun["outbounds"][0]["server_port"] == 32145
    with tempfile.TemporaryDirectory(prefix="vless-vpn-check-") as temp:
        for name, config, command in (
            ("xray", xray, [XRAY, "run", "-test", "-config"]),
            ("tun", tun, [SING_BOX, "check", "-c"]),
        ):
            path = Path(temp) / f"{name}.json"
            path.write_text(json.dumps(config))
            subprocess.run([*command, path], stdout=subprocess.DEVNULL, check=True)
    print("OK")


class StopRequested(Exception):
    pass


def interrupted(_signal, _frame):
    raise StopRequested


def request_reconnect(_signal, _frame):
    global wake_requested
    wake_requested = True


if __name__ == "__main__":
    os.umask(0o077)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGUSR1, request_reconnect)
    try:
        mode = sys.argv[1]
        if mode == "import":
            print(json.dumps(parse_profiles(sys.stdin.read(), sys.argv[2]), ensure_ascii=False))
        elif mode in ("connect", "connect-auto"):
            request = json.loads(sys.stdin.read())
            connect(validate(request.get("profile", request)), allow_install=mode == "connect",
                    protect="--no-kill-switch" not in sys.argv[2:], direct_sites=request.get("directSites", ""),
                    direct_ru=request.get("directRuSites") is True, previous_entry_ip=request.get("previousEntryIP"),
                    vpn_sites=request.get("vpnSites"))
        elif mode == "terminal-status":
            if terminal_session() is not None:
                print("active")
            else:
                print("blocked" if protection_blocked() else "inactive")
        elif mode == "release-protection":
            release_protection()
            say("disconnected", "Доступ в интернет восстановлен.")
        elif mode == "public-ip":
            address = probe()
            if address is None:
                sys.exit(1)
            print(address)
        elif mode == "stop-terminal":
            stop_terminal()
        elif mode == "self-test":
            self_test()
        else:
            raise ProfileError("Неизвестная команда.")
    except (StopRequested, InterruptedError, KeyboardInterrupt):
        say("disconnected", "VPN отключён.")
    except ProfileError as error:
        say("error", str(error))
        sys.exit(1)
    except (OSError, ValueError, TypeError, AttributeError, KeyError, subprocess.SubprocessError):
        say("error", "Не удалось запустить VPN или прочитать конфигурацию.")
        sys.exit(1)
