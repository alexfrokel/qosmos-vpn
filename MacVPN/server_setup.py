#!/usr/bin/env python3
"""Provision a direct Reality server, or a private relay reached over SSH."""
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
from contextlib import ExitStack, contextmanager
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qosmos_backend", HERE / "backend.py")
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)
Error = vpn.ProfileError
SNI = "www.debian.org"
RELAY_PORT = 24443
LOCAL_VPN_PORT = 24444
REASONS = {
    "os": "Нужен Debian 12+ или Ubuntu 22.04+ с systemd.",
    "arch": "Поддерживаются серверы x86-64 и ARM64.",
    "tools": "На сервере не хватает системных утилит (iproute2 или systemd).",
    "existing": "Найдена предыдущая установка Qosmos. Её файлы не изменены.",
    "port": "Порт VPN уже занят.",
    "relay_port": "На входе занят локальный порт 24443.",
    "apt": "Не удалось установить curl, unzip и сертификаты через apt.",
    "download": "Сервер не смог скачать Xray с GitHub.",
    "digest": "Контрольная сумма Xray не совпала.",
    "config": "Xray отклонил конфигурацию.",
    "service": "Не запустилась служба systemd.",
    "path": "Вход не может подключиться к выходу. Проверьте TCP-порт VPN в панели выходного VPS.",
    "server": "Сервер не смог завершить этот шаг.",
}


def emit(kind, **fields):
    print(json.dumps(dict(kind=kind, **fields), ensure_ascii=False), flush=True)


def address(value):
    try:
        ip = ipaddress.IPv4Address(value)
        if ip.is_global and not ip.is_multicast:
            return str(ip)
    except (ValueError, TypeError):
        pass
    raise Error("Укажите публичный IPv4 сервера из панели хостинга.")


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise Error("Порт должен быть числом от 1 до 65535.")
    return value


def server(value, role, credentials):
    result = dict(host=address(value["host"]), port=port(value["port"]), role=role)
    if credentials:
        user = value["user"]
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise Error(f"{role}: проверьте имя пользователя SSH.")
        password = value.get("password", "")
        key = value.get("key", "")
        if not key and not password:
            raise Error(f"{role}: введите пароль или выберите ключ SSH.")
        if password and (len(password.encode()) > 1024 or any(c in password for c in "\x00\r\n")):
            raise Error(f"{role}: некорректный пароль или парольная фраза.")
        if key and not Path(key).is_file():
            raise Error(f"{role}: файл ключа не найден.")
        result.update(user=user, password=password, key=key, hostKey=value.get("hostKey", ""))
    return result


def known_host(target):
    return target["host"] if target["port"] == 22 else f'[{target["host"]}]:{target["port"]}'


def parse_host_key(line, target):
    fields = line.split()
    if (len(fields) != 3 or fields[0] != known_host(target)
            or fields[1] not in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                                 "ecdsa-sha2-nistp521", "ssh-rsa")):
        raise ValueError("host key")
    blob = base64.b64decode(fields[2], validate=True)
    if not 32 <= len(blob) <= 8192:
        raise ValueError("host key")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return " ".join(fields), f"SHA256:{fingerprint}"


def inspect(target):
    try:
        scan = subprocess.run(["/usr/bin/ssh-keyscan", "-T", "5", "-p", str(target["port"]),
                               "-t", "ed25519,ecdsa,rsa", target["host"]],
                              capture_output=True, text=True, timeout=9)
        keys = []
        for line in scan.stdout.splitlines():
            try:
                keys.append(parse_host_key(line, target))
            except ValueError:
                continue
        if not keys:
            raise ValueError("no key")
    except (ValueError, subprocess.TimeoutExpired):
        raise Error(f'{target["role"]}: SSH не ответил на {target["host"]}:{target["port"]}.') from None

    known = Path.home() / ".ssh" / "known_hosts"
    if known.is_file():
        found = subprocess.run(["/usr/bin/ssh-keygen", "-F", known_host(target), "-f", str(known)],
                               capture_output=True, text=True, timeout=5).stdout
        records = [line.split() for line in found.splitlines() if line and not line.startswith("#")]
        if any(fields[0] == "@revoked" for fields in records):
            raise Error(f'{target["role"]}: в known_hosts есть отозванный ключ. Проверьте VPS.')
        if records:
            for line, fingerprint in keys:
                if any(fields[1:3] == line.split()[1:3] for fields in records):
                    return dict(role=target["role"], address=known_host(target), key=line, fingerprint=fingerprint)
            raise Error(f'{target["role"]}: ключ SSH не совпал с known_hosts. Проверьте ключ в панели VPS.')
    line, fingerprint = min(keys, key=lambda item: (
        0 if " ssh-ed25519 " in item[0] else 1 if " ecdsa-" in item[0] else 2
    ))
    return dict(role=target["role"], address=known_host(target), key=line, fingerprint=fingerprint)


@contextmanager
def askpass(directory, password):
    if not password:
        yield None
        return
    path = str(directory / "auth.sock")
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(path)
    listener.listen(1)
    listener.settimeout(0.2)
    stop = threading.Event()

    def send():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                try:
                    connection.sendall(password.encode() + b"\n")
                except OSError:
                    pass
            return

    helper = directory / "askpass"
    helper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I -B -c " + shlex.quote(
        "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]);"
        "sys.stdout.buffer.write(s.makefile('rb').read(1025))"
    ) + " " + shlex.quote(path) + "\n", encoding="utf-8")
    helper.chmod(0o700)
    worker = threading.Thread(target=send, daemon=True)
    worker.start()
    try:
        yield helper
    finally:
        stop.set()
        worker.join()
        listener.close()
        Path(path).unlink(missing_ok=True)


def run_remote(target, script, action, variables):
    label = target["role"]
    try:
        key, _ = parse_host_key(target["hostKey"], target)
    except ValueError:
        raise Error(f"{label}: сначала подтвердите отпечаток SSH.") from None
    with tempfile.TemporaryDirectory(prefix="qv-", dir="/private/tmp") as work:
        directory = Path(work)
        trust = directory / "known_hosts"
        trust.write_text(key + "\n", encoding="utf-8")
        trust.chmod(0o600)
        cmd = ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", str(target["port"]),
               "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
               "-o", f"UserKnownHostsFile={trust}", "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=7", "-o", "ServerAliveInterval=8", "-o", "ServerAliveCountMax=2",
               "-o", "ForwardAgent=no", "-o", "NumberOfPasswordPrompts=1", "-o", "IdentityAgent=none"]
        if target["key"]:
            cmd += ["-i", target["key"], "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey"]
        else:
            cmd += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive"]
        limit = 230 if action == "install" and script == "exit" else 30
        assignments = dict(variables, action=action)
        payload = "\n".join(f"{k}={shlex.quote(str(v))}" for k, v in assignments.items()) + "\n"
        payload += (HERE / f"server-setup-{script}.sh").read_text(encoding="utf-8")
        remote = ["/usr/bin/timeout", "-k", "5", str(limit), "/bin/bash", "-s"]
        if target["user"] != "root":
            remote = ["/usr/bin/sudo", "-n", "--", *remote]
        try:
            with askpass(directory, target["password"]) as helper:
                env = os.environ.copy()
                if helper:
                    env.update(SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE="force")
                else:
                    cmd += ["-o", "BatchMode=yes"]
                result = subprocess.run(
                    [*cmd, f'{target["user"]}@{target["host"]}', *remote],
                    input=payload, capture_output=True, text=True, errors="replace", env=env, timeout=limit + 20,
                    start_new_session=True,
                )
        except subprocess.TimeoutExpired:
            raise Error(f"{label}: установка на сервере не завершилась вовремя.") from None
    if result.returncode == 0 and "QOSMOS_OK" in result.stdout.splitlines():
        return
    errors = re.findall(r"^QOSMOS_FAIL ([a-z_]+)$", result.stdout, re.M)
    reason = REASONS.get(errors[-1]) if errors else None
    if not reason:
        stderr = result.stderr
        if "Permission denied" in stderr:
            reason = "SSH отклонил пароль или ключ."
        elif "Host key verification failed" in stderr or "REMOTE HOST IDENTIFICATION HAS CHANGED" in stderr:
            reason = "Ключ SSH изменился. Сверьте новый отпечаток в панели VPS."
        elif target["user"] != "root" and ("sudo" in stderr or result.returncode == 127):
            reason = "Для установки нужен root или пользователь с sudo без запроса пароля."
        else:
            reason = "Соединение SSH прервалось или сервер не запустил установку."
    raise Error(f"{label}: {reason}")


def new_reality(exit_host, vpn_port, name):
    result = subprocess.check_output([vpn.XRAY, "x25519"], text=True, timeout=5)
    private = re.search(r"(?m)^Private[Kk]ey:\s*([\w-]{43})\s*$", result)
    public = re.search(r"(?m)^(?:Password(?: \(PublicKey\))?|Public[Kk]ey):\s*([\w-]{43})\s*$", result)
    if not private or not public:
        raise Error("Не удалось создать ключи Reality.")
    user = str(uuid.uuid4())
    short = secrets.token_hex(8)
    profile = vpn.validate({
        "name": name, "host": exit_host, "port": vpn_port, "user": user, "flow": "xtls-rprx-vision",
        "encryption": "none", "network": "raw", "security": "reality", "sni": SNI,
        "fingerprint": "chrome", "key": public[1], "shortID": short, "spider": "",
    })
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "0.0.0.0", "port": vpn_port, "protocol": "vless",
            "settings": {"decryption": "none", "clients": [{"id": user, "flow": profile["flow"]}]},
            "streamSettings": {
                "network": "raw", "security": "reality",
                "realitySettings": {"target": f"{SNI}:443", "serverNames": [SNI],
                                    "privateKey": private[1], "shortIds": [short]},
            },
        }],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    return profile, config


def new_local_profile(host, name, identity, ssh_port):
    user = str(uuid.uuid4())
    profile = vpn.validate({
        "name": name, "host": host, "port": LOCAL_VPN_PORT, "user": user, "flow": "",
        "encryption": "none", "network": "raw", "security": "ssh", "sni": "",
        "fingerprint": "", "key": "", "shortID": "", "spider": "",
        "sshUser": "qosmos-local", "sshPort": ssh_port, "sshIdentity": identity,
    })
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": LOCAL_VPN_PORT, "protocol": "vless",
            "settings": {"decryption": "none", "clients": [{"id": user}]},
        }],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    return profile, config


def existing_reality(link):
    profile = vpn.parse_link(link.strip(), "")
    if profile.get("sshUser") or profile.get("cloudflareHost") or not profile.get("sni"):
        raise Error("Для выхода нужна прямая ссылка VLESS Reality с SNI.")
    address(profile["host"])
    return profile


def setup(request):
    mode = request["mode"]
    if mode not in ("single", "singleSSH", "pair", "existing"):
        raise Error("Выберите схему подключения.")
    single_ssh = mode == "singleSSH"
    paired = mode in ("pair", "existing")
    entry = server(request["entry"], "Вход", True) if paired else None
    exit_server = server(request["exit"], "Выход" if paired else "Сервер", True) if mode != "existing" else None
    ssh_server = exit_server if single_ssh else entry
    name = request["name"].strip() or ("Мой VPN · SSH" if single_ssh else "Вход → выход" if paired else "Мой VPN")
    run_id = uuid.uuid4().hex
    config = None
    if exit_server:
        exit_host = exit_server["host"]
        vpn_port = LOCAL_VPN_PORT if single_ssh else port(request["vpnPort"])
        if exit_server["port"] == vpn_port:
            raise Error("Порт VPN должен отличаться от порта SSH.")
        if single_ssh:
            profile, config = new_local_profile(exit_host, name, run_id, exit_server["port"])
        else:
            profile, config = new_reality(exit_host, vpn_port, name)
    else:
        profile = existing_reality(request["link"])
        exit_host, vpn_port = profile["host"], profile["port"]
        profile["name"] = name
    if entry and exit_host == entry["host"]:
        raise Error("У входа и выхода должны быть разные IP-адреса.")

    ssh_target_port = vpn_port if single_ssh else RELAY_PORT
    variables = dict(run_id=run_id, vpn_port=vpn_port, relay_port=ssh_target_port,
                     exit_host=exit_host, single_ssh=int(single_ssh))
    emit("progress", message="Проверяем SSH и настройки серверов…")
    if exit_server:
        run_remote(exit_server, "exit", "check", variables)
    if ssh_server:
        run_remote(ssh_server, "entry", "check", variables)
    identity_dir = None
    attempted = []
    try:
        if ssh_server:
            keys = Path.home() / ".ssh" / "qosmos"
            keys.mkdir(parents=True, exist_ok=True, mode=0o700)
            identity_dir = keys / run_id
            identity_dir.mkdir(mode=0o700)
            key = identity_dir / "id_ed25519"
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                            "Qosmos relay", "-f", str(key)], check=True, capture_output=True, timeout=8)
            trust = identity_dir / "known_hosts"
            trust.write_text(parse_host_key(ssh_server["hostKey"], ssh_server)[0] + "\n", encoding="utf-8")
            trust.chmod(0o600)
            variables["runtime_key"] = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
        if exit_server:
            emit("progress", message="Устанавливаем Xray…")
            attempted.append((exit_server, "exit"))
            run_remote(exit_server, "exit", "install", dict(variables, xray_config=json.dumps(config)))
        if ssh_server:
            emit("progress", message="Настраиваем подключение по SSH…")
            attempted.append((ssh_server, "entry"))
            run_remote(ssh_server, "entry", "install", variables)
            if not single_ssh:
                profile.update(host=ssh_server["host"], port=ssh_target_port, sshUser="qosmos-relay",
                               sshPort=ssh_server["port"], sshIdentity=run_id)
        vpn.validate(profile)

        emit("progress", message="Проверяем HTTPS через новый профиль…")
        with ExitStack() as stack:
            if ssh_server:
                *_, ip = vpn.start_ssh(profile, stack)
            else:
                try:
                    with socket.create_connection((exit_host, vpn_port), timeout=6):
                        pass
                except OSError:
                    raise Error(f"Mac не видит {exit_host}:{vpn_port}. Проверьте входящий TCP-порт в панели VPS.") from None
                local_port, *_ = vpn.start_xray(profile, ipaddress.IPv4Address(exit_host), stack)
                ip = vpn.probe(local_port)
                if ip is None:
                    hint = (" Если нужен один VPS, попробуйте режим «Через SSH»."
                            if mode == "single" else "")
                    raise Error("Не удалось открыть HTTPS через Reality." + hint)
        emit("complete", profile=profile, exitIP=str(ip))
    except (Error, OSError, ValueError, subprocess.SubprocessError) as error:
        if identity_dir:
            shutil.rmtree(identity_dir, ignore_errors=True)
        failed = []
        if attempted:
            emit("progress", message="Отменяем изменения на серверах…")
        for target, script in reversed(attempted):
            try:
                run_remote(target, script, "rollback", variables)
            except (Error, OSError, ValueError, subprocess.SubprocessError):
                failed.append(target["role"])
        message = str(error) if isinstance(error, Error) else "Не удалось завершить установку."
        if failed:
            message += " Не удалось подтвердить откат: " + ", ".join(failed) + "."
        raise Error(message) from None


def main():
    os.umask(0o077)
    try:
        request = json.loads(sys.stdin.read(32768))
        if sys.argv[1] == "inspect":
            mode = request["mode"]
            targets = []
            paired = mode in ("pair", "existing")
            if paired:
                targets.append(server(request["entry"], "Вход", False))
            if mode != "existing":
                targets.append(server(request["exit"], "Выход" if paired else "Сервер", False))
            emit("hosts", hosts=[inspect(target) for target in targets])
        elif sys.argv[1] == "install":
            setup(request)
        else:
            raise Error("Неизвестная команда мастера.")
    except Error as error:
        emit("error", message=str(error))
        return 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError):
        emit("error", message="Не удалось запустить мастер или прочитать настройки.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
