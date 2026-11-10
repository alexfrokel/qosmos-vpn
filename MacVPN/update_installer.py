"""Validate a GitHub release and replace the app after it has closed."""

import ctypes
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import time
import zipfile


APP_NAME = "Qosmos VPN.app"
MAX_ARCHIVE_SIZE = 256 * 1024**2
MAX_EXTRACTED_SIZE = 768 * 1024**2
RENAME_SWAP = 2


def prepare(staging, installed, version, expected_digest):
    archive = staging / "update.zip"
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        if os.fstat(source.fileno()).st_size > MAX_ARCHIVE_SIZE:
            raise ValueError("Release archive is too large")
        for chunk in iter(lambda: source.read(1024**2), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_digest:
        raise ValueError("Release archive checksum does not match")

    with zipfile.ZipFile(archive) as contents:
        members = contents.infolist()
        if len(members) > 20_000 or sum(member.file_size for member in members) > MAX_EXTRACTED_SIZE:
            raise ValueError("Expanded release is too large")
        for member in members:
            parts = member.filename.rstrip("/").split("/")
            mode = stat.S_IFMT(member.external_attr >> 16)
            if (parts[0] not in (APP_NAME, "__MACOSX") or any(part in ("", ".", "..") for part in parts)
                    or "\\" in member.filename or mode not in (0, stat.S_IFDIR, stat.S_IFREG)):
                raise ValueError("Unexpected entry in the release archive")
    subprocess.run(["/usr/bin/ditto", "-x", "-k", archive, staging], check=True)
    archive.unlink()

    candidate = staging / APP_NAME
    with (installed / "Contents/Info.plist").open("rb") as old_info:
        current = plistlib.load(old_info)
    with (candidate / "Contents/Info.plist").open("rb") as new_info:
        update = plistlib.load(new_info)
    if (update.get("CFBundleIdentifier") != current["CFBundleIdentifier"]
            or update.get("CFBundleExecutable") != current["CFBundleExecutable"]
            or update.get("CFBundleShortVersionString") != version):
        raise ValueError("The app bundle does not match the release")
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", candidate], check=True)


def wait_for_exit(pid):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.2)
    raise TimeoutError("Qosmos VPN is still running")


def swap(first, second):
    rename = ctypes.CDLL(None, use_errno=True).renamex_np
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(os.fsencode(first), os.fsencode(second), RENAME_SWAP) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def launch(app, flags):
    subprocess.run(["/usr/bin/open", "-n", "-a", app, "--args", *flags], check=True)


def install(staging, installed, pid, resume):
    wait_for_exit(pid)
    flags = ["--resume-after-update"] if resume else []
    candidate = staging / APP_NAME
    swapped = False
    try:
        swap(installed, candidate)
        swapped = True
        launch(installed, ["--update-installed", *flags])
    except (OSError, subprocess.SubprocessError):
        if swapped:
            swap(installed, candidate)
        launch(installed, ["--update-failed", *flags])
    shutil.rmtree(staging)


if __name__ == "__main__":
    operation, target, *arguments = sys.argv[1:]
    staging = Path(__file__).resolve().parent
    installed = Path(target)
    if operation == "prepare":
        prepare(staging, installed, *arguments)
    elif operation == "install":
        install(staging, installed, int(arguments[0]), arguments[1] == "resume")
    else:
        raise ValueError("Unknown update operation")
