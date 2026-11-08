#!/usr/bin/env python3
"""Seal native packages, execute their binaries and assemble a complete release."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import struct
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = ("amd64", "arm64", "armv7", "armv6", "386", "armv5", "s390x")
DOCKER_PLATFORMS = ("amd64", "arm64", "armv7")
TUIC_PLATFORMS = ("amd64", "arm64", "armv7", "386")
MACHINES = {"amd64": 62, "arm64": 183, "armv7": 40, "armv6": 40, "armv5": 40, "386": 3, "s390x": 22}
EMULATORS = {"amd64": [], "arm64": ["qemu-aarch64"], "386": ["qemu-i386"],
             "armv5": ["qemu-arm", "-cpu", "arm926"], "armv6": ["qemu-arm", "-cpu", "arm1176"],
             "armv7": ["qemu-arm", "-cpu", "cortex-a15"], "s390x": ["qemu-s390x"]}


def version():
    result = (ROOT / "config/version").read_text().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", result):
        raise ValueError("config/version must contain a stable semantic version")
    return result


def commit():
    result = os.environ.get("GITHUB_SHA") or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", result):
        raise ValueError("invalid source commit")
    return result


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def arch(platform):
    return "arm" if platform.startswith("armv") else platform


def executables(platform):
    suffix = arch(platform)
    result = ["x-ui", "x-ui.sh", f"bin/xray-linux-{suffix}", f"bin/mtg-linux-{suffix}",
              "bin/awg", "bin/awg-quick", "bin/amneziawg-go"]
    if platform in TUIC_PLATFORMS:
        result.append(f"bin/tuic-server-linux-{suffix}")
    if suffix == "arm":
        result.append(f"bin/xray-linux-{platform}")
    return result


def check_tree(directory, platform):
    expected = executables(platform) + ["x-ui.service", "LICENSE"]
    expected += ["bin/" + stem + suffix + ".dat" for stem in ("geoip", "geosite") for suffix in ("", "_IR", "_VN")]
    for name in expected:
        path = directory / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError("missing/empty package file: " + name)
    for name in executables(platform):
        path = directory / name
        if path.stat().st_mode & 0o111 != 0o111:
            raise ValueError("package executable has no execution permission: " + name)
        if name.endswith(".sh") or name == "bin/awg-quick":
            continue
        with path.open("rb") as stream:
            header = stream.read(20)
        if header[:4] != b"\x7fELF" or header[5] not in (1, 2):
            raise ValueError("not an ELF binary: " + name)
        machine = struct.unpack("<H" if header[5] == 1 else ">H", header[18:20])[0]
        if machine != MACHINES[platform]:
            raise ValueError("wrong ELF architecture: " + name)
        segments = subprocess.check_output(["readelf", "-l", str(path)], text=True)
        if re.search(r"\bINTERP\b", segments):
            raise ValueError("package binary requires a host dynamic loader: " + name)
    return {str(path.relative_to(directory)): digest(path) for path in sorted(directory.rglob("*"))
            if path.is_file() and path.name != "release.json"}


def seal(directory, platform):
    metadata = {"version": version(), "tag": "v" + version(), "commit": commit(), "platform": platform,
                "xray": (ROOT / "config/xray-version").read_text().strip(), "mtg": "1.16.1", "tuic": "1.0.0" if platform in TUIC_PLATFORMS else None,
                "amneziawg_tools": "3.1.20260812", "amneziawg_go": "3.1.20260828", "files": check_tree(directory, platform)}
    (directory / "release.json").write_text(json.dumps(metadata, indent=2) + "\n")


def extract(archive, destination):
    with tarfile.open(archive, "r:gz") as source:
        seen = set()
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "x-ui":
                raise ValueError("invalid package path: " + member.name)
            if member.name in seen or not (member.isfile() or member.isdir()):
                raise ValueError("duplicate or nonregular package entry: " + member.name)
            seen.add(member.name)
        source.extractall(destination, filter="data")
    return destination / "x-ui"


def verify(directory, platform):
    metadata = json.loads((directory / "release.json").read_text())
    if metadata["platform"] != platform or metadata["version"] != version() or metadata["commit"] != commit():
        raise ValueError("package metadata differs from this source commit/version/platform")
    if metadata["files"] != check_tree(directory, platform):
        raise ValueError("package contents differ from the sealed file checksums")
    return metadata


def smoke(directory, platform):
    metadata = verify(directory, platform)
    prefix = EMULATORS[platform]
    suffix = arch(platform)
    commands = [("x-ui", ["-v"], version()), (f"bin/xray-linux-{suffix}", ["version"], metadata["xray"]),
                (f"bin/mtg-linux-{suffix}", ["--version"], metadata["mtg"]), ("bin/awg", ["--version"], metadata["amneziawg_tools"]),
                ("bin/amneziawg-go", ["--version"], metadata["amneziawg_go"])]
    if metadata["tuic"]:
        commands.append((f"bin/tuic-server-linux-{suffix}", ["--version"], metadata["tuic"]))
    for binary, arguments, expected in commands:
        result = subprocess.run(prefix + [str(directory / binary)] + arguments, cwd=directory, check=True,
                                timeout=90, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        print(result.stdout.strip(), flush=True)
        if expected not in result.stdout:
            raise ValueError("unexpected binary version: " + binary)
    # Exercise SQLite and migrations on each CPU, not just the version flag.
    env = dict(os.environ, XUI_DB_FOLDER=str(directory / "smoke-db"))
    subprocess.run(prefix + [str(directory / "x-ui"), "setting", "-port", "2054", "-username", "release-check",
                             "-password", "local-release-check", "-webBasePath", "/"], cwd=directory, env=env, check=True, timeout=90)
    with sqlite3.connect(f"file:{directory / 'smoke-db/x-ui.db'}?mode=ro", uri=True) as db:
        if db.execute("SELECT value FROM settings WHERE key='webPort'").fetchone() != ("2054",):
            raise ValueError("packaged panel could not persist its SQLite settings")
    fixture = {"log": {"loglevel": "warning"}, "inbounds": [{"tag": "release-xhttp", "listen": "127.0.0.1", "port": 19089,
               "protocol": "vless", "settings": {"clients": [{"id": "11111111-1111-4111-8111-111111111111"}], "decryption": "none"},
               "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/release-check", "mode": "auto"}}}],
               "outbounds": [{"protocol": "freedom", "tag": "direct"}]}
    config = directory / "smoke-xhttp.json"
    config.write_text(json.dumps(fixture))
    subprocess.run(prefix + [str(directory / f"bin/xray-linux-{suffix}"), "run", "-test", "-c", str(config)],
                   cwd=directory, check=True, timeout=90)


def asset_names():
    return ({f"x-ui-linux-{p}.tar.gz" for p in PLATFORMS} |
            {f"3x-ui-docker-linux-{p}.tar.gz" for p in DOCKER_PLATFORMS} |
            {"install.sh", "x-ui.sh", "release-manifest.json", "SHA256SUMS"})


def assemble(directory):
    archives = asset_names() - {"install.sh", "x-ui.sh", "release-manifest.json", "SHA256SUMS"}
    if {p.name for p in directory.iterdir()} != archives:
        raise ValueError("release does not contain exactly seven native and three Docker archives")
    packages = []
    for platform in PLATFORMS:
        with tempfile.TemporaryDirectory() as tmp:
            extracted = extract(directory / f"x-ui-linux-{platform}.tar.gz", Path(tmp))
            packages.append(verify(extracted, platform))
    for name in ("install.sh", "x-ui.sh"):
        shutil.copy2(ROOT / name, directory / name)
    manifest = {"version": version(), "tag": "v" + version(), "commit": commit(), "repository": "9holy/3x-ui",
                "native": packages, "docker": list(DOCKER_PLATFORMS)}
    (directory / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    hashes = "".join(f"{digest(path)}  {path.name}\n" for path in sorted(directory.iterdir()))
    (directory / "SHA256SUMS").write_text(hashes)
    print(f"Verified complete release: {len(asset_names())} assets for v{version()} at {commit()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("seal", "verify", "smoke", "assemble"))
    parser.add_argument("path", type=Path)
    parser.add_argument("platform", choices=PLATFORMS, nargs="?")
    args = parser.parse_args()
    if args.command == "assemble":
        assemble(args.path.resolve())
    elif args.command == "seal":
        seal(args.path.resolve(), args.platform)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            extracted = extract(args.path, Path(tmp))
            (smoke if args.command == "smoke" else verify)(extracted, args.platform)


if __name__ == "__main__":
    main()
