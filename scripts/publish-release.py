#!/usr/bin/env python3
"""Publish only after every asset has been uploaded and downloaded for verification."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from release import asset_names, digest


def gh_json(arguments):
    return json.loads(subprocess.check_output(["gh"] + arguments, text=True))


def optional_api(path):
    result = subprocess.run(["gh", "api", path], text=True, capture_output=True)
    if result.returncode:
        if "HTTP 404" in result.stderr:
            return None
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout)


def verify_local(directory):
    if {p.name for p in directory.iterdir()} != asset_names():
        raise ValueError("release must contain exactly fourteen expected assets")
    hashes = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ", 1)
        if name in hashes or name not in asset_names() - {"SHA256SUMS"}:
            raise ValueError("duplicate or unexpected checksum entry")
        hashes[name] = checksum
    if set(hashes) != asset_names() - {"SHA256SUMS"}:
        raise ValueError("incomplete release checksums")
    for name, checksum in hashes.items():
        if digest(directory / name) != checksum:
            raise ValueError("release checksum mismatch: " + name)
    hashes["SHA256SUMS"] = digest(directory / "SHA256SUMS")
    return json.loads((directory / "release-manifest.json").read_text()), hashes


def tag_commit(repo, tag):
    ref = optional_api(f"repos/{repo}/git/ref/tags/{tag}")
    if not ref:
        return None
    obj = ref["object"]
    if obj["type"] == "tag":
        obj = gh_json(["api", f"repos/{repo}/git/tags/{obj['sha']}"])["object"]
    if obj["type"] != "commit":
        raise ValueError("release tag must point to a commit")
    return obj["sha"]


def publish(directory, repo, expected_commit):
    manifest, hashes = verify_local(directory)
    if manifest["commit"] != expected_commit or manifest["repository"] != repo:
        raise ValueError("release artifacts belong to a different source commit or repository")
    tag = manifest["tag"]
    existing_tag = tag_commit(repo, tag)
    if existing_tag and existing_tag != expected_commit:
        raise ValueError("refusing to move a release tag to another commit")
    existing = optional_api(f"repos/{repo}/releases/tags/{tag}")
    if existing and not existing["draft"]:
        raise ValueError("refusing to overwrite an already published release")
    if existing and existing["target_commitish"] != expected_commit:
        raise ValueError("existing draft belongs to another source commit")
    notes = (
        f"## 9holy/3x-ui {tag} 正式版\n\n"
        f"源代码提交：`{expected_commit}`。保留 aircross 面板与 SQLite，修复并更新协议支持。\n\n"
        "提供七种 Linux 架构安装包和三种 Docker-load 镜像归档。安装、更新脚本统一使用本仓库。"
        "所有文件均列入 SHA256SUMS；发布前已重新下载每个远端资产核对字节。\n\n"
        "安装器先对原数据库副本执行迁移与新核心配置检查，检查通过才替换旧程序；启动失败执行回滚。"
        "旧 H2/QUIC 传输及显式空 seed 的 KCP 配置需要先按审核文档迁移。\n\n"
        "TUIC 1.0.0 的官方服务端仅随 amd64、arm64、armv7、386 包提供。"
        "TUIC 当前支持认证、绝对到期和配置重载，不支持逐用户流量配额或 Xray 路由桥接；"
        "AmneziaWG 使用完整接口配置，尚不提供逐 Peer 面板计量。功能边界均在面板和审核文档明确。\n\n"
        "Docker 归档不依赖 GHCR 公开权限：核对 SHA256SUMS 后，"
        "`gzip -dc 3x-ui-docker-linux-amd64.tar.gz | docker load`（按 CPU 选择对应包）。\n\n"
        f"[安装说明](https://github.com/{repo}/blob/{expected_commit}/README.md) · "
        f"[逐项审核与迁移说明](https://github.com/{repo}/blob/{expected_commit}/docs/protocol-support-audit.md)\n"
    )
    if not existing:
        with tempfile.NamedTemporaryFile("w", suffix=".md") as note_file:
            note_file.write(notes)
            note_file.flush()
            subprocess.run(["gh", "release", "create", tag, "--repo", repo, "--target", expected_commit,
                            "--draft", "--title", tag, "--notes-file", note_file.name], check=True)
    subprocess.run(["gh", "release", "upload", tag, "--repo", repo, "--clobber"] +
                   [str(directory / name) for name in sorted(hashes)], check=True)
    release = gh_json(["api", f"repos/{repo}/releases/tags/{tag}"])
    assets = {a["name"]: a for a in release["assets"]}
    if not release["draft"] or set(assets) != set(hashes):
        raise ValueError("remote draft has missing or unexpected assets")
    for name, expected in hashes.items():
        asset = assets[name]
        if asset["state"] != "uploaded" or asset["size"] != (directory / name).stat().st_size:
            raise ValueError("incomplete remote upload: " + name)
        # gh follows GitHub's temporary asset redirect without exposing signed URLs.
        with tempfile.TemporaryFile() as downloaded:
            subprocess.run(["gh", "api", "-H", "Accept: application/octet-stream",
                            f"repos/{repo}/releases/assets/{asset['id']}"], stdout=downloaded, check=True)
            downloaded.seek(0)
            import hashlib
            actual = hashlib.file_digest(downloaded, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("remote checksum mismatch; release remains draft: " + name)
        print("Remote asset verified:", name, flush=True)
    # Publication is the final write, after every remote byte has been checked.
    subprocess.run(["gh", "release", "edit", tag, "--repo", repo, "--draft=false",
                    "--prerelease=false", "--latest"], check=True)
    published = gh_json(["api", f"repos/{repo}/releases/tags/{tag}"])
    if published["draft"] or published["prerelease"] or tag_commit(repo, tag) != expected_commit:
        raise ValueError("published release/tag verification failed")
    print(f"Published https://github.com/{repo}/releases/tag/{tag}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--repo", default="9holy/3x-ui")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA"))
    args = parser.parse_args()
    if not args.commit:
        parser.error("--commit or GITHUB_SHA is required")
    publish(args.directory, args.repo, args.commit)


if __name__ == "__main__":
    main()
