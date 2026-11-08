#!/usr/bin/env python3
"""Publish only after every asset has been uploaded and downloaded for verification."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import quote

from release import asset_names, digest


def gh_json(arguments, payload=None):
    if payload is not None:
        arguments = arguments + ["-H", "Content-Type: application/json", "--input", "-"]
    return json.loads(subprocess.check_output(
        ["gh"] + arguments, text=True,
        input=json.dumps(payload) if payload is not None else None))


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


def find_release(repo, tag):
    # The tag endpoint can return 404 for a draft whose Git tag does not yet
    # exist. Authenticated release listings include drafts; search every page.
    matches = []
    page = 1
    while True:
        releases = gh_json(["api", f"repos/{repo}/releases?per_page=100&page={page}"])
        matches.extend(release for release in releases if release["tag_name"] == tag)
        if len(releases) < 100:
            break
        page += 1
    if len(matches) > 1:
        raise ValueError("refusing to choose between duplicate releases for " + tag)
    return matches[0] if matches else None


def verify_draft(release, release_id, tag, expected_commit):
    if release["id"] != release_id or release["tag_name"] != tag:
        raise ValueError("release identity changed while publishing")
    if not release["draft"]:
        raise ValueError("refusing to overwrite an already published release")
    if release["target_commitish"] != expected_commit:
        raise ValueError("existing draft belongs to another source commit")


def asset_identity(assets):
    # Download counters change as we verify bytes; only content identity and
    # upload completeness must remain unchanged.
    return sorted((a["id"], a["name"], a["size"], a["state"]) for a in assets)


def publish(directory, repo, expected_commit):
    manifest, hashes = verify_local(directory)
    if manifest["commit"] != expected_commit or manifest["repository"] != repo:
        raise ValueError("release artifacts belong to a different source commit or repository")
    tag = manifest["tag"]
    existing_tag = tag_commit(repo, tag)
    if existing_tag and existing_tag != expected_commit:
        raise ValueError("refusing to move a release tag to another commit")
    existing = find_release(repo, tag)
    if existing:
        verify_draft(existing, existing["id"], tag, expected_commit)
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
        # Creation returns the authoritative ID before the draft necessarily
        # becomes visible in paginated listings.
        existing = gh_json(["api", "--method", "POST", f"repos/{repo}/releases"],
                           {"tag_name": tag, "target_commitish": expected_commit,
                            "name": tag, "body": notes, "draft": True, "prerelease": False})
        verify_draft(existing, existing["id"], tag, expected_commit)
    release_id = existing["id"]
    release_path = f"repos/{repo}/releases/{release_id}"
    release = gh_json(["api", release_path])
    verify_draft(release, release_id, tag, expected_commit)
    # A retry resumes only this same-source draft and refreshes its notes.
    release = gh_json(["api", "--method", "PATCH", release_path],
                      {"tag_name": tag, "target_commitish": expected_commit,
                       "name": tag, "body": notes})
    verify_draft(release, release_id, tag, expected_commit)
    for name in sorted(hashes):
        # Never reselect the upload destination by tag. Recheck this exact
        # draft before replacing an asset, including when resuming a partial run.
        release = gh_json(["api", release_path])
        verify_draft(release, release_id, tag, expected_commit)
        previous = {a["name"]: a for a in release["assets"]}
        if len(previous) != len(release["assets"]) or not set(previous).issubset(hashes):
            raise ValueError("remote draft has unexpected or duplicate assets")
        if name in previous:
            subprocess.run(["gh", "api", "--method", "DELETE",
                            f"repos/{repo}/releases/assets/{previous[name]['id']}"], check=True)
        path = directory / name
        gh_json(["api", "--method", "POST",
                 f"https://uploads.github.com/repos/{repo}/releases/{release_id}/assets?name={quote(name, safe='')}",
                 "-H", "Content-Type: application/octet-stream",
                 "-H", f"Content-Length: {path.stat().st_size}", "--input", str(path)])
    release = gh_json(["api", release_path])
    verify_draft(release, release_id, tag, expected_commit)
    assets = {a["name"]: a for a in release["assets"]}
    if len(assets) != len(release["assets"]) or set(assets) != set(hashes):
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
    # Check identity again before the irreversible step. In particular, never
    # select a second draft or publish through a tag-based lookup on a retry.
    listed = find_release(repo, tag)
    if listed:
        verify_draft(listed, release_id, tag, expected_commit)
    # Listing visibility can lag creation. The known ID is authoritative, and
    # a missing/deleted draft must still fail this direct read.
    current = gh_json(["api", release_path])
    verify_draft(current, release_id, tag, expected_commit)
    if asset_identity(current["assets"]) != asset_identity(release["assets"]):
        raise ValueError("remote draft assets changed during verification")
    current_tag = tag_commit(repo, tag)
    if current_tag and current_tag != expected_commit:
        raise ValueError("refusing to move a release tag to another commit")
    # Publication is the final write, after every remote byte has been checked.
    gh_json(["api", "--method", "PATCH", release_path],
            {"tag_name": tag, "target_commitish": expected_commit,
             "draft": False, "prerelease": False, "make_latest": "true"})
    published = gh_json(["api", release_path])
    if (published["id"] != release_id or published["tag_name"] != tag or
            published["target_commitish"] != expected_commit or
            published["draft"] or published["prerelease"] or
            tag_commit(repo, tag) != expected_commit):
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
