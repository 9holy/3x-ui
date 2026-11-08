#!/usr/bin/env python3
r"""Optional localhost-only legacy mKCP interoperability test.

Requires Python 3, a local Go toolchain with cached project dependencies, and
user-supplied Xray binaries. Nothing is downloaded. The audited combination is
Xray 24.9.19 (client) and 26.10.31 (server). Example from the repository root:

  LEGACY_XRAY_BINARY=/path/to/xray-24.9.19 \
  XUI_TEST_XRAY=/path/to/xray-26.10.31 python3 scripts/test-kcp-compat.py

Four cases must return HTTP 200 through SOCKS -> old KCP client -> current model
configuration -> new KCP server -> a local HTTP server. A fifth negative control
removes the required original authenticator and must time out. An explicit empty
legacy seed is checked for rejection, never silently migrated or dialed.
"""

import argparse
import copy
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time


MARKER = b"3x-ui-kcp-roundtrip"
CLIENT_ID = "11111111-1111-4111-8111-111111111111"
GO_FIXTURES = r'''
package main

import (
    "encoding/json"
    "os"
    "x-ui/database/model"
    "x-ui/xray"
)

func main() {
    if xray.CheckLegacyStreamSettings(`{"network":"kcp","kcpSettings":{"seed":""}}`) == nil {
        panic("explicit empty legacy seed must be rejected")
    }
    cases := []struct{Name, Stream string}{
        {"seed-header-none", `{"network":"kcp","kcpSettings":{"seed":"audit-shared-seed","header":{"type":"none"},"mtu":1350,"tti":20}}`},
        {"seed-header-wechat", `{"network":"kcp","kcpSettings":{"seed":"audit-shared-seed","header":{"type":"wechat-video"},"mtu":1350,"tti":20}}`},
        {"missing-seed-header-none", `{"network":"kcp","kcpSettings":{"header":{"type":"none"},"mtu":1350,"tti":20}}`},
        {"missing-seed-header-srtp", `{"network":"kcp","kcpSettings":{"header":{"type":"srtp"},"mtu":1350,"tti":20}}`},
    }
    result := make([]map[string]interface{}, 0, len(cases))
    for _, c := range cases {
        inbound := model.Inbound{
            Tag: "review", Protocol: model.VLESS, Listen: "127.0.0.1", Port: 23456, Enable: true,
            Settings: `{"clients":[{"id":"11111111-1111-4111-8111-111111111111","email":"review","enable":true}],"decryption":"none"}`,
            StreamSettings: c.Stream,
        }
        var oldStream map[string]interface{}
        if err := json.Unmarshal([]byte(c.Stream), &oldStream); err != nil { panic(err) }
        result = append(result, map[string]interface{}{
            "name": c.Name, "oldStream": oldStream, "newInbound": inbound.GenXrayInboundConfig(),
        })
    }
    raw, err := json.MarshalIndent(result, "", "  ")
    if err != nil { panic(err) }
    if err = os.WriteFile(os.Args[1], raw, 0600); err != nil { panic(err) }
}
'''


def binary_path(value, label):
    found = shutil.which(value) if value else None
    if not found:
        raise ValueError(f"{label}: supply an executable path (see --help)")
    return str(Path(found).resolve())


def export_fixtures(go, output):
    helper = output / "export-fixtures.go"
    helper.write_text(GO_FIXTURES)
    target = output / "fixtures.json"
    env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GONOPROXY="none")
    result = subprocess.run(
        [go, "run", "-mod=readonly", str(helper), str(target)],
        cwd=Path(__file__).resolve().parents[1], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    (output / "fixture-build.log").write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(
            f"Offline fixture build failed; a compatible local Go toolchain and cached "
            f"project dependencies are required. See {output / 'fixture-build.log'}"
        )
    return json.loads(target.read_text())


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(MARKER)))
        self.end_headers()
        self.wfile.write(MARKER)

    def log_message(self, *args):
        pass


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_exact(sock, size):
    result = b""
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result += part
    return result


def transfer(socks_port, http_port):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication negotiation failed")
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", http_port))
        response = recv_exact(sock, 4)
        if response[:2] != b"\x05\x00":
            raise RuntimeError("SOCKS CONNECT rejected: " + response.hex())
        if response[3] == 1:
            recv_exact(sock, 6)
        elif response[3] == 4:
            recv_exact(sock, 18)
        elif response[3] == 3:
            recv_exact(sock, recv_exact(sock, 1)[0] + 2)
        else:
            raise RuntimeError("bad SOCKS address type")
        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        data = b""
        while MARKER not in data:
            try:
                part = sock.recv(4096)
            except socket.timeout:
                return None  # Only an HTTP timeout can satisfy the negative control.
            if not part:
                break
            data += part
        if MARKER not in data or not data.startswith(b"HTTP/1.0 200"):
            raise RuntimeError("HTTP response incomplete: " + repr(data))
        return len(data)


def run_fixture(fixture, old, new, output, http_port, negative=False):
    name = fixture["name"] + ("-negative-without-original-mask" if negative else "")
    path = output / name
    path.mkdir()
    udp_port, socks_port = free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_STREAM)
    inbound = copy.deepcopy(fixture["newInbound"])
    inbound["port"] = udp_port
    if negative:
        original = inbound["streamSettings"]["finalmask"]["udp"].pop(0)
        if original != {"type": "mkcp-legacy", "settings": {"header": "", "value": ""}}:
            raise RuntimeError("negative control did not find the original authenticator")
    server = {
        "log": {"loglevel": "debug"}, "inbounds": [inbound],
        # Current freedom blocks loopback by default. Permit only this test target.
        "outbounds": [{"protocol": "freedom", "settings": {
            "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}],
        }}],
    }
    client = {
        "log": {"loglevel": "debug"},
        # Only SOCKS TCP CONNECT is used. A SOCKS UDP listener can steal the
        # legacy KCP client's replies when its ephemeral UDP source port overlaps.
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{
            "address": "127.0.0.1", "port": udp_port,
            "users": [{"id": CLIENT_ID, "encryption": "none"}],
        }]}, "streamSettings": fixture["oldStream"]}],
    }
    procs, logs = [], []
    started = time.monotonic()
    result = {"name": name, "expected": "http-timeout" if negative else "success",
              "masks": inbound["streamSettings"].get("finalmask", {}).get("udp")}
    try:
        for label, binary, config in [("server", new, server), ("client", old, client)]:
            config_file = path / (label + ".json")
            config_file.write_text(json.dumps(config, indent=2))
            log = (path / (label + ".log")).open("w")
            logs.append(log)
            procs.append(subprocess.Popen(
                [binary, "run", "-config", str(config_file)], stdout=log, stderr=subprocess.STDOUT,
            ))
        for _ in range(60):
            if any(p.poll() is not None for p in procs):
                raise RuntimeError("core exited early: " + str([p.poll() for p in procs]))
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("SOCKS listener did not start")
        response_bytes = transfer(socks_port, http_port)
        if any(p.poll() is not None for p in procs):
            raise RuntimeError("core exited during the request")
        result["actual"] = "http-timeout" if response_bytes is None else "success"
        if response_bytes is not None:
            result["response_bytes"] = response_bytes
    except Exception as error:
        result.update(actual="error", error=str(error))
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for log in logs:
            log.close()
    result["passed"] = result["actual"] == result["expected"]
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    print(json.dumps(result), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--legacy-xray", default=os.environ.get("LEGACY_XRAY_BINARY"), help="old client executable (or LEGACY_XRAY_BINARY)")
    parser.add_argument("--xray", default=os.environ.get("XUI_TEST_XRAY"), help="current server executable (or XUI_TEST_XRAY)")
    parser.add_argument("--go", default="go", help="local Go executable (default: go on PATH)")
    parser.add_argument("--output-dir", type=Path, help="new directory for configurations, logs, and results; default: temporary directory")
    parser.add_argument("--fixtures-only", action="store_true", help="export current model fixtures and check empty-seed rejection without starting Xray")
    args = parser.parse_args()
    try:
        go = binary_path(args.go, "--go")
        if not args.fixtures_only:
            old = binary_path(args.legacy_xray, "--legacy-xray / LEGACY_XRAY_BINARY")
            new = binary_path(args.xray, "--xray / XUI_TEST_XRAY")
        output = args.output_dir.resolve() if args.output_dir else Path(tempfile.mkdtemp(prefix="3x-ui-kcp-compat-"))
        if args.output_dir:
            output.mkdir(parents=True, exist_ok=False)
        print(f"Artifacts: {output}", flush=True)
        fixtures = export_fixtures(go, output)
        if args.fixtures_only:
            print(f"Exported {len(fixtures)} model fixtures; explicit empty seed rejected.")
            return 0
        versions = {label: subprocess.check_output([binary, "version"], text=True).strip()
                    for label, binary in [("client", old), ("server", new)]}
        print(json.dumps(versions), flush=True)
        http_server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=http_server.serve_forever, daemon=True).start()
        try:
            results = [run_fixture(f, old, new, output, http_server.server_port) for f in fixtures]
            results.append(run_fixture(fixtures[-1], old, new, output, http_server.server_port, negative=True))
        finally:
            http_server.shutdown()
            http_server.server_close()
        (output / "results.json").write_text(json.dumps({"versions": versions, "cases": results}, indent=2))
        return 0 if all(r["passed"] for r in results) else 1
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
