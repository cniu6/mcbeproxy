#!/usr/bin/env python3
"""Launch the actual server with isolated synthetic data and exercise export APIs.

Does not modify a running server, installed client, or system proxy settings.
The resulting JSON is input for the independent native v2rayN oracle.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    fixtures = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))
    nodes = [c for c in fixtures["cases"] if c.get("source")]
    work = Path(tempfile.mkdtemp(prefix="mcbeproxy-export-smoke-"))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        api_port = s.getsockname()[1]
    key = secrets.token_hex(24)
    cfg = {
        "api_port": api_port, "api_key": key, "api_entry_path": "/export-smoke",
        "database_path": str(work / "data.db"), "log_dir": str(work / "logs"),
        "proxy_ports_enabled": False,
    }
    (work / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    (work / "server_list.json").write_text("[]", encoding="utf-8")
    (work / "proxy_subscriptions.json").write_text("[]", encoding="utf-8")
    sources = [dict(c["source"], enabled=False) for c in nodes]
    sources += [
        {"name": "unsupported-http", "type": "http", "server": "example.com", "port": 8080, "enabled": False},
        {"name": "unsupported-hy1", "type": "hysteria", "server": "example.com", "port": 443, "password": "fake-pass", "enabled": False},
    ]
    (work / "proxy_outbounds.json").write_text(json.dumps(sources, ensure_ascii=False), encoding="utf-8")
    ports = [
        {"id": "socks", "name": "SOCKS API", "type": "socks5", "listen_addr": "127.0.0.1:1080", "enabled": False,
         "username": "u+name", "password": "p:a%2F +中文"},
        {"id": "http", "name": "HTTP API", "type": "http", "listen_addr": "127.0.0.1:8081", "enabled": False},
    ]
    (work / "proxy_ports.json").write_text(json.dumps(ports, ensure_ascii=False), encoding="utf-8")
    base = f"http://127.0.0.1:{api_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, body=None, auth=True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["X-API-Key"] = key
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(base + path, data=data, headers=headers)
        try:
            with opener.open(req, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, json.load(exc)

    output = {"scope": "actual mcbeproxy HTTP API; v2rayN parsing is a separate driver", "cases": []}
    checks = []
    with (work / "server.log").open("w", encoding="utf-8") as log:
        proc = subprocess.Popen([str(Path(args.server).resolve()), "-config", str(work / "config.json"),
                                 "-servers", str(work / "server_list.json")], cwd=work, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 25
            while True:
                if proc.poll() is not None:
                    raise RuntimeError(f"server exited {proc.returncode}; see {work / 'server.log'}")
                try:
                    status, _ = request("/api/public/status", auth=False)
                    if status == 200:
                        break
                except (OSError, ValueError):
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError("server readiness timed out")
                time.sleep(0.2)
            names = [p["name"] for p in sources]
            status, _ = request("/api/proxy-outbounds/export", {"names": names, "format": "share"}, auth=False)
            assert status == 401, f"export auth guard: {status}"
            checks.append("unauthenticated export rejected")
            for fmt in ("share", "links"):
                status, body = request("/api/proxy-outbounds/export", {"names": names, "format": fmt})
                assert status == 200 and body.get("success"), body
                data = body["data"]
                expected_count = len(nodes) if fmt == "share" else len(sources)
                assert data["count"] == expected_count, data
                assert data["format"] == fmt
                decoded = base64.b64decode(data["content"]).decode("utf-8") if fmt == "share" else data["content"]
                assert decoded.splitlines() == data["links"]
                if fmt == "share":
                    assert len(data["skipped"]) == 2 and all("v2rayN" in s["reason"] for s in data["skipped"])
                    output["cases"].append({"id": "api-node-subscription", "kind": "subscription", "input": data["content"],
                                            "expected": {"profiles": [c["expected"] for c in nodes]}, "expectedAccepted": True})
                    status, parsed = request("/api/proxy-outbounds/parse-import", {"content": data["content"]})
                    assert status == 200 and len(parsed["data"]["items"]) == len(nodes), parsed
                    checks.append("actual parse-import endpoint accepts export")
                checks.append(f"node {fmt} response count/encoding/skipped checked")
            status, body = request("/api/proxy-ports/bulk-share", {"ids": ["socks", "http"], "host": "203.0.113.9", "format": "share"})
            assert status == 200 and body.get("success"), body
            data = body["data"]
            assert data["count"] == 1 and len(data["skipped"]) == 1, data
            output["cases"].append({"id": "api-port-subscription", "kind": "subscription", "input": data["content"],
                                    "expected": {"profiles": [{"configType": "SOCKS", "address": "203.0.113.9", "port": 1080,
                                                                "username": "u+name", "password": "p:a%2F +中文", "valid": True}]}, "expectedAccepted": True})
            checks.append("port batch export filters HTTP and preserves SOCKS credentials")
            status, body = request("/api/proxy-outbounds/export", {"names": ["unsupported-http"], "format": "share"})
            assert status == 400 and "v2rayN" in json.dumps(body, ensure_ascii=False), body
            checks.append("all-unsupported export explains rejection")
            status, body = request("/api/proxy-outbounds/export", {"names": ["unsupported-http", "unsupported-hy1"], "format": "clash"})
            assert status == 200 and body["data"]["count"] == 2 and "proxies:" in body["data"]["content"], body
            checks.append("Clash fallback remains available")
            output["checks"] = checks
            Path(args.out).write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"API smoke passed: {len(checks)} checks; native oracle fixtures: {args.out}")
            print(f"Isolated data and server log: {work}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    main()
