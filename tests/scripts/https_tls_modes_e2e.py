#!/usr/bin/env python3
"""Test the actual Linux binary with file and pasted-PEM HTTPS proxy entries.

Run as root in Linux/WSL:
  python3 -I https_tls_modes_e2e.py --binary /absolute/path/to/linux/binary

The script re-execs itself in a new network namespace containing only loopback.
All configs, keys and the database live in a new temporary directory. No hosts,
firewall, system trust, real nodes or existing app processes are modified.
Requires Python 3, openssl, curl, ip and unshare; refuses non-isolated execution.
"""

import argparse
import copy
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

API_KEY = "isolated-tls-modes-test-key"
USER, PASSWORD = "test-user", "test-password"
BODY = b"https-modes-e2e-ok"
SERVER_NAME = "proxy.e2e.test"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def without_proxies():
    return {k: v for k, v in os.environ.items() if k.lower() not in {
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        "ssl_cert_file", "ssl_cert_dir", "curl_ca_bundle",
    }}


def generate_certificates(work):
    def openssl(*args):
        result = subprocess.run(["openssl", *args], cwd=work, capture_output=True, timeout=15)
        require(result.returncode == 0, "test certificate generation failed")

    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "2", "-subj", "/CN=isolated-test-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", "ca.key", "-out", "ca.pem")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-subj", "/CN=" + SERVER_NAME,
            "-keyout", "proxy.key", "-out", "proxy.csr")
    (work / "leaf.ext").write_text(
        "subjectAltName=DNS:" + SERVER_NAME + ",IP:127.0.0.1\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n", encoding="utf-8")
    for name, serial in [("first", "1001"), ("renewed", "1002")]:
        openssl("x509", "-req", "-in", "proxy.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-set_serial", serial, "-days", "1", "-extfile", "leaf.ext", "-out", name + ".pem")
        (work / (name + "-chain.pem")).write_bytes(
            (work / (name + ".pem")).read_bytes() + (work / "ca.pem").read_bytes())
    shutil.copyfile(work / "first-chain.pem", work / "live.pem")
    os.chmod(work / "proxy.key", 0o600)


class Origin(http.server.BaseHTTPRequestHandler):
    credential_leaked = False

    def do_GET(self):
        if self.headers.get("Proxy-Authorization"):
            Origin.credential_leaked = True
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        pass


class Check:
    def __init__(self, binary, work):
        self.work = work
        self.api_port = free_port()
        self.proc = None
        self.log = (work / "app.log").open("wb")
        self.env = without_proxies()
        self.passed = 0
        self.http_origin = None
        self.https_origin = None
        shutil.copyfile(binary, work / "app")
        (work / "app").chmod(0o700)
        for name in ["server_list.json", "proxy_outbounds.json", "proxy_subscriptions.json", "proxy_ports.json"]:
            (work / name).write_text("[]", encoding="utf-8")
        (work / "config.json").write_text(json.dumps({
            "api_port": self.api_port, "api_key": API_KEY, "proxy_ports_enabled": True,
            "database_path": "isolated.db", "log_dir": "logs", "api_entry_path": "/mcpe-admin",
        }), encoding="utf-8")

    def passed_check(self, name):
        self.passed += 1
        print("[PASS] " + name, flush=True)

    def api(self, method, path, data=None, expected=200):
        conn = http.client.HTTPConnection("127.0.0.1", self.api_port, timeout=8)
        try:
            body = None if data is None else json.dumps(data).encode()
            conn.request(method, path, body, {"X-API-Key": API_KEY, "Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read()
            require(response.status == expected, method + " " + path + ": HTTP " + str(response.status))
            # Don't print responses/requests: they may contain sensitive test values if the app regresses.
            require(b"-----BEGIN" not in raw and b'"key_pem":' not in raw and b'"cert_pem":' not in raw,
                    "API response exposed PEM material")
            require(response.getheader("Cache-Control") == "no-store", "API response is cacheable")
            result = json.loads(raw)
            require(bool(result.get("success")) == (expected == 200), "API success flag mismatch")
            return result.get("data")
        finally:
            conn.close()

    def start(self):
        self.proc = subprocess.Popen([str(self.work / "app")], cwd=self.work, env=self.env,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(80):
            require(self.proc.poll() is None, "app exited before API readiness")
            try:
                self.api("GET", "/api/proxy-ports")
                return
            except (OSError, http.client.HTTPException):
                time.sleep(0.25)
        raise RuntimeError("app API readiness timed out")

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def close(self):
        self.stop()
        for origin in [self.http_origin, self.https_origin]:
            if origin is not None:
                origin.shutdown()
                origin.server_close()
        self.log.close()

    def port(self, ident, tls=None, kind="https"):
        value = {"id": ident, "name": ident, "type": kind, "enabled": True,
                 "listen_addr": "127.0.0.1:" + str(free_port()),
                 "username": USER, "password": PASSWORD, "allow_list": ["127.0.0.1/32"]}
        if tls is not None:
            value["tls"] = tls
        return value

    def create(self, cfg):
        saved = self.api("POST", "/api/proxy-ports", cfg)
        if cfg["type"] == "https":
            inline = cfg["tls"].get("mode") == "pem"
            require(saved["tls"]["has_key_pem"] == inline and saved["tls"]["has_cert_pem"] == inline,
                    "create lost PEM presence flags")
        return saved

    def listed(self, ident):
        return next(x for x in self.api("GET", "/api/proxy-ports") if x["id"] == ident)

    def persisted(self, ident):
        records = json.loads((self.work / "proxy_ports.json").read_text())
        return next(x for x in records if x["id"] == ident)

    def update(self, cfg, expected=200):
        return self.api("PUT", "/api/proxy-ports/" + cfg["id"], cfg, expected)

    def curl(self, cfg, target, trust=True, credentials=True, password=PASSWORD):
        # --noproxy '' is essential: environment NO_PROXY must not bypass the tested listener.
        scheme = "https" if cfg["type"] == "https" else "http"
        args = ["curl", "--silent", "--max-time", "8", "--noproxy", "", "--proxy",
                scheme + "://" + cfg["listen_addr"], "--cacert", str(self.work / "ca.pem")]
        if trust and scheme == "https":
            args += ["--proxy-cacert", str(self.work / "ca.pem")]
        if credentials:
            args += ["--proxy-user", USER + ":" + password]
        result = subprocess.run(args + ["--write-out", "\n%{http_code}", target],
                                env=self.env, capture_output=True, timeout=12)
        body, _, status = result.stdout.rpartition(b"\n")
        return result.returncode, status.decode(), body

    def forwarded(self, cfg, url):
        code, status, body = self.curl(cfg, url)
        require(code == 0 and status == "200" and body == BODY, "forwarding failed for " + cfg["id"])

    def serial(self, cfg, name=SERVER_NAME):
        context = ssl.create_default_context(cafile=str(self.work / "ca.pem"))
        with socket.create_connection(("127.0.0.1", int(cfg["listen_addr"].rsplit(":", 1)[1])), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=name) as conn:
                return conn.getpeercert()["serialNumber"]

    def run(self):
        generate_certificates(self.work)
        cert = (self.work / "first-chain.pem").read_text()
        renewed = (self.work / "renewed-chain.pem").read_text()
        key = (self.work / "proxy.key").read_text()
        ca = str(self.work / "ca.pem")
        self.http_origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        self.https_origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.work / "first-chain.pem", self.work / "proxy.key")
        self.https_origin.socket = context.wrap_socket(self.https_origin.socket, server_side=True)
        for origin in [self.http_origin, self.https_origin]:
            threading.Thread(target=origin.serve_forever, daemon=True).start()
        http_url = "http://127.0.0.1:" + str(self.http_origin.server_port) + "/"
        https_url = "https://127.0.0.1:" + str(self.https_origin.server_port) + "/"
        self.start()
        initial_pid = self.proc.pid
        self.passed_check("real app starts with isolated empty configuration")

        plain = self.create(self.port("plain", kind="http"))
        file = self.create(self.port("file", {"cert_file": str(self.work / "live.pem"),
            "key_file": str(self.work / "proxy.key"), "server_name": SERVER_NAME, "ca_file": ca}))
        inline = self.create(self.port("inline", {"mode": "pem", "cert_pem": cert,
            "key_pem": key, "server_name": SERVER_NAME, "ca_file": ca}))
        self.passed_check("legacy file and PEM creation; responses hide certificate/key bodies")
        self.forwarded(plain, http_url)
        self.passed_check("existing HTTP listener still forwards")

        for cfg in [file, inline]:
            self.forwarded(cfg, http_url)
            self.forwarded(cfg, https_url)
            self.passed_check(cfg["id"] + ": verified HTTPS proxy forwards HTTP and CONNECT HTTPS")
            for credentials, password in [(False, PASSWORD), (True, "wrong-password")]:
                _, status, _ = self.curl(cfg, http_url, credentials=credentials, password=password)
                require(status == "407", "missing/wrong proxy password did not yield 407")
            self.passed_check(cfg["id"] + ": missing/wrong password rejected (407)")
            code, _, _ = self.curl(cfg, http_url, trust=False)
            require(code == 60, "untrusted proxy certificate was accepted")
            try:
                self.serial(cfg, "wrong.example.test")
            except ssl.SSLCertVerificationError:
                pass
            else:
                raise RuntimeError("wrong certificate name was accepted")
            self.passed_check(cfg["id"] + ": untrusted certificate and wrong name rejected")
            plaintext = dict(cfg, type="http")
            code, _, _ = self.curl(plaintext, http_url)
            require(code != 0, "HTTPS listener accepted a plaintext proxy request")
            result = self.api("POST", "/api/proxy-ports/" + cfg["id"] + "/test", {"url": http_url})
            require(result["success"], "connectivity test API failed")
            self.passed_check(cfg["id"] + ": no plaintext downgrade; app connectivity test passes")

        require(not Origin.credential_leaked, "origin received proxy credentials")
        self.passed_check("origin never receives Proxy-Authorization")
        require((self.work / "proxy_ports.json").stat().st_mode & 0o777 == 0o600, "PEM config is not owner-only")
        require(self.persisted("inline")["tls"]["key_pem"] == key, "inline key was not persisted")
        self.passed_check("inline key persisted to config with POSIX 0600 permissions")

        edit = self.listed("inline")
        require(edit["tls"]["has_cert_pem"] and edit["tls"]["has_key_pem"], "list lost configured flags")
        edit["name"] = "renamed without resending secrets"
        self.update(edit)
        require(self.persisted("inline")["tls"]["key_pem"] == key, "redacted roundtrip erased key")
        self.forwarded(inline, http_url)
        self.passed_check("list/edit/save leaves saved PEM intact when text is omitted")

        before = self.serial(inline)
        bad = copy.deepcopy(edit)
        bad["tls"]["key_pem"] = "invalid-private-key-test-marker"
        self.update(bad, expected=400)
        require(self.persisted("inline")["tls"]["key_pem"] == key and self.serial(inline) == before,
                "bad PEM replacement changed saved material or live certificate")
        self.forwarded(inline, http_url)
        self.passed_check("invalid PEM update rejected; existing TLS listener keeps forwarding")
        edit["tls"]["cert_pem"] = renewed
        self.update(edit)
        require(self.serial(inline) != before and self.persisted("inline")["tls"]["key_pem"] == key,
                "certificate-only PEM replacement failed")
        require(self.proc.pid == initial_pid and self.proc.poll() is None, "PEM update restarted process")
        self.forwarded(inline, https_url)
        self.passed_check("PEM certificate-only rotation preserves key and does not restart app")

        before_file = self.serial(file)
        (self.work / "next.pem").write_text(renewed, encoding="utf-8")
        (self.work / "next.pem").replace(self.work / "live.pem")
        require(self.serial(file) != before_file, "file renewal not detected")
        self.passed_check("file-mode certificate renewal still applies on the next handshake")

        for suffix, payload in [
            ("/inline/share", {"address": SERVER_NAME, "format": "clash"}),
            ("/bulk-share", {"ids": ["inline", "file"], "host": SERVER_NAME, "format": "clash"}),
        ]:
            self.api("POST", "/api/proxy-ports" + suffix, payload)
        self.passed_check("single/bulk export never returns certificate or private key PEM")

        edit = self.listed("inline")
        edit["tls"] = {"mode": "file", "server_name": SERVER_NAME, "ca_file": ca,
                       "cert_file": str(self.work / "live.pem"), "key_file": str(self.work / "proxy.key")}
        self.update(edit)
        stored = self.persisted("inline")["tls"]
        require(not stored.get("key_pem") and not stored.get("cert_pem"), "file switch retained inline material")
        self.forwarded(inline, http_url)
        edit["tls"] = {"mode": "pem", "server_name": SERVER_NAME, "ca_file": ca,
                       "cert_pem": renewed, "key_pem": key}
        self.update(edit)
        self.forwarded(inline, https_url)
        self.passed_check("PEM/file mode switches require a new source and both keep forwarding")
        bad = self.listed("inline")
        bad["tls"] = {"mode": "file", "server_name": SERVER_NAME}
        self.update(bad, expected=400)
        self.forwarded(inline, http_url)
        self.passed_check("incomplete source switch cannot overwrite the working entry")

        self.stop()
        self.start()
        self.forwarded(inline, http_url)
        self.forwarded(file, https_url)
        self.passed_check("restart restores both listener modes directly from persisted config")
        require(not Origin.credential_leaked, "proxy credentials leaked during later checks")
        print("summary: " + str(self.passed) + " passed, 0 failed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--isolated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(sys.platform.startswith("linux"), "run this test in Linux/WSL")
    require(os.geteuid() == 0, "root is required to create a network namespace")
    binary = args.binary.resolve(strict=True)
    for command in ["unshare", "ip", "openssl", "curl"]:
        require(shutil.which(command) is not None, "missing prerequisite: " + command)
    if not args.isolated:
        return subprocess.run(["unshare", "--net", "--", sys.executable, "-I", str(Path(__file__).resolve()),
                               "--binary", str(binary), "--isolated"]).returncode
    interfaces = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    require({x["ifname"] for x in interfaces} == {"lo"}, "refusing to run outside loopback-only namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with tempfile.TemporaryDirectory(prefix="mcbeproxy-tls-modes-") as directory:
        check = Check(binary, Path(directory))
        try:
            check.run()
        finally:
            check.close()
    print("cleanup: owned process stopped; temporary configs/keys removed; namespace released", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        # Intentionally no request/response/PEM dumps on failure.
        print("[FAIL] " + str(error), file=sys.stderr)
        sys.exit(1)
