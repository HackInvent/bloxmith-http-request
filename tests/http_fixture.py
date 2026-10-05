"""Owned local test API. No requests leave loopback and no real credentials are loaded."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
from types import SimpleNamespace


@contextmanager
def api_fixture(tls=False):
    """Create a bounded disposable HTTP(S) service and stop every owned thread."""
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        closing, calls = threading.Event(), []
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *args):
                pass
            def do_HEAD(self):
                self.handle_request()
            def do_GET(self):
                self.handle_request()
            def do_POST(self):
                self.handle_request()
            def handle_request(self):
                body = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 1048577))
                calls.append({"method": self.command, "path": self.path, "body": body,
                              "authorization": self.headers.get("Authorization", ""),
                              "api_key": self.headers.get("X-API-Key", "")})
                code, payload, headers, content_type = 200, {"ok": True}, {}, "application/json"
                if self.path.startswith("/v1/page"):
                    if "page=2" in self.path:
                        payload = {"page": 2}
                    else:
                        payload = {"page": 1}
                        headers["Link"] = '<?page=2>; rel="next"'
                elif self.path.startswith("/v1/next-outside"):
                    headers["Link"] = '</outside>; rel="next"'
                elif self.path.startswith("/v1/redirect-outside"):
                    code, headers["Location"] = 302, "/outside"
                elif self.path.startswith("/v1/redirect"):
                    code, headers["Location"] = 302, "/v1/ok"
                elif self.path.startswith("/v1/mutation"):
                    payload = {"applied": True}
                elif self.path.startswith("/v1/slow"):
                    closing.wait(5)
                elif self.path.startswith("/v1/large"):
                    payload = {"text": "x" * 8192}
                elif self.path.startswith("/v1/error"):
                    code, payload = 503, {"message": "Temporary failure"}
                elif self.path.startswith("/v1/duplicate"):
                    payload = b'{"x":1,"x":2}'
                elif self.path.startswith("/v1/binary"):
                    content_type, payload = "application/octet-stream", b"binary"
                elif self.path.startswith("/v1/echo-secret"):
                    payload = {"value": self.headers.get("Authorization", "")}
                elif self.path.startswith("/v1/auth"):
                    payload = {"authenticated": self.headers.get("Authorization") == "Bearer fixture-dummy-token",
                               "custom_header": self.headers.get("X-API-Key") == "fixture-dummy-token"}
                elif self.path.startswith("/v1/text"):
                    content_type, payload = "text/plain; charset=utf-8", "Café fixture".encode("utf-8")
                elif self.path.startswith("/v1/truncated"):
                    payload = b'{"ok":true}'
                    headers["Content-Length"] = str(len(payload) + 10)
                elif self.path.startswith("/v1/compressed"):
                    headers["Content-Encoding"] = "gzip"
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
                if closing.is_set():
                    return
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", content_type)
                    if "Content-Length" not in headers:
                        self.send_header("Content-Length", str(99999999 if self.command == "HEAD" else len(raw)))
                    self.send_header("Connection", "close")
                    self.send_header("Set-Cookie", "do-not-forward=fixture")
                    for key, value in headers.items():
                        self.send_header(key, value)
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(raw)
                except (BrokenPipeError, ConnectionError):
                    pass
                finally:
                    self.close_connection = True
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = False
        ca = None
        if tls:
            assert shutil.which("openssl"), "OpenSSL is required for disposable HTTPS tests"
            ca, key = directory / "ca.pem", directory / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(key), "-out", str(ca), "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, timeout=15,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(ca, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05})
        thread.start()
        try:
            yield SimpleNamespace(base_url=("https" if tls else "http") + "://127.0.0.1:" + str(server.server_port) + "/v1/",
                ca_file=str(ca) if ca else "", calls=calls)
        finally:
            closing.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            assert not thread.is_alive()
