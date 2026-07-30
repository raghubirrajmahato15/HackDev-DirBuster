"""
A tiny local HTTP server simulating exactly the behaviors HackDev-DirBuster
is designed to handle: a real directory (redirect), a soft-404 wildcard that
returns 200 for literally anything unknown, a WordPress-like signal on the
root page, and a path that throttles with 429 a few times before succeeding.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

KNOWN_PATHS = {"realdir", "realdir/", "admin"}


class DirBusterTestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    throttle_counters: dict[str, int] = {}
    throttle_lock = threading.Lock()

    def log_message(self, format, *args):  # noqa: A002
        pass

    def _send(self, status: int, body: str, headers: dict[str, str] | None = None) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):  # noqa: N802
        path = self.path.lstrip("/")

        if path == "":
            # Root page: carries a WordPress-like signal for tech detection.
            self._send(200, "<html><body>Welcome. See wp-content/uploads for media.</body></html>")

        elif path == "realdir":
            self._send(301, "", headers={"Location": "/realdir/"})

        elif path == "realdir/":
            self._send(200, "<html><body>Index of /realdir/</body></html>")

        elif path == "admin":
            self._send(200, "<html><body>Admin panel</body></html>")

        elif path == "throttle":
            key = self.client_address[0]
            with self.throttle_lock:
                count = self.throttle_counters.get(key, 0)
                self.throttle_counters[key] = count + 1
            if count < 3:
                self._send(429, "slow down", headers={"Retry-After": "0"})
            else:
                self._send(200, "<html><body>ok now</body></html>")

        else:
            # Soft-404: EVERY unknown path returns 200 with a near-identical
            # generic page instead of a real 404, to exercise both the
            # baseline soft-404 detector and the fingerprint-dedup collapse.
            self._send(200, f"<html><body>Nothing found for {path} - try again later. Ref #{hash(path) % 1000}</body></html>")


@pytest.fixture()
def dirbuster_server():
    DirBusterTestHandler.throttle_counters = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), DirBusterTestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/"
    server.shutdown()
    server.server_close()
