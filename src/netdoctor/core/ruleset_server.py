"""Lightweight HTTP server providing dynamic JSON rule_set endpoints with ETag / 304 support for sing-box."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

DEFAULT_RULESET_PORT = 19091
DEFAULT_RULESET_TAGS: tuple[str, ...] = (
    "rs-doh",
    "rs-smartdns",
    "rs-vpn",
    "rs-vpn-ai",
    "rs-byedpi",
    "rs-quic-reject",
    "rs-bundles-direct",
    "rs-bundles-vpn",
    "rs-bundles-dns-vpn",
)


def _encode_ruleset_payload(rules: list[dict[str, Any]]) -> tuple[bytes, str]:
    payload = {"version": 3, "rules": rules}
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    etag = f'"{hashlib.sha256(body).hexdigest()[:16]}"'
    return body, etag


class RuleSetServer:
    """In-memory HTTP server serving sing-box source rule_set JSON documents on 127.0.0.1."""

    def __init__(self, host: str = "127.0.0.1", preferred_port: int = DEFAULT_RULESET_PORT) -> None:
        self.host = host
        self.preferred_port = int(preferred_port)
        self._lock = threading.RLock()
        self._token = secrets.token_urlsafe(16)
        self._rulesets: dict[str, tuple[bytes, str]] = {
            tag: _encode_ruleset_payload([]) for tag in DEFAULT_RULESET_TAGS
        }
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._port: int = 0

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    @property
    def port(self) -> int:
        with self._lock:
            return self._port

    @property
    def base_url(self) -> str:
        with self._lock:
            p = self._port or self.preferred_port
            return f"http://{self.host}:{p}/{self._token}"

    def url_for(self, tag: str) -> str:
        clean = str(tag or "").strip().lstrip("/")
        if not clean.endswith(".json"):
            clean = f"{clean}.json"
        return f"{self.base_url}/{clean}"

    def update_rulesets(self, rulesets: dict[str, list[dict[str, Any]]]) -> dict[str, str]:
        """Update in-memory rule_set documents and return {tag: etag}."""
        etags: dict[str, str] = {}
        with self._lock:
            for tag, rules in rulesets.items():
                clean_tag = str(tag or "").strip().removesuffix(".json")
                if not clean_tag:
                    continue
                body, etag = _encode_ruleset_payload(list(rules or []))
                self._rulesets[clean_tag] = (body, etag)
                etags[clean_tag] = etag
        return etags

    def get_ruleset_bytes(self, tag: str) -> tuple[bytes, str] | None:
        clean_tag = str(tag or "").strip().lstrip("/").removesuffix(".json")
        with self._lock:
            return self._rulesets.get(clean_tag)

    def start(self) -> str:
        """Start the background HTTP server (choosing a free port if preferred_port is busy) and return base_url."""
        with self._lock:
            if self._httpd is not None and self._thread is not None and self._thread.is_alive():
                return self.base_url

            parent = self

            class _Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def do_GET(self) -> None:  # noqa: N802
                    path = self.path.split("?", 1)[0].strip("/")
                    prefix = f"{parent._token}/"
                    if not path.startswith(prefix):
                        self.send_response(403)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    rel_path = path[len(prefix) :]
                    if not rel_path.endswith(".json"):
                        self.send_response(404)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    tag = rel_path.removesuffix(".json")
                    entry = parent.get_ruleset_bytes(tag)
                    if entry is None:
                        self.send_response(404)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    body, etag = entry
                    inm = (self.headers.get("If-None-Match") or "").strip()
                    inm_norm = inm[2:].strip() if inm.startswith("W/") else inm
                    if inm_norm == etag or inm_norm == etag.strip('"'):
                        self.send_response(304)
                        self.send_header("ETag", etag)
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("ETag", etag)
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                    return

            class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
                allow_reuse_address = True
                daemon_threads = True

            httpd: ThreadingHTTPServer | None = None
            for cand_port in (self.preferred_port, 0):
                try:
                    httpd = _ReusableThreadingHTTPServer((self.host, cand_port), _Handler)
                    break
                except OSError:
                    continue
            if httpd is None:
                raise RuntimeError(f"Unable to bind RuleSetServer on {self.host}")
            self._httpd = httpd
            self._port = int(httpd.server_address[1])
            self._thread = threading.Thread(target=httpd.serve_forever, name="netdoctor-ruleset-srv", daemon=True)
            self._thread.start()
            return self.base_url

    def stop(self) -> None:
        with self._lock:
            httpd = self._httpd
            thr = self._thread
            self._httpd = None
            self._thread = None
            self._port = 0
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        if thr is not None and thr.is_alive() and thr is not threading.current_thread():
            thr.join(timeout=1.5)
