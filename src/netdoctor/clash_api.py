"""Async and sync client for sing-box Clash API (proxies, delay tests, outbound selection, connections)."""

from __future__ import annotations

import urllib.parse
from typing import Any

import httpx


class ClashApiClient:
    """Client for sing-box's experimental Clash API controller."""

    def __init__(
        self,
        controller_addr: str = "127.0.0.1:19090",
        secret: str = "",
        timeout: float = 3.0,
    ) -> None:
        raw_addr = (controller_addr or "127.0.0.1:19090").strip().rstrip("/")
        if raw_addr.startswith(("http://", "https://")):
            self.base_url = raw_addr
        else:
            self.base_url = f"http://{raw_addr}"
        self.controller_addr = raw_addr
        self.secret = secret
        self.timeout = float(timeout)
        self._headers: dict[str, str] = {"Authorization": f"Bearer {secret}"} if secret else {}

    @staticmethod
    def _quote(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    @staticmethod
    def _parse_json_dict(resp: httpx.Response) -> dict[str, Any]:
        if not (200 <= resp.status_code < 300):
            return {}
        try:
            data = resp.json()
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def unwrap_proxies(data: dict[str, Any]) -> dict[str, Any]:
        """Unwrap sing-box Clash API `{"proxies": {...}}` envelope if present."""
        if not isinstance(data, dict):
            return {}
        inner = data.get("proxies")
        return inner if isinstance(inner, dict) else data

    @staticmethod
    def resolve_active_proxy(
        proxies: dict[str, Any],
        selector_tag: str = "vpn-select",
    ) -> tuple[str | None, str | None, float | None]:
        """Return `(direct_selected, resolved_leaf, last_delay_ms)` for a selector outbound."""
        pmap = ClashApiClient.unwrap_proxies(proxies)
        sel = pmap.get(selector_tag)
        if not isinstance(sel, dict) or not sel.get("now"):
            return None, None, None

        direct_selected = str(sel["now"])
        cur = direct_selected
        visited: set[str] = {selector_tag}
        for _ in range(6):
            if cur in visited:
                break
            visited.add(cur)
            info = pmap.get(cur)
            if not isinstance(info, dict) or not info.get("now"):
                break
            cur = str(info["now"])

        last_delay_ms: float | None = None
        leaf_info = pmap.get(cur)
        if isinstance(leaf_info, dict) and isinstance(leaf_info.get("history"), list):
            for entry in reversed(leaf_info["history"]):
                if isinstance(entry, dict) and entry.get("delay") is not None:
                    try:
                        val = float(entry["delay"])
                        if val > 0:
                            last_delay_ms = val
                            break
                    except (TypeError, ValueError):
                        continue
        return direct_selected, cur, last_delay_ms

    @staticmethod
    def _parse_delay_response(resp: httpx.Response) -> dict[str, Any]:
        try:
            payload = resp.json()
        except ValueError:
            payload = None

        if resp.status_code == 200 and isinstance(payload, dict) and payload.get("delay") is not None:
            try:
                return {"ok": True, "delay_ms": float(payload["delay"]), "error": None}
            except (TypeError, ValueError):
                pass

        err_msg: str
        if isinstance(payload, dict) and payload.get("message"):
            err_msg = str(payload["message"])
        elif isinstance(payload, dict) and payload.get("error"):
            err_msg = str(payload["error"])
        else:
            err_msg = resp.text.strip() or f"HTTP {resp.status_code}"
        return {"ok": False, "delay_ms": None, "error": err_msg}

    def _delay_timeout(self, timeout_ms: int) -> float:
        return max(self.timeout, (max(int(timeout_ms), 100) / 1000.0) + 1.5)

    # ------------------------------------------------------------------
    # Async API
    # ------------------------------------------------------------------

    async def get_proxies(self) -> dict[str, Any]:
        """Return `GET /proxies` payload or `{}` if Clash API is unavailable."""
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = await client.get("/proxies")
                return self.unwrap_proxies(self._parse_json_dict(resp))
        except Exception:
            return {}

    async def measure_node_delay(
        self,
        tag: str,
        url: str = "https://www.gstatic.com/generate_204",
        timeout_ms: int = 3500,
    ) -> dict[str, Any]:
        """Measure delay of a single proxy/outbound tag via Clash API."""
        req_timeout = self._delay_timeout(timeout_ms)
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers,
                timeout=req_timeout,
            ) as client:
                resp = await client.get(
                    f"/proxies/{self._quote(tag)}/delay",
                    params={"url": url, "timeout": int(timeout_ms)},
                )
                return self._parse_delay_response(resp)
        except Exception as exc:
            return {"ok": False, "delay_ms": None, "error": str(exc)}

    async def select_outbound(self, selector_tag: str, target_tag: str) -> bool:
        """Select `target_tag` inside a Clash selector outbound (`PUT /proxies/{selector}`)."""
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = await client.put(
                    f"/proxies/{self._quote(selector_tag)}",
                    json={"name": target_tag},
                )
                return 200 <= resp.status_code < 300
        except Exception:
            return False

    async def get_connections(self) -> dict[str, Any]:
        """Return `GET /connections` snapshot or `{}` if Clash API is unavailable."""
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = await client.get("/connections")
                return self._parse_json_dict(resp)
        except Exception:
            return {}

    async def close_connections_by_node(self, node_tag: str) -> int:
        """Close all active connections passing through `node_tag` and return closed count."""
        closed = 0
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = await client.get("/connections")
                data = self._parse_json_dict(resp)
                for conn in data.get("connections") or []:
                    if not isinstance(conn, dict):
                        continue
                    chains = conn.get("chains") or []
                    conn_id = conn.get("id")
                    if conn_id and node_tag in chains:
                        del_resp = await client.delete(f"/connections/{self._quote(str(conn_id))}")
                        if 200 <= del_resp.status_code < 300:
                            closed += 1
        except Exception:
            return closed
        return closed

    # ------------------------------------------------------------------
    # Synchronous helpers (safe to call from GUI/threads/sync code)
    # ------------------------------------------------------------------

    def get_proxies_sync(self) -> dict[str, Any]:
        """Synchronous counterpart of `get_proxies()`."""
        try:
            with httpx.Client(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = client.get("/proxies")
                return self.unwrap_proxies(self._parse_json_dict(resp))
        except Exception:
            return {}

    def measure_node_delay_sync(
        self,
        tag: str,
        url: str = "https://www.gstatic.com/generate_204",
        timeout_ms: int = 3500,
    ) -> dict[str, Any]:
        """Synchronous counterpart of `measure_node_delay()`."""
        req_timeout = self._delay_timeout(timeout_ms)
        try:
            with httpx.Client(
                base_url=self.base_url,
                headers=self._headers,
                timeout=req_timeout,
            ) as client:
                resp = client.get(
                    f"/proxies/{self._quote(tag)}/delay",
                    params={"url": url, "timeout": int(timeout_ms)},
                )
                return self._parse_delay_response(resp)
        except Exception as exc:
            return {"ok": False, "delay_ms": None, "error": str(exc)}

    def select_outbound_sync(self, selector_tag: str, target_tag: str) -> bool:
        """Synchronous counterpart of `select_outbound()`."""
        try:
            with httpx.Client(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = client.put(
                    f"/proxies/{self._quote(selector_tag)}",
                    json={"name": target_tag},
                )
                return 200 <= resp.status_code < 300
        except Exception:
            return False

    def get_connections_sync(self) -> dict[str, Any]:
        """Synchronous counterpart of `get_connections()`."""
        try:
            with httpx.Client(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = client.get("/connections")
                return self._parse_json_dict(resp)
        except Exception:
            return {}

    def close_connections_by_node_sync(self, node_tag: str) -> int:
        """Synchronous counterpart of `close_connections_by_node()`."""
        closed = 0
        try:
            with httpx.Client(
                base_url=self.base_url,
                headers=self._headers,
                timeout=self.timeout,
            ) as client:
                resp = client.get("/connections")
                data = self._parse_json_dict(resp)
                for conn in data.get("connections") or []:
                    if not isinstance(conn, dict):
                        continue
                    chains = conn.get("chains") or []
                    conn_id = conn.get("id")
                    if conn_id and node_tag in chains:
                        del_resp = client.delete(f"/connections/{self._quote(str(conn_id))}")
                        if 200 <= del_resp.status_code < 300:
                            closed += 1
        except Exception:
            return closed
        return closed
