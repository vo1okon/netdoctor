"""SQLite storage for networks, verdicts, decisions, strategies, and VPN subscriptions."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netdoctor.models import (
    Decision,
    DiagnosticReport,
    NetworkFingerprint,
    NetworkKind,
    ProbesSummary,
    Protocol,
    RecommendedAction,
    Strategy,
    VerdictClass,
)


CURRENT_DB_VERSION = 2

_INITIALIZED_DB_SIGNATURES: dict[str, tuple[int, int, int]] = {}
_INIT_DB_LOCK = threading.Lock()


class Storage:
    def __init__(self, db_path: str | Path = "netdoctor.db") -> None:
        self.db_path = Path(db_path)
        is_memory = str(db_path) == ":memory:"
        pre_sig: tuple[int, int, int] | None = None
        resolved_key = ""
        if not is_memory:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            resolved_key = str(self.db_path.resolve())
            try:
                st = self.db_path.stat()
                if st.st_size > 0:
                    pre_sig = (int(st.st_dev), int(st.st_ino), int(st.st_ctime_ns))
            except OSError:
                pre_sig = None

        self.conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA busy_timeout=10000")
            need_init = is_memory or pre_sig is None
            if not need_init and resolved_key:
                with _INIT_DB_LOCK:
                    need_init = _INITIALIZED_DB_SIGNATURES.get(resolved_key) != pre_sig
            if need_init:
                try:
                    self.conn.execute("PRAGMA journal_mode=WAL")
                except (OSError, sqlite3.OperationalError):
                    pass
                self._init_schema()
                if not is_memory and resolved_key:
                    try:
                        st_after = self.db_path.stat()
                        if st_after.st_size > 0:
                            with _INIT_DB_LOCK:
                                if len(_INITIALIZED_DB_SIGNATURES) > 64:
                                    _INITIALIZED_DB_SIGNATURES.clear()
                                _INITIALIZED_DB_SIGNATURES[resolved_key] = (
                                    int(st_after.st_dev),
                                    int(st_after.st_ino),
                                    int(st_after.st_ctime_ns),
                                )
                    except OSError:
                        pass
        except Exception:
            self.conn.close()
            raise

    def get_schema_version(self) -> int:
        """Return the SQLite `PRAGMA user_version` schema version."""
        row = self.conn.execute("PRAGMA user_version").fetchone()
        return int(row[0]) if row else 0

    def _init_schema(self) -> None:
        ver = self.get_schema_version()
        if ver < 1:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS networks (
                    network_key TEXT PRIMARY KEY,
                    asn INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    isp TEXT DEFAULT '',
                    gateway_mac TEXT DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS verdicts (
                    network_key TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    verdicts_json TEXT NOT NULL,
                    probes_json TEXT NOT NULL,
                    recommended_json TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    bypass_active INTEGER NOT NULL DEFAULT 0,
                    checked_at TEXT NOT NULL,
                    ttl_sec INTEGER NOT NULL,
                    PRIMARY KEY (network_key, domain, protocol)
                );

                CREATE TABLE IF NOT EXISTS decisions (
                    network_key TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    strategy_id TEXT,
                    fallback_json TEXT NOT NULL DEFAULT '[]',
                    ttfb_ms REAL,
                    throughput_kbps REAL,
                    consecutive_fails INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'active',
                    pinned INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    ttl_sec INTEGER NOT NULL DEFAULT 21600,
                    PRIMARY KEY (network_key, domain, protocol)
                );

                CREATE TABLE IF NOT EXISTS strategies (
                    id TEXT PRIMARY KEY,
                    family TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    tier INTEGER NOT NULL,
                    args_json TEXT NOT NULL,
                    description TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS subscriptions (
                    id TEXT PRIMARY KEY,
                    url_or_uri TEXT NOT NULL,
                    nodes_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custom_dns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    doh_url TEXT DEFAULT '',
                    description TEXT DEFAULT '',
                    category TEXT DEFAULT 'custom',
                    badges_json TEXT DEFAULT '["DoH"]',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vpn_node_health (
                    node_tag TEXT PRIMARY KEY,
                    subscription_id TEXT NOT NULL DEFAULT 'default',
                    cb_state TEXT NOT NULL DEFAULT 'closed',
                    consecutive_fails INTEGER NOT NULL DEFAULT 0,
                    quarantined_until TEXT DEFAULT '',
                    ewma_rtt_ms REAL,
                    protocol_ok INTEGER NOT NULL DEFAULT 1,
                    egress_ip TEXT DEFAULT '',
                    egress_country TEXT DEFAULT '',
                    target_caps_json TEXT DEFAULT '{}',
                    last_error TEXT DEFAULT '',
                    last_checked_at TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS domain_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network_key TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    service_group TEXT NOT NULL DEFAULT '',
                    preset_id TEXT NOT NULL DEFAULT '',
                    strategy_id TEXT NOT NULL DEFAULT '',
                    ok INTEGER NOT NULL,
                    status_code INTEGER,
                    latency_ms REAL,
                    stage TEXT NOT NULL DEFAULT 'https',
                    error TEXT NOT NULL DEFAULT '',
                    tested_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_domain_tests_net_dom
                    ON domain_tests (network_key, domain, id DESC);

                CREATE TABLE IF NOT EXISTS zapret_presets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    content TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'user',
                    is_working INTEGER NOT NULL DEFAULT 1,
                    success_rate REAL,
                    last_tested_at TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            with self.conn:
                self.conn.execute("PRAGMA user_version = 1")
            ver = 1

        if ver < 2:
            with self.conn:
                dec_cols = {
                    str(r["name"])
                    for r in self.conn.execute("PRAGMA table_info(decisions)").fetchall()
                }
                if "pinned" not in dec_cols:
                    self.conn.execute("ALTER TABLE decisions ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
                self.conn.execute("PRAGMA user_version = 2")
            ver = 2

    def upsert_network(self, net: NetworkFingerprint) -> str:
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        with self.conn:
            row = self.conn.execute(
                "SELECT first_seen FROM networks WHERE network_key = ?", (net.key,)
            ).fetchone()
            first_seen = row["first_seen"] if row else now
            self.conn.execute(
                """
                INSERT INTO networks (network_key, asn, kind, isp, gateway_mac, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(network_key) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    isp = excluded.isp
                """,
                (net.key, net.asn, net.kind.value, net.isp, net.gateway_mac, first_seen, now),
            )
            if net.asn > 0 and net.gateway_mac:
                existing_cnt = int(
                    self.conn.execute(
                        "SELECT COUNT(*) FROM decisions WHERE network_key = ?", (net.key,)
                    ).fetchone()[0]
                )
                if existing_cnt == 0:
                    legacy_key = f"AS0:{net.kind.value}:{net.gateway_mac}"
                    self.conn.execute(
                        """
                        INSERT OR IGNORE INTO decisions (
                            network_key, domain, protocol, layer, strategy_id, fallback_json,
                            ttfb_ms, throughput_kbps, consecutive_fails, status, pinned, updated_at, ttl_sec
                        )
                        SELECT
                            ?, domain, protocol, layer, strategy_id, fallback_json,
                            ttfb_ms, throughput_kbps, consecutive_fails, status, pinned, updated_at, ttl_sec
                        FROM decisions
                        WHERE network_key = ?
                          AND (
                              pinned = 1
                              OR layer IN ('dns', 'vpn')
                              OR domain IN (
                                  SELECT domain FROM verdicts
                                  WHERE network_key = ?
                                    AND (
                                        verdicts_json LIKE '%sni_dpi%'
                                        OR verdicts_json LIKE '%throttle%'
                                        OR verdicts_json LIKE '%ip_block%'
                                    )
                              )
                          )
                        """,
                        (net.key, legacy_key, legacy_key),
                    )
        return net.key

    def save_verdict(
        self,
        network_key: str,
        report: DiagnosticReport,
        protocol: Protocol = Protocol.TLS,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO verdicts (
                    network_key, domain, protocol, verdicts_json, probes_json,
                    recommended_json, confidence, bypass_active, checked_at, ttl_sec
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(network_key, domain, protocol) DO UPDATE SET
                    verdicts_json = excluded.verdicts_json,
                    probes_json = excluded.probes_json,
                    recommended_json = excluded.recommended_json,
                    confidence = excluded.confidence,
                    bypass_active = excluded.bypass_active,
                    checked_at = excluded.checked_at,
                    ttl_sec = excluded.ttl_sec
                """,
                (
                    network_key,
                    report.domain,
                    protocol.value,
                    json.dumps([v.value for v in report.verdicts]),
                    report.probes.model_dump_json(),
                    json.dumps([r.model_dump() for r in report.recommended]),
                    report.confidence,
                    1 if report.bypass_active else 0,
                    report.checked_at,
                    report.ttl_sec,
                ),
            )

    def get_verdict(
        self,
        network_key: str,
        domain: str,
        protocol: Protocol = Protocol.TLS,
    ) -> DiagnosticReport | None:
        row = self.conn.execute(
            "SELECT * FROM verdicts WHERE network_key = ? AND domain = ? AND protocol = ?",
            (network_key, domain, protocol.value),
        ).fetchone()
        if not row:
            return None
        net_row = self.conn.execute(
            "SELECT asn, kind, gateway_mac FROM networks WHERE network_key = ?", (network_key,)
        ).fetchone()
        if net_row:
            net_dict: dict[str, Any] = {"asn": net_row["asn"], "kind": net_row["kind"]}
            if net_row["gateway_mac"]:
                net_dict["gateway_mac"] = net_row["gateway_mac"]
        else:
            net_dict = {"asn": 0, "kind": NetworkKind.HOME.value}
        return DiagnosticReport(
            domain=row["domain"],
            network=net_dict,
            checked_at=row["checked_at"],
            bypass_active=bool(row["bypass_active"]),
            probes=ProbesSummary.model_validate_json(row["probes_json"]),
            verdicts=[VerdictClass(v) for v in json.loads(row["verdicts_json"])],
            confidence=row["confidence"],
            recommended=[RecommendedAction(**r) for r in json.loads(row["recommended_json"])],
            ttl_sec=row["ttl_sec"],
        )

    def save_decision(self, decision: Decision) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO decisions (
                    network_key, domain, protocol, layer, strategy_id, fallback_json,
                    ttfb_ms, throughput_kbps, consecutive_fails, status, pinned, updated_at, ttl_sec
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(network_key, domain, protocol) DO UPDATE SET
                    layer = excluded.layer,
                    strategy_id = excluded.strategy_id,
                    fallback_json = excluded.fallback_json,
                    ttfb_ms = excluded.ttfb_ms,
                    throughput_kbps = excluded.throughput_kbps,
                    consecutive_fails = excluded.consecutive_fails,
                    status = excluded.status,
                    pinned = excluded.pinned,
                    updated_at = excluded.updated_at,
                    ttl_sec = excluded.ttl_sec
                """,
                (
                    decision.network_key,
                    decision.domain,
                    decision.protocol.value,
                    decision.layer,
                    decision.strategy_id,
                    json.dumps(decision.fallback_strategies),
                    decision.ttfb_ms,
                    decision.throughput_kbps,
                    decision.consecutive_fails,
                    decision.status,
                    1 if decision.pinned else 0,
                    decision.updated_at,
                    decision.ttl_sec,
                ),
            )

    def set_decision_pinned(
        self,
        network_key: str,
        domain: str,
        protocol: Protocol | str,
        pinned: bool,
    ) -> bool:
        proto_val = protocol.value if isinstance(protocol, Protocol) else str(protocol).strip().lower()
        with self.conn:
            cur = self.conn.execute(
                "UPDATE decisions SET pinned = ? WHERE network_key = ? AND domain = ? AND protocol = ?",
                (1 if pinned else 0, network_key, domain.strip().lower(), proto_val),
            )
        return cur.rowcount > 0

    def get_decisions(self, network_key: str, active_only: bool = True) -> list[Decision]:
        query = "SELECT * FROM decisions WHERE network_key = ?"
        params: list[Any] = [network_key]
        if active_only:
            query += " AND status = 'active'"
        rows = self.conn.execute(query, params).fetchall()
        return [
            Decision(
                network_key=r["network_key"],
                domain=r["domain"],
                protocol=Protocol(r["protocol"]),
                layer=r["layer"],
                strategy_id=r["strategy_id"],
                fallback_strategies=json.loads(r["fallback_json"]),
                ttfb_ms=r["ttfb_ms"],
                throughput_kbps=r["throughput_kbps"],
                consecutive_fails=r["consecutive_fails"],
                status=r["status"],
                pinned=bool(r["pinned"]) if "pinned" in r.keys() else False,
                updated_at=r["updated_at"],
                ttl_sec=r["ttl_sec"],
            )
            for r in rows
        ]

    def upsert_strategies(self, strategies: list[Strategy]) -> None:
        with self.conn:
            for s in strategies:
                self.conn.execute(
                    """
                    INSERT INTO strategies (id, family, protocol, tier, args_json, description)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        family = excluded.family,
                        protocol = excluded.protocol,
                        tier = excluded.tier,
                        args_json = excluded.args_json,
                        description = excluded.description
                    """,
                    (
                        s.id,
                        s.family,
                        s.protocol.value,
                        s.tier,
                        json.dumps(s.args_template),
                        s.description,
                    ),
                )

    def get_strategies(self, protocol: Protocol | None = None) -> list[Strategy]:
        if protocol:
            rows = self.conn.execute(
                "SELECT * FROM strategies WHERE protocol = ? ORDER BY tier ASC, id ASC",
                (protocol.value,),
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM strategies ORDER BY tier ASC, id ASC").fetchall()
        return [
            Strategy(
                id=r["id"],
                family=r["family"],
                protocol=Protocol(r["protocol"]),
                tier=r["tier"],
                args_template=json.loads(r["args_json"]),
                description=r["description"],
            )
            for r in rows
        ]

    def save_subscription(self, sub_id: str, url_or_uri: str, nodes: list[dict[str, Any]]) -> None:
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO subscriptions (id, url_or_uri, nodes_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    url_or_uri = excluded.url_or_uri,
                    nodes_json = excluded.nodes_json,
                    updated_at = excluded.updated_at
                """,
                (sub_id, url_or_uri, json.dumps(nodes), now),
            )

    def get_subscriptions(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id, url_or_uri, nodes_json, updated_at FROM subscriptions ORDER BY id ASC"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "url_or_uri": r["url_or_uri"],
                "nodes": json.loads(r["nodes_json"]),
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def get_all_subscription_nodes(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT id, nodes_json FROM subscriptions ORDER BY id ASC").fetchall()
        priorities_map = self.get_vpn_selection_policy()["priorities"]
        all_nodes: list[dict[str, Any]] = []
        seen: set[str] = set()
        for r in rows:
            sub_id = str(r["id"] or "default")
            for raw_node in json.loads(r["nodes_json"]):
                node = dict(raw_node)
                orig_tag = str(node.get("tag") or "").strip() or "vpn-node"
                shown_name = str(node.get("display_name") or orig_tag).strip() or orig_tag
                node["display_name"] = shown_name
                node_sub_id = str(node.get("subscription_id") or sub_id)
                if orig_tag in seen:
                    base_tag = f"{node_sub_id}__{orig_tag}"
                    final_tag = base_tag
                    suffix = 2
                    while final_tag in seen:
                        final_tag = f"{base_tag}_{suffix}"
                        suffix += 1
                else:
                    final_tag = orig_tag
                seen.add(final_tag)
                node["tag"] = final_tag
                raw_outbound = node.get("raw_outbound")
                if isinstance(raw_outbound, dict):
                    updated_ob = dict(raw_outbound)
                    updated_ob["tag"] = final_tag
                    node["raw_outbound"] = updated_ob
                if final_tag in priorities_map:
                    node["priority"] = int(priorities_map[final_tag])
                elif node.get("priority") is None:
                    node["priority"] = 100
                else:
                    node["priority"] = int(node["priority"])
                raw_reg = str(node.get("region") or "").strip().lower()
                if not raw_reg or raw_reg == "other":
                    from netdoctor.vpn import infer_node_region

                    node["region"] = infer_node_region(shown_name, str(node.get("server") or ""))
                if "enabled" not in node or node.get("enabled") is None:
                    node["enabled"] = True
                else:
                    node["enabled"] = bool(node["enabled"])
                all_nodes.append(node)
        return all_nodes

    def has_usable_vpn(self) -> bool:
        """Return True when hybrid VPN mode is active and at least one usable VPN node is configured."""
        stack_mode = self.get_setting("stack_mode", "hybrid").strip().lower() or "hybrid"
        if stack_mode == "dpi_only":
            return False
        from netdoctor.vpn import has_usable_vpn_nodes

        return has_usable_vpn_nodes(self.get_all_subscription_nodes())

    def upsert_vpn_node_health(self, record: dict[str, Any]) -> None:
        node_tag = str(record.get("node_tag") or record.get("tag") or "").strip()
        if not node_tag:
            raise ValueError("node_tag is required")
        subscription_id = str(record.get("subscription_id") or "default")
        cb_state = str(record.get("cb_state") or "closed")
        consecutive_fails = int(record.get("consecutive_fails") or 0)
        quarantined_until = str(record.get("quarantined_until") or "")
        ewma_raw = record.get("ewma_rtt_ms")
        ewma_rtt_ms = float(ewma_raw) if ewma_raw is not None else None
        protocol_ok = 1 if record.get("protocol_ok", True) else 0
        egress_ip = str(record.get("egress_ip") or "")
        egress_country = str(record.get("egress_country") or "")
        if "target_caps_json" in record and isinstance(record["target_caps_json"], str):
            target_caps_json = record["target_caps_json"]
        elif isinstance(record.get("target_caps"), dict):
            target_caps_json = json.dumps(record["target_caps"])
        elif isinstance(record.get("target_caps_json"), dict):
            target_caps_json = json.dumps(record["target_caps_json"])
        else:
            target_caps_json = "{}"
        last_error = str(record.get("last_error") or "")
        if "last_checked_at" in record:
            last_checked_at = str(record.get("last_checked_at") or "")
        else:
            last_checked_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO vpn_node_health (
                    node_tag, subscription_id, cb_state, consecutive_fails, quarantined_until,
                    ewma_rtt_ms, protocol_ok, egress_ip, egress_country, target_caps_json,
                    last_error, last_checked_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_tag) DO UPDATE SET
                    subscription_id = excluded.subscription_id,
                    cb_state = excluded.cb_state,
                    consecutive_fails = excluded.consecutive_fails,
                    quarantined_until = excluded.quarantined_until,
                    ewma_rtt_ms = excluded.ewma_rtt_ms,
                    protocol_ok = excluded.protocol_ok,
                    egress_ip = excluded.egress_ip,
                    egress_country = excluded.egress_country,
                    target_caps_json = excluded.target_caps_json,
                    last_error = excluded.last_error,
                    last_checked_at = excluded.last_checked_at
                """,
                (
                    node_tag,
                    subscription_id,
                    cb_state,
                    consecutive_fails,
                    quarantined_until,
                    ewma_rtt_ms,
                    protocol_ok,
                    egress_ip,
                    egress_country,
                    target_caps_json,
                    last_error,
                    last_checked_at,
                ),
            )

    def get_vpn_node_health_map(self) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM vpn_node_health ORDER BY node_tag ASC").fetchall()
        out: dict[str, dict[str, Any]] = {}
        for r in rows:
            raw_caps = str(r["target_caps_json"] or "{}")
            try:
                parsed_caps = json.loads(raw_caps)
                if not isinstance(parsed_caps, dict):
                    parsed_caps = {}
            except (json.JSONDecodeError, TypeError):
                parsed_caps = {}
            tag = str(r["node_tag"])
            out[tag] = {
                "node_tag": tag,
                "subscription_id": str(r["subscription_id"] or "default"),
                "cb_state": str(r["cb_state"] or "closed"),
                "consecutive_fails": int(r["consecutive_fails"] or 0),
                "quarantined_until": str(r["quarantined_until"] or ""),
                "ewma_rtt_ms": r["ewma_rtt_ms"],
                "protocol_ok": bool(r["protocol_ok"]),
                "egress_ip": str(r["egress_ip"] or ""),
                "egress_country": str(r["egress_country"] or ""),
                "target_caps_json": raw_caps,
                "target_caps": parsed_caps,
                "last_error": str(r["last_error"] or ""),
                "last_checked_at": str(r["last_checked_at"] or ""),
            }
        return out

    def get_setting(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, str(value)),
            )

    def get_vpn_selection_policy(self) -> dict[str, Any]:
        """Read persisted VPN node selection mode (`auto` | `priority`), preferred node tag, and priority map."""
        raw_mode = self.get_setting("vpn_selection_mode", "auto").strip().lower()
        mode = "priority" if raw_mode == "priority" else "auto"
        priority_node = self.get_setting("vpn_priority_node", "").strip()
        raw_prio = self.get_setting("vpn_node_priorities", "{}")
        priorities: dict[str, int] = {}
        try:
            parsed = json.loads(raw_prio)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    clean_tag = str(k or "").strip()
                    if not clean_tag:
                        continue
                    try:
                        val = max(1, min(999, int(v)))
                    except (TypeError, ValueError):
                        continue
                    priorities[clean_tag] = val
        except (json.JSONDecodeError, TypeError):
            priorities = {}
        return {
            "mode": mode,
            "priority_node": priority_node,
            "priorities": priorities,
        }

    def set_vpn_selection_policy(
        self,
        *,
        mode: str | None = None,
        priority_node: str | None = None,
        priorities: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        """Persist VPN selection mode, preferred priority node tag, and/or per-node priority mapping."""
        if mode is not None:
            clean_mode = "priority" if str(mode).strip().lower() == "priority" else "auto"
            self.set_setting("vpn_selection_mode", clean_mode)
        if priority_node is not None:
            self.set_setting("vpn_priority_node", str(priority_node).strip())
        if priorities is not None:
            sanitized: dict[str, int] = {}
            for k, v in priorities.items():
                clean_tag = str(k or "").strip()
                if not clean_tag:
                    continue
                try:
                    sanitized[clean_tag] = max(1, min(999, int(v)))
                except (TypeError, ValueError):
                    continue
            self.set_setting("vpn_node_priorities", json.dumps(sanitized, ensure_ascii=False))
        return self.get_vpn_selection_policy()

    def save_custom_dns(self, entry: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        dns_id = str(entry["id"]).strip()
        name = str(entry["name"]).strip()
        ip = str(entry["ip"]).strip()
        doh_url = str(entry.get("doh_url") or "").strip()
        desc = str(entry.get("description") or "").strip()
        category = str(entry.get("category") or "custom").strip() or "custom"
        badges = list(entry.get("badges") or (["DoH"] if doh_url else ["Custom"]))
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO custom_dns (id, name, ip, doh_url, description, category, badges_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    ip = excluded.ip,
                    doh_url = excluded.doh_url,
                    description = excluded.description,
                    category = excluded.category,
                    badges_json = excluded.badges_json
                """,
                (dns_id, name, ip, doh_url, desc, category, json.dumps(badges), now),
            )
        return {
            "id": dns_id,
            "name": name,
            "ip": ip,
            "doh_url": doh_url,
            "description": desc,
            "category": category,
            "badges": badges,
            "builtin": False,
            "created_at": now,
        }

    def delete_custom_dns(self, dns_id: str) -> bool:
        with self.conn:
            cur = self.conn.execute("DELETE FROM custom_dns WHERE id = ?", (dns_id,))
        return cur.rowcount > 0

    def get_custom_dns_list(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id, name, ip, doh_url, description, category, badges_json, created_at FROM custom_dns ORDER BY created_at ASC"
        ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                badges = list(json.loads(r["badges_json"] or "[]"))
            except (json.JSONDecodeError, TypeError):
                badges = []
            out.append(
                {
                    "id": str(r["id"]),
                    "name": str(r["name"]),
                    "ip": str(r["ip"]),
                    "doh_url": str(r["doh_url"] or ""),
                    "description": str(r["description"] or ""),
                    "category": str(r["category"] or "custom"),
                    "badges": badges,
                    "builtin": False,
                    "created_at": str(r["created_at"]),
                }
            )
        return out

    # ---------------------------------------------------------------- Domain Connectivity Test History

    def record_domain_test(
        self,
        network_key: str,
        domain: str,
        *,
        ok: bool,
        service_group: str = "",
        preset_id: str = "",
        strategy_id: str = "",
        status_code: int | None = None,
        latency_ms: float | None = None,
        stage: str = "https",
        error: str = "",
        tested_at: str | None = None,
    ) -> dict[str, Any]:
        ts = tested_at or datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        clean_dom = domain.strip().lower()
        with self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO domain_tests (
                    network_key, domain, service_group, preset_id, strategy_id,
                    ok, status_code, latency_ms, stage, error, tested_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    network_key,
                    clean_dom,
                    service_group.strip(),
                    preset_id.strip(),
                    strategy_id.strip(),
                    1 if ok else 0,
                    int(status_code) if status_code is not None else None,
                    round(float(latency_ms), 1) if latency_ms is not None else None,
                    stage.strip() or "https",
                    error.strip(),
                    ts,
                ),
            )
            row_id = int(cur.lastrowid or 0)
            # Keep bounded history (last 30 runs per network+domain)
            self.conn.execute(
                """
                DELETE FROM domain_tests
                WHERE network_key = ? AND domain = ? AND id NOT IN (
                    SELECT id FROM domain_tests
                    WHERE network_key = ? AND domain = ?
                    ORDER BY id DESC LIMIT 30
                )
                """,
                (network_key, clean_dom, network_key, clean_dom),
            )
        return {
            "id": row_id,
            "network_key": network_key,
            "domain": clean_dom,
            "service_group": service_group.strip(),
            "preset_id": preset_id.strip(),
            "strategy_id": strategy_id.strip(),
            "ok": bool(ok),
            "status_code": status_code,
            "latency_ms": round(float(latency_ms), 1) if latency_ms is not None else None,
            "stage": stage.strip() or "https",
            "error": error.strip(),
            "tested_at": ts,
        }

    def get_domain_test_stats(
        self,
        network_key: str,
        window: int = 10,
    ) -> dict[str, dict[str, Any]]:
        """Aggregate recent test pass/fail stats and success rate (%) per domain."""
        rows = self.conn.execute(
            """
            SELECT id, domain, service_group, preset_id, strategy_id,
                   ok, status_code, latency_ms, stage, error, tested_at
            FROM domain_tests
            WHERE network_key = ?
            ORDER BY id DESC
            """,
            (network_key,),
        ).fetchall()

        grouped: dict[str, list[dict[str, Any]]] = {}
        for r in rows:
            dom = str(r["domain"]).lower()
            bucket = grouped.setdefault(dom, [])
            if len(bucket) < max(window, 1):
                bucket.append(
                    {
                        "id": int(r["id"]),
                        "domain": dom,
                        "service_group": str(r["service_group"] or ""),
                        "preset_id": str(r["preset_id"] or ""),
                        "strategy_id": str(r["strategy_id"] or ""),
                        "ok": bool(r["ok"]),
                        "status_code": r["status_code"],
                        "latency_ms": r["latency_ms"],
                        "stage": str(r["stage"] or ""),
                        "error": str(r["error"] or ""),
                        "tested_at": str(r["tested_at"] or ""),
                    }
                )

        stats: dict[str, dict[str, Any]] = {}
        for dom, items in grouped.items():
            total = len(items)
            passed = sum(1 for x in items if x["ok"])
            latencies = [float(x["latency_ms"]) for x in items if x["ok"] and x["latency_ms"] is not None]
            latest = items[0]
            stats[dom] = {
                "domain": dom,
                "total_runs": total,
                "passed_runs": passed,
                "failed_runs": total - passed,
                "success_rate": round((passed / total) * 100.0, 1) if total else None,
                "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
                "last_ok": latest["ok"],
                "last_status_code": latest["status_code"],
                "last_latency_ms": latest["latency_ms"],
                "last_stage": latest["stage"],
                "last_error": latest["error"],
                "last_tested_at": latest["tested_at"],
                "service_group": latest["service_group"],
                "recent": items[:5],
            }
        return stats

    def get_overall_test_summary(self, network_key: str, window: int = 10) -> dict[str, Any]:
        """Compute overall domain & key-service connectivity success rates."""
        per_dom = self.get_domain_test_stats(network_key, window=window)
        if not per_dom:
            return {
                "tested_domains": 0,
                "passing_domains": 0,
                "total_runs": 0,
                "passed_runs": 0,
                "overall_success_rate": None,
                "by_service": {},
                "by_domain": {},
            }
        total_runs = sum(int(s["total_runs"]) for s in per_dom.values())
        passed_runs = sum(int(s["passed_runs"]) for s in per_dom.values())
        passing_domains = sum(1 for s in per_dom.values() if s["last_ok"] is True)
        by_service_acc: dict[str, dict[str, Any]] = {}
        for dom, s in per_dom.items():
            sg = s.get("service_group") or "other"
            entry = by_service_acc.setdefault(
                sg,
                {"service_group": sg, "domains": [], "passed_latest": 0, "total_latest": 0, "runs": 0, "passed_runs": 0, "latencies": []},
            )
            entry["domains"].append(dom)
            entry["total_latest"] += 1
            if s["last_ok"]:
                entry["passed_latest"] += 1
            entry["runs"] += int(s["total_runs"])
            entry["passed_runs"] += int(s["passed_runs"])
            if s["last_latency_ms"] is not None:
                entry["latencies"].append(float(s["last_latency_ms"]))
        by_service: dict[str, dict[str, Any]] = {}
        for sg, info in by_service_acc.items():
            runs = info["runs"]
            lats = info["latencies"]
            by_service[sg] = {
                "service_group": sg,
                "domains": sorted(info["domains"]),
                "passing_domains": info["passed_latest"],
                "total_domains": info["total_latest"],
                "ok": info["passed_latest"] > 0 and info["passed_latest"] == info["total_latest"],
                "partial": 0 < info["passed_latest"] < info["total_latest"],
                "success_rate": round((info["passed_runs"] / runs) * 100.0, 1) if runs else None,
                "avg_latency_ms": round(sum(lats) / len(lats), 1) if lats else None,
            }
        return {
            "tested_domains": len(per_dom),
            "passing_domains": passing_domains,
            "total_runs": total_runs,
            "passed_runs": passed_runs,
            "overall_success_rate": round((passed_runs / total_runs) * 100.0, 1) if total_runs else None,
            "by_service": by_service,
            "by_domain": per_dom,
        }

    # ---------------------------------------------------------------- User Zapret2 Presets

    def save_zapret_preset(self, entry: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        pid = str(entry["id"]).strip()
        name = str(entry["name"]).strip()
        desc = str(entry.get("description") or "").strip()
        content = str(entry.get("content") or "")
        source = str(entry.get("source") or "user").strip() or "user"
        is_working = 1 if entry.get("is_working", True) else 0
        success_rate = entry.get("success_rate")
        last_tested_at = str(entry.get("last_tested_at") or "")
        with self.conn:
            existing = self.conn.execute("SELECT created_at FROM zapret_presets WHERE id = ?", (pid,)).fetchone()
            created_at = str(existing["created_at"]) if existing else now
            self.conn.execute(
                """
                INSERT INTO zapret_presets (
                    id, name, description, content, source, is_working,
                    success_rate, last_tested_at, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    content = excluded.content,
                    source = excluded.source,
                    is_working = excluded.is_working,
                    success_rate = COALESCE(excluded.success_rate, zapret_presets.success_rate),
                    last_tested_at = CASE
                        WHEN excluded.last_tested_at != '' THEN excluded.last_tested_at
                        ELSE zapret_presets.last_tested_at
                    END,
                    updated_at = excluded.updated_at
                """,
                (
                    pid,
                    name,
                    desc,
                    content,
                    source,
                    is_working,
                    float(success_rate) if success_rate is not None else None,
                    last_tested_at,
                    created_at,
                    now,
                ),
            )
        return {
            "id": pid,
            "name": name,
            "description": desc,
            "content": content,
            "source": source,
            "is_working": bool(is_working),
            "success_rate": float(success_rate) if success_rate is not None else None,
            "last_tested_at": last_tested_at,
            "builtin": False,
            "created_at": created_at,
            "updated_at": now,
        }

    def get_zapret_presets(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM zapret_presets ORDER BY is_working DESC, updated_at DESC, name ASC"
        ).fetchall()
        return [
            {
                "id": str(r["id"]),
                "name": str(r["name"]),
                "description": str(r["description"] or ""),
                "content": str(r["content"] or ""),
                "source": str(r["source"] or "user"),
                "is_working": bool(r["is_working"]),
                "success_rate": r["success_rate"],
                "last_tested_at": str(r["last_tested_at"] or ""),
                "builtin": False,
                "created_at": str(r["created_at"] or ""),
                "updated_at": str(r["updated_at"] or ""),
            }
            for r in rows
        ]

    def get_zapret_preset(self, preset_id: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT * FROM zapret_presets WHERE id = ?", (preset_id.strip(),)).fetchone()
        if not r:
            return None
        return {
            "id": str(r["id"]),
            "name": str(r["name"]),
            "description": str(r["description"] or ""),
            "content": str(r["content"] or ""),
            "source": str(r["source"] or "user"),
            "is_working": bool(r["is_working"]),
            "success_rate": r["success_rate"],
            "last_tested_at": str(r["last_tested_at"] or ""),
            "builtin": False,
            "created_at": str(r["created_at"] or ""),
            "updated_at": str(r["updated_at"] or ""),
        }

    def delete_zapret_preset(self, preset_id: str) -> bool:
        with self.conn:
            cur = self.conn.execute("DELETE FROM zapret_presets WHERE id = ?", (preset_id.strip(),))
        return cur.rowcount > 0

    def update_zapret_preset_test_stats(
        self,
        preset_id: str,
        success_rate: float,
        is_working: bool | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        with self.conn:
            if is_working is not None:
                self.conn.execute(
                    """
                    UPDATE zapret_presets
                    SET success_rate = ?, is_working = ?, last_tested_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (round(float(success_rate), 1), 1 if is_working else 0, now, now, preset_id.strip()),
                )
            else:
                self.conn.execute(
                    """
                    UPDATE zapret_presets
                    SET success_rate = ?, last_tested_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (round(float(success_rate), 1), now, now, preset_id.strip()),
                )

    def close(self) -> None:
        self.conn.close()
