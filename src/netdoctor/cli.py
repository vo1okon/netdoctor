"""CLI entry point for netdoctor (`diag`, `sub-add`, `apply`, `fetch-bins`, `status`)."""

from __future__ import annotations

import asyncio
import json
import signal
import sys
import time
import urllib.parse
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netdoctor.classifier import classify_probes
from netdoctor.config_gen import (
    detect_physical_egress_iface,
    generate_singbox_config,
    generate_winws2_config,
    to_cygwin_safe_path,
)
from netdoctor.dynamics import run_canary_cycle
from netdoctor.gui import _has_console_window, launch_gui
from netdoctor.gui_backend import elevate_gui, launch_gui_detached
from netdoctor.models import Protocol, VerdictClass, VpnNode
from netdoctor.orchestrators import DnsLayerOrchestrator, build_unlocker_protection_context
from netdoctor.probes import detect_bypass_active, detect_network_fingerprint, run_domain_probes
from netdoctor.tray import terminate_pid_gracefully
from netdoctor.selector import (
    DEFAULT_STRATEGIES,
    evaluate_domains_live_batch,
    live_winws2_strategy_evaluator,
    load_targets_from_yaml,
    select_best_strategy,
)
from netdoctor.storage import Storage
from netdoctor.supervisor import (
    ProcessSupervisor,
    _is_admin,
    fetch_all_bins,
    inspect_supervisor_state,
    stop_persisted_supervisor,
    verify_binaries,
)
from netdoctor.vpn import fetch_subscription, refresh_all_subscriptions

app = typer.Typer(help="netdoctor: adaptive censorship circumvention orchestrator")
console = Console()


@app.command("diag")
def cmd_diag(
    domain: str | None = typer.Argument(None, help="Target domain to diagnose (e.g. discord.com)"),
    as_json: bool = typer.Option(False, "--json", help="Output verdict report as JSON"),
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
    timeout: float = typer.Option(3.0, "--timeout", help="Probe timeout in seconds"),
    all_targets: bool = typer.Option(False, "--all", help="Diagnose all domains listed in targets.yaml"),
    targets_file: str = typer.Option("configs/targets.yaml", "--targets", help="Path to targets YAML file"),
    live_eval: bool = typer.Option(
        True,
        "--live-eval/--no-live-eval",
        help="Test candidate strategies using isolated winws2 processes when running as Administrator",
    ),
) -> None:
    """Run the diagnostic probe ladder for one domain or all targets and classify blocking type."""
    if domain is None and not all_targets:
        console.print("[red]Error: Provide a DOMAIN argument or pass --all.[/red]")
        raise typer.Exit(code=2)

    target_domains: list[str]
    if all_targets:
        entries = load_targets_from_yaml(targets_file)
        target_domains = [e["domain"] for e in entries]
        if not target_domains:
            console.print(f"[red]No domains found in {targets_file}[/red]")
            raise typer.Exit(code=1)
    else:
        assert domain is not None
        target_domains = [domain]

    async def _run() -> None:
        bypass = detect_bypass_active()
        net = await detect_network_fingerprint(timeout=timeout)
        can_live_eval = live_eval and _is_admin() and not bypass
        if live_eval and not _is_admin() and not as_json:
            console.print(
                "[yellow]Note: Not running as Administrator — live winws2 probing skipped "
                "(using heuristic DPI selection). Run PowerShell as Admin for live winws2 testing.[/yellow]"
            )
        eval_fn = (
            (lambda d, ip, s: live_winws2_strategy_evaluator(d, ip, s))
            if can_live_eval
            else None
        )

        reports_json: list[dict] = []
        storage = Storage(db_path)
        try:
            net_key = storage.upsert_network(net)
            storage.upsert_strategies(DEFAULT_STRATEGIES)

            probes_list = await asyncio.gather(
                *(run_domain_probes(target_dom, timeout=timeout) for target_dom in target_domains)
            )
            reports = [
                classify_probes(domain=target_dom, probes=probes, network=net, bypass_active=bypass)
                for target_dom, probes in zip(target_domains, probes_list)
            ]

            domains_info: list[tuple[str, str, list[VerdictClass]]] = []
            for target_dom, probes, report in zip(target_domains, probes_list, reports):
                storage.save_verdict(net_key, report, protocol=Protocol.TLS)
                ip = probes.tcp.target_ip or (probes.dns.doh_ips[0] if probes.dns.doh_ips else "127.0.0.1")
                domains_info.append((target_dom, ip, report.verdicts))

            if len(target_domains) == 1:
                dom0, ip0, v0 = domains_info[0]
                decisions_map = {
                    dom0: await select_best_strategy(
                        network_key=net_key,
                        domain=dom0,
                        ip=ip0,
                        verdicts=v0,
                        candidates=DEFAULT_STRATEGIES,
                        protocol=Protocol.TLS,
                        evaluator=eval_fn,
                        early_stop=True,
                    )
                }
            else:
                decisions_map = await evaluate_domains_live_batch(
                    domains_info=domains_info,
                    network_key=net_key,
                    candidates=DEFAULT_STRATEGIES,
                    use_live_eval=can_live_eval,
                )

            quic_tasks = []
            quic_targets: list[tuple[str, str, object]] = []
            for target_dom, ip, verdicts in domains_info:
                decision = decisions_map[target_dom]
                storage.save_decision(decision)

                report = next(r for r in reports if r.domain == target_dom)
                if VerdictClass.QUIC_BLOCK in verdicts:
                    storage.save_verdict(net_key, report, protocol=Protocol.QUIC)
                    quic_targets.append((target_dom, ip, report))
                    quic_tasks.append(
                        select_best_strategy(
                            network_key=net_key,
                            domain=target_dom,
                            ip=ip,
                            verdicts=[VerdictClass.QUIC_BLOCK],
                            candidates=DEFAULT_STRATEGIES,
                            protocol=Protocol.QUIC,
                            evaluator=eval_fn if len(target_domains) == 1 else None,
                            early_stop=True,
                        )
                    )

            if quic_tasks:
                quic_decisions = await asyncio.gather(*quic_tasks)
                for qdec in quic_decisions:
                    storage.save_decision(qdec)

            for report in reports:
                decision = decisions_map[report.domain]
                reports_json.append(report.model_dump(mode="json"))
                if not as_json:
                    console.print(f"[bold cyan]Domain:[/bold cyan] {report.domain}")
                    console.print(f"[bold cyan]Network:[/bold cyan] AS{net.asn} ({net.kind.value}, {net.isp})")
                    console.print(f"[bold cyan]Verdicts:[/bold cyan] {', '.join(v.value for v in report.verdicts)}")
                    console.print(
                        f"[bold cyan]Decision:[/bold cyan] layer={decision.layer}, strategy={decision.strategy_id}"
                    )
        finally:
            storage.close()

        if as_json:
            output_obj = reports_json if all_targets else reports_json[0]
            typer.echo(json.dumps(output_obj, indent=2, ensure_ascii=False))

    asyncio.run(_run())


@app.command("sub-add")
def cmd_sub_add(
    url_or_uri: str = typer.Argument(..., help="Happ/V2Ray subscription URL, Amnezia vpn:// link, or raw URI"),
    sub_id: str = typer.Option("default", "--id", help="Subscription identifier"),
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
) -> None:
    """Import a VPN subscription (Happ, Amnezia vpn://, V2Ray/Xray base64, Sing-box JSON) into storage."""

    async def _run() -> None:
        nodes = await fetch_subscription(url_or_uri, subscription_id=sub_id)
        if not nodes:
            console.print("[red]Error: 0 valid VPN nodes found in subscription input.[/red]")
            raise typer.Exit(code=1)
        storage = Storage(db_path)
        try:
            storage.save_subscription(
                sub_id=sub_id,
                url_or_uri=url_or_uri,
                nodes=[n.model_dump(mode="json") for n in nodes],
            )
        finally:
            storage.close()
        console.print(f"[green]Imported {len(nodes)} VPN nodes into subscription '{sub_id}':[/green]")
        for n in nodes:
            console.print(f"  - [bold]{n.tag}[/bold] ({n.protocol} -> {n.server}:{n.server_port})")

    asyncio.run(_run())


def _resolve_winws2_live_args(
    winws_args: list[str],
    lists_path: Path,
    debug_log: bool = False,
    bin_path: Path | None = None,
) -> list[str]:
    """Rewrite list/blob paths to Cygwin-safe paths (relative or 8.3 short paths) so winws2.exe handles Cyrillic paths cleanly."""
    resolved_args: list[str] = ["--debug=1"] if debug_log else []
    path_prefixes = ("--hostlist=", "--hostlist-exclude=", "--ipset=", "--ipset-exclude=")
    for tok in winws_args:
        matched_prefix = next((p for p in path_prefixes if tok.startswith(p)), None)
        if matched_prefix is not None:
            raw_val = tok[len(matched_prefix) :]
            p = Path(raw_val)
            if not p.is_absolute():
                if p.exists():
                    p = p.resolve()
                elif (lists_path / p.name).exists():
                    p = (lists_path / p.name).resolve()
                elif (lists_path / "zapret2" / p.name).exists():
                    p = (lists_path / "zapret2" / p.name).resolve()
                else:
                    p = p.resolve()
            safe_str = to_cygwin_safe_path(p, base_dir=bin_path)
            resolved_args.append(f"{matched_prefix}{safe_str}")
        elif tok.startswith("--blob=") and ":@" in tok:
            head, raw_ref = tok.split(":@", 1)
            bp = Path(raw_ref)
            if bp.is_absolute() and bp.exists():
                resolved_args.append(f"{head}:@{to_cygwin_safe_path(bp, base_dir=bin_path)}")
            else:
                resolved_args.append(tok)
        else:
            resolved_args.append(tok)
    return resolved_args


def build_winws2_launch_cmd(
    winws2_exe: Path,
    live_args: list[str],
    *,
    configs_dir: Path | None = None,
    bin_path: Path | None = None,
    at_file_threshold: int = 6000,
) -> list[str]:
    """Build argv for winws2.exe, transparently switching to `@config` file for large Zapret2 presets (>6KB)."""
    total_chars = sum(len(a) + 1 for a in live_args)
    if configs_dir is not None and total_chars > at_file_threshold:
        configs_dir.mkdir(parents=True, exist_ok=True)
        at_file = configs_dir / "winws2_live_at.txt"
        at_file.write_text("\n".join(live_args) + "\n", encoding="utf-8")
        safe_at = to_cygwin_safe_path(at_file, base_dir=bin_path)
        return [str(winws2_exe), f"@{safe_at}"]
    return [str(winws2_exe), *live_args]


@app.command("apply")
def cmd_apply(
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
    configs_dir: str = typer.Option("configs", "--configs-dir", help="Output directory for generated configs"),
    lists_dir: str = typer.Option("lists", "--lists-dir", help="Output directory for winws2 hostlists"),
    bin_dir: str = typer.Option("bin", "--bin-dir", help="Directory containing external binaries"),
    logs_dir: str = typer.Option("logs", "--logs-dir", help="Directory for process logs and supervisor state"),
    iface: int | None = typer.Option(None, "--iface", help="Physical network interface index (ifIndex) for winws2"),
    profile: str | None = typer.Option(None, "--profile", help="Optional strategy ID filter"),
    no_start: bool = typer.Option(False, "--no-start", help="Only generate configuration files without starting processes"),
    force: bool = typer.Option(False, "--force", help="Start even if conflicting host bypass/VPN is active"),
    duration: float = typer.Option(0.0, "--duration", help="Optional run duration in seconds (0 = until interrupted)"),
) -> None:
    """Generate winws2 preset + hostlists and sing-box config, and optionally start the supervised Stage 1 stack."""
    if iface is not None and (iface <= 0 or iface > 65535):
        console.print(f"[red]Invalid network interface index (iface={iface}): no such adapter.[/red]")
        raise typer.Exit(code=1)

    storage = Storage(db_path)
    try:
        storage.upsert_strategies(DEFAULT_STRATEGIES)
        strategies = {s.id: s for s in storage.get_strategies()}
        if profile is not None and profile not in strategies:
            console.print(f"[red]Unknown strategy profile: {profile}[/red]")
            raise typer.Exit(code=1)
        row = storage.conn.execute("SELECT network_key FROM networks ORDER BY last_seen DESC LIMIT 1").fetchone()
        net_key = row["network_key"] if row else "AS12389:home:default"
        decisions = storage.get_decisions(net_key, active_only=True)
        if profile is not None:
            decisions = [d for d in decisions if d.strategy_id == profile]
        raw_nodes = storage.get_all_subscription_nodes()
        vpn_nodes = [VpnNode(**n) for n in raw_nodes]
        game_filter = storage.get_setting("game_filter", "0") == "1"
        dns_orch = DnsLayerOrchestrator()
        active_dns = dns_orch.get_active_dns(storage)
        dns_catalog_map = {s["id"]: s for s in dns_orch.get_all_dns_servers(storage)}
        guard = build_unlocker_protection_context(storage=storage)
    finally:
        storage.close()

    if guard["enabled"]:
        prot_doms = set(guard["domains"])
        explicit_per_dns = {
            d.domain.lower()
            for d in decisions
            if d.layer == "dns" and isinstance(d.strategy_id, str) and d.strategy_id.startswith("dns:")
        }
        decisions = [
            d
            for d in decisions
            if not (
                d.layer in ("dpi", "vpn")
                and any(
                    d.domain.lower() == pd or d.domain.lower().endswith("." + pd)
                    for pd in prot_doms
                )
            )
        ]
        exclude_domains = [dom for dom in guard["domains"] if dom not in explicit_per_dns]
        exclude_ips = list(guard["proxy_ips"])
        extra_procs = list(guard["processes"])
    else:
        exclude_domains = []
        exclude_ips = []
        extra_procs = []

    vpn_ips = [n.server for n in vpn_nodes if n.server] + exclude_ips
    effective_iface = iface if iface is not None else detect_physical_egress_iface()
    winws_args, hostlists = generate_winws2_config(
        decisions=decisions,
        strategies=strategies,
        lists_dir=lists_dir,
        vpn_server_ips=vpn_ips,
        iface=effective_iface,
        game_filter=game_filter,
        exclude_domains=exclude_domains,
        expand_cdn_domains=True,
        enable_tcp_in=True,
    )

    cfg_path = Path(configs_dir)
    cfg_path.mkdir(parents=True, exist_ok=True)
    winws_preset_file = cfg_path / "winws2_preset.txt"
    winws_preset_file.write_text("\n".join(winws_args) + "\n", encoding="utf-8")

    badges = list(active_dns.get("badges") or [])
    doh_url = str(active_dns.get("doh_url") or "")
    use_https = ("DoH" in badges) or doh_url.startswith("https://")
    dns_type = "https" if use_https else "udp"
    parsed_doh = urllib.parse.urlparse(doh_url) if doh_url.startswith("https://") else None
    doh_path = (parsed_doh.path or "/dns-query") if parsed_doh else "/dns-query"
    doh_tls_sni = parsed_doh.hostname if (parsed_doh and parsed_doh.hostname) else None

    singbox_file = cfg_path / "sing-box.json"
    generate_singbox_config(
        decisions=decisions,
        vpn_nodes=vpn_nodes,
        output_path=singbox_file,
        doh_server=str(active_dns.get("ip") or doh_tls_sni or "1.1.1.1"),
        dns_type=dns_type,
        doh_path=doh_path,
        dns_catalog=dns_catalog_map,
        bypass_domains=exclude_domains,
        extra_bypass_processes=extra_procs,
        use_wireguard_endpoints=True,
        doh_tls_sni=doh_tls_sni,
    )

    console.print(f"[green]Generated winws2 preset:[/green] {winws_preset_file} ({len(hostlists)} hostlists)")
    console.print(f"[green]Generated sing-box config:[/green] {singbox_file} ({len(vpn_nodes)} VPN nodes in urltest)")

    if no_start:
        return

    if not _is_admin():
        console.print(
            "[red]Error: Administrator privileges required (UAC elevation / WinError 740) "
            "to start live TUN and WinDivert processes. Use --no-start to only generate configs.[/red]"
        )
        raise typer.Exit(code=1)

    stop_persisted_supervisor(logs_dir=Path(logs_dir))

    if not force and detect_bypass_active():
        console.print(
            "[red]Error: Conflicting host bypass/VPN is already active. Stop it first or pass --force.[/red]"
        )
        raise typer.Exit(code=1)

    bin_path = Path(bin_dir).resolve()
    lists_path = Path(lists_dir).resolve()
    logs_path = Path(logs_dir).resolve()

    winws2_exe = bin_path / "winws2.exe"
    singbox_exe = bin_path / "sing-box.exe"
    if not winws2_exe.is_file() or not singbox_exe.is_file():
        console.print(f"[yellow]Missing binaries in {bin_path} — downloading dependencies automatically...[/yellow]")
        try:
            asyncio.run(fetch_all_bins(bin_path, lists_path))
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Failed to auto-fetch required binaries: {exc}[/red]")
            raise typer.Exit(code=1) from exc
        if not winws2_exe.is_file() or not singbox_exe.is_file():
            console.print(f"[red]Missing required binaries in {bin_path} after auto-fetch.[/red]")
            raise typer.Exit(code=1)

    specs: list[tuple[str, list[str], Path | None]] = []

    tg_script = bin_path / "tg-ws-proxy" / "proxy" / "tg_ws_proxy.py"
    tg_exe = bin_path / "tg-ws-proxy" / "TgWsProxy_windows.exe"
    if tg_script.is_file():
        specs.append(
            (
                "tg-ws-proxy",
                [
                    sys.executable,
                    "-u",
                    str(tg_script),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "10808",
                    "--secret",
                    "0123456789abcdef0123456789abcdef",
                ],
                tg_script.parent.parent,
            )
        )
    elif tg_exe.is_file():
        specs.append(("tg-ws-proxy", [str(tg_exe)], tg_exe.parent))

    live_winws_args = _resolve_winws2_live_args(winws_args, lists_path, bin_path=bin_path)
    specs.append(
        (
            "winws2",
            build_winws2_launch_cmd(winws2_exe, live_winws_args, configs_dir=cfg_path, bin_path=bin_path),
            bin_path,
        )
    )
    specs.append(("sing-box", [str(singbox_exe), "run", "-c", str(singbox_file.resolve())], bin_path))

    sup = ProcessSupervisor(bin_dir=bin_path, logs_dir=logs_path)
    stop_requested = False

    def _handle_sig(_signum: int, _frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True

    prev_handlers: list[tuple[int, object]] = []
    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                prev_handlers.append((sig, signal.getsignal(sig)))
                signal.signal(sig, _handle_sig)
            except (ValueError, OSError):
                pass

    try:
        sup.start_stack(specs, startup_wait=0.5)
        console.print("[bold green]Stage 1 stack started:[/bold green] " + ", ".join(s[0] for s in specs))
        started_at = time.monotonic()
        while not stop_requested:
            if duration > 0 and (time.monotonic() - started_at) >= duration:
                break
            st = sup.status()
            exited = [name for name, info in st.items() if not info["running"]]
            if exited:
                console.print(f"[red]Service(s) exited unexpectedly: {', '.join(exited)}[/red]")
                raise typer.Exit(code=1)
            time.sleep(0.25)
    finally:
        sup.stop_all()
        for sig, prev in prev_handlers:
            try:
                signal.signal(sig, prev)  # type: ignore[arg-type]
            except (ValueError, OSError):
                pass


@app.command("stop")
def cmd_stop(
    logs_dir: str = typer.Option("logs", "--logs-dir", help="Directory for process logs and supervisor state"),
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
) -> None:
    """Stop any running Stage 1 processes managed by the supervisor."""
    if Path(db_path).is_file():
        try:
            st = Storage(db_path)
            try:
                st.set_setting("stack_desired_running", "0")
            finally:
                st.close()
        except Exception:  # noqa: BLE001
            pass
    stopped = stop_persisted_supervisor(logs_dir=Path(logs_dir))
    if stopped:
        console.print(f"[green]Stopped processes: {', '.join(stopped)}[/green]")
    else:
        console.print("[yellow]Supervisor is idle (no running processes stopped).[/yellow]")


@app.command("fetch-bins")
def cmd_fetch_bins(
    bin_dir: str = typer.Option("bin", "--bin-dir", help="Directory to store external binaries"),
    lists_dir: str = typer.Option("lists", "--lists-dir", help="Directory to store domain and IP lists"),
    presets_dir: str | None = typer.Option(
        None,
        "--presets-dir",
        help="Directory to store reference presets (defaults to <bin_dir>/../presets)",
    ),
    force: bool = typer.Option(False, "--force", help="Re-download artifacts even if already present"),
    verify_only: bool = typer.Option(False, "--verify-only", help="Skip downloads and only verify local artifacts"),
) -> None:
    """Download external binaries/lists/presets and verify integrity."""
    presets_path = Path(presets_dir) if presets_dir is not None else None

    async def _run() -> dict:
        if not verify_only:
            await fetch_all_bins(Path(bin_dir), Path(lists_dir), presets_path, force=force)
        return verify_binaries(Path(bin_dir), Path(lists_dir), presets_path)

    report = asyncio.run(_run())

    table = Table(title="netdoctor Dependency Verification")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Path")
    table.add_column("SHA256 / Details")

    def _style_status(status: str) -> str:
        if status == "ok":
            return "[green]ok[/green]"
        if status == "warn_uac":
            return "[yellow]warn_uac[/yellow]"
        return f"[red]{status}[/red]"

    for name, info in report["tools"].items():
        sha = info.get("sha256")
        sha_short = f"{sha[:12]}..." if isinstance(sha, str) and len(sha) >= 12 else "-"
        detail = info.get("detail", "")
        table.add_row(
            name,
            _style_status(info["status"]),
            info.get("path", "-"),
            f"{sha_short} | {detail}" if sha_short != "-" else detail,
        )

    lists_info = report["lists"]
    table.add_row("lists", _style_status(lists_info["status"]), lists_info["path"], lists_info["detail"])

    presets_info = report["presets"]
    table.add_row("presets", _style_status(presets_info["status"]), presets_info["path"], presets_info["detail"])

    manifest_info = report["manifest"]
    table.add_row("manifest", _style_status(manifest_info["status"]), manifest_info["path"], manifest_info["detail"])

    console.print(table)
    if not report["ok"]:
        console.print("[red]One or more dependencies failed verification.[/red]")
        raise typer.Exit(code=1)


@app.command("status")
def cmd_status(
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
    logs_dir: str = typer.Option("logs", "--logs-dir", help="Directory for process logs and supervisor state"),
) -> None:
    """Display stored decisions, active VPN nodes, and supervised process state."""
    try:
        storage = Storage(db_path)
    except Exception as exc:
        console.print(f"[red]Database error: {exc}[/red]")
        raise typer.Exit(code=1)
    try:
        rows = storage.conn.execute("SELECT * FROM decisions ORDER BY updated_at DESC").fetchall()
        nodes = storage.get_all_subscription_nodes()
    except Exception as exc:
        console.print(f"[red]Database error: {exc}[/red]")
        raise typer.Exit(code=1)
    finally:
        storage.close()

    table = Table(title="netdoctor Decisions")
    table.add_column("Network")
    table.add_column("Domain")
    table.add_column("Proto")
    table.add_column("Layer")
    table.add_column("Strategy")
    table.add_column("Throughput (kbps)")

    for r in rows:
        table.add_row(
            r["network_key"],
            r["domain"],
            r["protocol"],
            r["layer"],
            r["strategy_id"] or "-",
            str(r["throughput_kbps"] or "-"),
        )
    console.print(table)
    console.print(f"Configured VPN nodes in pool: [bold]{len(nodes)}[/bold]")

    proc_states = inspect_supervisor_state(logs_dir=Path(logs_dir))
    running_any = any(info["running"] for info in proc_states.values())
    if proc_states:
        for name, info in proc_states.items():
            if info["running"]:
                console.print(f"  - [bold]{name}[/bold] (pid={info['pid']}): [green]running[/green]")
            else:
                console.print(f"  - [bold]{name}[/bold]: [yellow]stopped[/yellow]")
    if not running_any:
        console.print("Supervisor status: [yellow]stopped[/yellow] (no processes running)")


@app.command("sub-update")
def cmd_sub_update(
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
    timeout: float = typer.Option(10.0, "--timeout", help="HTTP fetch timeout in seconds"),
) -> None:
    """Refresh all saved VPN subscriptions from their source URLs/URIs."""

    async def _run() -> dict[str, int]:
        storage = Storage(db_path)
        try:
            return await refresh_all_subscriptions(storage, timeout=timeout)
        finally:
            storage.close()

    results = asyncio.run(_run())
    if not results:
        console.print("[yellow]No subscriptions saved to refresh.[/yellow]")
        return
    for sub_id, count in results.items():
        console.print(f"[green]Subscription '{sub_id}':[/green] {count} VPN nodes")


@app.command("daemon")
def cmd_daemon(
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
    interval: float = typer.Option(60.0, "--interval", help="Seconds between canary cycles"),
    iterations: int = typer.Option(1, "--iterations", help="Number of cycles (0 = run indefinitely)"),
    domain: list[str] | None = typer.Option(None, "--domain", help="Optional domain filter for canary probes"),
) -> None:
    """Run periodic canary checks, TTL expiry detection, and fallback promotion."""

    async def _run() -> None:
        cycle = 0
        while iterations == 0 or cycle < iterations:
            cycle += 1
            storage = Storage(db_path)
            try:
                summary = await run_canary_cycle(storage, domains=domain)
            finally:
                storage.close()
            console.print(
                f"[cyan]Canary cycle {cycle}:[/cyan] net={summary['network_key']}, "
                f"checked={len(summary['checked'])}, promoted={summary['promoted']}, expired={summary['expired']}"
            )
            if iterations == 0 or cycle < iterations:
                await asyncio.sleep(interval)

    asyncio.run(_run())


@app.command("gui")
def cmd_gui(
    db_path: str = typer.Option("netdoctor.db", "--db", help="Path to SQLite database"),
    logs_dir: str = typer.Option("logs", "--logs-dir", help="Directory for process logs and supervisor state"),
    configs_dir: str = typer.Option("configs", "--configs-dir", help="Directory for generated configs"),
    lists_dir: str = typer.Option("lists", "--lists-dir", help="Directory for winws2 hostlists"),
    bin_dir: str = typer.Option("bin", "--bin-dir", help="Directory containing external binaries"),
    headless_check: bool = typer.Option(False, "--headless-check", help="Print GUI controller snapshot JSON and exit"),
    minimized: bool = typer.Option(False, "--minimized", help="Start minimized to system tray"),
    auto_start_stack: bool = typer.Option(False, "--auto-start", help="Trigger protection autopilot right after GUI startup"),
    replace_pid: int | None = typer.Option(None, "--replace-pid", help="Gracefully stop an older GUI PID (used after UAC relaunch)"),
    no_elevate: bool = typer.Option(False, "--no-elevate", help="Launch GUI without requesting Administrator elevation"),
    foreground: bool = typer.Option(False, "--foreground", help="Keep GUI attached to current console instead of detaching"),
) -> None:
    """Launch minimal netdoctor desktop control panel."""
    if headless_check:
        snap = launch_gui(
            db_path=db_path,
            logs_dir=logs_dir,
            configs_dir=configs_dir,
            lists_dir=lists_dir,
            bin_dir=bin_dir,
            headless_check=True,
            minimized=minimized,
            auto_start_stack=auto_start_stack,
        )
        typer.echo(json.dumps(snap, indent=2, ensure_ascii=False))
        return

    if sys.platform == "win32":
        cwd = Path.cwd().resolve()
        if not no_elevate and not _is_admin():
            res = elevate_gui(
                db_path=db_path,
                configs_dir=configs_dir,
                lists_dir=lists_dir,
                logs_dir=logs_dir,
                working_dir=cwd,
                bin_dir=bin_dir,
                replace_pid=replace_pid,
                auto_start=auto_start_stack,
                minimized=minimized,
            )
            if res.get("ok"):
                return
            if res.get("cancelled"):
                console.print("[yellow]Запрос прав администратора отменён.[/yellow]")
                return
            console.print(f"[red]Не удалось запустить GUI от имени администратора: {res.get('error')}[/red]")
            raise typer.Exit(code=1)

        if not foreground and (_has_console_window() or Path(sys.executable).name.lower() != "pythonw.exe"):
            res = launch_gui_detached(
                db_path=db_path,
                configs_dir=configs_dir,
                lists_dir=lists_dir,
                logs_dir=logs_dir,
                working_dir=cwd,
                bin_dir=bin_dir,
                replace_pid=replace_pid,
                auto_start=auto_start_stack,
                minimized=minimized,
                no_elevate=no_elevate,
            )
            if res.get("ok"):
                return

    if replace_pid is not None:
        terminate_pid_gracefully(replace_pid)
    launch_gui(
        db_path=db_path,
        logs_dir=logs_dir,
        configs_dir=configs_dir,
        lists_dir=lists_dir,
        bin_dir=bin_dir,
        headless_check=False,
        minimized=minimized,
        auto_start_stack=auto_start_stack,
    )


if __name__ == "__main__":
    app()
