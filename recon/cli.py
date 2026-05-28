from __future__ import annotations

"""Typer-based CLI for the recon engine.

Usage:
    python recon.py example.com
    python recon.py example.com --output json --output-dir ./results
    python recon.py example.com --modules dns,ct_logs,subdomains --passive-only
    python recon.py example.com --thorough --proxy socks5://127.0.0.1:9050
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional

import typer
from loguru import logger
from rich import print as rprint
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .config import Config
from .engine import Engine, _ALL_MODULES
from .output import OutputFormat, write_csv, write_json, write_subdomain_list, write_text

app = typer.Typer(
    name="recon",
    help="OSINT surface-recon toolkit — authorised use only.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console(stderr=True)

# ── Level → colour map ────────────────────────────────────────────────────────
_LEVEL_STYLE: dict[str, str] = {
    "info":    "cyan",
    "success": "green",
    "warn":    "yellow",
    "error":   "red bold",
}
_LEVEL_ICON: dict[str, str] = {
    "info":    "[*]",
    "success": "[+]",
    "warn":    "[!]",
    "error":   "[✗]",
}


def _make_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        redirect_stdout=False,
    )


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain or URL to scan (e.g. example.com)"),

    # ── Output options ─────────────────────────────────────────────────────────
    output: list[str] = typer.Option(
        ["text"],
        "--output", "-o",
        help="Output format(s): text, json, csv  (repeat for multiple)",
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output-dir", "-d",
        help="Directory for output files (default: cwd / results / <domain>)",
    ),
    stdout: bool = typer.Option(
        False, "--stdout",
        help="Also print text report to stdout",
    ),
    subdomain_list: bool = typer.Option(
        False, "--subdomain-list",
        help="Write a plain host list (for piping to httpx/nuclei)",
    ),

    # ── Scope options ──────────────────────────────────────────────────────────
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m",
        help="Comma-separated module list (default: all). E.g. dns,ct_logs,subdomains",
    ),
    passive_only: bool = typer.Option(
        False, "--passive-only",
        help="Only run passive modules (no active scanning or outbound connections to target)",
    ),
    thorough: bool = typer.Option(
        False, "--thorough",
        help="Enable all optional features: JS analysis, AXFR attempts, subdomain permutations",
    ),
    skip: Optional[str] = typer.Option(
        None, "--skip",
        help="Comma-separated list of modules to skip",
    ),

    # ── Config / credentials ───────────────────────────────────────────────────
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c",
        help="Path to config.yaml (default: ./config.yaml)",
    ),
    proxy: Optional[str] = typer.Option(
        None, "--proxy",
        help="Proxy URL, e.g. socks5://127.0.0.1:9050 or http://proxy:8080",
    ),

    # ── Presentation ───────────────────────────────────────────────────────────
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress progress messages; only write output files",
    ),
    no_color: bool = typer.Option(
        False, "--no-color",
        help="Disable colour output",
    ),
) -> None:
    """Run a full OSINT surface-recon scan against TARGET."""

    if no_color:
        console._color_system = None  # type: ignore[attr-defined]

    # ── Load config ────────────────────────────────────────────────────────────
    cfg = Config.load(config_file)
    if proxy:
        cfg.proxy.enabled = True
        cfg.proxy.url = proxy

    if thorough:
        cfg.scan.axfr_attempt = True
        cfg.scan.js_analysis = True
        cfg.scan.subdomain_permutations = True
        cfg.scan.external_tools = True

    # ── Resolve module list ────────────────────────────────────────────────────
    _PASSIVE_MODULES = {
        "ip_whois", "dns", "axfr", "domain_whois",
        "ct_logs", "wayback", "api_sources",
    }

    if passive_only:
        allowed = _PASSIVE_MODULES
    elif modules:
        allowed = {m.strip() for m in modules.split(",") if m.strip()}
    else:
        allowed = set(_ALL_MODULES)

    if skip:
        allowed -= {m.strip() for m in skip.split(",") if m.strip()}

    # ── Set up output directory ────────────────────────────────────────────────
    norm_target = target.split("://")[-1].split("/")[0].split(":")[0].lower()
    if not output_dir:
        output_dir = Path("results") / norm_target
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Progress tracking ──────────────────────────────────────────────────────
    total_mods = len(allowed)
    completed: list[str] = []
    log_lines: list[str] = []
    MAX_LOG = 12  # visible lines in the live panel

    progress = _make_progress()
    overall_task: TaskID = progress.add_task("Scanning", total=total_mods)

    def _cb(module: str, level: str, message: str) -> None:
        if quiet:
            return
        style = _LEVEL_STYLE.get(level, "white")
        icon = _LEVEL_ICON.get(level, "   ")
        line = f"[{style}]{icon} [{module}] {message}[/{style}]"
        log_lines.append(line)
        if len(log_lines) > MAX_LOG:
            log_lines.pop(0)
        if level == "success" and module in allowed and module not in completed:
            completed.append(module)
            progress.update(overall_task, advance=1)

    # ── Cancel on Ctrl+C ──────────────────────────────────────────────────────
    cancel_event = asyncio.Event()

    def _handle_sigint(sig, frame):
        if not cancel_event.is_set():
            console.print("\n[yellow][!] Cancelling — waiting for current module to finish…[/yellow]")
            cancel_event.set()

    signal.signal(signal.SIGINT, _handle_sigint)

    # ── Run ────────────────────────────────────────────────────────────────────
    engine = Engine(cfg, progress_cb=_cb, cancel_event=cancel_event)

    if not quiet:
        _print_banner(target, allowed)

    result = None
    with Live(console=console, refresh_per_second=8) as live:
        def _render():
            table = Table.grid(expand=True)
            table.add_row(progress)
            if log_lines:
                log_text = Text.from_markup("\n".join(log_lines[-MAX_LOG:]))
                table.add_row(Panel(log_text, title="[bold]Progress[/bold]", border_style="dim"))
            live.update(table)

        async def _run():
            nonlocal result
            try:
                result = await engine.scan(target, modules=list(allowed))
            except Exception as exc:
                logger.exception(f"Engine error: {exc}")

        # Periodic render pump
        async def _main():
            scan_task = asyncio.create_task(_run())
            while not scan_task.done():
                _render()
                await asyncio.sleep(0.12)
            await scan_task

        asyncio.run(_main())

    if result is None:
        console.print("[red][✗] Scan did not complete.[/red]")
        raise typer.Exit(code=1)

    # ── Write output files ─────────────────────────────────────────────────────
    from datetime import datetime
    ts = (result.started_at or datetime.utcnow()).strftime("%Y%m%d_%H%M%S")
    stem = f"{norm_target}_{ts}"

    written: list[Path] = []

    for fmt in output:
        fmt = fmt.strip().lower()
        if fmt == OutputFormat.JSON:
            p = output_dir / f"{stem}.json"
            write_json(result, p)
            written.append(p)
        elif fmt == OutputFormat.TEXT:
            p = output_dir / f"{stem}.txt"
            write_text(result, p)
            written.append(p)
        elif fmt == OutputFormat.CSV:
            csv_files = write_csv(result, output_dir)
            written.extend(csv_files)
        else:
            console.print(f"[yellow][!] Unknown output format: {fmt}[/yellow]")

    if subdomain_list and result.subdomains:
        p = output_dir / f"{stem}_subdomains.txt"
        write_subdomain_list(result, p)
        written.append(p)

    if stdout:
        import io
        buf = io.StringIO()
        write_text(result, buf)
        typer.echo(buf.getvalue())

    # ── Print summary table ────────────────────────────────────────────────────
    if not quiet:
        _print_summary(result, written)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_banner(target: str, modules: set[str]) -> None:
    console.print(Panel(
        f"[bold cyan]Surface Recon[/bold cyan]\n"
        f"Target: [bold white]{target}[/bold white]\n"
        f"Modules: [dim]{len(modules)} selected[/dim]",
        border_style="cyan",
        expand=False,
    ))


def _print_summary(result, written: list[Path]) -> None:
    from datetime import timezone
    elapsed = ""
    if result.started_at and result.finished_at:
        secs = (result.finished_at - result.started_at).total_seconds()
        elapsed = f"  Elapsed: {secs:.0f}s"

    table = Table(title="Scan Summary", border_style="cyan", show_header=True, header_style="bold cyan")
    table.add_column("Module", style="white")
    table.add_column("Result", style="green")

    if result.ip_info:
        table.add_row("IP/RDAP", f"{result.ip_info.ip}  ASN{result.ip_info.asn}  {result.ip_info.asn_description}")
    if result.dns:
        recs = sum(len(v) for v in result.dns.records.values())
        axfr = "  [bold red][AXFR SUCCESS][/bold red]" if result.dns.axfr_success else ""
        table.add_row("DNS", f"{recs} records{axfr}")
    if result.domain_whois:
        w = result.domain_whois
        exp = f"  [red]EXPIRING SOON[/red]" if w.expiry_warning else ""
        table.add_row("Domain WHOIS", f"Registrar: {w.registrar or 'n/a'}{exp}")
    if result.ct_logs:
        table.add_row("CT Logs", f"{len(result.ct_logs.domains)} unique domains")
    if result.subdomains:
        table.add_row("Subdomains", f"{len(result.subdomains)} found")
    if result.geolocation:
        g = result.geolocation
        edge = " [dim](CDN edge)[/dim]" if g.cdn_edge else ""
        table.add_row("Geolocation", f"{g.city}, {g.country}  ISP:{g.isp}{edge}")
    if result.cdn and result.cdn.detected:
        table.add_row("CDN", f"[yellow]{result.cdn.provider}[/yellow]")
    if result.ports:
        table.add_row("Ports", f"{len(result.ports)} open")
    if result.tls:
        flags = f"  [red]{', '.join(result.tls.flags[:2])}[/red]" if result.tls.flags else ""
        table.add_row("TLS", f"{result.tls.subject_cn}{flags}")
    if result.headers:
        table.add_row("Headers", f"Grade: [bold]{result.headers.score}[/bold]")
    if result.technologies:
        names = ", ".join(t.name for t in result.technologies[:5])
        more = f" +{len(result.technologies)-5}" if len(result.technologies) > 5 else ""
        table.add_row("Tech Stack", f"{names}{more}")
    if result.directories:
        table.add_row("Dir Scan", f"{len(result.directories)} paths")
    if result.exposed_files:
        table.add_row("Exposed Files", f"[red bold]{len(result.exposed_files)} VERIFIED[/red bold]")
    if result.wayback:
        table.add_row("Wayback", f"{result.wayback.total_urls} URLs  {len(result.wayback.interesting)} flagged")
    if result.emails:
        table.add_row("Emails", f"{len(result.emails)} found")
    if result.js_findings and result.js_findings.potential_secrets:
        table.add_row("JS Secrets", f"[red bold]{len(result.js_findings.potential_secrets)} potential secret(s)[/red bold]")
    if result.ping:
        status = "[green]reachable[/green]" if result.ping.reachable else "[yellow]filtered[/yellow]"
        table.add_row("Ping", status)

    console.print(table)

    if written:
        console.print("\n[bold]Output files:[/bold]")
        for p in written:
            console.print(f"  [dim]{p}[/dim]")

    console.print(f"\n[bold green][✔] Done.{elapsed}[/bold green]")

    # Highlight any critical findings
    crits: list[str] = []
    if result.dns and result.dns.axfr_success:
        crits.append("[red bold][CRITICAL] Zone transfer succeeded — full zone contents exposed[/red bold]")
    if result.exposed_files:
        crits.append(f"[red bold][CRITICAL] {len(result.exposed_files)} exposed file(s) verified (e.g. .git, .env)[/red bold]")
    if result.js_findings and result.js_findings.potential_secrets:
        crits.append(f"[red bold][HIGH] {len(result.js_findings.potential_secrets)} potential secret(s) in JS[/red bold]")
    if result.domain_whois and result.domain_whois.expiry_warning:
        crits.append("[yellow bold][WARN] Domain expiring within 30 days[/yellow bold]")

    if crits:
        console.print("\n[bold]Critical findings:[/bold]")
        for c in crits:
            console.print(f"  {c}")


@app.command("modules")
def list_modules() -> None:
    """List all available modules and exit."""
    table = Table(title="Available Modules", border_style="cyan", header_style="bold cyan")
    table.add_column("Name", style="bold white")
    table.add_column("Phase")
    table.add_column("Type")

    rows = [
        ("ip_whois",      "1 – Foundation", "passive"),
        ("dns",           "1 – Foundation", "passive"),
        ("axfr",          "1 – Foundation", "active"),
        ("domain_whois",  "1 – Foundation", "passive"),
        ("ct_logs",       "2 – OSINT",      "passive"),
        ("wayback",       "2 – OSINT",      "passive"),
        ("api_sources",   "2 – OSINT",      "passive"),
        ("subdomains",    "3 – Enum",       "active"),
        ("geo",           "4 – Network",    "passive"),
        ("cdn",           "4 – Network",    "active"),
        ("ports",         "5 – Active",     "active"),
        ("tls",           "5 – Active",     "active"),
        ("headers",       "5 – Active",     "active"),
        ("tech_detect",   "5 – Active",     "active"),
        ("js_analysis",   "5 – Active",     "active"),
        ("dir_scan",      "5 – Active",     "active"),
        ("email_harvest", "5 – Active",     "active"),
        ("ping",          "6 – Diagnostics","active"),
        ("traceroute",    "6 – Diagnostics","active"),
    ]
    for name, phase, kind in rows:
        table.add_row(name, phase, f"[{'green' if kind=='passive' else 'yellow'}]{kind}[/]")

    console.print(table)
