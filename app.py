#!/usr/bin/env python3
"""
Cyber Squad TUI (Terminal User Interface Forensic Suite)
SIH 2026 Problem Statement #26106 | Team Cyber Squad

A dedicated, 100% offline, air-gap ready terminal forensic engine for
Law Enforcement Officers (LEOs), SOC Analysts, and Incident Responders.
"""
from __future__ import annotations

import argparse
import os
import select
import sys
import termios
import time
import tty
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.align import Align
from rich.box import DOUBLE, ROUNDED, SIMPLE
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from core.batch import export_batch_to_csv, scan_evidence_directory
from core.bsa_cert import export_bsa_certificate, format_bsa_certificate_text, generate_bsa_certificate_data
from core.carver import (
    analyze_attachment_forensics,
    calculate_shannon_entropy,
    generate_hex_dump,
    get_entropy_spectrum_bars,
    identify_magic_type,
)
from core.forensics import analyze_relay_hops, evaluate_forensic_threat_matrix
from core.parser import parse_email_evidence
from core.rule_gen import export_threat_rules, generate_snort_rule, generate_stix_bundle, generate_yara_rule

console = Console()

# Default sample mock data if no file is passed
SAMPLE_RAW_EML = b"""From: "Bank of Baroda Security" <support@b0b-security-update.in>
To: <investigator@target.gov.in>
Subject: URGENT: Action required immediately - Account Access Restricted
Date: Mon, 31 Aug 2026 14:10:00 +0530
Message-ID: <20260831141000.spoofed.0091@b0b-security-update.in>
Return-Path: <bounce@attacker-vps-c2.cn>
Authentication-Results: mx.nic.in; spf=fail (nic.in: domain of b0b-security-update.in does not designate 185.220.101.5 as permitted sender); dkim=fail; dmarc=reject
Received: from mail-relay.target.gov.in (mail-relay.target.gov.in [10.20.30.1]) by mx.target.gov.in with ESMTP; Mon, 31 Aug 2026 14:10:12 +0530
Received: from attacker-relay.vps (attacker-relay.vps [192.0.2.146]) by mail-relay.target.gov.in with ESMTP; Mon, 31 Aug 2026 14:10:05 +0530
Received: from tor-exit-node.cn (tor-exit-node.cn [185.220.101.5]) by attacker-relay.vps with SMTP; Mon, 31 Aug 2026 14:10:00 +0530
Content-Type: multipart/mixed; boundary="====BOUNDARY_FORENSIC===="

--====BOUNDARY_FORENSIC====
Content-Type: text/plain; charset="utf-8"

URGENT NOTICE FROM CYBER SECURITY DIVISION:
Your official net-banking credentials have been flagged for unauthorized access from an unrecognized IP in Moscow.
To avoid immediate permanent account suspension and legal penalty, you are required to verify your password and 2FA code immediately.

Please click the secure authorization link below within 24 hours:
https://b0b-security-update.in/login/verify-credentials?user=admin

Failure to comply will result in an immediate freeze of all wire transfers and legal notice.
Bank of Baroda Security Operations

--====BOUNDARY_FORENSIC====
Content-Type: application/octet-stream; name="Invoice_BOB_Security_Patch.pdf.exe"
Content-Disposition: attachment; filename="Invoice_BOB_Security_Patch.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
--====BOUNDARY_FORENSIC====--
"""


class ForensicTUIState:
    """State manager for the interactive TUI application."""
    def __init__(self, evidence_data: Dict[str, Any], evidence_path: str = ""):
        self.evidence_path = evidence_path or evidence_data.get("filename", "evidence.eml")
        self.evidence = evidence_data
        self.threat = evaluate_forensic_threat_matrix(self.evidence)
        self.hops = analyze_relay_hops(self.evidence.get("received_hops", []))
        self.active_tab = 1
        self.status_msg = "[dim]TUI ready. Press [1-8] to switch tabs, [E] to export Section 63 BSA certificate.[/dim]"
        self.scroll_offset = 0
        self.hex_offset = 0
        self.batch_data: Optional[Dict[str, Any]] = None
        self.batch_selected_idx = 0
        self.case_id = f"CS-CASE-{datetime.now().strftime('%Y%m%d')}-{self.evidence.get('sha256', '0000')[:6].upper()}"

    def reload_file(self, file_path: str | Path):
        """Loads and processes a new evidence file."""
        try:
            self.evidence = parse_email_evidence(file_path)
            self.evidence_path = str(file_path)
            self.threat = evaluate_forensic_threat_matrix(self.evidence)
            self.hops = analyze_relay_hops(self.evidence.get("received_hops", []))
            self.case_id = f"CS-CASE-{datetime.now().strftime('%Y%m%d')}-{self.evidence.get('sha256', '0000')[:6].upper()}"
            self.scroll_offset = 0
            self.hex_offset = 0
            self.status_msg = f"[bold green][✓] Successfully loaded evidence: {Path(file_path).name}[/bold green]"
        except Exception as e:
            self.status_msg = f"[bold red][✗] Error loading file: {str(e)}[/bold red]"

    def run_batch_scan(self, dir_path: str | Path):
        """Executes a batch triage scan on an evidence folder."""
        self.status_msg = f"[yellow][*] Scanning evidence folder: {dir_path}...[/yellow]"
        self.batch_data = scan_evidence_directory(dir_path)
        if self.batch_data.get("error"):
            self.status_msg = f"[bold red][✗] {self.batch_data['error']}[/bold red]"
        else:
            cnt = self.batch_data["stats"]["total_files"]
            self.status_msg = f"[bold green][✓] Batch scan complete: {cnt} evidence files analyzed.[/bold green]"
            self.active_tab = 6


def render_header(state: ForensicTUIState) -> Panel:
    """Renders the top application header and forensic status banner."""
    time_str = datetime.now().strftime("%I:%M:%S %p")
    risk_score = state.threat.get("risk_score", 0)
    
    score_color = "bright_red" if risk_score >= 75 else "yellow" if risk_score >= 45 else "green"
    badge = f"[{score_color}]THREAT SCORE: {risk_score}/100[/{score_color}]"

    title_text = Text.from_markup(
        f"[bold bright_magenta]AICTE - SIH 2026 #26106[/bold bright_magenta] [dim]|[/dim] "
        f"[bold bright_cyan]TEAM CYBER SQUAD FORENSIC SUITE[/bold bright_cyan] [dim]|[/dim] "
        f"[bold yellow]CASE:[/bold yellow] [white]{state.case_id}[/white]   "
        f"{badge}   "
        f"[dim][{time_str}][/dim]"
    )
    return Panel(title_text, box=ROUNDED, border_style="cyan", padding=(0, 1))



def render_tabs_bar(active_tab: int) -> Panel:
    """Renders the interactive navigation tab bar."""
    tabs = [
        (1, "1. Overview"),
        (2, "2. Headers & Hops"),
        (3, "3. Hex & Entropy"),
        (4, "4. URL Matrix"),
        (5, "5. BSA-63 Cert"),
        (6, "6. Batch Queue"),
        (7, "7. Threat Rules"),
        (8, "8. Help / Hotkeys"),
    ]
    parts: List[str] = []
    for num, label in tabs:
        if num == active_tab:
            parts.append(f"[bold black on bright_cyan] {label} [/bold black on bright_cyan]")
        else:
            parts.append(f"[dim white] {label} [/dim white]")

    tab_markup = "  ".join(parts)
    return Panel(Align.center(Text.from_markup(tab_markup)), box=ROUNDED, border_style="blue", padding=(0, 0))


def render_tab_1_overview(state: ForensicTUIState) -> Layout:
    """Tab 1: High level forensic case card, threat verdict, and authentication matrix."""
    layout = Layout()
    layout.split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )

    meta = state.evidence.get("meta", {})
    sha256 = state.evidence.get("sha256", "")
    threat = state.threat
    auth = threat.get("auth_matrix", {})

    # Left: Evidence File & Detection Signals
    left_table = Table(expand=True, box=None, padding=(0, 1))
    left_table.add_column("Property", style="bold cyan", width=18)
    left_table.add_column("Forensic Artifact Value", style="white")

    left_table.add_row("Evidence File", f"[bold yellow]{state.evidence.get('filename')}[/bold yellow]")
    left_table.add_row("SHA-256 Digest", f"[bold green]{sha256}[/bold green]")
    left_table.add_row("File Size", f"{state.evidence.get('size_bytes', 0):,} bytes")
    left_table.add_row("Sender (From)", f"[bold white]{meta.get('from', 'N/A')}[/bold white]")
    left_table.add_row("Recipient (To)", f"{meta.get('to', 'N/A')}")
    left_table.add_row("Subject Line", f"[bold white]{meta.get('subject', 'N/A')}[/bold white]")
    left_table.add_row("Message-ID", f"[dim]{meta.get('message_id', 'N/A')}[/dim]")
    left_table.add_row("RFC Date", f"{meta.get('date', 'N/A')}")

    # Signals breakdown
    signals = threat.get("signals", [])
    signals_table = Table(expand=True, box=SIMPLE, title="[bold red]OBSERVED FORENSIC THREAT SIGNALS[/bold red]")
    signals_table.add_column("Severity", width=10)
    signals_table.add_column("Threat Indicator", style="bold white")
    signals_table.add_column("Details", style="dim")

    if signals:
        for sig in signals:
            sev = sig.get("severity", "MED")
            color = "red" if sev == "CRITICAL" else "bright_red" if sev == "HIGH" else "yellow"
            signals_table.add_row(f"[{color}]{sev}[/{color}]", sig.get("title", ""), sig.get("details", ""))
    else:
        signals_table.add_row("[green]CLEAN[/green]", "No high-risk threat indicators flagged", "Standard RFC structure")

    left_panel = Panel(
        Group(left_table, Text(""), signals_table),
        title="[bold cyan]EVIDENCE CASE CARD & THREAT INDICATORS[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["left"].update(left_panel)

    # Right: Auth Matrix & Risk Gauge
    score = threat.get("risk_score", 0)
    verdict = threat.get("verdict_badge", "UNKNOWN")

    auth_table = Table(expand=True, box=ROUNDED, title="[bold yellow]RFC PROTOCOL AUTHENTICATION MATRIX[/bold yellow]")
    auth_table.add_column("Mechanism", style="bold white", width=10)
    auth_table.add_column("Status", width=12)
    auth_table.add_column("Forensic Evaluation", style="dim")

    def format_auth(status: str) -> str:
        if status == "PASS":
            return "[bold green][ PASS ][/bold green]"
        if status in {"FAIL", "REJECT"}:
            return "[bold red][ FAIL ][/bold red]"
        if status == "SOFTFAIL":
            return "[bold yellow][ SOFTFAIL ][/bold yellow]"
        return f"[dim][ {status} ][/dim]"

    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})
    arc = auth.get("arc", {})

    auth_table.add_row("SPF", format_auth(spf.get("status", "NONE")), spf.get("reason", ""))
    auth_table.add_row("DKIM", format_auth(dkim.get("status", "NONE")), dkim.get("reason", ""))
    auth_table.add_row("DMARC", format_auth(dmarc.get("status", "NONE")), dmarc.get("reason", ""))
    auth_table.add_row("ARC Seal", format_auth(arc.get("status", "NONE")), "Authenticated Received Chain")
    auth_table.add_row("Alignment", f"[bold {'green' if auth.get('alignment') == 'ALIGNED' else 'red'}]{auth.get('alignment')}[/]", "From vs Return-Path domain")

    risk_panel_text = f"""
[bold white]FINAL TRIAGE VERDICT:[/bold white]
{verdict}

[bold white]COMPOSITE THREAT SCORE:[/bold white]
[bold {'red' if score >= 75 else 'yellow' if score >= 45 else 'green'}]{score} / 100[/bold {'red' if score >= 75 else 'yellow' if score >= 45 else 'green'}]

[bold yellow]INVESTIGATIVE SUMMARY:[/bold yellow]
• Relay Hop Count   : {len(state.evidence.get('received_hops', []))} MTAs traversed
• Carved Attachments : {len(state.evidence.get('attachments', []))} extracted
• Analyzed Links    : {len(threat.get('url_analysis', []))} URLs evaluated
• RFC Parser Defects: {len(state.evidence.get('defects', []))} syntax anomalies
"""
    right_panel = Panel(
        Group(Panel(Text.from_markup(risk_panel_text.strip()), box=ROUNDED, border_style="red" if score >= 75 else "cyan"), Text(""), auth_table),
        title="[bold cyan]SECURITY PROTOCOL & VERDICT[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["right"].update(right_panel)

    return layout


def render_tab_2_headers(state: ForensicTUIState) -> Layout:
    """Tab 2: RFC 5322 Headers explorer and Relay Hop Chronology Timeline."""
    layout = Layout()
    layout.split_row(
        Layout(name="headers", ratio=3),
        Layout(name="hops", ratio=3),
    )

    # Headers Table
    headers_table = Table(expand=True, box=SIMPLE)
    headers_table.add_column("Header Field", style="bold cyan", width=22)
    headers_table.add_column("Value", style="white")

    headers_list = state.evidence.get("headers_list", [])
    for k, v in headers_list[:25]:
        headers_table.add_row(k, v[:80] + ("..." if len(v) > 80 else ""))

    headers_panel = Panel(
        headers_table,
        title=f"[bold cyan]RFC 5322 RAW HEADERS ({len(headers_list)} Total)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["headers"].update(headers_panel)

    # Relay Hop Sequence Timeline
    hops_table = Table(expand=True, box=ROUNDED)
    hops_table.add_column("Hop", style="bold cyan", justify="center", width=5)
    hops_table.add_column("Relay IP", style="bold white", width=16)
    hops_table.add_column("Type", width=14)
    hops_table.add_column("MTA Hostnames & Delta", style="yellow")
    hops_table.add_column("ISP / Network Classification", style="magenta")

    if state.hops:
        for h in state.hops:
            ip_color = "red" if "Tor" in h["isp_label"] or h["is_private"] is False and "INVALID" in h["ip_type"] else "green" if h["is_private"] else "white"
            hops_table.add_row(
                str(h["hop_number"]),
                f"[{ip_color}]{h['ip']}[/{ip_color}]",
                h["ip_type"],
                f"From: {h['from_host'][:20]}\nBy: {h['by_host'][:20]} [green]({h['delta']})[/green]",
                h["isp_label"],
            )
    else:
        hops_table.add_row("N/A", "None logged", "N/A", "No Received: headers found in RFC stream", "N/A")

    hops_panel = Panel(
        Group(
            Text.from_markup("[bold yellow]CHRONOLOGICAL RELAY HOP SEQUENCE (Originator → Destination):[/bold yellow]"),
            hops_table,
            Text.from_markup("[dim]Hop latency and reverse DNS categorization detected automatically.[/dim]"),
        ),
        title="[bold cyan]MULTI-HOP RELAY TIMELINE & INFRASTRUCTURE[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["hops"].update(hops_panel)

    return layout


def render_tab_3_hex_carver(state: ForensicTUIState) -> Layout:
    """Tab 3: Shannon Entropy Spectrum & ANSI Terminal Hex Dump."""
    layout = Layout()
    layout.split_row(
        Layout(name="carver", ratio=2),
        Layout(name="hexdump", ratio=3),
    )

    attachments = state.evidence.get("attachments", [])
    raw_bytes = state.evidence.get("raw_bytes", b"")

    # Left: Attachment list & Entropy spectrum
    carver_items: List[Any] = []
    
    # Mail body overall entropy
    body_bytes = state.evidence.get("body", "").encode("utf-8")
    body_ent = calculate_shannon_entropy(body_bytes)
    body_bars = get_entropy_spectrum_bars(body_bytes, num_blocks=24)
    
    carver_items.append(Text.from_markup(f"[bold cyan]Raw Evidence Stream Entropy:[/bold cyan] [bold white]{calculate_shannon_entropy(raw_bytes)}/8.0[/bold white]"))
    carver_items.append(Text.from_markup(f"Distribution: {get_entropy_spectrum_bars(raw_bytes, num_blocks=32)}\n"))
    
    if attachments:
        att_table = Table(expand=True, box=ROUNDED, title="[bold yellow]CARVED EVIDENCE ATTACHMENTS[/bold yellow]")
        att_table.add_column("Filename", style="bold white")
        att_table.add_column("Size", justify="right")
        att_table.add_column("Entropy", justify="center")
        att_table.add_column("Magic Type", style="cyan")
        att_table.add_column("Anomalies", style="bold red")

        for att in attachments:
            forensics = analyze_attachment_forensics(att)
            ent_val = forensics["entropy"]
            ent_color = "red" if ent_val >= 7.2 else "yellow" if ent_val >= 5.5 else "green"
            anom_text = "\n".join(forensics["anomalies"]) if forensics["anomalies"] else "[green]None[/green]"
            
            att_table.add_row(
                att.get("filename", "unnamed"),
                f"{len(att.get('bytes', b'')):,} B",
                f"[{ent_color}]{ent_val}[/{ent_color}]\n{forensics['spectrum']}",
                forensics["magic_type"],
                anom_text,
            )
        carver_items.append(att_table)
    else:
        carver_items.append(Text.from_markup("[dim yellow]No MIME attachments embedded in this message.[/dim yellow]"))

    carver_panel = Panel(
        Group(*carver_items),
        title="[bold cyan]SHANNON ENTROPY & ATTACHMENT CARVER[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["carver"].update(carver_panel)

    # Right: ANSI Terminal Hex Dump
    # Use attachment bytes if present, otherwise raw email bytes
    target_data = attachments[0].get("bytes", b"") if attachments else raw_bytes[:1024]
    dump_lines = generate_hex_dump(target_data, max_bytes=384, offset_start=state.hex_offset)

    hex_table = Table(expand=True, box=SIMPLE)
    hex_table.add_column("Offset", style="dim cyan", width=10)
    hex_table.add_column("Hexadecimal Bytes (16 bytes/line)", style="bold yellow")
    hex_table.add_column("ASCII", style="bright_green", width=18)

    for line in dump_lines:
        hex_table.add_row(line["offset"], line["hex"], line["ascii"])

    data_source_label = f"Attachment: {attachments[0].get('filename')}" if attachments else "Raw RFC Stream"
    hexdump_panel = Panel(
        Group(
            Text.from_markup(f"[dim]Viewing Hex Stream for: [bold white]{data_source_label}[/bold white] | Total: {len(target_data)} bytes[/dim]"),
            hex_table,
        ),
        title="[bold cyan]ANSI TERMINAL HEX DUMP VIEWER[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["hexdump"].update(hexdump_panel)

    return layout


def render_tab_4_urls(state: ForensicTUIState) -> Panel:
    """Tab 4: Extracted URL Matrix, Punycode detection, and Link Defense."""
    urls = state.threat.get("url_analysis", [])
    
    table = Table(expand=True, box=ROUNDED)
    table.add_column("Risk", justify="center", width=12)
    table.add_column("Extracted URL / Destination", style="bold white")
    table.add_column("Hostname / Domain", style="cyan", width=24)
    table.add_column("TLD", style="yellow", width=8)
    table.add_column("Threat & Spoofing Flags", style="magenta")

    if urls:
        for u in urls:
            lvl = u.get("risk_level", "CLEAN")
            color = "red" if lvl == "CRITICAL" else "bright_red" if lvl == "HIGH" else "yellow" if lvl == "SUSPICIOUS" else "green"
            flags_str = "\n".join(f"• {f}" for f in u.get("flags", [])) if u.get("flags") else "[green]Clean structure[/green]"
            
            table.add_row(
                f"[{color}]{lvl} ({u.get('risk_score')})[/{color}]",
                u.get("url", ""),
                u.get("domain", ""),
                u.get("tld", ""),
                flags_str,
            )
    else:
        table.add_row("[green]CLEAN[/green]", "No HTTP/HTTPS hyper-links discovered in email body or HTML parts", "N/A", "N/A", "N/A")

    return Panel(
        Group(
            Text.from_markup(f"[bold yellow]EXTRACTED HYPERLINK THREAT EVALUATION ({len(urls)} Total Links):[/bold yellow]"),
            table,
            Text.from_markup("[dim]Detects Punycode IDN homographs, raw IP hostnames, deep subdomains, and credential theft endpoints.[/dim]"),
        ),
        title="[bold cyan]URL DEFENSE & PHISHING LINK MATRIX[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )


def render_tab_5_bsa_cert(state: ForensicTUIState) -> Panel:
    """Tab 5: Live preview of Section 63 BSA 2023 Digital Evidence Certificate."""
    cert_data = generate_bsa_certificate_data(state.evidence, case_id=state.case_id)
    cert_text = format_bsa_certificate_text(cert_data)
    
    syntax = Syntax(cert_text, "yaml", theme="monokai", line_numbers=True)

    return Panel(
        Group(
            Text.from_markup("[bold yellow]SECTION 63 BHARATIYA SAKSHYA ADHINIYAM (BSA 2023) LEGAL CERTIFICATE PREVIEW[/bold yellow]"),
            Text.from_markup("[dim]Press [bold cyan][E][/bold cyan] to export this signed certificate (.cert.txt, .json, .sha256) to ./forensic_exports/[/dim]\n"),
            syntax,
        ),
        title="[bold cyan]COURT-ADMISSIBLE BSA 2023 SECTION 63 CERTIFICATE[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )


def render_tab_6_batch(state: ForensicTUIState) -> Panel:
    """Tab 6: Batch Evidence Queue and Folder Triage."""
    if not state.batch_data:
        default_dir = os.path.dirname(state.evidence_path) or "./"
        hint = f"""
[bold yellow]BATCH EVIDENCE FOLDER AUDITING ENGINE[/bold yellow]

No batch directory scan loaded yet.
You can run a batch scan on any folder containing multiple .eml / .msg / .mbox evidence files.

[bold white]ACTIONS:[/bold white]
• Press [bold cyan][B][/bold cyan] to scan the current working directory ([bold yellow]{default_dir}[/bold yellow])
• Run CLI: [bold cyan]python3 app.py --batch /path/to/evidence_folder/ --export-csv triage.csv[/bold cyan]
"""
        return Panel(Align.center(Text.from_markup(hint.strip())), title="[bold cyan]BATCH EVIDENCE TRIAGE QUEUE[/bold cyan]", box=ROUNDED, border_style="cyan")

    stats = state.batch_data.get("stats", {})
    results = state.batch_data.get("results", [])

    stats_bar = (
        f"[bold white]Total Scanned:[/bold white] {stats.get('total_files', 0)}   "
        f"[bold red]Critical:[/bold red] {stats.get('critical', 0)}   "
        f"[bold yellow]Suspicious:[/bold yellow] {stats.get('suspicious', 0)}   "
        f"[bold cyan]Review:[/bold cyan] {stats.get('review', 0)}   "
        f"[bold green]Clean:[/bold green] {stats.get('clean', 0)}   "
        f"[dim]| Attachments: {stats.get('total_attachments', 0)} | URLs: {stats.get('total_urls', 0)}[/dim]"
    )

    table = Table(expand=True, box=ROUNDED)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Evidence File", style="bold white", width=22)
    table.add_column("Verdict", width=18)
    table.add_column("Sender (From)", style="cyan", width=25)
    table.add_column("Subject Line", style="yellow")
    table.add_column("Top Signal", style="dim")

    for r in results[:15]:
        score = r.get("risk_score", 0)
        color = "red" if score >= 75 else "yellow" if score >= 45 else "green"
        table.add_row(
            f"[{color}]{score}[/{color}]",
            r.get("filename", "")[:20],
            r.get("verdict", ""),
            r.get("sender", "")[:23],
            r.get("subject", "")[:35],
            r.get("top_signal", "")[:30],
        )

    return Panel(
        Group(
            Text.from_markup(stats_bar),
            Text(""),
            table,
            Text.from_markup("[dim]Press [bold cyan][B][/bold cyan] to re-scan. Results sorted by risk score descending.[/dim]"),
        ),
        title=f"[bold cyan]BATCH EVIDENCE TRIAGE QUEUE ({len(results)} Files)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )


def render_tab_7_rules(state: ForensicTUIState) -> Layout:
    """Tab 7: Auto-generated YARA and Snort/Suricata threat hunting rules."""
    layout = Layout()
    layout.split_row(
        Layout(name="yara", ratio=1),
        Layout(name="snort", ratio=1),
    )

    yara_code = generate_yara_rule(state.evidence, state.threat)
    snort_code = generate_snort_rule(state.evidence, state.threat)

    yara_syntax = Syntax(yara_code, "c", theme="monokai", line_numbers=True)
    snort_syntax = Syntax(snort_code, "bash", theme="monokai", line_numbers=True)

    layout["yara"].update(Panel(
        Group(
            Text.from_markup("[dim]Auto-generated based on observed hashes, subject, and sender.[/dim]\n"),
            yara_syntax,
        ),
        title="[bold cyan]AUTO-GENERATED YARA FILE RULE (Press [Y] to Export)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    layout["snort"].update(Panel(
        Group(
            Text.from_markup("[dim]Auto-generated network signature for perimeter IDS/IPS.[/dim]\n"),
            snort_syntax,
        ),
        title="[bold cyan]SNORT / SURICATA NETWORK RULE (Press [S] to Export)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


def render_tab_8_help() -> Panel:
    """Tab 8: Hotkeys reference and investigator cheat-sheet."""
    help_text = """
[bold bright_magenta]AICTE - SMART INDIA HACKATHON 2026 | PROBLEM STATEMENT #26106[/bold bright_magenta]
[bold bright_cyan]TEAM CYBER SQUAD — AIR-GAPPED FORENSIC TERMINAL SUITE[/bold bright_cyan]

[bold cyan]NAVIGATION HOTKEYS:[/bold cyan]
  [bold white][1][/bold white]  Overview & Threat Verdict       [bold white][5][/bold white]  Section 63 BSA 2023 Certificate
  [bold white][2][/bold white]  RFC Headers & Hop Chronology     [bold white][6][/bold white]  Batch Evidence Triage Queue
  [bold white][3][/bold white]  Hex Dump & Shannon Entropy       [bold white][7][/bold white]  YARA & Snort Rule Generator
  [bold white][4][/bold white]  URL Defense & Phishing Matrix    [bold white][8][/bold white]  Help & Keybindings Reference

[bold cyan]FORENSIC ACTIONS:[/bold cyan]
  [bold white][E][/bold white]  Export Section 63 BSA 2023 Legal Certificate (.txt, .json, .sha256)
  [bold white][Y][/bold white]  Export YARA Threat Rule to disk
  [bold white][S][/bold white]  Export Snort / Suricata IDS Network Rule to disk
  [bold white][B][/bold white]  Execute Batch Folder Scan on directory
  [bold white][O][/bold white]  Open / Load a different .eml file interactively
  [bold white][Q][/bold white]  Quit Forensic TUI

[bold cyan]CLI COMMAND PIPELINE EXAMPLES:[/bold cyan]
  • Open specific evidence: [green]python3 app.py /path/to/evidence.eml[/green]
  • Batch triage folder   : [green]python3 app.py --batch /cases/incident_01/ --export-csv results.csv[/green]
  • Generate Legal Cert   : [green]python3 app.py --cert /evidence.eml --officer "IO Sharma" --agency "CERT-In"[/green]
  • Stream via Stdin Pipe : [green]cat suspicious_mail.eml | python3 app.py --stdin[/green]
"""
    return Panel(Text.from_markup(help_text.strip()), title="[bold cyan]AICTE SIH #26106 | TEAM CYBER SQUAD INVESTIGATOR CHEAT-SHEET[/bold cyan]", box=ROUNDED, border_style="cyan")



def render_footer(state: ForensicTUIState) -> Panel:
    """Renders the status message and active action bar."""
    hotkey_bar = (
        "[bold cyan][1-8][/bold cyan] Switch Tabs   "
        "[bold cyan][E][/bold cyan] Export BSA Cert   "
        "[bold cyan][Y][/bold cyan] Export YARA   "
        "[bold cyan][S][/bold cyan] Export Snort   "
        "[bold cyan][B][/bold cyan] Batch Scan   "
        "[bold cyan][O][/bold cyan] Open File   "
        "[bold cyan][Q][/bold cyan] Quit"
    )
    content = Group(
        Text.from_markup(state.status_msg),
        Text.from_markup(hotkey_bar),
    )
    return Panel(content, box=ROUNDED, border_style="blue", padding=(0, 1))


def build_full_layout(state: ForensicTUIState) -> Layout:
    """Constructs the complete Rich terminal layout for the active tab."""
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="tabs", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=4),
    )

    layout["header"].update(render_header(state))
    layout["tabs"].update(render_tabs_bar(state.active_tab))
    layout["footer"].update(render_footer(state))

    if state.active_tab == 1:
        layout["body"].update(render_tab_1_overview(state))
    elif state.active_tab == 2:
        layout["body"].update(render_tab_2_headers(state))
    elif state.active_tab == 3:
        layout["body"].update(render_tab_3_hex_carver(state))
    elif state.active_tab == 4:
        layout["body"].update(render_tab_4_urls(state))
    elif state.active_tab == 5:
        layout["body"].update(render_tab_5_bsa_cert(state))
    elif state.active_tab == 6:
        layout["body"].update(render_tab_6_batch(state))
    elif state.active_tab == 7:
        layout["body"].update(render_tab_7_rules(state))
    elif state.active_tab == 8:
        layout["body"].update(render_tab_8_help())

    return layout


def get_key_nonblocking() -> Optional[str]:
    """Reads a single keypress in a non-blocking way on POSIX systems."""
    if not sys.stdin.isatty():
        return None
    rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
    if rlist:
        try:
            ch = sys.stdin.read(1)
            # Handle escape sequences for arrow keys
            if ch == "\x1b":
                # Check if more characters follow
                rlist2, _, _ = select.select([sys.stdin], [], [], 0.02)
                if rlist2:
                    seq = sys.stdin.read(2)
                    if seq == "[A":
                        return "UP"
                    elif seq == "[B":
                        return "DOWN"
                    elif seq == "[C":
                        return "RIGHT"
                    elif seq == "[D":
                        return "LEFT"
                return "ESC"
            return ch
        except Exception:
            return None
    return None


def run_interactive_tui(state: ForensicTUIState):
    """Runs the main interactive full-screen event loop."""
    console.clear()
    is_tty = sys.stdin.isatty()
    old_settings = None

    if is_tty:
        old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())

    try:
        with Live(build_full_layout(state), console=console, screen=True, refresh_per_second=8) as live:
            while True:
                live.update(build_full_layout(state))
                
                if not is_tty:
                    # If running without interactive TTY, print once and exit cleanly
                    break

                key = get_key_nonblocking()
                if not key:
                    continue

                if key in {"q", "Q"}:
                    break
                elif key in {"1", "2", "3", "4", "5", "6", "7", "8"}:
                    state.active_tab = int(key)
                    state.status_msg = f"[dim]Switched to Tab {key}.[/dim]"
                elif key in {"e", "E"}:
                    res = export_bsa_certificate(state.evidence, output_dir="./forensic_exports", case_id=state.case_id)
                    state.status_msg = f"[bold green][✓] Section 63 BSA Certificate exported: {Path(res['txt_path']).name}[/bold green]"
                elif key in {"y", "Y", "s", "S"}:
                    res = export_threat_rules(state.evidence, state.threat, output_dir="./forensic_exports")
                    state.status_msg = f"[bold green][✓] Rules exported to ./forensic_exports/ (YARA, Snort, STIX)[/bold green]"
                elif key in {"b", "B"}:
                    scan_dir = os.path.dirname(state.evidence_path) or "./"
                    state.run_batch_scan(scan_dir)
                elif key in {"o", "O"}:
                    # Interactive prompt to load a new file
                    # Restore terminal temporarily for prompt
                    if old_settings:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                    console.print("\n[bold cyan]Enter path to .eml evidence file:[/bold cyan] ", end="")
                    sys.stdout.flush()
                    new_path = input().strip()
                    if new_path and os.path.exists(new_path):
                        state.reload_file(new_path)
                    else:
                        state.status_msg = f"[bold red][✗] File not found: {new_path}[/bold red]"
                    if is_tty and old_settings:
                        tty.setcbreak(sys.stdin.fileno())

    finally:
        if is_tty and old_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        console.clear()
        console.print("[bold green][✓] Cyber Squad Forensic TUI session closed cleanly.[/bold green]\n")


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Squad TUI - Standalone Terminal Forensic Engine (SIH #26106)"
    )
    parser.add_argument("file", nargs="?", default=None, help="Path to evidence file (.eml, .msg)")
    parser.add_argument("--batch", metavar="DIR", help="Run batch forensic triage on directory of evidence files")
    parser.add_argument("--export-csv", metavar="OUT_CSV", help="Export batch triage report to CSV")
    parser.add_argument("--cert", metavar="FILE", help="Generate Section 63 BSA 2023 Certificate for file")
    parser.add_argument("--officer", default="Forensic Officer (Cyber Squad)", help="Investigating Officer name for BSA Certificate")
    parser.add_argument("--agency", default="CERT-In / Cyber Crime Forensic Lab", help="Agency/Lab name for BSA Certificate")
    parser.add_argument("--export-yara", metavar="FILE", help="Generate YARA threat hunting rule for file")
    parser.add_argument("--export-snort", metavar="FILE", help="Generate Snort network IDS rule for file")
    parser.add_argument("--stdin", action="store_true", help="Read raw email stream from STDIN pipe")

    args = parser.parse_args()

    # CLI Headless: BSA Certificate Generator
    if args.cert:
        evidence = parse_email_evidence(args.cert)
        paths = export_bsa_certificate(evidence, output_dir="./forensic_exports", officer_name=args.officer, agency_name=args.agency)
        console.print(f"[bold green][✓] Section 63 BSA Certificate Generated Successfully:[/bold green]")
        console.print(f"  • Plain Text : [cyan]{paths['txt_path']}[/cyan]")
        console.print(f"  • JSON Data  : [cyan]{paths['json_path']}[/cyan]")
        console.print(f"  • Checksum   : [cyan]{paths['sha_path']}[/cyan]")
        sys.exit(0)

    # CLI Headless: YARA Export
    if args.export_yara:
        evidence = parse_email_evidence(args.export_yara)
        threat = evaluate_forensic_threat_matrix(evidence)
        yara_str = generate_yara_rule(evidence, threat)
        console.print(yara_str)
        sys.exit(0)

    # CLI Headless: Snort Export
    if args.export_snort:
        evidence = parse_email_evidence(args.export_snort)
        threat = evaluate_forensic_threat_matrix(evidence)
        snort_str = generate_snort_rule(evidence, threat)
        console.print(snort_str)
        sys.exit(0)

    # CLI Headless: Batch Mode
    if args.batch:
        console.print(f"[bold yellow][*] Running Batch Forensic Scan on:[/] {args.batch}")
        batch_res = scan_evidence_directory(args.batch)
        if batch_res.get("error"):
            console.print(f"[bold red][✗] {batch_res['error']}[/bold red]")
            sys.exit(1)
        
        stats = batch_res["stats"]
        console.print(f"\n[bold green]Scan Summary:[/bold green] {stats['total_files']} files | [red]{stats['critical']} Critical[/red] | [yellow]{stats['suspicious']} Suspicious[/yellow] | [green]{stats['clean']} Clean[/green]")
        
        if args.export_csv:
            csv_path = export_batch_to_csv(batch_res, args.export_csv)
            console.print(f"[bold green][✓] Batch CSV Report saved to:[/] {csv_path}")
        sys.exit(0)

    # Ingestion Mode: STDIN, File, or Default Mock
    if args.stdin:
        raw_stdin = sys.stdin.buffer.read()
        evidence_data = parse_email_evidence(raw_stdin, filename="stdin_stream.eml")
        state = ForensicTUIState(evidence_data, evidence_path="STDIN")
    elif args.file and os.path.exists(args.file):
        evidence_data = parse_email_evidence(args.file)
        state = ForensicTUIState(evidence_data, evidence_path=args.file)
    else:
        # Load sample evidence
        evidence_data = parse_email_evidence(SAMPLE_RAW_EML, filename="incident_0091_phish.eml")
        state = ForensicTUIState(evidence_data, evidence_path="incident_0091_phish.eml")

    # Run Interactive TUI
    run_interactive_tui(state)


if __name__ == "__main__":
    main()
