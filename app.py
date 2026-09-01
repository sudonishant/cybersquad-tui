#!/usr/bin/env python3
"""
Cyber Squad TUI (Terminal User Interface Forensic Suite)
AICTE - Smart India Hackathon 2026 | Problem Statement #26106
Team Cyber Squad — 100% Offline & Air-Gap Ready Email Forensic Engine with AI Analyst
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
from rich.box import DOUBLE, ROUNDED, SIMPLE, SIMPLE_HEAVY
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from core.ai_engine import perform_offline_cognitive_nlp_analysis, request_online_llm_analysis
from core.batch import export_batch_to_csv, scan_evidence_directory
from core.bsa_cert import export_bsa_certificate, format_bsa_certificate_text, generate_bsa_certificate_data
from core.carver import (
    analyze_attachment_forensics,
    calculate_shannon_entropy,
    generate_hex_dump,
    get_entropy_spectrum_bars,
)
from core.forensics import analyze_relay_hops, evaluate_forensic_threat_matrix
from core.parser import parse_email_evidence
from core.rule_gen import export_threat_rules, generate_snort_rule, generate_stix_bundle, generate_yara_rule

console = Console()

# Built-in sample phishing email for instant demonstration
SAMPLE_RAW_EML = b"""From: "Bank of Baroda Security" <support@b0b-security-update.in>
To: <investigator@target.gov.in>
Subject: URGENT: Action required immediately - Account Access Restricted
Date: Mon, 31 Aug 2026 14:10:00 +0530
Message-ID: <20260831141000.spoofed.0091@b0b-security-update.in>
Return-Path: <bounce@attacker-vps-c2.cn>
Authentication-Results: mx.nic.in; spf=fail (nic.in: domain does not designate 185.220.101.5); dkim=fail; dmarc=reject
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
        self.ai_review = perform_offline_cognitive_nlp_analysis(self.evidence, self.threat)
        self.active_tab = 1
        self.status_msg = "[bold green]Ready.[/bold green] Use keys [bold cyan][1-8][/bold cyan] to navigate, [bold cyan][A][/bold cyan] for AI Second Opinion, [bold cyan][E][/bold cyan] to export BSA Cert."
        self.hex_offset = 0
        self.batch_data: Optional[Dict[str, Any]] = None
        self.case_id = f"CS-CASE-{datetime.now().strftime('%Y%m%d')}-{self.evidence.get('sha256', '0000')[:6].upper()}"

    def reload_file(self, file_path: str | Path):
        """Loads and processes a new evidence file."""
        try:
            self.evidence = parse_email_evidence(file_path)
            self.evidence_path = str(file_path)
            self.threat = evaluate_forensic_threat_matrix(self.evidence)
            self.hops = analyze_relay_hops(self.evidence.get("received_hops", []))
            self.ai_review = perform_offline_cognitive_nlp_analysis(self.evidence, self.threat)
            self.case_id = f"CS-CASE-{datetime.now().strftime('%Y%m%d')}-{self.evidence.get('sha256', '0000')[:6].upper()}"
            self.hex_offset = 0
            self.status_msg = f"[bold green]✔ Loaded: {Path(file_path).name} | AI Analysis Ready[/bold green]"
        except Exception as e:
            self.status_msg = f"[bold red]✖ Error loading file: {str(e)}[/bold red]"

    def refresh_ai(self):
        """Refreshes or runs AI analysis."""
        self.status_msg = "[yellow]Running AI Cognitive Forensic Analysis...[/yellow]"
        self.ai_review = request_online_llm_analysis(self.evidence, self.threat)
        self.status_msg = "[bold green]✔ AI Second Opinion Analysis Complete.[/bold green]"
        self.active_tab = 5

    def run_batch_scan(self, dir_path: str | Path):
        """Executes a batch triage scan on an evidence folder."""
        self.status_msg = f"[yellow]Scanning folder: {dir_path}...[/yellow]"
        self.batch_data = scan_evidence_directory(dir_path)
        if self.batch_data.get("error"):
            self.status_msg = f"[bold red]✖ {self.batch_data['error']}[/bold red]"
        else:
            cnt = self.batch_data["stats"]["total_files"]
            self.status_msg = f"[bold green]✔ Batch scan complete: {cnt} files analyzed.[/bold green]"
            self.active_tab = 7


def make_threat_bar(score: int, width: int = 20) -> str:
    """Generates a clean ASCII meter bar."""
    filled = int((score / 100) * width)
    unfilled = width - filled
    color = "bright_red" if score >= 75 else "yellow" if score >= 45 else "green"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * unfilled}[/dim]"


def render_header(state: ForensicTUIState) -> Panel:
    """Renders top header with AICTE SIH and Team Cyber Squad branding."""
    time_str = datetime.now().strftime("%I:%M:%S %p")
    risk_score = state.threat.get("risk_score", 0)
    
    score_color = "bright_red" if risk_score >= 75 else "yellow" if risk_score >= 45 else "green"
    badge = f"[{score_color}]THREAT: {risk_score}/100[/{score_color}]"

    title_text = Text.from_markup(
        f"[bold bright_magenta]AICTE - SIH #26106[/bold bright_magenta]  [dim]•[/dim]  "
        f"[bold bright_cyan]TEAM CYBER SQUAD[/bold bright_cyan]  [dim]•[/dim]  "
        f"[white]{Path(state.evidence_path).name}[/white]  [dim]•[/dim]  "
        f"{badge}  [dim]| {time_str}[/dim]"
    )
    return Panel(title_text, box=ROUNDED, border_style="cyan", padding=(0, 1))


def render_tabs_bar(active_tab: int) -> Panel:
    """Renders the clean navigation tab bar."""
    tabs = [
        (1, "1. Overview"),
        (2, "2. Headers & Hops"),
        (3, "3. Hex & Entropy"),
        (4, "4. URL Matrix"),
        (5, "5. 🤖 AI Analyst"),
        (6, "6. BSA-63 Cert"),
        (7, "7. Batch Queue"),
        (8, "8. Rules & Help"),
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
    """Tab 1: Simple & Clean Forensic Case Overview."""
    layout = Layout()
    layout.split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )

    meta = state.evidence.get("meta", {})
    sha256 = state.evidence.get("sha256", "")
    threat = state.threat
    auth = threat.get("auth_matrix", {})
    score = threat.get("risk_score", 0)

    # Left: Clean Evidence Metadata Table
    info_table = Table(expand=True, box=None, padding=(0, 1))
    info_table.add_column("Key", style="bold cyan", width=14)
    info_table.add_column("Forensic Artifact", style="white")

    info_table.add_row("File Name", f"[bold yellow]{state.evidence.get('filename')}[/bold yellow]")
    info_table.add_row("SHA-256", f"[bold green]{sha256}[/bold green]")
    info_table.add_row("Sender", f"[bold white]{meta.get('from', 'N/A')}[/bold white]")
    info_table.add_row("Recipient", f"{meta.get('to', 'N/A')}")
    info_table.add_row("Subject", f"[bold white]{meta.get('subject', 'N/A')}[/bold white]")
    info_table.add_row("Date", f"{meta.get('date', 'N/A')}")

    # Observed threat points list
    signals = threat.get("signals", [])
    signals_table = Table(expand=True, box=SIMPLE_HEAVY, title="[bold red]DETECTION SIGNALS & THREAT INDICATORS[/bold red]")
    signals_table.add_column("Severity", width=10)
    signals_table.add_column("Finding", style="bold white")

    if signals:
        for sig in signals[:4]:
            sev = sig.get("severity", "MED")
            color = "red" if sev == "CRITICAL" else "bright_red" if sev == "HIGH" else "yellow"
            signals_table.add_row(f"[{color}]{sev}[/{color}]", f"{sig.get('title')}\n[dim]{sig.get('details')}[/dim]")
    else:
        signals_table.add_row("[green]CLEAN[/green]", "No suspicious markers found in envelope, body, or attachments.")

    left_panel = Panel(
        Group(info_table, Text(""), signals_table),
        title="[bold cyan]1. CASE CARD & ARTIFACTS[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["left"].update(left_panel)

    # Right: Verdict Card & Auth Protocol Status
    verdict_badge = threat.get("verdict_badge", "UNKNOWN")
    score_bar = make_threat_bar(score, width=22)

    ai_vector = state.ai_review.get("attack_vector", "Standard Analysis")
    ai_conf = state.ai_review.get("confidence_percent", 0)

    verdict_text = f"""
[bold white]TRIAGE VERDICT:[/bold white]
{verdict_badge}

[bold white]THREAT SCORE:[/bold white]
{score_bar} [bold {'red' if score >= 75 else 'yellow' if score >= 45 else 'green'}]{score}/100[/]

[bold cyan]🤖 AI Vector Opinion:[/bold cyan]
[bold yellow]{ai_vector}[/bold yellow] ({ai_conf}% confidence)
[dim]Press [bold cyan][A][/bold cyan] or [bold cyan][5][/bold cyan] for complete AI Linguistic Breakdown[/dim]
"""
    auth_table = Table(expand=True, box=ROUNDED, title="[bold yellow]EMAIL AUTH MATRIX[/bold yellow]")
    auth_table.add_column("Protocol", style="bold white", width=10)
    auth_table.add_column("Status", width=12)
    auth_table.add_column("Evaluation", style="dim")

    def fmt_auth(st: str) -> str:
        if st == "PASS":
            return "[bold green]✔ PASS[/bold green]"
        if st in {"FAIL", "REJECT"}:
            return "[bold red]✖ FAIL[/bold red]"
        if st == "SOFTFAIL":
            return "[bold yellow]~ SOFTFAIL[/bold yellow]"
        return f"[dim]{st}[/dim]"

    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})

    auth_table.add_row("SPF", fmt_auth(spf.get("status", "NONE")), spf.get("reason", ""))
    auth_table.add_row("DKIM", fmt_auth(dkim.get("status", "NONE")), dkim.get("reason", ""))
    auth_table.add_row("DMARC", fmt_auth(dmarc.get("status", "NONE")), dmarc.get("reason", ""))
    auth_table.add_row("Alignment", f"[bold {'green' if auth.get('alignment') == 'ALIGNED' else 'red'}]{auth.get('alignment')}[/]", "From vs Return-Path")

    right_panel = Panel(
        Group(
            Panel(Text.from_markup(verdict_text.strip()), box=ROUNDED, border_style="red" if score >= 75 else "cyan"),
            Text(""),
            auth_table,
        ),
        title="[bold cyan]2. SECURITY STATUS[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )
    layout["right"].update(right_panel)

    return layout


def render_tab_2_headers(state: ForensicTUIState) -> Layout:
    """Tab 2: Clean RFC Headers & Relay Hop Timeline."""
    layout = Layout()
    layout.split_row(
        Layout(name="headers", ratio=3),
        Layout(name="hops", ratio=3),
    )

    headers_table = Table(expand=True, box=SIMPLE)
    headers_table.add_column("Header", style="bold cyan", width=20)
    headers_table.add_column("Value", style="white")

    headers_list = state.evidence.get("headers_list", [])
    for k, v in headers_list[:20]:
        headers_table.add_row(k, v[:70] + ("..." if len(v) > 70 else ""))

    layout["headers"].update(Panel(
        headers_table,
        title=f"[bold cyan]RFC 5322 HEADERS ({len(headers_list)} Total)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    hops_table = Table(expand=True, box=ROUNDED)
    hops_table.add_column("#", justify="center", width=4)
    hops_table.add_column("Relay IP", style="bold white", width=16)
    hops_table.add_column("Latency", style="green", width=10)
    hops_table.add_column("ISP / Network", style="magenta")

    if state.hops:
        for h in state.hops:
            ip_color = "red" if "Tor" in h["isp_label"] or h["is_private"] is False and "INVALID" in h["ip_type"] else "green" if h["is_private"] else "white"
            hops_table.add_row(
                str(h["hop_number"]),
                f"[{ip_color}]{h['ip']}[/{ip_color}]",
                h["delta"],
                h["isp_label"],
            )
    else:
        hops_table.add_row("-", "None logged", "-", "No Received hops found")

    layout["hops"].update(Panel(
        Group(
            Text.from_markup("[bold yellow]Relay Path (Originator → Destination):[/bold yellow]"),
            hops_table,
            Text.from_markup("\n[dim]Multi-hop chronological trace with reverse IP and ISP categorization.[/dim]"),
        ),
        title="[bold cyan]RELAY HOP TIMELINE[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


def render_tab_3_hex_carver(state: ForensicTUIState) -> Layout:
    """Tab 3: Shannon Entropy & Hex Dump."""
    layout = Layout()
    layout.split_row(
        Layout(name="carver", ratio=2),
        Layout(name="hexdump", ratio=3),
    )

    attachments = state.evidence.get("attachments", [])
    raw_bytes = state.evidence.get("raw_bytes", b"")

    carver_items: List[Any] = []
    total_ent = calculate_shannon_entropy(raw_bytes)
    carver_items.append(Text.from_markup(f"[bold white]Overall Stream Entropy:[/bold white] [bold cyan]{total_ent}/8.0[/bold cyan]"))
    carver_items.append(Text.from_markup(f"Distribution: {get_entropy_spectrum_bars(raw_bytes, num_blocks=24)}\n"))

    if attachments:
        att_table = Table(expand=True, box=ROUNDED, title="[bold yellow]ATTACHMENTS[/bold yellow]")
        att_table.add_column("File", style="bold white")
        att_table.add_column("Entropy", justify="center")
        att_table.add_column("Type", style="cyan")

        for att in attachments:
            forensics = analyze_attachment_forensics(att)
            ent_val = forensics["entropy"]
            ent_color = "red" if ent_val >= 7.2 else "yellow" if ent_val >= 5.5 else "green"
            att_table.add_row(
                att.get("filename", "unnamed")[:22],
                f"[{ent_color}]{ent_val}[/{ent_color}]",
                forensics["magic_type"][:25],
            )
        carver_items.append(att_table)
    else:
        carver_items.append(Text.from_markup("[dim]No MIME attachments in this email.[/dim]"))

    layout["carver"].update(Panel(
        Group(*carver_items),
        title="[bold cyan]ENTROPY & ATTACHMENTS[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    target_data = attachments[0].get("bytes", b"") if attachments else raw_bytes[:512]
    dump_lines = generate_hex_dump(target_data, max_bytes=288, offset_start=state.hex_offset)

    hex_table = Table(expand=True, box=SIMPLE)
    hex_table.add_column("Offset", style="dim cyan", width=10)
    hex_table.add_column("Hexadecimal (16 B/line)", style="bold yellow")
    hex_table.add_column("ASCII", style="bright_green", width=18)

    for line in dump_lines:
        hex_table.add_row(line["offset"], line["hex"], line["ascii"])

    layout["hexdump"].update(Panel(
        hex_table,
        title="[bold cyan]ANSI HEX DUMP (Live Byte Stream)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


def render_tab_4_urls(state: ForensicTUIState) -> Panel:
    """Tab 4: Clean URL Link Breakdown Table."""
    urls = state.threat.get("url_analysis", [])
    table = Table(expand=True, box=ROUNDED)
    table.add_column("Risk", justify="center", width=12)
    table.add_column("Extracted URL", style="bold white")
    table.add_column("Domain", style="cyan", width=24)
    table.add_column("Indicators / Flags", style="magenta")

    if urls:
        for u in urls:
            lvl = u.get("risk_level", "CLEAN")
            color = "red" if lvl == "CRITICAL" else "bright_red" if lvl == "HIGH" else "yellow" if lvl == "SUSPICIOUS" else "green"
            flags_str = "; ".join(u.get("flags", [])) if u.get("flags") else "[green]Clean structure[/green]"
            table.add_row(f"[{color}]{lvl}[/{color}]", u.get("url", ""), u.get("domain", ""), flags_str)
    else:
        table.add_row("[green]CLEAN[/green]", "No hyperlinks found in body", "-", "-")

    return Panel(
        Group(
            Text.from_markup(f"[bold yellow]Extracted Links ({len(urls)} Total):[/bold yellow]"),
            table,
        ),
        title="[bold cyan]URL DEFENSE & LINK MATRIX[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )


def render_tab_5_ai_analyst(state: ForensicTUIState) -> Layout:
    """Tab 5: Dedicated AI Forensic Analyst & Second Opinion Panel."""
    layout = Layout()
    layout.split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )

    ai = state.ai_review
    triggers = ai.get("psychological_triggers", [])
    mitigations = ai.get("mitigation_steps", [])

    # Left: AI Executive Narrative & Psychological Triggers
    left_items = [
        Text.from_markup(f"[bold cyan]AI Analysis Engine:[/bold cyan] [bold white]{ai.get('engine')}[/bold white]"),
        Text.from_markup(f"[bold cyan]Attack Vector Classification:[/bold cyan] [bold yellow]{ai.get('attack_vector')}[/bold yellow] ([green]{ai.get('confidence_percent')}% confidence[/green])\n"),
        Panel(Text.from_markup(f"[bold white]Executive Case Assessment:[/bold white]\n{ai.get('executive_summary')}"), box=ROUNDED, border_style="cyan"),
        Text(""),
    ]

    trigger_table = Table(expand=True, box=SIMPLE_HEAVY, title="[bold red]PSYCHOLOGICAL COERCION & ATTACK INTENT[/bold red]")
    trigger_table.add_column("Impact", width=10)
    trigger_table.add_column("Psychological Trigger", style="bold white")
    trigger_table.add_column("Observed Forensic Behavior", style="dim")

    if triggers:
        for t in triggers:
            imp = t.get("impact", "MED")
            imp_color = "red" if imp == "CRITICAL" else "bright_red" if imp == "HIGH" else "yellow"
            trigger_table.add_row(f"[{imp_color}]{imp}[/{imp_color}]", t.get("trigger"), t.get("description"))
    else:
        trigger_table.add_row("[green]NORMAL[/green]", "No coercive linguistic manipulation detected", "Standard communication tone")

    left_items.append(trigger_table)

    layout["left"].update(Panel(
        Group(*left_items),
        title="[bold cyan]🤖 AI THREAT CLASSIFICATION & LINGUISTICS[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    # Right: Synthetic Phish Detector & Actionable Mitigations
    is_synth = ai.get("synthetic_llm_detected", False)
    synth_badge = "[bold red]🚨 SYNTHETIC / LLM-GENERATED[/bold red]" if is_synth else "[bold green]👤 HUMAN AUTHORED / STANDARD[/bold green]"

    synth_text = f"""
[bold white]SYNTHETIC / AI PHISHING DETECTOR:[/bold white]
Status: {synth_badge}
[dim]{'Generative phrasing & vocabulary repetition cues found.' if is_synth else 'No anomalous synthetic generation markers.'}[/dim]
"""
    mitig_table = Table(expand=True, box=ROUNDED, title="[bold yellow]INCIDENT RESPONSE PLAYBOOK[/bold yellow]")
    mitig_table.add_column("#", justify="center", width=4)
    mitig_table.add_column("Actionable Mitigation Step", style="bold white")

    for idx, m in enumerate(mitigations, start=1):
        mitig_table.add_row(str(idx), m)

    layout["right"].update(Panel(
        Group(
            Panel(Text.from_markup(synth_text.strip()), box=ROUNDED, border_style="red" if is_synth else "green"),
            Text(""),
            mitig_table,
            Text.from_markup("\n[dim]Press [bold cyan][A][/bold cyan] to refresh AI Analysis anytime.[/dim]"),
        ),
        title="[bold cyan]INVESTIGATOR PLAYBOOK[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


def render_tab_6_bsa_cert(state: ForensicTUIState) -> Panel:
    """Tab 6: Live preview of Section 63 BSA 2023 Digital Evidence Certificate."""
    cert_data = generate_bsa_certificate_data(state.evidence, case_id=state.case_id)
    cert_text = format_bsa_certificate_text(cert_data)
    syntax = Syntax(cert_text, "yaml", theme="monokai", line_numbers=True)

    return Panel(
        Group(
            Text.from_markup("[bold yellow]Section 63 Bharatiya Sakshya Adhiniyam (BSA 2023) Certificate Preview:[/bold yellow]"),
            Text.from_markup("[dim]Press [bold cyan][E][/bold cyan] to export this signed certificate to ./forensic_exports/[/dim]\n"),
            syntax,
        ),
        title="[bold cyan]SECTION 63 BSA 2023 LEGAL CERTIFICATE[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )


def render_tab_7_batch(state: ForensicTUIState) -> Panel:
    """Tab 7: Batch Folder Triage Table."""
    if not state.batch_data:
        default_dir = os.path.dirname(state.evidence_path) or "./"
        hint = f"""
[bold yellow]BATCH FOLDER AUDIT ENGINE[/bold yellow]

Scan all .eml / .msg files in an evidence directory at once.

[bold white]ACTIONS:[/bold white]
• Press [bold cyan][B][/bold cyan] to scan current folder ([bold yellow]{default_dir}[/bold yellow])
• CLI Command: [bold cyan]python3 app.py --batch /path/to/folder --export-csv triage.csv[/bold cyan]
"""
        return Panel(Align.center(Text.from_markup(hint.strip())), title="[bold cyan]BATCH EVIDENCE QUEUE[/bold cyan]", box=ROUNDED, border_style="cyan")

    stats = state.batch_data.get("stats", {})
    results = state.batch_data.get("results", [])

    stats_bar = (
        f"[bold white]Total:[/bold white] {stats.get('total_files', 0)}  "
        f"[bold red]Critical:[/bold red] {stats.get('critical', 0)}  "
        f"[bold yellow]Suspicious:[/bold yellow] {stats.get('suspicious', 0)}  "
        f"[bold green]Clean:[/bold green] {stats.get('clean', 0)}"
    )

    table = Table(expand=True, box=ROUNDED)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Evidence File", style="bold white", width=22)
    table.add_column("Verdict", width=18)
    table.add_column("Sender", style="cyan", width=25)
    table.add_column("Top Signal", style="dim")

    for r in results[:15]:
        score = r.get("risk_score", 0)
        color = "red" if score >= 75 else "yellow" if score >= 45 else "green"
        table.add_row(
            f"[{color}]{score}[/{color}]",
            r.get("filename", "")[:20],
            r.get("verdict", ""),
            r.get("sender", "")[:23],
            r.get("top_signal", "")[:30],
        )

    return Panel(
        Group(
            Text.from_markup(stats_bar),
            Text(""),
            table,
        ),
        title=f"[bold cyan]BATCH EVIDENCE QUEUE ({len(results)} Files)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )


def render_tab_8_rules_and_help(state: ForensicTUIState) -> Layout:
    """Tab 8: Auto-generated YARA / Snort Rules and Keybinding Reference."""
    layout = Layout()
    layout.split_row(
        Layout(name="rules", ratio=1),
        Layout(name="help", ratio=1),
    )

    yara_code = generate_yara_rule(state.evidence, state.threat)
    yara_syntax = Syntax(yara_code, "c", theme="monokai", line_numbers=True)

    layout["rules"].update(Panel(
        Group(
            Text.from_markup("[dim]Auto-generated YARA rule based on extracted hashes & cues. Press [bold cyan][Y][/bold cyan] to Export.[/dim]\n"),
            yara_syntax,
        ),
        title="[bold cyan]YARA THREAT RULE[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    help_text = """
[bold bright_magenta]AICTE - SMART INDIA HACKATHON 2026 | PROBLEM STATEMENT #26106[/bold bright_magenta]
[bold bright_cyan]TEAM CYBER SQUAD — AIR-GAPPED FORENSIC TERMINAL SUITE[/bold bright_cyan]

[bold cyan]KEYBOARD CONTROLS:[/bold cyan]
  [bold white][1-8][/bold white]  Switch views (Overview, Headers, Hex, URLs, AI, BSA-63, Batch, Rules)
  [bold white][A][/bold white]    Run / View 🤖 AI Second Opinion
  [bold white][E][/bold white]    Export Section 63 BSA 2023 Certificate (.txt, .json, .sha256)
  [bold white][Y][/bold white]    Export YARA Threat Rule to disk
  [bold white][S][/bold white]    Export Snort / Suricata IDS Network Rule to disk
  [bold white][B][/bold white]    Run Batch Folder Scan on directory
  [bold white][O][/bold white]    Open / Load a different .eml file interactively
  [bold white][Q][/bold white]    Quit TUI

[bold cyan]CLI COMMAND EXAMPLES:[/bold cyan]
  • Open file       : [green]python3 app.py /path/to/evidence.eml[/green]
  • Batch scan & CSV : [green]python3 app.py --batch /folder --export-csv results.csv[/green]
  • Export BSA Cert  : [green]python3 app.py --cert /evidence.eml[/green]
  • Stream via Stdin : [green]cat suspicious_mail.eml | python3 app.py --stdin[/green]
"""
    layout["help"].update(Panel(Text.from_markup(help_text.strip()), title="[bold cyan]HELP & KEYBOARD CONTROLS[/bold cyan]", box=ROUNDED, border_style="cyan"))

    return layout


def render_footer(state: ForensicTUIState) -> Panel:
    """Renders bottom action bar."""
    hotkey_bar = (
        "[bold cyan][1-8][/bold cyan] Tabs  [dim]•[/dim] "
        "[bold cyan][A][/bold cyan] 🤖 AI Analyst  [dim]•[/dim] "
        "[bold cyan][E][/bold cyan] Export Cert  [dim]•[/dim] "
        "[bold cyan][Y][/bold cyan] YARA  [dim]•[/dim] "
        "[bold cyan][B][/bold cyan] Batch  [dim]•[/dim] "
        "[bold cyan][O][/bold cyan] Open  [dim]•[/dim] "
        "[bold cyan][Q][/bold cyan] Quit"
    )
    content = Group(
        Text.from_markup(state.status_msg),
        Text.from_markup(hotkey_bar),
    )
    return Panel(content, box=ROUNDED, border_style="blue", padding=(0, 1))


def build_full_layout(state: ForensicTUIState) -> Layout:
    """Constructs the complete layout."""
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
        layout["body"].update(render_tab_5_ai_analyst(state))
    elif state.active_tab == 6:
        layout["body"].update(render_tab_6_bsa_cert(state))
    elif state.active_tab == 7:
        layout["body"].update(render_tab_7_batch(state))
    elif state.active_tab == 8:
        layout["body"].update(render_tab_8_rules_and_help(state))

    return layout


def get_key_nonblocking() -> Optional[str]:
    """Reads a single keypress without blocking."""
    if not sys.stdin.isatty():
        return None
    rlist, _, _ = select.select([sys.stdin], [], [], 0.05)
    if rlist:
        try:
            ch = sys.stdin.read(1)
            if ch == "\x1b":
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
    """Runs interactive full-screen event loop."""
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
                    break

                key = get_key_nonblocking()
                if not key:
                    continue

                if key in {"q", "Q"}:
                    break
                elif key in {"1", "2", "3", "4", "5", "6", "7", "8"}:
                    state.active_tab = int(key)
                    state.status_msg = f"[dim]Switched to Tab {key}.[/dim]"
                elif key in {"a", "A"}:
                    state.refresh_ai()
                elif key in {"e", "E"}:
                    res = export_bsa_certificate(state.evidence, output_dir="./forensic_exports", case_id=state.case_id)
                    state.status_msg = f"[bold green]✔ Section 63 BSA Certificate exported: {Path(res['txt_path']).name}[/bold green]"
                elif key in {"y", "Y", "s", "S"}:
                    res = export_threat_rules(state.evidence, state.threat, output_dir="./forensic_exports")
                    state.status_msg = f"[bold green]✔ Rules exported to ./forensic_exports/[/bold green]"
                elif key in {"b", "B"}:
                    scan_dir = os.path.dirname(state.evidence_path) or "./"
                    state.run_batch_scan(scan_dir)
                elif key in {"o", "O"}:
                    if old_settings:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                    console.print("\n[bold cyan]Enter path to .eml evidence file:[/bold cyan] ", end="")
                    sys.stdout.flush()
                    new_path = input().strip()
                    if new_path and os.path.exists(new_path):
                        state.reload_file(new_path)
                    else:
                        state.status_msg = f"[bold red]✖ File not found: {new_path}[/bold red]"
                    if is_tty and old_settings:
                        tty.setcbreak(sys.stdin.fileno())

    finally:
        if is_tty and old_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        console.clear()
        console.print("[bold green]✔ Cyber Squad Forensic TUI session closed.[/bold green]\n")


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Squad TUI - Standalone Terminal Forensic Engine (SIH #26106)"
    )
    parser.add_argument("file", nargs="?", default=None, help="Path to evidence file (.eml, .msg)")
    parser.add_argument("--batch", metavar="DIR", help="Run batch forensic triage on directory of evidence files")
    parser.add_argument("--export-csv", metavar="OUT_CSV", help="Export batch triage report to CSV")
    parser.add_argument("--cert", metavar="FILE", help="Generate Section 63 BSA 2023 Certificate for file")
    parser.add_argument("--officer", default="Digital Forensic Examiner (Team Cyber Squad)", help="Investigating Officer name for BSA Certificate")
    parser.add_argument("--agency", default="Digital Forensics Lab (AICTE SIH #26106)", help="Agency/Lab name for BSA Certificate")
    parser.add_argument("--export-yara", metavar="FILE", help="Generate YARA threat hunting rule for file")
    parser.add_argument("--export-snort", metavar="FILE", help="Generate Snort network IDS rule for file")
    parser.add_argument("--ai", action="store_true", help="Run AI Cognitive Forensic Second Opinion")
    parser.add_argument("--stdin", action="store_true", help="Read raw email stream from STDIN pipe")

    args = parser.parse_args()

    # CLI Headless: AI Mode
    if args.ai and (args.file or args.cert):
        target = args.file or args.cert
        evidence = parse_email_evidence(target)
        threat = evaluate_forensic_threat_matrix(evidence)
        ai_res = perform_offline_cognitive_nlp_analysis(evidence, threat)
        console.print(f"[bold cyan]🤖 AI Forensic Analysis Result for {Path(target).name}:[/bold cyan]\n")
        console.print(f"[bold white]Engine:[/bold white] {ai_res['engine']}")
        console.print(f"[bold white]Attack Vector:[/bold white] [yellow]{ai_res['attack_vector']}[/yellow] ({ai_res['confidence_percent']}% confidence)")
        console.print(f"[bold white]Synthetic LLM Lure:[/bold white] {'[red]YES[/red]' if ai_res['synthetic_llm_detected'] else '[green]NO[/green]'}")
        console.print(f"\n[bold white]Executive Summary:[/bold white]\n{ai_res['executive_summary']}\n")
        console.print("[bold yellow]Actionable Mitigation Steps:[/bold yellow]")
        for idx, s in enumerate(ai_res['mitigation_steps'], 1):
            console.print(f"  {idx}. {s}")
        sys.exit(0)

    # CLI Headless: BSA Certificate Generator
    if args.cert:
        evidence = parse_email_evidence(args.cert)
        paths = export_bsa_certificate(evidence, output_dir="./forensic_exports", officer_name=args.officer, agency_name=args.agency)
        console.print(f"[bold green]✔ Section 63 BSA Certificate Generated Successfully:[/bold green]")
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
        console.print(f"[bold yellow]Scanning Evidence Folder:[/] {args.batch}")
        batch_res = scan_evidence_directory(args.batch)
        if batch_res.get("error"):
            console.print(f"[bold red]✖ {batch_res['error']}[/bold red]")
            sys.exit(1)
        
        stats = batch_res["stats"]
        console.print(f"\n[bold green]Scan Summary:[/bold green] {stats['total_files']} files | [red]{stats['critical']} Critical[/red] | [yellow]{stats['suspicious']} Suspicious[/yellow] | [green]{stats['clean']} Clean[/green]")
        
        if args.export_csv:
            csv_path = export_batch_to_csv(batch_res, args.export_csv)
            console.print(f"[bold green]✔ Batch CSV Report saved to:[/] {csv_path}")
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
        evidence_data = parse_email_evidence(SAMPLE_RAW_EML, filename="incident_0091_phish.eml")
        state = ForensicTUIState(evidence_data, evidence_path="incident_0091_phish.eml")

    # Run Interactive TUI
    run_interactive_tui(state)


if __name__ == "__main__":
    main()
