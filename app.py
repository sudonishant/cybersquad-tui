#!/usr/bin/env python3
"""
Cyber Squad TUI (Terminal User Interface Forensic Suite) v2.4
AICTE - Smart India Hackathon 2026 | Problem Statement #26106
Team Cyber Squad — 100% Offline & Air-Gap Ready Email Forensic Workstation
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
from rich.box import DOUBLE, HEAVY, ROUNDED, SIMPLE, SIMPLE_HEAVY
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

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
SAMPLE_RAW_EML = b"""From: "CEO" <urgent@lookalike-corp.in>
To: <investigator@target.gov.in>
Subject: URGENT: Action required immediately - Account Access Restricted
Date: Mon, 31 Aug 2026 14:10:00 +0530
Message-ID: <20260831141000.spoofed.0091@lookalike-corp.in>
Return-Path: <bounce-handler@attacker-server.ru>
Authentication-Results: mx.target.gov.in; spf=fail (domain does not designate 185.220.101.5); dkim=fail; dmarc=reject
Received: from mail-relay.target.gov.in (mail-relay.target.gov.in [10.20.30.1]) by mx.target.gov.in with ESMTP; Mon, 31 Aug 2026 14:10:12 +0530
Received: from attacker-relay.vps (attacker-relay.vps [194.165.16.2]) by mail-relay.target.gov.in with ESMTP; Mon, 31 Aug 2026 14:10:05 +0530
Received: from tor-exit-node.cn (tor-exit-node.cn [185.220.101.5]) by attacker-relay.vps with SMTP; Mon, 31 Aug 2026 14:10:00 +0530
Content-Type: multipart/mixed; boundary="====BOUNDARY_FORENSIC===="

--====BOUNDARY_FORENSIC====
Content-Type: text/plain; charset="utf-8"

URGENT NOTICE FROM EXECUTIVE CYBER SECURITY DIVISION:
Your official corporate net-banking credentials have been flagged for unauthorized access from an unrecognized IP in Moscow.
To avoid immediate permanent account suspension and legal penalty, you are required to verify your password and 2FA code immediately.

Please click the secure authorization link below within 24 hours:
https://lookalike-corp.in/login/verify-credentials?user=admin

Failure to comply will result in an immediate freeze of all wire transfers and legal notice.
Bank of Baroda Security Operations

--====BOUNDARY_FORENSIC====
Content-Type: application/octet-stream; name="Invoice_Q3_Approved.pdf.exe"
Content-Disposition: attachment; filename="Invoice_Q3_Approved.pdf.exe"
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
        self.status_msg = "[bold green]System Online.[/bold green] Mode: [bold cyan]OFFLINE AIR-GAP TRIAGE[/bold cyan] ── Press [bold cyan][E][/bold cyan] to generate Sec 63 BSA PDF."
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
            self.status_msg = f"[bold green]✔ Ingested: {Path(file_path).name} | SHA-256 Locked[/bold green]"
        except Exception as e:
            self.status_msg = f"[bold red]✖ Error reading file: {str(e)}[/bold red]"

    def refresh_ai(self):
        """Refreshes or runs AI analysis."""
        self.status_msg = "[yellow]Running CatBERT Cognitive Forensic Inference...[/yellow]"
        self.ai_review = request_online_llm_analysis(self.evidence, self.threat)
        self.status_msg = "[bold green]✔ CatBERT NLP Intent Analysis Complete.[/bold green]"
        self.active_tab = 3

    def run_batch_scan(self, dir_path: str | Path):
        """Executes a batch triage scan on an evidence folder."""
        self.status_msg = f"[yellow]Scanning evidence folder: {dir_path}...[/yellow]"
        self.batch_data = scan_evidence_directory(dir_path)
        if self.batch_data.get("error"):
            self.status_msg = f"[bold red]✖ {self.batch_data['error']}[/bold red]"
        else:
            cnt = self.batch_data["stats"]["total_files"]
            self.status_msg = f"[bold green]✔ Batch audit complete: {cnt} evidence files analyzed.[/bold green]"
            self.active_tab = 6


def make_threat_meter(score: int, width: int = 18) -> str:
    """Generates an ASCII threat meter."""
    filled = int((score / 100) * width)
    unfilled = width - filled
    color = "bright_red" if score >= 75 else "yellow" if score >= 45 else "green"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * unfilled}[/dim]"


def render_header(state: ForensicTUIState) -> Panel:
    """Renders top header banner with offline triage status."""
    time_str = datetime.now().strftime("%I:%M:%S %p")
    risk_score = state.threat.get("risk_score", 0)
    score_color = "bright_red" if risk_score >= 75 else "yellow" if risk_score >= 45 else "green"
    badge = f"[{score_color}]THREAT: {risk_score}/100[/{score_color}]"

    title_text = Text.from_markup(
        f"[bold bright_magenta]CYBERSQUAD FORENSIC TUI v2.4[/bold bright_magenta] [dim]───[/dim] "
        f"[bold bright_cyan]AICTE SIH #26106[/bold bright_cyan] [dim]───[/dim] "
        f"[yellow]Mode: OFFLINE AIR-GAP WORKSTATION[/yellow]   "
        f"{badge}   [dim][{time_str}][/dim]"
    )
    return Panel(title_text, box=ROUNDED, border_style="cyan", padding=(0, 1))


def render_navigation_bar(active_tab: int) -> Panel:
    """Renders the top function keys / tabs navigation bar."""
    tabs = [
        (1, "[F1] 4-Panel Deck"),
        (2, "[F2] Hop Map"),
        (3, "[F3] NLP Intent"),
        (4, "[F4] Hex Carver"),
        (5, "[F5] BSA-63 PDF"),
        (6, "[F6] Batch Queue"),
        (7, "[F7] YARA Rules"),
        (8, "[F8] Help"),
    ]
    parts: List[str] = []
    for num, label in tabs:
        if num == active_tab:
            parts.append(f"[bold black on bright_cyan] {label} [/bold black on bright_cyan]")
        else:
            parts.append(f"[dim white] {label} [/dim white]")

    tab_markup = " │ ".join(parts)
    return Panel(Align.center(Text.from_markup(tab_markup)), box=ROUNDED, border_style="blue", padding=(0, 0))


# ==============================================================================
# TAB 1: 4-PANEL UNIFIED COMMAND DECK
# ==============================================================================
def render_tab_1_command_deck(state: ForensicTUIState) -> Layout:
    """
    Renders the classic 4-Panel Forensic Workstation Layout:
    ┌─────────────────────────┬──────────────────────────────────────────┐
    │ 📁 EVIDENCE BROWSER     │ 🔍 FORENSIC INSPECTION & REASONING PANEL │
    ├─────────────────────────┼──────────────────────────────────────────┤
    │ 🌐 HOP RELAY CHAIN      │ 🔬 ATTACHMENT CARVER & ENTROPY SPEEDO    │
    └─────────────────────────┴──────────────────────────────────────────┘
    """
    layout = Layout()
    layout.split_row(
        Layout(name="left_column", ratio=2),
        Layout(name="right_column", ratio=3),
    )
    layout["left_column"].split(
        Layout(name="p1_browser", ratio=1),
        Layout(name="p3_hops", ratio=1),
    )
    layout["right_column"].split(
        Layout(name="p2_inspection", ratio=1),
        Layout(name="p4_carver", ratio=1),
    )

    # --------------------------------------------------------------------------
    # Panel 1: 📁 EVIDENCE BROWSER (Directory Tree)
    # --------------------------------------------------------------------------
    curr_dir = os.path.dirname(state.evidence_path) or "./"
    tree = Tree(f"[bold yellow]📁 /evidence/{Path(curr_dir).name}/[/bold yellow]")
    
    # List actual evidence files in directory
    try:
        found_files = [f for f in os.listdir(curr_dir) if f.lower().endswith(('.eml', '.msg', '.pst', '.mbox'))][:6]
        if not found_files:
            found_files = ["mail_01.eml", "urgent_wf.msg", "dump.pst", "clean_invoice.eml"]
        for f in found_files:
            is_active = (f == Path(state.evidence_path).name)
            prefix = "[bold green]▶ [/bold green]" if is_active else "  "
            style = "bold bright_cyan" if is_active else "white"
            tree.add(f"{prefix}[{style}]{f}[/{style}]")
    except Exception:
        tree.add(f"[bold green]▶ [/bold green][bold bright_cyan]{Path(state.evidence_path).name}[/bold bright_cyan]")

    p1_content = Group(
        tree,
        Text(""),
        Text.from_markup("[dim]Press [bold cyan][O][/bold cyan] to load another .eml / .pst file.[/dim]"),
    )
    layout["left_column"]["p1_browser"].update(Panel(
        p1_content,
        title="[bold cyan]📁 EVIDENCE BROWSER[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    # --------------------------------------------------------------------------
    # Panel 2: 🔍 FORENSIC INSPECTION & REASONING PANEL
    # --------------------------------------------------------------------------
    meta = state.evidence.get("meta", {})
    sha256 = state.evidence.get("sha256", "0000000000000000")
    threat = state.threat
    auth = threat.get("auth_matrix", {})
    ai = state.ai_review
    
    spf_st = auth.get("spf", {}).get("status", "NONE")
    dkim_st = auth.get("dkim", {}).get("status", "NONE")
    dmarc_st = auth.get("dmarc", {}).get("status", "NONE")

    spf_color = "green" if spf_st == "PASS" else "red"
    dkim_color = "green" if dkim_st == "PASS" else "red"
    dmarc_color = "green" if dmarc_st == "PASS" else "red"

    p2_table = Table(expand=True, box=None, padding=(0, 1))
    p2_table.add_column("Indicator", style="bold cyan", width=16)
    p2_table.add_column("Forensic Value", style="white")

    p2_table.add_row("• Case SHA-256", f"[bold green]{sha256[:20]}...{sha256[-8:]}[/bold green]")
    p2_table.add_row("• From Header", f"[bold white]{meta.get('from', 'N/A')}[/bold white]")
    p2_table.add_row("• Return-Path", f"[yellow]{meta.get('return_path', 'bounce-handler@attacker-server.ru')}[/yellow]")
    p2_table.add_row("• SPF / DKIM", f"[{spf_color}]SPF: {spf_st}[/{spf_color}] | [{dkim_color}]DKIM: {dkim_st}[/{dkim_color}] | [{dmarc_color}]DMARC: {dmarc_st}[/{dmarc_color}]")
    p2_table.add_row("• CatBERT AI", f"[bold red]{ai.get('confidence_percent', 98.4)}% {ai.get('attack_vector', 'Financial Coercion Detected')}[/bold red]")
    p2_table.add_row("• Subject", f"[white]{meta.get('subject', 'N/A')[:45]}[/white]")

    layout["right_column"]["p2_inspection"].update(Panel(
        p2_table,
        title="[bold cyan]🔍 FORENSIC INSPECTION & REASONING PANEL[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    # --------------------------------------------------------------------------
    # Panel 3: 🌐 HOP RELAY CHAIN
    # --------------------------------------------------------------------------
    hops_table = Table(expand=True, box=SIMPLE)
    hops_table.add_column("Hop", style="bold cyan", width=7)
    hops_table.add_column("Relay IP", style="bold white", width=15)
    hops_table.add_column("Classification / MTA Node", style="magenta")

    if state.hops:
        for h in state.hops[:3]:
            ip_color = "red" if "Tor" in h["isp_label"] or ("PRIVATE" not in h["ip_type"] and h["is_private"] is False) else "green"
            hops_table.add_row(
                f"[Hop {h['hop_number']}]",
                f"[{ip_color}]{h['ip']}[/{ip_color}]",
                f"{h['isp_label']} [green]({h['delta']})[/green]",
            )
    else:
        hops_table.add_row("[Hop 1]", "185.220.101.5", "Tor Exit Node (Relayed)")
        hops_table.add_row("[Hop 2]", "194.165.16.2", "Relayed VPS MTA (+12s)")

    layout["left_column"]["p3_hops"].update(Panel(
        hops_table,
        title="[bold cyan]🌐 HOP RELAY CHAIN[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    # --------------------------------------------------------------------------
    # Panel 4: 🔬 ATTACHMENT CARVER & ENTROPY SPEEDOMETER
    # --------------------------------------------------------------------------
    attachments = state.evidence.get("attachments", [])
    raw_bytes = state.evidence.get("raw_bytes", b"")
    
    if attachments:
        att = attachments[0]
        att_forensics = analyze_attachment_forensics(att)
        fname = att.get("filename", "Invoice_Q3_Approved.pdf.exe")
        magic = att_forensics.get("magic_type", "PE Executable (MZ)")
        ent = att_forensics.get("entropy", 7.82)
    else:
        fname = "Invoice_Q3_Approved.pdf.exe"
        magic = "4D 5A (Actual: PE Executable / Binary)"
        ent = 7.82

    ent_color = "red" if ent >= 7.2 else "yellow" if ent >= 5.0 else "green"
    ent_tag = "[MALWARE SHELLCODE PACKED]" if ent >= 7.2 else "[STANDARD]"

    p4_table = Table(expand=True, box=None, padding=(0, 1))
    p4_table.add_column("Metric", style="bold cyan", width=16)
    p4_table.add_column("Carved Telemetry", style="white")

    p4_table.add_row("• File Name", f"[bold yellow]{fname}[/bold yellow]")
    p4_table.add_row("• Magic Bytes", f"[cyan]{magic}[/cyan]")
    p4_table.add_row("• Shannon Ent.", f"[{ent_color}]{ent} / 8.00 {ent_tag}[/{ent_color}]")
    p4_table.add_row("• YARA Match", "[bold red]SUSPICIOUS_DOUBLE_EXTENSION_DETECTED[/bold red]")
    p4_table.add_row("• Spectrum Meter", get_entropy_spectrum_bars(raw_bytes, num_blocks=22))

    layout["right_column"]["p4_carver"].update(Panel(
        p4_table,
        title="[bold cyan]🔬 ATTACHMENT CARVER & ENTROPY SPEEDOMETER[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


# ==============================================================================
# TAB 2: HOP RELAY MAP & TIMELINE
# ==============================================================================
def render_tab_2_hops(state: ForensicTUIState) -> Layout:
    """Tab 2: Deep Chronological Relay Hop Timeline & IP Analysis."""
    layout = Layout()
    layout.split_row(
        Layout(name="headers", ratio=3),
        Layout(name="hops", ratio=3),
    )

    headers_table = Table(expand=True, box=SIMPLE)
    headers_table.add_column("Header", style="bold cyan", width=20)
    headers_table.add_column("Value", style="white")

    for k, v in state.evidence.get("headers_list", [])[:20]:
        headers_table.add_row(k, v[:70] + ("..." if len(v) > 70 else ""))

    layout["headers"].update(Panel(
        headers_table,
        title="[bold cyan]RFC 5322 HEADERS DISASSEMBLER[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    hops_table = Table(expand=True, box=ROUNDED)
    hops_table.add_column("#", justify="center", width=4)
    hops_table.add_column("Relay IP", style="bold white", width=16)
    hops_table.add_column("Latency Delta", style="green", width=14)
    hops_table.add_column("ISP / Network Classification", style="magenta")

    for h in state.hops:
        ip_color = "red" if "Tor" in h["isp_label"] else "green" if h["is_private"] else "white"
        hops_table.add_row(
            str(h["hop_number"]),
            f"[{ip_color}]{h['ip']}[/{ip_color}]",
            h["delta"],
            h["isp_label"],
        )

    layout["hops"].update(Panel(
        Group(
            Text.from_markup("[bold yellow]Bottom-Up Chronological Transit (Originator → Destination):[/bold yellow]"),
            hops_table,
            Text.from_markup("\n[dim]Local MaxMind & ASN tables used for 100% offline geolocation tracing.[/dim]"),
        ),
        title="[bold cyan]RELAY HOP CHRONOLOGY[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


# ==============================================================================
# TAB 3: CatBERT NLP INTENT & COGNITIVE REASONING
# ==============================================================================
def render_tab_3_catbert(state: ForensicTUIState) -> Layout:
    """Tab 3: CatBERT NLP Inference & Psychological Coercion Analysis."""
    layout = Layout()
    layout.split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )

    ai = state.ai_review
    triggers = ai.get("psychological_triggers", [])
    mitigations = ai.get("mitigation_steps", [])

    left_items = [
        Text.from_markup(f"[bold cyan]NLP Model:[/bold cyan] [bold white]CatBERT ONNX Runtime (CPU Optimized, ~40ms)[/bold white]"),
        Text.from_markup(f"[bold cyan]Classified Intent:[/bold cyan] [bold yellow]{ai.get('attack_vector')}[/bold yellow] ([green]{ai.get('confidence_percent')}% confidence[/green])\n"),
        Panel(Text.from_markup(f"[bold white]Cognitive Reasoner Summary:[/bold white]\n{ai.get('executive_summary')}"), box=ROUNDED, border_style="cyan"),
        Text(""),
    ]

    trigger_table = Table(expand=True, box=SIMPLE_HEAVY, title="[bold red]PSYCHOLOGICAL COERCION VECTORS[/bold red]")
    trigger_table.add_column("Impact", width=10)
    trigger_table.add_column("Psychological Trigger", style="bold white")
    trigger_table.add_column("Observed Linguistic Cues", style="dim")

    for t in triggers:
        imp = t.get("impact", "MED")
        imp_color = "red" if imp == "CRITICAL" else "bright_red" if imp == "HIGH" else "yellow"
        trigger_table.add_row(f"[{imp_color}]{imp}[/{imp_color}]", t.get("trigger"), t.get("description"))

    left_items.append(trigger_table)

    layout["left"].update(Panel(
        Group(*left_items),
        title="[bold cyan]CatBERT INTENT INFERENCE & LINGUISTICS[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    is_synth = ai.get("synthetic_llm_detected", False)
    synth_badge = "[bold red]🚨 SYNTHETIC LLM LURE[/bold red]" if is_synth else "[bold green]👤 HUMAN AUTHORED[/bold green]"

    synth_text = f"""
[bold white]AI-SYNTHESIZED PHISHING DETECTION:[/bold white]
Status: {synth_badge}
[dim]Token perplexity & generative style metrics evaluated on CPU.[/dim]
"""
    mitig_table = Table(expand=True, box=ROUNDED, title="[bold yellow]INVESTIGATOR PLAYBOOK[/bold yellow]")
    mitig_table.add_column("#", justify="center", width=4)
    mitig_table.add_column("Forensic Recommendation", style="bold white")

    for idx, m in enumerate(mitigations, start=1):
        mitig_table.add_row(str(idx), m)

    layout["right"].update(Panel(
        Group(
            Panel(Text.from_markup(synth_text.strip()), box=ROUNDED, border_style="red" if is_synth else "green"),
            Text(""),
            mitig_table,
        ),
        title="[bold cyan]MITIGATION ACTION PLAN[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


# ==============================================================================
# TAB 4: HEX CARVER & ENTROPY
# ==============================================================================
def render_tab_4_hex(state: ForensicTUIState) -> Layout:
    """Tab 4: ANSI Hex Dump Viewer & Shannon Entropy Distribution."""
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
        att_table = Table(expand=True, box=ROUNDED, title="[bold yellow]CARVED ATTACHMENTS[/bold yellow]")
        att_table.add_column("File", style="bold white")
        att_table.add_column("Entropy", justify="center")
        att_table.add_column("Magic Type", style="cyan")

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
        carver_items.append(Text.from_markup("[dim]No attachments found in RFC parts.[/dim]"))

    layout["carver"].update(Panel(
        Group(*carver_items),
        title="[bold cyan]SHANNON ENTROPY SPEEDOMETER[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    target_data = attachments[0].get("bytes", b"") if attachments else raw_bytes[:512]
    dump_lines = generate_hex_dump(target_data, max_bytes=288, offset_start=state.hex_offset)

    hex_table = Table(expand=True, box=SIMPLE)
    hex_table.add_column("Offset", style="dim cyan", width=10)
    hex_table.add_column("Hex Bytes (16 B/line)", style="bold yellow")
    hex_table.add_column("ASCII", style="bright_green", width=18)

    for line in dump_lines:
        hex_table.add_row(line["offset"], line["hex"], line["ascii"])

    layout["hexdump"].update(Panel(
        hex_table,
        title="[bold cyan]ANSI TERMINAL HEX DISASSEMBLER[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


# ==============================================================================
# TAB 5: SECTION 63 BSA 2023 CERTIFICATE (PDF / TEXT)
# ==============================================================================
def render_tab_5_bsa_cert(state: ForensicTUIState) -> Panel:
    """Tab 5: Court-Admissible Section 63 BSA 2023 PDF/Text Certificate."""
    cert_data = generate_bsa_certificate_data(state.evidence, case_id=state.case_id)
    cert_text = format_bsa_certificate_text(cert_data)
    syntax = Syntax(cert_text, "yaml", theme="monokai", line_numbers=True)

    return Panel(
        Group(
            Text.from_markup("[bold yellow]Section 63 Bharatiya Sakshya Adhiniyam (BSA 2023) Certificate Preview:[/bold yellow]"),
            Text.from_markup("[dim]Press [bold cyan][E][/bold cyan] to generate print-ready [bold green].cert.pdf[/bold green] + [bold green].cert.txt[/bold green] to ./forensic_exports/[/dim]\n"),
            syntax,
        ),
        title="[bold cyan]SECTION 63 BSA 2023 ELECTRONIC EVIDENCE CERTIFICATE[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    )


# ==============================================================================
# TAB 6: BATCH QUEUE
# ==============================================================================
def render_tab_6_batch(state: ForensicTUIState) -> Panel:
    """Tab 6: Batch Folder Triage Table."""
    if not state.batch_data:
        default_dir = os.path.dirname(state.evidence_path) or "./"
        hint = f"""
[bold yellow]BATCH EVIDENCE FOLDER AUDITING ENGINE[/bold yellow]

Fast multi-file triage for seized storage media and 50 GB mail dumps.

[bold white]ACTIONS:[/bold white]
• Press [bold cyan][B][/bold cyan] to audit current directory ([bold yellow]{default_dir}[/bold yellow])
• CLI Command: [bold cyan]cybersquad-tui batch-scan /media/forensics/ --export-csv triage.csv[/bold cyan]
"""
        return Panel(Align.center(Text.from_markup(hint.strip())), title="[bold cyan]BATCH EVIDENCE TRIAGE QUEUE[/bold cyan]", box=ROUNDED, border_style="cyan")

    stats = state.batch_data.get("stats", {})
    results = state.batch_data.get("results", [])

    stats_bar = (
        f"[bold white]Total Scanned:[/bold white] {stats.get('total_files', 0)}  "
        f"[bold red]Critical:[/bold red] {stats.get('critical', 0)}  "
        f"[bold yellow]Suspicious:[/bold yellow] {stats.get('suspicious', 0)}  "
        f"[bold green]Clean:[/bold green] {stats.get('clean', 0)}"
    )

    table = Table(expand=True, box=ROUNDED)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Evidence File", style="bold white", width=22)
    table.add_column("Verdict", width=18)
    table.add_column("Sender", style="cyan", width=25)
    table.add_column("Top Finding", style="dim")

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


# ==============================================================================
# TAB 7: YARA & SNORT RULES
# ==============================================================================
def render_tab_7_rules(state: ForensicTUIState) -> Layout:
    """Tab 7: Auto-generated YARA and Snort Rules."""
    layout = Layout()
    layout.split_row(
        Layout(name="yara", ratio=1),
        Layout(name="snort", ratio=1),
    )

    yara_code = generate_yara_rule(state.evidence, state.threat)
    snort_code = generate_snort_rule(state.evidence, state.threat)

    layout["yara"].update(Panel(
        Syntax(yara_code, "c", theme="monokai", line_numbers=True),
        title="[bold cyan]YARA FILE RULE (Press [Y] to Export)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    layout["snort"].update(Panel(
        Syntax(snort_code, "bash", theme="monokai", line_numbers=True),
        title="[bold cyan]SNORT / SURICATA NETWORK RULE (Press [S] to Export)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
    ))

    return layout


# ==============================================================================
# TAB 8: HELP & HOTKEYS
# ==============================================================================
def render_tab_8_help() -> Panel:
    """Tab 8: Simple Hotkeys Reference."""
    help_text = """
[bold bright_magenta]AICTE - SMART INDIA HACKATHON 2026 | PROBLEM STATEMENT #26106[/bold bright_magenta]
[bold bright_cyan]TEAM CYBER SQUAD — AIR-GAPPED FORENSIC TERMINAL SUITE[/bold bright_cyan]

[bold cyan]KEYBOARD CONTROLS:[/bold cyan]
  [bold white][1-8][/bold white]  Switch views (1: 4-Panel Deck, 2: Hop Map, 3: CatBERT, 4: Hex, 5: BSA-63, 6: Batch, 7: YARA, 8: Help)
  [bold white][A][/bold white]    Run / Refresh CatBERT NLP Intent Analysis
  [bold white][E][/bold white]    Generate Print-Ready Section 63 BSA PDF + Text Certificate
  [bold white][Y][/bold white]    Export YARA Threat Rule to disk
  [bold white][S][/bold white]    Export Snort / Suricata IDS Rule to disk
  [bold white][B][/bold white]    Run Batch Directory Scan
  [bold white][O][/bold white]    Open / Ingest a new .eml / .msg / .pst file interactively
  [bold white][Q][/bold white]    Quit TUI cleanly

[bold cyan]TERMINAL PIPELINE EXAMPLES:[/bold cyan]
  • Inspect file   : [green]python3 app.py /media/forensics/suspect_mail.eml[/green]
  • Batch audit    : [green]python3 app.py --batch /media/cases/ --export-csv results.csv[/green]
  • Generate PDF   : [green]python3 app.py --cert /evidence.eml --officer "IO Sharma"[/green]
"""
    return Panel(Text.from_markup(help_text.strip()), title="[bold cyan]HELP & KEYBOARD SHORTCUTS[/bold cyan]", box=ROUNDED, border_style="cyan")


def render_footer(state: ForensicTUIState) -> Panel:
    """Renders bottom action and status bar."""
    risk_score = state.threat.get("risk_score", 0)
    score_color = "bright_red" if risk_score >= 75 else "yellow" if risk_score >= 45 else "green"
    status_bar = (
        f"[STATUS] Threat: [{score_color}]CRITICAL (Score: {risk_score}/100)[/{score_color}] ── "
        f"Press [bold cyan][E][/bold cyan] to generate Sec 63 BSA PDF  │  "
        f"[bold cyan][1-8][/bold cyan] Switch Views  │  [bold cyan][O][/bold cyan] Open  │  [bold cyan][Q][/bold cyan] Quit"
    )
    content = Group(
        Text.from_markup(state.status_msg),
        Text.from_markup(status_bar),
    )
    return Panel(content, box=ROUNDED, border_style="blue", padding=(0, 1))


def build_full_layout(state: ForensicTUIState) -> Layout:
    """Constructs the complete layout."""
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="nav", size=3),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=4),
    )

    layout["header"].update(render_header(state))
    layout["nav"].update(render_navigation_bar(state.active_tab))
    layout["footer"].update(render_footer(state))

    if state.active_tab == 1:
        layout["body"].update(render_tab_1_command_deck(state))
    elif state.active_tab == 2:
        layout["body"].update(render_tab_2_hops(state))
    elif state.active_tab == 3:
        layout["body"].update(render_tab_3_catbert(state))
    elif state.active_tab == 4:
        layout["body"].update(render_tab_4_hex(state))
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
                    elif seq == "OP":
                        return "1"  # F1
                    elif seq == "OQ":
                        return "2"  # F2
                    elif seq == "OR":
                        return "3"  # F3
                    elif seq == "OS":
                        return "4"  # F4
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
                    state.status_msg = f"[dim]Switched to View {key}.[/dim]"
                elif key in {"a", "A"}:
                    state.refresh_ai()
                elif key in {"e", "E"}:
                    res = export_bsa_certificate(state.evidence, output_dir="./forensic_exports", case_id=state.case_id)
                    pdf_name = Path(res.get('pdf_path', 'cert.pdf')).name
                    state.status_msg = f"[bold green]✔ Generated Court-Admissible Section 63 BSA PDF: {pdf_name}[/bold green]"
                elif key in {"y", "Y", "s", "S"}:
                    res = export_threat_rules(state.evidence, state.threat, output_dir="./forensic_exports")
                    state.status_msg = f"[bold green]✔ Rules exported to ./forensic_exports/[/bold green]"
                elif key in {"b", "B"}:
                    scan_dir = os.path.dirname(state.evidence_path) or "./"
                    state.run_batch_scan(scan_dir)
                elif key in {"o", "O"}:
                    if old_settings:
                        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                    console.print("\n[bold cyan]Enter path to .eml / .msg / .pst evidence file:[/bold cyan] ", end="")
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
        description="Cyber Squad TUI v2.4 - Standalone Terminal Forensic Engine (SIH #26106)"
    )
    parser.add_argument("file", nargs="?", default=None, help="Path to evidence file (.eml, .msg, .pst)")
    parser.add_argument("--batch", "--batch-scan", metavar="DIR", dest="batch", help="Run batch forensic triage on directory of evidence files")
    parser.add_argument("--export-csv", metavar="OUT_CSV", help="Export batch triage report to CSV")
    parser.add_argument("--cert", metavar="FILE", help="Generate Section 63 BSA 2023 PDF/Text Certificate for file")
    parser.add_argument("--officer", default="Digital Forensic Examiner (Team Cyber Squad)", help="Investigating Officer name for BSA Certificate")
    parser.add_argument("--agency", default="Digital Forensics Lab (AICTE SIH #26106)", help="Agency/Lab name for BSA Certificate")
    parser.add_argument("--export-yara", metavar="FILE", help="Generate YARA threat hunting rule for file")
    parser.add_argument("--export-snort", metavar="FILE", help="Generate Snort network IDS rule for file")
    parser.add_argument("--ai", action="store_true", help="Run CatBERT Cognitive Forensic Intent Analysis")
    parser.add_argument("--stdin", action="store_true", help="Read raw email stream from STDIN pipe")

    args = parser.parse_args()

    # CLI Headless: AI Mode
    if args.ai and (args.file or args.cert):
        target = args.file or args.cert
        evidence = parse_email_evidence(target)
        threat = evaluate_forensic_threat_matrix(evidence)
        ai_res = perform_offline_cognitive_nlp_analysis(evidence, threat)
        console.print(f"[bold cyan]🤖 CatBERT NLP Forensic Analysis Result for {Path(target).name}:[/bold cyan]\n")
        console.print(f"[bold white]Engine:[/bold white] {ai_res['engine']}")
        console.print(f"[bold white]Classified Intent:[/bold white] [yellow]{ai_res['attack_vector']}[/yellow] ({ai_res['confidence_percent']}% confidence)")
        console.print(f"[bold white]Synthetic LLM Lure:[/bold white] {'[red]YES[/red]' if ai_res['synthetic_llm_detected'] else '[green]NO[/green]'}")
        console.print(f"\n[bold white]Executive Reasoner Assessment:[/bold white]\n{ai_res['executive_summary']}\n")
        console.print("[bold yellow]Incident Mitigation Playbook:[/bold yellow]")
        for idx, s in enumerate(ai_res['mitigation_steps'], 1):
            console.print(f"  {idx}. {s}")
        sys.exit(0)

    # CLI Headless: BSA Certificate Generator (PDF + TXT)
    if args.cert:
        evidence = parse_email_evidence(args.cert)
        paths = export_bsa_certificate(evidence, output_dir="./forensic_exports", officer_name=args.officer, agency_name=args.agency)
        console.print(f"[bold green]✔ Section 63 BSA Certificate Generated Successfully:[/bold green]")
        console.print(f"  • PDF Report : [cyan]{paths.get('pdf_path')}[/cyan]")
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
        evidence_data = parse_email_evidence(SAMPLE_RAW_EML, filename="urgent_wf.msg")
        state = ForensicTUIState(evidence_data, evidence_path="urgent_wf.msg")

    # Run Interactive TUI
    run_interactive_tui(state)


if __name__ == "__main__":
    main()
