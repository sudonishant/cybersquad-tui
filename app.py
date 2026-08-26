#!/usr/bin/env python3
"""
Cyber Squad TUI (Terminal User Interface) - Forensic Engine
SIH 2026 Problem Statement #26106
"""

import os
import sys
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich.live import Live

console = Console()

def make_layout() -> Layout:
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=3)
    )
    
    layout["main"].split_row(
        Layout(name="archive_tree", ratio=1),
        Layout(name="case_details", ratio=2)
    )
    
    layout["case_details"].split(
        Layout(name="case_info", ratio=2),
        Layout(name="hop_grid", ratio=1)
    )
    
    return layout

def get_header() -> Panel:
    time_str = datetime.now().strftime("%I:%M:%S %p")
    header_text = Text(f"Cyber Squad TUI (Terminal Forensic Engine)                        [{time_str}]", style="bold cyan")
    return Panel(header_text, style="blue")

def get_archive_tree() -> Panel:
    tree_text = """[bold yellow][Folder] /evidence/cases/[/bold yellow]
├── incident_01.eml
├── spoof_bob_alert.msg
├── phish_campaign.pst
└── clean_mail.eml"""
    return Panel(tree_text, title="EVIDENCE FOLDER ARCHIVE", border_style="cyan")

def get_case_info() -> Panel:
    info_text = """[bold white]Case ID:[/bold white] CS-CASE-2026-0091
[bold white]SHA-256:[/bold white] 8e4823a6504e7daf70bcf5b248f1ba75b204918a
[bold white]Subject:[/bold white] URGENT: Action required immediately
[bold white]Sender:[/bold white] support@b0b-security-update.in
[bold white]Threat Score:[/bold white] [bold red][ CRITICAL - 98 / 100 ][/bold red]

[bold yellow]AUTHENTICATION CHECKS:[/bold yellow]
- SPF: [bold red][FAIL][/bold red]   - DKIM: [bold red][FAIL][/bold red]   - DMARC: [bold red][REJECT][/bold red]

[bold yellow]DETECTION LOGS:[/bold yellow]
- [HIGH] Typosquatted sender targeting BOB domain
- [HIGH] Urgent Cognitive Linguistic pressure cues
- [LEGAL] Section 63 BSA 2023 Certificate Generated"""
    return Panel(info_text, title="PARSED FORENSIC RESULTS", border_style="bold red")

def get_hop_grid() -> Panel:
    table = Table(expand=True, box=None)
    table.add_column("Hop #", style="cyan", justify="center")
    table.add_column("IP Address", style="bold white")
    table.add_column("Location", style="yellow")
    table.add_column("ISP / Network", style="magenta")
    table.add_column("Delta", style="green", justify="right")
    
    table.add_row("1", "185.220.101.5", "China (CN)", "Tor Exit Node Provider", "0s")
    table.add_row("2", "192.0.2.146", "Germany (DE)", "Commercial Cloud ISP", "12s")
    
    return Panel(table, title="HOP SEQUENCE GRID", border_style="green")

def get_footer() -> Panel:
    footer_text = "[bold cyan][Q][/bold cyan] Quit   [bold cyan][P][/bold cyan] Run deep parse   [bold cyan][B][/bold cyan] Export Section 63 Certificate   [bold cyan][G][/bold cyan] Graph Sync"
    return Panel(Text.from_markup(footer_text), style="bold blue")

def main():
    layout = make_layout()
    layout["header"].update(get_header())
    layout["archive_tree"].update(get_archive_tree())
    layout["case_info"].update(get_case_info())
    layout["hop_grid"].update(get_hop_grid())
    layout["footer"].update(get_footer())
    
    console.clear()
    console.print(layout)

if __name__ == "__main__":
    main()
