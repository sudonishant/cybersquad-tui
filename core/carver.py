"""
Shannon Entropy Visualizer, Magic Byte Signature Carver & ANSI Hex Dump Engine
Cyber Squad TUI - SIH Problem Statement #26106
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Dict, List, Tuple


MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE Executable / DLL (MZ)"),
    (b"\x7fELF", "Linux ELF Executable"),
    (b"%PDF", "Adobe PDF Document"),
    (b"PK\x03\x04", "ZIP Archive / OpenXML (DOCX/XLSX/PPTX) / JAR"),
    (b"Rar!\x1a\x07", "RAR Archive v4+"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive"),
    (b"\x1f\x8b", "GZIP Compressed File"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 Compound Document (DOC/XLS/PPT/MSI)"),
    (b"{\\rtf", "Rich Text Format (RTF)"),
    (b"\x89PNG\r\n\x1a\n", "PNG Image"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"GIF87a", "GIF87a Image"),
    (b"GIF89a", "GIF89a Image"),
    (b"#!/bin/", "Unix Shell Script"),
    (b"#!/usr/bin/", "Unix Shell Script / Python"),
    (b"<?xml", "XML Data Document"),
    (b"<!DOCTYPE html", "HTML Web Document"),
    (b"<html", "HTML Web Document"),
]

END_MARKERS = {
    "Adobe PDF Document": b"%%EOF",
    "JPEG Image": b"\xff\xd9",
    "PNG Image": b"IEND\xaeB`\x82",
}


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for i in range(256):
        count = data.count(i)
        if count:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return round(entropy, 3)


def get_entropy_spectrum_bars(data: bytes, num_blocks: int = 32) -> str:
    """
    Generates a terminal visual spectrum bar of entropy distribution across the file.
    Block characters: ' ' (0.0), '░' (<3.0), '▒' (<5.5), '▓' (<7.2), '█' (>=7.2 packed/encrypted).
    """
    if not data:
        return "[dim]No Data[/dim]"
    
    total_len = len(data)
    block_size = max(1, total_len // num_blocks)
    spectrum: List[str] = []

    for i in range(0, total_len, block_size):
        chunk = data[i:i + block_size]
        ent = calculate_shannon_entropy(chunk)
        if ent >= 7.2:
            spectrum.append("[bold red]█[/bold red]")
        elif ent >= 5.5:
            spectrum.append("[bold yellow]▓[/bold yellow]")
        elif ent >= 3.5:
            spectrum.append("[bold green]▒[/bold green]")
        elif ent >= 1.0:
            spectrum.append("[cyan]░[/cyan]")
        else:
            spectrum.append("[dim] [/dim]")

    return "".join(spectrum[:num_blocks])


def identify_magic_type(data: bytes) -> Tuple[str, str]:
    """Identifies file type by magic byte header signature and returns (type, description)."""
    if not data:
        return "EMPTY", "Empty byte stream"
    for signature, label in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return label, f"Matched magic header: {signature.hex().upper()}"
    return "RAW / UNKNOWN", "No standard magic signature recognized"


def inspect_format_boundaries(data: bytes, file_type: str) -> Dict[str, Any]:
    """
    Detects boundary anomalies such as hidden payloads appended after EOF markers.
    """
    marker = END_MARKERS.get(file_type)
    if not marker or not data:
        return {"has_trailing": False, "trailing_bytes": 0, "details": "No EOF check for this format"}

    eof_pos = data.rfind(marker)
    if eof_pos < 0:
        return {"has_trailing": False, "trailing_bytes": 0, "details": "Standard EOF marker not observed"}

    trailing_start = eof_pos + len(marker)
    trailing_data = data[trailing_start:]
    non_ws_trailing = sum(1 for b in trailing_data if b not in b"\t\r\n ")

    if non_ws_trailing > 0:
        trailing_magic, _ = identify_magic_type(trailing_data.lstrip(b"\t\r\n "))
        return {
            "has_trailing": True,
            "trailing_bytes": len(trailing_data),
            "non_ws_trailing": non_ws_trailing,
            "trailing_magic": trailing_magic,
            "eof_offset": eof_pos,
            "details": f"Found {non_ws_trailing} non-whitespace bytes trailing past {file_type} EOF marker at offset {eof_pos}!"
        }

    return {"has_trailing": False, "trailing_bytes": len(trailing_data), "details": "Clean format boundary"}


def generate_hex_dump(data: bytes, max_bytes: int = 512, offset_start: int = 0) -> List[Dict[str, str]]:
    """
    Generates structured lines for an ANSI terminal Hex Dump viewer.
    Columns: Offset (Hex), Hex values (16 bytes), ASCII representation.
    """
    lines: List[Dict[str, str]] = []
    chunk = data[offset_start:offset_start + max_bytes]
    
    for i in range(0, len(chunk), 16):
        line_bytes = chunk[i:i + 16]
        offset = offset_start + i
        
        # Hex representation with 8-byte spacing
        hex_parts = []
        for b in line_bytes:
            hex_parts.append(f"{b:02x}")
        
        first_half = " ".join(hex_parts[:8])
        second_half = " ".join(hex_parts[8:]) if len(hex_parts) > 8 else ""
        hex_formatted = f"{first_half:<23}  {second_half:<23}".rstrip()

        # ASCII representation
        ascii_chars = []
        for b in line_bytes:
            if 32 <= b <= 126:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append(".")
        ascii_formatted = "".join(ascii_chars)

        lines.append({
            "offset": f"{offset:08x}",
            "hex": hex_formatted,
            "ascii": ascii_formatted,
        })

    return lines


def analyze_attachment_forensics(attachment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Runs full deep forensic inspection on an extracted email attachment:
    - Shannon Entropy + Entropy Spectrum
    - Magic Byte Verification
    - Extension Mismatch Anomaly
    - Format Boundary & Trailing Payload Inspection
    - Embedded Suspicious Macros / Scripts
    """
    data = attachment.get("bytes", b"")
    fname = attachment.get("filename", "unnamed.bin")
    ext = fname.lower().split(".")[-1] if "." in fname else ""
    
    entropy = calculate_shannon_entropy(data)
    spectrum = get_entropy_spectrum_bars(data)
    magic_type, magic_desc = identify_magic_type(data)
    boundary = inspect_format_boundaries(data, magic_type)
    
    anomalies: List[str] = []
    risk_score = 0

    # High entropy warning (Packed / Encrypted / Obfuscated)
    if entropy >= 7.5:
        anomalies.append(f"Extremely High Shannon Entropy ({entropy}/8.0) - Likely Packed / Encrypted")
        risk_score += 45
    elif entropy >= 6.8:
        anomalies.append(f"Elevated Shannon Entropy ({entropy}/8.0)")
        risk_score += 20

    # Extension vs Magic Byte Mismatch
    if "Executable" in magic_type and ext in {"pdf", "docx", "xlsx", "png", "jpg", "txt", "csv"}:
        anomalies.append(f"CRITICAL MISMATCH: File has extension '.{ext}' but is actually a {magic_type}!")
        risk_score += 90

    # Double Extension
    if re.search(r"\.(pdf|docx?|xlsx?|png|jpg|txt)\.(exe|scr|bat|cmd|vbs|js|ps1|hta)$", fname, re.IGNORECASE):
        anomalies.append("Double Extension Anomaly detected (Disguised executable payload)")
        risk_score += 70

    # Trailing Boundary Payload
    if boundary.get("has_trailing"):
        anomalies.append(f"Boundary Violation: {boundary.get('details')}")
        risk_score += 60

    # Active content / Macros in Office/PDF
    if data and (ext in {"doc", "docx", "xls", "xlsx", "docm", "xlsm"} or "OLE2" in magic_type):
        if re.search(b"VBA_Project|vbaProject|AutoOpen|Document_Open|Shell|powershell|wscript", data, re.IGNORECASE):
            anomalies.append("Embedded VBA Macro / Script Execution markers found in Office document")
            risk_score += 65

    if data and (ext == "pdf" or "PDF" in magic_type):
        if re.search(b"/JavaScript|/JS|/Launch|/OpenAction|/EmbeddedFiles", data, re.IGNORECASE):
            anomalies.append("Embedded JavaScript / Auto-Launch Active Content detected in PDF stream")
            risk_score += 60

    return {
        "filename": fname,
        "extension": ext.upper(),
        "size": len(data),
        "entropy": entropy,
        "spectrum": spectrum,
        "magic_type": magic_type,
        "boundary": boundary,
        "anomalies": anomalies,
        "risk_score": min(100, risk_score),
    }
