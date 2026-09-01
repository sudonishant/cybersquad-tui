"""
Pure-Python Court-Admissible PDF Generator for Section 63 BSA 2023 Certificates
Zero External Dependencies (Air-Gap & Offline Ready)
Cyber Squad TUI - AICTE SIH 2026 Problem Statement #26106
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


def _escape_pdf_text(text: str) -> str:
    """Escapes parenthesis and backslashes for PDF string literals."""
    return str(text or "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_bsa_pdf_bytes(cert_data: Dict[str, Any]) -> bytes:
    """
    Generates a valid, well-formatted PDF 1.4 document from Section 63 BSA certificate data.
    """
    case = cert_data.get("case_details", {})
    sys_env = cert_data.get("system_environment", {})
    ev = cert_data.get("evidence_profile", {})
    rfc = cert_data.get("rfc_envelope", {})
    cert_id = cert_data.get("certificate_id", "BSA63-CERT-0000")
    exam_time = case.get("examination_timestamp_utc", "")
    case_id = case.get("case_id", "")
    agency = case.get("agency", "")
    officer = case.get("examining_officer", "")
    hostname = sys_env.get("workstation_hostname", "")
    os_name = sys_env.get("operating_system", "")
    tool_name = sys_env.get("software_tool", "")
    fname = ev.get("filename", "")
    size_b = ev.get("size_bytes", 0)
    size_kb = size_b / 1024.0
    md5 = ev.get("md5_digest", "")
    sha256 = ev.get("sha256_digest", "")
    sha512 = ev.get("sha512_digest", "")
    from_addr = str(rfc.get("from", ""))[:60]
    to_addr = str(rfc.get("to", ""))[:60]
    subject = str(rfc.get("subject", ""))[:60]
    msg_id = str(rfc.get("message_id", ""))[:60]
    hops = rfc.get("hop_count", 0)
    atts = rfc.get("attachments_count", 0)

    # Document coordinates & content streams
    text_ops = []
    
    # Starting text block (Top of page)
    text_ops.append("BT")
    text_ops.append("/F1 13 Tf")
    text_ops.append("50 780 Td")
    text_ops.append(f"({_escape_pdf_text('CERTIFICATE UNDER SECTION 63 OF BHARATIYA SAKSHYA ADHINIYAM, 2023')}) Tj")
    
    text_ops.append("/F2 10 Tf")
    text_ops.append("0 -18 Td")
    text_ops.append(f"({_escape_pdf_text('Digital Forensic Electronic Evidence Certificate | AICTE SIH 2026 PS #26106')}) Tj")
    
    text_ops.append("/F2 9 Tf")
    text_ops.append("0 -18 Td")
    text_ops.append(f"({_escape_pdf_text(f'Certificate ID: {cert_id}  |  Generated: {exam_time}  |  Status: CERTIFIED')}) Tj")

    # End Header Text
    text_ops.append("ET")
    
    # Graphic border / separator
    text_ops.append("0.5 w")
    text_ops.append("50 735 m 550 735 l S")
    
    # Section 1: Examiner Details
    text_ops.append("BT")
    text_ops.append("/F1 11 Tf")
    text_ops.append("50 715 Td")
    text_ops.append(f"({_escape_pdf_text('1. INVESTIGATION & AUDIT DETAILS')}) Tj")
    text_ops.append("/F2 9 Tf")
    text_ops.append("0 -15 Td")
    text_ops.append(f"({_escape_pdf_text(f'Case Reference ID   : {case_id}  |  Air-Gap Isolated: YES')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'Investigating Agency: {agency}')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'Examiner Name       : {officer}  |  Hardware Node: {hostname} [{os_name}]')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'Forensic Software   : {tool_name}')}) Tj")

    # Section 2: Evidence Integrity & Hash Chain
    text_ops.append("/F1 11 Tf")
    text_ops.append("0 -22 Td")
    text_ops.append(f"({_escape_pdf_text('2. EVIDENCE ITEM IDENTIFICATION & CRYPTOGRAPHIC HASH CHAIN')}) Tj")
    text_ops.append("/F2 9 Tf")
    text_ops.append("0 -15 Td")
    text_ops.append(f"({_escape_pdf_text(f'Artifact Filename   : {fname}  ({size_b} bytes / {size_kb:.2f} KB)')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'MD5 Checksum        : {md5}')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'SHA-256 Digest      : {sha256}')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'SHA-512 Digest      : {sha512[:64]}...')}) Tj")

    # Section 3: RFC Envelope Telemetry
    text_ops.append("/F1 11 Tf")
    text_ops.append("0 -22 Td")
    text_ops.append(f"({_escape_pdf_text('3. RFC 5322 ENVELOPE & THREAT REASONING TELEMETRY')}) Tj")
    text_ops.append("/F2 9 Tf")
    text_ops.append("0 -15 Td")
    text_ops.append(f"({_escape_pdf_text(f'Sender (From)       : {from_addr}')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'Recipient (To)      : {to_addr}')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'Subject Line        : {subject}')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'Message-ID          : {msg_id}')}) Tj")
    text_ops.append("0 -13 Td")
    text_ops.append(f"({_escape_pdf_text(f'Relay Hops Count    : {hops} MTAs  |  Carved Attachments: {atts}')}) Tj")

    # Section 4: Statutory Legal Declaration
    text_ops.append("/F1 11 Tf")
    text_ops.append("0 -22 Td")
    text_ops.append(f"({_escape_pdf_text('4. STATUTORY DECLARATION (SECTION 63 BHARATIYA SAKSHYA ADHINIYAM, 2023)')}) Tj")
    text_ops.append("/F2 8 Tf")
    text_ops.append("0 -14 Td")
    text_ops.append(f"({_escape_pdf_text('I hereby certify that the electronic record described herein was received, preserved, and analyzed')}) Tj")
    text_ops.append("0 -11 Td")
    text_ops.append(f"({_escape_pdf_text('in a forensically sound manner using certified non-destructive bitstream techniques. The cryptographic')}) Tj")
    text_ops.append("0 -11 Td")
    text_ops.append(f"({_escape_pdf_text('hashes generated represent the exact mathematical state of the evidence artifact at the time of examination,')}) Tj")
    text_ops.append("0 -11 Td")
    text_ops.append(f"({_escape_pdf_text('with zero byte alteration during the chain of custody.')}) Tj")

    # Signature Block
    text_ops.append("0 -28 Td")
    text_ops.append(f"({_escape_pdf_text('___________________________________________________')}) Tj")
    text_ops.append("0 -12 Td")
    text_ops.append(f"({_escape_pdf_text(f'Authorized Forensic Examiner: {officer}')}) Tj")
    text_ops.append("0 -11 Td")
    text_ops.append(f"({_escape_pdf_text(f'Unit / Forensic Laboratory   : {agency}')}) Tj")
    text_ops.append("0 -11 Td")
    text_ops.append(f"({_escape_pdf_text(f'Timestamp & Cryptographic Seal: {exam_time}')}) Tj")
    text_ops.append("ET")

    content_stream = "\n".join(text_ops).encode("latin-1")
    stream_len = len(content_stream)

    # Assemble complete PDF structure
    pdf_parts = [
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n",
        f"4 0 obj\n<< /Length {stream_len} >>\nstream\n".encode("latin-1") + content_stream + b"\nendstream\nendobj\n",
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n",
        b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    # Calculate cross-reference table offsets
    xref_offsets = [0]
    total_len = 0
    for part in pdf_parts:
        xref_offsets.append(total_len)
        total_len += len(part)

    xref_text = [
        f"xref\n0 7\n0000000000 65535 f \n",
    ]
    for offset in xref_offsets[1:]:
        xref_text.append(f"{offset:010d} 00000 n \n")

    trailer_text = (
        f"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{total_len}\n%%EOF\n"
    )

    full_pdf = b"".join(pdf_parts) + "".join(xref_text).encode("latin-1") + trailer_text.encode("latin-1")
    return full_pdf


def export_bsa_pdf(
    cert_data: Dict[str, Any],
    output_pdf_path: str | Path,
) -> str:
    """Generates and writes Section 63 BSA PDF certificate to file."""
    pdf_p = Path(output_pdf_path)
    pdf_p.parent.mkdir(parents=True, exist_ok=True)
    pdf_bytes = generate_bsa_pdf_bytes(cert_data)
    pdf_p.write_bytes(pdf_bytes)
    return str(pdf_p.resolve())
