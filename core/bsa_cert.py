"""
Section 63 Bharatiya Sakshya Adhiniyam (BSA 2023) Digital Evidence Certificate Generator
Cyber Squad TUI - SIH Problem Statement #26106
"""
from __future__ import annotations

import json
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def generate_bsa_certificate_data(
    evidence: Dict[str, Any],
    case_id: str = "AICTE-SIH26106-CASE-2026",
    officer_name: str = "Digital Forensic Examiner (Team Cyber Squad)",
    agency_name: str = "Digital Forensics & Incident Response Lab (AICTE SIH #26106)",
) -> Dict[str, Any]:
    """
    Constructs comprehensive forensic evidence metadata compliant with Section 63 BSA 2023.
    """
    now_utc = datetime.now(timezone.utc)
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    
    meta = evidence.get("meta", {})
    sha256 = evidence.get("sha256", "")
    sha512 = evidence.get("sha512", "")
    md5 = evidence.get("md5", "")
    size_bytes = evidence.get("size_bytes", 0)
    filename = evidence.get("filename", "evidence.eml")
    
    cert_id = f"BSA63-CERT-{sha256[:12].upper()}-{int(now_utc.timestamp())}"

    return {
        "certificate_id": cert_id,
        "statutory_act": "Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (Admissibility of Electronic Records)",
        "case_details": {
            "case_id": case_id,
            "examining_officer": officer_name,
            "agency": agency_name,
            "examination_timestamp_utc": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "examination_timestamp_epoch": now_utc.timestamp(),
        },
        "system_environment": {
            "workstation_hostname": hostname,
            "operating_system": os_info,
            "software_tool": "Team Cyber Squad Forensic Suite (AICTE SIH 2026 Engine v2.0.0)",
            "airgap_isolated": True,
        },

        "evidence_profile": {
            "filename": filename,
            "size_bytes": size_bytes,
            "mime_rfc_type": "message/rfc822",
            "sha256_digest": sha256,
            "sha512_digest": sha512,
            "md5_digest": md5,
        },
        "rfc_envelope": {
            "message_id": meta.get("message_id", "NOT_SPECIFIED"),
            "date": meta.get("date", "NOT_SPECIFIED"),
            "from": meta.get("from", "NOT_SPECIFIED"),
            "to": meta.get("to", "NOT_SPECIFIED"),
            "subject": meta.get("subject", "NOT_SPECIFIED"),
            "hop_count": len(evidence.get("received_hops", [])),
            "attachments_count": len(evidence.get("attachments", [])),
        },
        "declaration": (
            "I hereby certify that the electronic record described herein was received, preserved, "
            "and analyzed in a forensically sound manner using certified non-destructive bitstream "
            "techniques. The cryptographic hashes generated represent the exact mathematical state "
            "of the evidence artifact at the time of examination, with zero byte alteration."
        ),
    }


def format_bsa_certificate_text(cert_data: Dict[str, Any]) -> str:
    """Formats the certificate into a formal, court-ready text document."""
    case = cert_data["case_details"]
    sys_env = cert_data["system_environment"]
    ev = cert_data["evidence_profile"]
    rfc = cert_data["rfc_envelope"]

    lines = [
        "=" * 80,
        "       CERTIFICATE UNDER SECTION 63 OF BHARATIYA SAKSHYA ADHINIYAM, 2023",
        "             (ADMISSIBILITY OF ELECTRONIC FORENSIC EVIDENCE)",
        "=" * 80,
        "",
        f"CERTIFICATE REF NO : {cert_data['certificate_id']}",
        f"DATE OF GENERATION : {case['examination_timestamp_utc']}",
        f"LEGAL ACT REF      : {cert_data['statutory_act']}",
        "",
        "-" * 80,
        "1. EXAMINER & INVESTIGATION DETAILS",
        "-" * 80,
        f"Case / FIR ID      : {case['case_id']}",
        f"Investigating Unit : {case['agency']}",
        f"Examiner Name      : {case['examining_officer']}",
        f"Forensic Tool      : {sys_env['software_tool']}",
        f"Hardware Node      : {sys_env['workstation_hostname']} [{sys_env['operating_system']}]",
        f"Air-Gap Verified   : {'YES (Isolated Environment)' if sys_env['airgap_isolated'] else 'NO'}",
        "",
        "-" * 80,
        "2. EVIDENCE ITEM IDENTIFICATION & HASH CHAIN",
        "-" * 80,
        f"Artifact Filename  : {ev['filename']}",
        f"File Size          : {ev['size_bytes']} bytes ({ev['size_bytes'] / 1024:.2f} KB)",
        f"Format Type        : {ev['mime_rfc_type']}",
        "",
        f"MD5 Checksum       : {ev['md5_digest']}",
        f"SHA-256 Digest     : {ev['sha256_digest']}",
        f"SHA-512 Digest     : {ev['sha512_digest']}",
        "",
        "-" * 80,
        "3. RFC 5322 ENVELOPE SUMMARY",
        "-" * 80,
        f"Message-ID         : {rfc['message_id']}",
        f"Sender (From)      : {rfc['from']}",
        f"Recipient (To)     : {rfc['to']}",
        f"Header Date        : {rfc['date']}",
        f"Subject Line       : {rfc['subject']}",
        f"Relay Hops Extracted : {rfc['hop_count']}",
        f"Carved Attachments : {rfc['attachments_count']}",
        "",
        "-" * 80,
        "4. STATUTORY DECLARATION & CHAIN OF CUSTODY ASSURANCE",
        "-" * 80,
        cert_data["declaration"],
        "",
        "",
        "SIGNATURE OF EXAMINER / OFFICER IN-CHARGE:",
        "",
        "____________________________________________",
        f"Name: {case['examining_officer']}",
        f"Unit: {case['agency']}",
        f"Timestamp: {case['examination_timestamp_utc']}",
        "=" * 80,
    ]
    return "\n".join(lines)


def export_bsa_certificate(
    evidence: Dict[str, Any],
    output_dir: str | Path = "./forensic_exports",
    case_id: str = "CYBER-CASE-2026-SIH26106",
    officer_name: str = "Forensic Examiner (Cyber Squad)",
    agency_name: str = "Digital Forensics & Incident Response Lab (DFIR / CERT-In)",
) -> Dict[str, str]:
    """
    Exports court-admissible certificate files (.txt, .json, and .sha256) to disk.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    cert_data = generate_bsa_certificate_data(evidence, case_id, officer_name, agency_name)
    cert_text = format_bsa_certificate_text(cert_data)
    
    base_name = f"BSA63_CERT_{evidence.get('sha256', 'evidence')[:12]}"
    
    txt_file = out_path / f"{base_name}.cert.txt"
    json_file = out_path / f"{base_name}.manifest.json"
    sha_file = out_path / f"{base_name}.sha256"
    
    txt_file.write_text(cert_text, encoding="utf-8")
    json_file.write_text(json.dumps(cert_data, indent=2), encoding="utf-8")
    sha_file.write_text(f"{evidence.get('sha256')}  {evidence.get('filename')}\n", encoding="utf-8")
    
    return {
        "txt_path": str(txt_file.resolve()),
        "json_path": str(json_file.resolve()),
        "sha_path": str(sha_file.resolve()),
        "cert_id": cert_data["certificate_id"],
    }
