"""
RFC 5322 MIME Email Forensic Parser & Defect Analyzer
Cyber Squad TUI - SIH Problem Statement #26106
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: List[str] = []

    def handle_data(self, data: str) -> None:
        clean = data.strip()
        if clean:
            self.parts.append(clean)

    def text(self) -> str:
        return " ".join(self.parts)


def strip_html(html_text: str) -> str:
    """Strips HTML tags, styles, and scripts cleanly for forensic analysis."""
    if not html_text:
        return ""
    cleaned = re.sub(r"<style[\s\S]*?</style>", " ", html_text, flags=re.IGNORECASE)
    cleaned = re.sub(r"<script[\s\S]*?</script>", " ", cleaned, flags=re.IGNORECASE)
    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(cleaned)
        return extractor.text()
    except Exception:
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", cleaned)).strip()


def parse_received_header(received_str: str) -> Dict[str, Any]:
    """
    Parses an RFC 5322 Received header to extract:
    - From hop
    - By hop
    - IP address (IPv4 / IPv6)
    - Protocol (SMTP, ESMTP, SMTPS, HTTP, etc.)
    - Timestamp (epoch and ISO string)
    """
    received_str = re.sub(r"\s+", " ", received_str).strip()
    
    # Extract IP address
    ip_match = re.search(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9a-fA-F:]{3,39})\]", received_str)
    ip_addr = ip_match.group(1) if ip_match else ""
    
    # Extract from
    from_match = re.search(r"\bfrom\s+([^\s;()]+)", received_str, re.IGNORECASE)
    from_host = from_match.group(1) if from_match else ""
    
    # Extract by
    by_match = re.search(r"\bby\s+([^\s;()]+)", received_str, re.IGNORECASE)
    by_host = by_match.group(1) if by_match else ""
    
    # Extract with protocol
    with_match = re.search(r"\bwith\s+([^\s;()]+)", received_str, re.IGNORECASE)
    with_proto = with_match.group(1) if with_match else "SMTP"
    
    # Extract timestamp after semicolon
    time_str = ""
    timestamp_dt = None
    if ";" in received_str:
        time_part = received_str.split(";")[-1].strip()
        time_str = time_part
        try:
            timestamp_dt = email.utils.parsedate_to_datetime(time_part)
        except Exception:
            timestamp_dt = None
            
    return {
        "raw": received_str,
        "from_host": from_host,
        "by_host": by_host,
        "ip": ip_addr,
        "protocol": with_proto,
        "time_str": time_str,
        "datetime": timestamp_dt.isoformat() if timestamp_dt else "",
        "epoch": timestamp_dt.timestamp() if timestamp_dt else 0.0,
    }


def parse_email_evidence(file_path_or_bytes: str | bytes | Path, filename: str = "") -> Dict[str, Any]:
    """
    Forensically parses an email file or raw bytes into a rich structured evidence dictionary.
    Computes cryptographic hashes and extracts all RFC artifacts.
    """
    raw_bytes: bytes
    target_filename = filename
    
    if isinstance(file_path_or_bytes, (str, Path)):
        p = Path(file_path_or_bytes)
        target_filename = target_filename or p.name
        with open(p, "rb") as f:
            raw_bytes = f.read()
    else:
        raw_bytes = bytes(file_path_or_bytes)
        target_filename = target_filename or "evidence.eml"

    # Compute Cryptographic Hashes
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    sha512 = hashlib.sha512(raw_bytes).hexdigest()
    md5 = hashlib.md5(raw_bytes).hexdigest()
    size_bytes = len(raw_bytes)

    parse_error = None
    defects: List[str] = []
    headers: Dict[str, str] = {}
    headers_list: List[Tuple[str, str]] = []
    received_hops: List[Dict[str, Any]] = []
    attachments: List[Dict[str, Any]] = []
    plain_parts: List[str] = []
    html_parts: List[str] = []
    meta = {
        "from": "",
        "to": "",
        "cc": "",
        "bcc": "",
        "subject": "",
        "date": "",
        "message_id": "",
        "return_path": "",
        "reply_to": "",
    }

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        
        # Extract all headers preserving duplicates and case
        for k, v in msg.items():
            val_str = str(v or "")
            headers_list.append((k, val_str))
            k_lower = k.lower()
            if k_lower in headers:
                headers[k_lower] = f"{headers[k_lower]}\n{val_str}"
            else:
                headers[k_lower] = val_str
                
        # Parse standard metadata
        meta["from"] = str(msg.get("From") or "")
        meta["to"] = str(msg.get("To") or "")
        meta["cc"] = str(msg.get("Cc") or "")
        meta["bcc"] = str(msg.get("Bcc") or "")
        meta["subject"] = str(msg.get("Subject") or "")
        meta["date"] = str(msg.get("Date") or "")
        meta["message_id"] = str(msg.get("Message-ID") or "")
        meta["return_path"] = str(msg.get("Return-Path") or "")
        meta["reply_to"] = str(msg.get("Reply-To") or "")

        # Extract Received: headers (chronological hop sequence)
        raw_received_headers = msg.get_all("Received") or []
        for r_hdr in raw_received_headers:
            parsed_hop = parse_received_header(str(r_hdr))
            received_hops.append(parsed_hop)

        # Walk parts to extract body and attachments
        for part in msg.walk():
            disposition = (part.get_content_disposition() or "").lower()
            part_filename = part.get_filename()
            content_type = (part.get_content_type() or "").lower()
            
            # Check if attachment
            if part_filename or disposition == "attachment" or disposition == "inline" and part_filename:
                payload = part.get_payload(decode=True) or b""
                att_sha256 = hashlib.sha256(payload).hexdigest()
                att_md5 = hashlib.md5(payload).hexdigest()
                attachments.append({
                    "filename": part_filename or "unnamed_attachment.bin",
                    "content_type": content_type,
                    "size": len(payload),
                    "bytes": payload,
                    "sha256": att_sha256,
                    "md5": att_md5,
                    "disposition": disposition,
                })
                continue

            # Body extraction
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text_str = payload.decode(charset, errors="replace")
                    except Exception:
                        text_str = payload.decode("utf-8", errors="replace")
                    plain_parts.append(text_str)
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        html_str = payload.decode(charset, errors="replace")
                    except Exception:
                        html_str = payload.decode("utf-8", errors="replace")
                    html_parts.append(html_str)

        # Collect defects
        for d in getattr(msg, "defects", []):
            defects.append(f"{d.__class__.__name__}: {str(d)}")

    except Exception as e:
        parse_error = str(e)

    # Build primary body
    body_plain = "\n\n".join(plain_parts).strip()
    raw_html = "\n\n".join(html_parts).strip()
    if not body_plain and raw_html:
        body_plain = strip_html(raw_html)

    return {
        "filename": target_filename,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "sha512": sha512,
        "md5": md5,
        "meta": meta,
        "body": body_plain,
        "html_body": raw_html,
        "headers": headers,
        "headers_list": headers_list,
        "received_hops": received_hops,
        "attachments": attachments,
        "defects": defects,
        "parse_error": parse_error,
        "raw_bytes": raw_bytes,
    }
