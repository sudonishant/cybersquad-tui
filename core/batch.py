"""
Batch Forensic Processing, Folder Auditing & Triage Engine
Cyber Squad TUI - SIH Problem Statement #26106
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.forensics import evaluate_forensic_threat_matrix
from core.parser import parse_email_evidence


def scan_evidence_directory(
    directory_path: str | Path,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> Dict[str, Any]:
    """
    Recursively scans a directory for email evidence files (.eml, .msg, .mbox)
    and computes triage forensics for each file.
    """
    dir_p = Path(directory_path)
    if not dir_p.exists() or not dir_p.is_dir():
        return {"error": f"Directory not found: {directory_path}", "results": [], "stats": {}}

    extensions = {".eml", ".msg", ".mbox", ".txt"}
    files = [p for p in dir_p.rglob("*") if p.is_file() and p.suffix.lower() in extensions]
    
    total = len(files)
    results: List[Dict[str, Any]] = []
    
    stats = {
        "total_files": total,
        "critical": 0,
        "suspicious": 0,
        "review": 0,
        "clean": 0,
        "total_attachments": 0,
        "total_urls": 0,
    }

    for idx, file_p in enumerate(files, start=1):
        if progress_callback:
            progress_callback(idx, total, file_p.name)
            
        try:
            evidence = parse_email_evidence(file_p)
            threat = evaluate_forensic_threat_matrix(evidence)
            score = threat.get("risk_score", 0)
            
            if score >= 75:
                stats["critical"] += 1
            elif score >= 45:
                stats["suspicious"] += 1
            elif score >= 20:
                stats["review"] += 1
            else:
                stats["clean"] += 1

            att_cnt = len(evidence.get("attachments", []))
            url_cnt = len(threat.get("url_analysis", []))
            stats["total_attachments"] += att_cnt
            stats["total_urls"] += url_cnt

            results.append({
                "filename": file_p.name,
                "filepath": str(file_p.resolve()),
                "size_bytes": evidence.get("size_bytes", 0),
                "sha256": evidence.get("sha256", ""),
                "subject": evidence.get("meta", {}).get("subject", ""),
                "sender": evidence.get("meta", {}).get("from", ""),
                "date": evidence.get("meta", {}).get("date", ""),
                "risk_score": score,
                "verdict": threat.get("verdict", "UNKNOWN"),
                "spf": threat.get("auth_matrix", {}).get("spf", {}).get("status", "NONE"),
                "dkim": threat.get("auth_matrix", {}).get("dkim", {}).get("status", "NONE"),
                "dmarc": threat.get("auth_matrix", {}).get("dmarc", {}).get("status", "NONE"),
                "attachments_count": att_cnt,
                "urls_count": url_cnt,
                "signals_count": len(threat.get("signals", [])),
                "top_signal": threat.get("signals", [{}])[0].get("title", "No critical signal") if threat.get("signals") else "None",
            })
        except Exception as e:
            results.append({
                "filename": file_p.name,
                "filepath": str(file_p.resolve()),
                "risk_score": 0,
                "verdict": f"PARSE ERROR: {str(e)}",
                "sha256": "",
                "subject": "",
                "sender": "",
                "attachments_count": 0,
                "urls_count": 0,
            })

    # Sort results by risk_score descending
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    return {
        "directory": str(dir_p.resolve()),
        "stats": stats,
        "results": results,
    }


def export_batch_to_csv(batch_data: Dict[str, Any], output_csv_path: str | Path) -> str:
    """Exports batch triage results to a clean CSV report."""
    csv_p = Path(output_csv_path)
    csv_p.parent.mkdir(parents=True, exist_ok=True)
    
    results = batch_data.get("results", [])
    fieldnames = [
        "filename", "risk_score", "verdict", "subject", "sender",
        "spf", "dkim", "dmarc", "attachments_count", "urls_count",
        "top_signal", "sha256", "size_bytes", "filepath"
    ]
    
    with open(csv_p, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)
            
    return str(csv_p.resolve())
