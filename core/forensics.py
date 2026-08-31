"""
Forensic Threat Matrix, Relay Chronologist, & Authentication Engine
Cyber Squad TUI - SIH Problem Statement #26106
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


TYPOSQUAT_TARGETS = [
    "google", "gmail", "microsoft", "outlook", "office365", "apple", "icloud",
    "sbi", "onlinesbi", "hdfc", "hdfcbank", "icici", "icicibank", "axisbank",
    "pnb", "bob", "bankofbaroda", "rbi", "rbi.org.in", "incometax", "gov.in",
    "cybercrime.gov.in", "paypal", "amazon", "netflix", "fedex", "dhl", "ups"
]

HIGH_RISK_TLDS = {
    "xyz", "top", "icu", "click", "rest", "work", "fit", "buzz", "cfd", "monster",
    "live", "surf", "casa", "sbs", "zip", "mov", "gq", "ml", "cf", "ga", "tk"
}


def evaluate_authentication_matrix(headers: Dict[str, str], sender: str = "") -> Dict[str, Any]:
    """
    Evaluates SPF, DKIM, DMARC, and ARC authentication statuses from RFC headers.
    """
    auth_results_str = headers.get("authentication-results", "") + " " + headers.get("arc-authentication-results", "")
    received_spf_str = headers.get("received-spf", "")
    
    # SPF Analysis
    spf_status = "NONE"
    spf_reason = "No SPF header present"
    if "spf=pass" in auth_results_str.lower() or received_spf_str.lower().startswith("pass"):
        spf_status = "PASS"
        spf_reason = "Sender IP authorized by domain SPF record"
    elif "spf=fail" in auth_results_str.lower() or received_spf_str.lower().startswith("fail"):
        spf_status = "FAIL"
        spf_reason = "Sender IP NOT permitted by domain SPF record"
    elif "spf=softfail" in auth_results_str.lower() or received_spf_str.lower().startswith("softfail"):
        spf_status = "SOFTFAIL"
        spf_reason = "Domain SPF designates IP as questionable (~all)"
    elif "spf=neutral" in auth_results_str.lower() or received_spf_str.lower().startswith("neutral"):
        spf_status = "NEUTRAL"
        spf_reason = "Domain SPF makes no assertions (?all)"
    elif "spf=permerror" in auth_results_str.lower():
        spf_status = "PERMERROR"
        spf_reason = "SPF record syntax error or circular reference"

    # DKIM Analysis
    dkim_status = "NONE"
    dkim_reason = "No DKIM signature validated"
    if "dkim=pass" in auth_results_str.lower():
        dkim_status = "PASS"
        dkim_reason = "Cryptographic signature verified against sender DNS key"
    elif "dkim=fail" in auth_results_str.lower():
        dkim_status = "FAIL"
        dkim_reason = "Cryptographic signature verification failed (forged or altered content)"
    elif "dkim=neutral" in auth_results_str.lower():
        dkim_status = "NEUTRAL"
        dkim_reason = "DKIM signature present but not verifiable"
    elif headers.get("dkim-signature"):
        dkim_status = "UNVERIFIED"
        dkim_reason = "DKIM-Signature header present in message"

    # DMARC Analysis
    dmarc_status = "NONE"
    dmarc_reason = "No DMARC evaluation found"
    if "dmarc=pass" in auth_results_str.lower():
        dmarc_status = "PASS"
        dmarc_reason = "Message passes SPF/DKIM alignment policy"
    elif "dmarc=fail" in auth_results_str.lower():
        dmarc_status = "FAIL"
        dmarc_reason = "Message violates domain DMARC alignment policy"
    elif "dmarc=reject" in auth_results_str.lower():
        dmarc_status = "REJECT"
        dmarc_reason = "Domain policy instructed receiving server to reject message"

    # ARC Analysis
    arc_status = "NONE"
    if headers.get("arc-seal") and "arc=pass" in auth_results_str.lower():
        arc_status = "PASS"
    elif headers.get("arc-seal"):
        arc_status = "PRESENT"

    # Alignment Check
    from_domain = sender.split("@")[-1].strip().lower() if "@" in sender else ""
    return_path = headers.get("return-path", "").strip("<> ").lower()
    return_domain = return_path.split("@")[-1] if "@" in return_path else ""
    
    alignment = "ALIGNED" if from_domain and return_domain and from_domain == return_domain else "MISALIGNED"
    if not return_domain:
        alignment = "UNKNOWN"

    return {
        "spf": {"status": spf_status, "reason": spf_reason},
        "dkim": {"status": dkim_status, "reason": dkim_reason},
        "dmarc": {"status": dmarc_status, "reason": dmarc_reason},
        "arc": {"status": arc_status},
        "alignment": alignment,
        "from_domain": from_domain,
        "return_path_domain": return_domain,
    }


def analyze_relay_hops(received_hops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Processes Received: headers in chronological order (from source MTA to destination MX).
    Calculates time deltas between hops and categorizes IP addresses.
    """
    if not received_hops:
        return []

    # In RFC 5322, Received headers are prepended on arrival: top is newest (destination), bottom is oldest (origin)
    ordered_hops = list(reversed(received_hops))
    processed: List[Dict[str, Any]] = []
    prev_epoch: Optional[float] = None

    for idx, hop in enumerate(ordered_hops, start=1):
        ip = hop.get("ip", "")
        ip_type = "UNKNOWN"
        is_private = False
        
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    ip_type = "PRIVATE (RFC1918)"
                    is_private = True
                elif ip_obj.is_loopback:
                    ip_type = "LOOPBACK"
                    is_private = True
                elif ip_obj.is_reserved:
                    ip_type = "RESERVED"
                    is_private = True
                else:
                    ip_type = "PUBLIC WAN"
            except Exception:
                ip_type = "INVALID_IP"

        # Calculate time delta
        epoch = hop.get("epoch", 0.0)
        delta_str = "0s"
        if prev_epoch and epoch and epoch >= prev_epoch:
            diff_secs = int(epoch - prev_epoch)
            if diff_secs < 60:
                delta_str = f"+{diff_secs}s"
            elif diff_secs < 3600:
                delta_str = f"+{diff_secs // 60}m {diff_secs % 60}s"
            else:
                delta_str = f"+{diff_secs // 3600}h {(diff_secs % 3600) // 60}m"
        elif prev_epoch and epoch and epoch < prev_epoch:
            delta_str = f"TIMEDELTA SKEW ({int(prev_epoch - epoch)}s)"

        if epoch:
            prev_epoch = epoch

        # Heuristic Network/ISP label
        from_host = hop.get("from_host", "")
        by_host = hop.get("by_host", "")
        isp_label = "Standard Relay Node"
        
        lower_host = f"{from_host} {by_host}".lower()
        if "google.com" in lower_host or "gmail.com" in lower_host:
            isp_label = "Google Workspace / Gmail MTA"
        elif "outlook.com" in lower_host or "microsoft.com" in lower_host or "protection.outlook" in lower_host:
            isp_label = "Microsoft 365 Exchange Online Protection"
        elif "sendgrid" in lower_host:
            isp_label = "SendGrid (Twilio) ESP"
        elif "mailgun" in lower_host:
            isp_label = "Mailgun Marketing ESP"
        elif "amazonses" in lower_host:
            isp_label = "Amazon Simple Email Service (SES)"
        elif "ovh" in lower_host or "hetzner" in lower_host or "digitalocean" in lower_host or "linode" in lower_host:
            isp_label = "Commercial Cloud Hosting / VPS"
        elif "tor-exit" in lower_host or "exitnode" in lower_host:
            isp_label = "Tor Anonymity Exit Node"
        elif is_private:
            isp_label = "Internal Enterprise Subnet / Mail Gateway"

        processed.append({
            "hop_number": idx,
            "ip": ip or "Not Logged",
            "ip_type": ip_type,
            "is_private": is_private,
            "from_host": from_host or "Unknown Host",
            "by_host": by_host or "Unknown Host",
            "protocol": hop.get("protocol", "SMTP"),
            "time_str": hop.get("time_str", ""),
            "delta": delta_str,
            "isp_label": isp_label,
            "raw": hop.get("raw", ""),
        })

    return processed


def extract_and_analyze_urls(text: str) -> List[Dict[str, Any]]:
    """
    Extracts all HTTP/HTTPS links and runs threat heuristics.
    """
    raw_urls = re.findall(r"https?://[^\s<>\"'{}|\\^`]+", text or "", flags=re.IGNORECASE)
    seen = set()
    results: List[Dict[str, Any]] = []

    for raw in raw_urls:
        clean = raw.rstrip(".,;!?)>]\'\"")
        if clean in seen:
            continue
        seen.add(clean)

        parsed = urlparse(clean)
        hostname = (parsed.hostname or "").lower()
        tld = hostname.split(".")[-1] if "." in hostname else ""
        flags: List[str] = []
        risk_score = 0

        # Protocol check
        if parsed.scheme.lower() == "http":
            flags.append("Insecure HTTP protocol")
            risk_score += 15

        # Punycode / IDN Homograph check
        if "xn--" in hostname:
            flags.append("Punycode / IDN Homograph domain")
            risk_score += 45

        # Direct IP in URL check
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
            flags.append("Direct IP address used as URL hostname")
            risk_score += 50
        except Exception:
            pass

        # High risk TLD check
        if tld in HIGH_RISK_TLDS:
            flags.append(f"Suspicious / High-Abuse TLD (.{tld})")
            risk_score += 35

        # Deep subdomain check
        parts = hostname.split(".")
        if len(parts) > 4:
            flags.append("Suspiciously deep subdomain nesting")
            risk_score += 25

        # Phishing keywords in path
        path_lower = parsed.path.lower()
        if re.search(r"/(login|signin|account|verify|update|secure|billing|banking|invoice|webscr|auth|otp)", path_lower):
            flags.append("Credential or financial harvesting path marker")
            risk_score += 35

        # Brand impersonation in domain
        for brand in TYPOSQUAT_TARGETS:
            if brand in hostname and not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com") or hostname.endswith(f".{brand}.in") or hostname.endswith(f".{brand}.org")):
                flags.append(f"Brand impersonation / typosquat cue ({brand})")
                risk_score += 40
                break

        risk_level = "CRITICAL" if risk_score >= 60 else "HIGH" if risk_score >= 35 else "SUSPICIOUS" if risk_score > 0 else "CLEAN"

        results.append({
            "url": clean,
            "domain": hostname,
            "tld": tld,
            "is_ip": is_ip,
            "risk_score": min(100, risk_score),
            "risk_level": risk_level,
            "flags": flags,
        })

    return results


def evaluate_forensic_threat_matrix(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive forensic threat scoring matrix for email evidence.
    Evaluates:
    - BEC and Wire Redirection
    - Phishing and Credential Theft
    - Brand Impersonation & Typosquatting
    - Cognitive Urgency & Psychological Coercion
    - Authentication Failures (SPF/DKIM/DMARC)
    - Suspicious Attachments & URL Threats
    """
    subject = evidence.get("meta", {}).get("subject", "")
    body = evidence.get("body", "")
    sender = evidence.get("meta", {}).get("from", "")
    headers = evidence.get("headers", {})
    attachments = evidence.get("attachments", [])
    
    full_text = f"{subject}\n{body}"
    threat_signals: List[Dict[str, Any]] = []
    total_score = 0

    # 1. BEC / Wire Transfer / Payment Redirection Rules
    bec_matches = re.findall(r"\b(wire transfer|bank transfer|change (of )?bank details|swift|iban|remittance|gift card|crypto|bitcoin|invoice payment|beneficiary account)\b", full_text, re.IGNORECASE)
    if bec_matches:
        threat_signals.append({
            "category": "BEC_FINANCIAL",
            "severity": "HIGH",
            "weight": 35,
            "title": "Business Email Compromise (BEC) / Financial Redirection",
            "details": f"Detected financial keywords: {', '.join(set([m[0] if isinstance(m, tuple) else m for m in bec_matches]))}"
        })
        total_score += 35

    # 2. Executive / Authority Impersonation
    exec_matches = re.findall(r"\b(ceo|cfo|managing director|board of directors|president|legal team|compliance officer|police commissioner|cbi|ed|income tax department)\b", full_text, re.IGNORECASE)
    if exec_matches:
        threat_signals.append({
            "category": "AUTHORITY_PRESSURE",
            "severity": "MEDIUM",
            "weight": 20,
            "title": "Executive Authority / Law Enforcement Pretexting",
            "details": f"High-authority pretexts observed: {', '.join(set(exec_matches))}"
        })
        total_score += 20

    # 3. Urgency & Coercive Psychological Pressure
    urgency_matches = re.findall(r"\b(urgent|immediately|asap|within 24 hours|account suspended|final notice|action required|immediate action|lawsuit|legal penalty|arrest warrant)\b", full_text, re.IGNORECASE)
    if urgency_matches:
        threat_signals.append({
            "category": "COGNITIVE_URGENCY",
            "severity": "MEDIUM",
            "weight": 20,
            "title": "Cognitive Urgency & Psychological Coercion",
            "details": f"Pressure phrases detected: {', '.join(set(urgency_matches))}"
        })
        total_score += 20

    # 4. Credential Harvesting / OTP Phishing
    cred_matches = re.findall(r"\b(verify your account|password expired|login to continue|enter your otp|2fa code|confirm identity|update credentials|sign in required)\b", full_text, re.IGNORECASE)
    if cred_matches:
        threat_signals.append({
            "category": "CREDENTIAL_HARVESTING",
            "severity": "HIGH",
            "weight": 30,
            "title": "Credential / Identity Harvesting Intent",
            "details": f"Account harvesting hooks detected: {', '.join(set(cred_matches))}"
        })
        total_score += 30

    # 5. Authentication Matrix
    auth_eval = evaluate_authentication_matrix(headers, sender)
    if auth_eval["spf"]["status"] == "FAIL":
        threat_signals.append({
            "category": "AUTH_SPOOFING",
            "severity": "HIGH",
            "weight": 30,
            "title": "SPF Authentication Failure (Sender Address Spoofed)",
            "details": auth_eval["spf"]["reason"]
        })
        total_score += 30
    if auth_eval["dkim"]["status"] == "FAIL":
        threat_signals.append({
            "category": "AUTH_TAMPERING",
            "severity": "HIGH",
            "weight": 30,
            "title": "DKIM Signature Cryptographic Verification Failed",
            "details": auth_eval["dkim"]["reason"]
        })
        total_score += 30
    if auth_eval["dmarc"]["status"] in {"FAIL", "REJECT"}:
        threat_signals.append({
            "category": "DMARC_VIOLATION",
            "severity": "HIGH",
            "weight": 25,
            "title": "DMARC Domain Alignment Policy Violation",
            "details": auth_eval["dmarc"]["reason"]
        })
        total_score += 25

    # 6. Attachment Threat Evaluation
    for att in attachments:
        fname = att.get("filename", "").lower()
        if re.search(r"\.(exe|scr|bat|cmd|vbs|js|ps1|hta|jar|iso|img|vhd|apk)$", fname):
            threat_signals.append({
                "category": "MALICIOUS_ATTACHMENT",
                "severity": "CRITICAL",
                "weight": 50,
                "title": f"Direct Executable / Script Payload: {att.get('filename')}",
                "details": f"Attachment has high-risk extension with SHA-256: {att.get('sha256')[:16]}..."
            })
            total_score += 50
        elif re.search(r"\.(pdf|docx?|xlsx?)\.(exe|vbs|scr|bat|js)$", fname):
            threat_signals.append({
                "category": "DOUBLE_EXTENSION",
                "severity": "CRITICAL",
                "weight": 50,
                "title": f"Deceptive Double Extension Anomaly: {att.get('filename')}",
                "details": "Double extension used to mask malicious executable as document"
            })
            total_score += 50

    # 7. URL Threat Evaluation
    url_items = extract_and_analyze_urls(body + "\n" + evidence.get("html_body", ""))
    for u in url_items:
        if u["risk_score"] >= 40:
            threat_signals.append({
                "category": "MALICIOUS_LINK",
                "severity": "HIGH" if u["risk_score"] < 60 else "CRITICAL",
                "weight": min(30, u["risk_score"]),
                "title": f"High-Risk URL Detected: {u['domain']}",
                "details": "; ".join(u["flags"]) or u["url"]
            })
            total_score += min(30, u["risk_score"])

    # Bound Threat Score
    final_score = min(100, max(0, total_score))
    
    verdict = "BENIGN / INFORMATIONAL"
    verdict_badge = "[bold green]CLEAN / LOW RISK[/bold green]"
    if final_score >= 75:
        verdict = "MALICIOUS / CRITICAL THREAT"
        verdict_badge = "[bold red]CRITICAL THREAT (QUARANTINE)[/bold red]"
    elif final_score >= 45:
        verdict = "SUSPICIOUS / HIGH RISK"
        verdict_badge = "[bold yellow]SUSPICIOUS (INVESTIGATE)[/bold yellow]"
    elif final_score >= 20:
        verdict = "ELEVATED RISK / REVIEW"
        verdict_badge = "[bold cyan]REVIEW RECOMMENDED[/bold cyan]"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "verdict_badge": verdict_badge,
        "signals": threat_signals,
        "auth_matrix": auth_eval,
        "url_analysis": url_items,
    }
