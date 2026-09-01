"""
AI Forensic Analyst & Second Opinion Engine
Cyber Squad TUI - AICTE SIH Problem Statement #26106

Supports:
1. Offline Deterministic Cognitive NLP & Linguistic Forensic Analyzer (100% Air-Gap Safe)
2. Online LLM Analysis via OpenRouter / Ollama / OpenAI / Gemini (Optional)
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


def perform_offline_cognitive_nlp_analysis(evidence: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
    """
    Offline Cognitive & Linguistic Forensic Analyzer.
    Analyzes:
    - Psychological Coercion Triggers (Urgency, Authority, Fear, Greed, Social Proof)
    - Social Engineering Attack Vectors (BEC, Impersonation, Credential Theft, Malware Delivery)
    - AI-Generated / Synthetic Phishing Likelihood Markers
    - Actionable Forensic Mitigation Advice
    """
    subject = evidence.get("meta", {}).get("subject", "")
    body = evidence.get("body", "")
    full_text = f"{subject}\n{body}".lower()
    headers = evidence.get("headers", {})
    sender = evidence.get("meta", {}).get("from", "")
    score = threat.get("risk_score", 0)

    # 1. Psychological Coercion Vectors
    psych_vectors = []
    if re.search(r"\b(urgent|immediately|asap|within 24 hours|final warning|last chance|act now|instant)\b", full_text):
        psych_vectors.append({
            "trigger": "Artificial Time Pressure (Urgency)",
            "description": "Forcing rapid decision making to bypass logical verification.",
            "impact": "HIGH"
        })
    if re.search(r"\b(ceo|director|police|cbi|income tax|rbi|admin|security team|compliance|court)\b", full_text):
        psych_vectors.append({
            "trigger": "Authority & Institutional Pretexting",
            "description": "Impersonating institutional authority to compel compliance.",
            "impact": "HIGH"
        })
    if re.search(r"\b(suspended|blocked|terminated|legal action|penalty|arrest|frozen|unauthorized)\b", full_text):
        psych_vectors.append({
            "trigger": "Fear & Threat of Loss (Coercion)",
            "description": "Threatening punitive consequences or service termination.",
            "impact": "CRITICAL"
        })
    if re.search(r"\b(reward|prize|cashback|bonus|refund|lottery|crypto|free gift|won|claim)\b", full_text):
        psych_vectors.append({
            "trigger": "Greed & Opportunity Lures",
            "description": "Enticing recipient with financial gains or unexpected refunds.",
            "impact": "MEDIUM"
        })

    # 2. Attack Vector Classification
    attack_vector = "General Phishing / Spam"
    confidence = 70
    if re.search(r"\b(wire transfer|bank account|invoice|swift|iban|remittance|payment details)\b", full_text):
        attack_vector = "Business Email Compromise (BEC) / Financial Fraud"
        confidence = 92
    elif re.search(r"\b(password|login|otp|2fa|verify account|sign in|credentials)\b", full_text):
        attack_vector = "Credential Harvesting / Account Takeover"
        confidence = 88
    elif len(evidence.get("attachments", [])) > 0:
        attack_vector = "Malicious Payload / Malspam Delivery"
        confidence = 85

    # 3. Synthetic / AI-Generated Phishing Analysis
    is_synthetic = False
    synthetic_cues = []
    # Check for hyper-polite corporate diction combined with malicious intent
    if re.search(r"\b(we kindly request|please be advised that|in accordance with our policies|prompt attention to this matter)\b", full_text):
        synthetic_cues.append("Polished corporate generative phrasing patterns observed.")
    if len(full_text.split()) > 30 and len(set(full_text.split())) / len(full_text.split()) > 0.75:
        synthetic_cues.append("High vocabulary lexical diversity typical of LLM-synthesized lures.")
    if synthetic_cues and score >= 40:
        is_synthetic = True

    # 4. Mitigation Recommendations for Investigators
    mitigations = []
    if score >= 75:
        mitigations.append("Block sender domain and return-path on perimeter mail gateways (EOP / IronPort).")
        mitigations.append("Search enterprise mailboxes for subject match to quarantine widespread campaign.")
        mitigations.append("Isolate recipient endpoint and check proxy logs for outbound connections to extracted URLs.")
        mitigations.append("Preserve RFC bitstream evidence and export Section 63 BSA certificate for legal escalation.")
    elif score >= 45:
        mitigations.append("Verify sender authenticity via out-of-band communication (phone/internal chat).")
        mitigations.append("Inspect carved attachments in an air-gapped sandbox before executing.")
        mitigations.append("Do not enter credentials or 2FA codes on the linked landing pages.")
    else:
        mitigations.append("Email exhibits standard benign markers; standard routine monitoring applies.")

    narrative = (
        f"Based on automated NLP forensic analysis, this artifact exhibits hallmarks of a "
        f"'{attack_vector}' targeting the recipient through "
        f"{', '.join(v['trigger'] for v in psych_vectors) if psych_vectors else 'informational cues'}. "
        f"The calculated forensic risk score is {score}/100."
    )

    return {
        "engine": "CyberSquad Cognitive AI Forensics (Offline NLP Model)",
        "attack_vector": attack_vector,
        "confidence_percent": confidence,
        "psychological_triggers": psych_vectors,
        "synthetic_llm_detected": is_synthetic,
        "synthetic_cues": synthetic_cues,
        "executive_summary": narrative,
        "mitigation_steps": mitigations,
    }


def request_online_llm_analysis(
    evidence: Dict[str, Any],
    threat: Dict[str, Any],
    api_key: Optional[str] = None,
    base_url: str = "https://openrouter.ai/api/v1",
    model: str = "openrouter/free",
) -> Dict[str, Any]:
    """
    Queries an online LLM (OpenRouter/Ollama) if API key is provided,
    otherwise falls back smoothly to the offline cognitive engine.
    """
    key = api_key or os.getenv("OPENROUTER_API_KEY", "").strip() or os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("OPENAI_API_KEY", "").strip()
    
    if not key:
        return perform_offline_cognitive_nlp_analysis(evidence, threat)

    meta = evidence.get("meta", {})
    prompt = f"""You are an expert digital email forensic investigator for Law Enforcement and Incident Response (AICTE SIH 2026).
Analyze this email artifact and return pure JSON:

Subject: {meta.get('subject')}
From: {meta.get('from')}
To: {meta.get('to')}
Date: {meta.get('date')}
Calculated Threat Score: {threat.get('risk_score')}/100
Authentication: {json.dumps(threat.get('auth_matrix', {}))}
Body Excerpt:
{evidence.get('body', '')[:1000]}

Return JSON format:
{{
  "engine": "Online LLM Forensic Review",
  "attack_vector": "...",
  "confidence_percent": 85,
  "psychological_triggers": [{{"trigger": "...", "description": "...", "impact": "HIGH"}}],
  "synthetic_llm_detected": false,
  "synthetic_cues": [],
  "executive_summary": "...",
  "mitigation_steps": ["step 1", "step 2"]
}}"""

    try:
        req_data = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{base_url}/chat/completions",
            data=req_data,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://cybersquad-sih2026.gov.in",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            # Clean JSON markdown
            content_clean = re.sub(r"^```(?:json)?\s*", "", content.strip(), flags=re.IGNORECASE)
            content_clean = re.sub(r"\s*```$", "", content_clean).strip()
            return json.loads(content_clean)
    except Exception:
        # Fallback to offline cognitive engine
        return perform_offline_cognitive_nlp_analysis(evidence, threat)
