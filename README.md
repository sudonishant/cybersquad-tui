# 🛡️ Cyber Squad TUI (Terminal Forensic Engine) — SIH #26106

Standalone, 100% Offline, Air-Gap Ready Terminal Forensic Suite for **Law Enforcement Officers (LEOs)**, **SOC Incident Responders**, and **Forensic Labs** by **Team Cyber Squad**.

---

## 🌟 Why Cyber Squad TUI is Distinct from Web UI

| Feature | Web Interface (`cybersquad-web`) | Cyber Squad TUI (`cybersquad-tui`) |
| :--- | :--- | :--- |
| **Operational Environment** | Browser-based, requires HTTP ports, Node.js, Web servers. | **100% Offline / Air-Gapped / Headless SSH**. Runs directly on SANS SIFT, Kali Linux, CAINE, headless servers. |
| **Data Privacy & Sanitization** | Client-server HTTP requests. | **Zero-Network In-Memory Processing**, zero disk cache leakage, memory-safe. |
| **Low-Level Byte Analysis** | High-level HTML view. | **Color-Coded Hex Dump & Shannon Entropy Map (`█▓▒░`)** with byte offsets and format boundary anomaly detection. |
| **Legal Admissibility** | On-screen risk badge. | **Section 63 BSA 2023 Certificate Generator** with SHA-256/512 cryptographic digests, custody chain, examiner signature block. |
| **Threat Intelligence** | Basic indicators. | **Auto-Generates YARA Rules, Snort/Suricata IDS Signatures, and STIX 2.1 Threat Intel Objects** directly to disk. |
| **Batch Folder Forensics** | One file at a time. | **Bulk Evidence Queue**: Scans entire directories of `.eml`/`.msg` files with live triage ranking, sorting, and CSV export. |
| **Speed & Workflow** | Mouse-driven, browser DOM latency. | **Sub-millisecond keyboard navigation** (1-8 quick views, Vim `j`/`k`, `/` filter, `[E]` export, `[B]` batch). |

---

## 🚀 Quick Start & Installation

```bash
# 1. Navigate to TUI directory
cd cybersquad-tui-master

# 2. Install minimal dependencies (Only 'rich')
pip install -r requirements.txt

# 3. Launch Interactive Forensic TUI
python3 app.py
```

---

## ⌨️ Interactive TUI Navigation & Hotkeys

### Navigation Tabs:
- `[1]`: **Overview & Threat Verdict** — Score dial, SPF/DKIM/DMARC matrix, cognitive/urgency triggers.
- `[2]`: **RFC Headers & Hop Chronology** — Full header tree, multi-hop relay IP timeline, delta analysis.
- `[3]`: **Hex Dump & Shannon Entropy Carver** — Live 16-byte hex dump + ASCII view, entropy distribution spectrum (`█▓▒░`).
- `[4]`: **URL Defense Matrix** — Link breakdown table, punycode detection, credential harvesting flags.
- `[5]`: **Section 63 BSA 2023 Certificate** — Live preview of court-admissible electronic evidence certificate.
- `[6]`: **Batch Evidence Triage Queue** — Multi-evidence folder analysis table with risk scores.
- `[7]`: **Threat Intel & Rules Generator** — Live generated YARA and Snort/Suricata rules.
- `[8]` or `[?]`: **Help & Keybindings Reference** — Complete investigator guide.

### Forensic Actions:
- `[E]`: Export Section 63 BSA 2023 Certificate (`.cert.txt`, `.json`, `.sha256`) to `./forensic_exports/`
- `[Y]`: Export YARA Threat Hunting Rule to disk
- `[S]`: Export Snort / Suricata IDS Network Rule to disk
- `[B]`: Run Batch Folder Scan on current/parent directory
- `[O]`: Open and load a new `.eml` file interactively
- `[Q]`: Quit application cleanly

---

## 💻 CLI Pipeline & Automation Commands

### 1. Directly Open a Specific Evidence File
```bash
python3 app.py "/path/to/suspicious_mail.eml"
```

### 2. Batch Folder Scan with CSV Export
```bash
python3 app.py --batch /cases/incident_2026/ --export-csv /cases/triage_summary.csv
```

### 3. Generate Section 63 BSA 2023 Certificate (Headless)
```bash
python3 app.py --cert /path/to/evidence.eml --officer "Inspector Rajesh Sharma" --agency "CERT-In DFIR Lab"
```

### 4. Headless Threat Rule Generation (YARA / Snort)
```bash
python3 app.py --export-yara /path/to/evidence.eml > threat_rule.yar
python3 app.py --export-snort /path/to/evidence.eml > snort_rule.rules
```

### 5. Unix Pipe & STDIN Ingestion
```bash
cat raw_email.eml | python3 app.py --stdin
```

---

## 🏛️ Legal Compliance: Section 63 BSA 2023

The Bharatiya Sakshya Adhiniyam, 2023 (BSA) governs the admissibility of electronic evidence in Indian courts. Cyber Squad TUI automatically generates:
1. **Cryptographic Digests**: SHA-256, SHA-512, and MD5 computed directly from raw byte streams.
2. **Chain of Custody**: UTC timestamping, host hardware node signature, and tool provenance.
3. **Court-Ready Plain Text & Machine-Readable Manifests**: Exported with standard formatting ready for submission alongside cyber chargesheets.

---

## 📁 Architecture

```
cybersquad-tui-master/
├── app.py                     # Main CLI entrypoint & interactive event loop
├── requirements.txt           # Minimal dependencies
├── README.md                  # Comprehensive investigator documentation
└── core/
    ├── __init__.py
    ├── parser.py              # Loss-aware RFC 5322 MIME parser & defect analyzer
    ├── forensics.py           # Threat matrix, BEC detector, Relay hop chronologist
    ├── carver.py              # Shannon entropy, magic byte carver, ANSI Hex dump
    ├── bsa_cert.py            # Section 63 BSA 2023 legal certificate generator
    ├── rule_gen.py            # YARA, Snort/Suricata & STIX 2.1 rule generator
    └── batch.py               # Recursive multi-evidence folder scanner & CSV reporter
```
