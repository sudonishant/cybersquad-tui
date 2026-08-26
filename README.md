# Cyber Squad TUI (Terminal User Interface Engine) - SIH #26106

Standalone Terminal User Interface (TUI) Application for Law Enforcement & SOC Forensic Investigators by **Team Cyber Squad**.

---

## 💻 Features

- **Asynchronous Rich Terminal Dashboard:** High-fidelity ASCII interface for headless servers and terminal environments.
- **Evidence Archive Navigator:** Tree navigator for inspecting `.eml`, `.msg`, and `.pst` file archives.
- **Forensic Case Card:** Instant display of SHA-256 hashes, CatBERT Threat Score, SPF/DKIM/DMARC flags, and BSA 2023 legal status.
- **Relonym Hop Sequence Grid:** Multi-hop relay IP tracker with geographic location and exit node detection.

---

## 🚀 Usage Instructions

```bash
# Install dependencies
pip install -r requirements.txt

# Launch TUI Terminal Application
python3 app.py
```

### Keybindings:
- `[Q]`: Quit TUI
- `[P]`: Run deep parse
- `[B]`: Export Section 63 BSA Certificate
- `[G]`: Sync with Neo4j Graph Database
