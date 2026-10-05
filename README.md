# Martinovation-Hackathon-Blockchain-Cybersecurity-
Mobile Malware Detection System for Android APKs

# 🛡️ DroidGuard // Static APK Threat Intelligence & Classifier

[![Engine Status](https://img.shields.io/badge/Engine-Online-10b981?style=for-the-badge&logo=shield)](https://github.com/)
[![Ruleset](https://img.shields.io/badge/Ruleset-v2026.04-06b6d4?style=for-the-badge)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

**DroidGuard** is a fast, client-side, browser-based static threat intelligence dashboard designed for Android application packages (`.apk`). It analyzes Dalvik bytecode markers, decompressed manifest permissions, and common malicious attack vectors mapped to the **MITRE ATT&CK® for Mobile** framework.

---

## ⚡ Key Capabilities

- **Zero Exfiltration Sandbox:** Static inspection runs client-side inside the browser—no binaries or metadata are transmitted to external servers.
- **Dynamic Risk Reactor:** Real-time animated score meter that adjusts dynamically across Risk Indexes (0–100) based on severity weighting.
- **MITRE ATT&CK Matrix Mapping:** Classifies indicators into recognized mobile attack patterns (e.g., Overlay Hijacking, Accessibility Service Abuse, Dynamic Dex Classloading).
- **Permissions Threat Matrix:** Categorizes declared Android permissions into high-privilege/dangerous vs. standard system groups, explaining potential abuse vectors.
- **Pre-Loaded Threat Profiles:** Instantly test and demonstrate using synthetic malware samples:
  - **Cerberus Banking Trojan** (Accessibility keylogging & 2FA SMS interception)
  - **Pegasus Spyware Profile** (Microphone background capture & silent GPS beacons)
  - **Signal Messenger** (Clean baseline / verified benign)
- **Forensics Export:** Download complete analysis summaries in standardized JSON format for SIEM ingestion.

---

## 📂 Project Structure

```text
├── index.html         # Main cyber-themed UI dashboard
├── styles.css         # Custom animations, scanlines & cyber grid styling (optional/inline)
├── app.js             # Core heuristic engine, scanner pipeline & UI events
└── README.md          # Project documentation