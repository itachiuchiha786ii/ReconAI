# 🔍 ReconAI — Automated Reconnaissance & AI Analysis Tool

**ReconAI** is an automated, intelligent reconnaissance framework designed for ethical hackers and red teamers. It runs recon tools, saves results, and uses `sgpt` (Shell GPT) for AI-powered analysis — producing professional-grade HTML reports.

---

## 🚀 Features

- WHOIS, NSLOOKUP, DIG, Traceroute, DNSRecon, Nmap, SSLScan, WhatWeb, WAFW00F, Nuclei
- Auto-generates HTML reports with structured tool output
- Integrates with ShellGPT for AI analysis
- Outputs actionable insights (vulns, misconfigs, next steps)

---

## 🧠 Requirements

- Python 3.x
- ShellGPT (`sgpt`) CLI installed
- Tools installed: `nmap`, `dnsrecon`, `wafw00f`, `whatweb`, `nuclei`, `sslscan`, etc.

Install Python dependencies:
```bash
pip install -r requirements.txt
