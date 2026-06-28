# 🔍 OSINT Pro — Reconnaissance Tool v4.0

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-stdlib%20only-brightgreen)
![GUI](https://img.shields.io/badge/Interface-GUI%20%2B%20CLI-purple)

> A professional, fully open-source OSINT reconnaissance toolkit with a dark-theme GUI and headless CLI mode — **zero external dependencies**, pure Python 3.9+ stdlib only.

---

## ✨ Features

| Module | What it does |
|---|---|
| 🌐 **DNS & Host** | A/AAAA records, FQDN, reverse PTR lookup |
| 🔌 **Port Scan** | nmap (with service detection) → socket fallback |
| 📡 **HTTP Headers** | Server fingerprint + security header audit (CSP, HSTS, etc.) |
| 🔐 **SSL / TLS** | Certificate details, SAN enumeration, TLS 1.2/1.3 probe |
| 🛡️ **WAF Detection** | Cloudflare, Akamai, Fastly, Sucuri, Imperva, AWS WAF, Azure, GCP |
| ☁️ **AWS Detection** | CloudFront, S3, ALB, API Gateway, EC2 IP ranges |
| 🟠 **Cloudflare** | Header + ASN/IP range fingerprinting |
| 🖥️ **Web Server** | Nginx/Apache/IIS fingerprint + sensitive path probe |
| 🗺️ **Subdomains** | crt.sh CT logs + DNS brute-force wordlist |
| 📧 **Email Harvest** | Emails, external domains, social media profiles |
| 📋 **WHOIS** | Registrar, dates, nameservers via public JSON API |
| 🤖 **Robots/Sitemap** | robots.txt, sitemap.xml, security.txt discovery |

---

## 🚀 Quick Start

### GUI Mode (default)
```bash
python osint_pro.py
```

### CLI / Headless Mode
```bash
# Full scan
python osint_pro.py --cli example.com

# Specific modules only
python osint_pro.py --cli example.com --modules "DNS & Host" "SSL / TLS" "WAF Detection"

# Verbose debug output
python osint_pro.py --cli example.com --verbose
```

---

## 📸 Screenshots

> Dark GitHub-inspired terminal aesthetic. Progress dots per-module, JSON export, Ctrl+Enter to scan.

```
════════════════════════════════════════════════════════════════
  ◈  SSL/TLS Certificate Analysis
════════════════════════════════════════════════════════════════
  [+]  Supported TLS: TLS 1.2, TLS 1.3
  [+]  Common Name: *.example.com
  [+]  Issued By: DigiCert Inc
  [+]  Valid Until: Sep 14 23:59:59 2025 GMT
  [+]  Cipher Suite: TLS_AES_256_GCM_SHA384
  [+]  SAN Count: 3
       •  example.com
       •  www.example.com
       •  api.example.com
```

---

## 🏗️ Architecture

```
osint_pro.py
├── OutputBridge        # Thread-safe GUI ↔ CLI output layer
├── fetch()             # Resilient HTTP helper (gzip, retry, browser UA)
├── Modules (12 total)  # Each returns typed dict[str, Any]
├── MODULE_MAP          # Name → function registry
├── save_results()      # JSON report serialiser
├── run_cli()           # Headless pipeline
└── OSINTApp (Tk)       # Dark GUI, progress dots, scan thread
```

---

## 📦 Output — JSON Report

Every scan auto-saves a structured report:

```json
{
  "meta": {
    "target": "example.com",
    "tool": "OSINT Pro v4.0",
    "scan_time": "2024-06-28T14:30:00",
    "python": "3.12.0"
  },
  "results": {
    "DNS & Host": { "ip": "93.184.216.34", "all_ips": [...], "ptr": "..." },
    "WAF Detection": { "detected": ["Cloudflare"] },
    "SSL / TLS": { "tls_versions": ["TLS 1.2", "TLS 1.3"], "sans": [...] }
  }
}
```

---

## ⚙️ Requirements

- **Python 3.9+** — no pip, no venv, no install step
- **Optional**: `nmap` in PATH for enhanced port scanning with service detection
- **Tkinter** — included in standard Python on most platforms (not required for `--cli` mode)

---

## 🔒 Ethical Use & Legal Notice

This tool is intended for:
- **Security research** on systems you own or have explicit written permission to test
- **CTF challenges** and lab environments
- **Bug bounty programmes** within defined scope

> ⚠️ Unauthorized scanning of systems you do not own may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in your jurisdiction. Use responsibly.

---

## 🤝 Contributing

Pull requests welcome. Please open an issue first to discuss major changes.

```bash
# Run a quick sanity check
python osint_pro.py --cli scanme.nmap.org --modules "DNS & Host" "Port Scan"
```

---

## 📄 License

MIT © 2024 — see [LICENSE](LICENSE) for details.
