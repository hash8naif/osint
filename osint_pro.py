#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║           OSINT Pro — Reconnaissance Tool  v4.0                     ║
║           أداة استخبارات احترافية شاملة                             ║
╠══════════════════════════════════════════════════════════════════════╣
║  Modules  : DNS · Ports · HTTP · SSL/TLS · WAF · AWS · Cloudflare  ║
║             Nginx · Subdomains · Emails · WHOIS · Robots/Sitemap    ║
║  Author   : github.com/yourhandle                                   ║
║  License  : MIT                                                     ║
║  Python   : 3.9+  (stdlib only — no pip install needed)            ║
╚══════════════════════════════════════════════════════════════════════╝

Usage:
    python osint_pro.py                    # launch GUI
    python osint_pro.py --cli example.com  # headless CLI mode
"""

from __future__ import annotations

# ── stdlib only — zero external dependencies ──────────────────────────
import argparse
import gzip
import json
import logging
import queue
import re
import socket
import ssl
import subprocess
import sys
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from threading import Thread, Event
from typing import Any, Callable, Optional
from urllib import request as urllib_request
from urllib import error as urllib_error

# ── GUI (optional — only imported when not in --cli mode) ─────────────
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    _HAS_TK = True
except ImportError:
    _HAS_TK = False

# ══════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("osint_pro")


# ══════════════════════════════════════════════════════════════════════
# COLOUR TOKENS  (dark terminal aesthetic — GitHub-inspired)
# ══════════════════════════════════════════════════════════════════════
class C:
    BG      = "#0d1117"
    BG2     = "#161b22"
    BG3     = "#21262d"
    ACCENT  = "#58a6ff"
    GREEN   = "#3fb950"
    RED     = "#f85149"
    YELLOW  = "#e3b341"
    CYAN    = "#79c0ff"
    WHITE   = "#e6edf3"
    MUTED   = "#8b949e"
    BORDER  = "#30363d"
    PURPLE  = "#bc8cff"
    ORANGE  = "#f0883e"


# ══════════════════════════════════════════════════════════════════════
# RESULT MODEL
# ══════════════════════════════════════════════════════════════════════
class Status(Enum):
    IDLE    = auto()
    RUNNING = auto()
    OK      = auto()
    ERROR   = auto()


@dataclass
class ScanResult:
    """Typed container for a single module's findings."""
    module:    str
    status:    Status       = Status.IDLE
    data:      dict[str, Any] = field(default_factory=dict)
    error:     Optional[str]  = None
    started:   Optional[float] = None
    finished:  Optional[float] = None

    @property
    def elapsed(self) -> float:
        if self.started and self.finished:
            return round(self.finished - self.started, 2)
        return 0.0


# ══════════════════════════════════════════════════════════════════════
# OUTPUT BRIDGE  (GUI ↔ CLI agnostic)
# ══════════════════════════════════════════════════════════════════════
class OutputBridge:
    """
    Thread-safe output layer.  Attach a Tkinter Text widget for GUI use;
    leave unattached for CLI / headless mode (falls back to print).
    """

    ANSI = {
        "section":   "\033[94m",
        "sec_title": "\033[96;1m",
        "ok":        "\033[92m",
        "bad":       "\033[91m",
        "info":      "\033[96m",
        "warn":      "\033[93m",
        "item":      "\033[0m",
        "purple":    "\033[35m",
        "reset":     "\033[0m",
    }

    def __init__(self) -> None:
        self._widget:     Optional[tk.Text]       = None
        self._status_var: Optional[tk.StringVar]  = None

    def attach(self, widget: tk.Text, status_var: tk.StringVar) -> None:
        self._widget     = widget
        self._status_var = status_var

    # ── internal ───────────────────────────────────────────────────
    def _write(self, msg: str, tag: str = "normal") -> None:
        if self._widget:
            self._widget.after(0, self._tk_insert, msg, tag)
        else:
            colour = self.ANSI.get(tag, "")
            reset  = self.ANSI["reset"] if colour else ""
            print(f"{colour}{msg}{reset}")

    def _tk_insert(self, msg: str, tag: str) -> None:
        w = self._widget
        w.configure(state="normal")
        w.insert("end", msg + "\n", tag)
        w.see("end")
        w.configure(state="disabled")

    def _set_status(self, msg: str) -> None:
        if self._status_var:
            self._widget.after(0, self._status_var.set, msg)

    # ── public API ─────────────────────────────────────────────────
    def section(self, title: str) -> None:
        self._write(f"\n{'═' * 64}", "section")
        self._write(f"  ◈  {title}", "sec_title")
        self._write("═" * 64, "section")
        self._set_status(f"⟳  {title} …")

    def ok(self, label: str, value: Any) -> None:
        self._write(f"  [+]  {label}: {str(value)[:140]}", "ok")

    def bad(self, msg: str) -> None:
        self._write(f"  [-]  {msg}", "bad")

    def info(self, msg: str) -> None:
        self._write(f"  [*]  {msg}", "info")

    def warn(self, msg: str) -> None:
        self._write(f"  [!]  {msg}", "warn")

    def item(self, text: str) -> None:
        self._write(f"       •  {text}", "item")

    def raw(self, msg: str, tag: str = "normal") -> None:
        self._write(msg, tag)


OUT = OutputBridge()


# ══════════════════════════════════════════════════════════════════════
# HTTP HELPER  —  resilient, browser-like
# ══════════════════════════════════════════════════════════════════════
_CHROME_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


def _decode_body(resp: Any, raw: bytes) -> str:
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    try:
        if enc == "gzip":
            raw = gzip.decompress(raw)
        elif enc == "deflate":
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        pass
    return raw.decode("utf-8", errors="ignore")


def _ssl_ctx(strict: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not strict:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def fetch(
    url: str,
    timeout: int = 14,
    retries: int = 2,
    extra_headers: Optional[dict] = None,
) -> tuple[Any, str, dict[str, str]]:
    """
    Fetch *url* with browser headers, automatic gzip decoding, and retry.

    Returns
    -------
    (response_object, body_str, headers_dict)

    Raises the last exception after all retries are exhausted.
    """
    headers = {**_CHROME_HEADERS, **(extra_headers or {})}
    opener  = urllib_request.build_opener(
        urllib_request.HTTPSHandler(context=_ssl_ctx())
    )
    last_exc: Optional[Exception] = None

    for attempt in range(retries + 1):
        try:
            req = urllib_request.Request(url, headers=headers)
            with opener.open(req, timeout=timeout) as r:
                raw  = r.read()
                body = _decode_body(r, raw)
                return r, body, dict(r.headers)
        except Exception as exc:
            last_exc = exc
            log.debug("fetch %s attempt %d failed: %s", url, attempt, exc)
            if attempt < retries:
                time.sleep(1.2 * (attempt + 1))

    raise last_exc  # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════
# MODULE 1 — DNS & HOST INFO
# ══════════════════════════════════════════════════════════════════════
def dns_host(domain: str) -> dict[str, Any]:
    """Resolve DNS, enumerate IPs, and perform reverse PTR lookup."""
    OUT.section("DNS & Host Information")
    r: dict[str, Any] = {}

    # Primary A record
    try:
        ip = socket.gethostbyname(domain)
        OUT.ok("Main IP", ip)
        r["ip"] = ip
    except socket.gaierror as exc:
        OUT.bad(f"IP resolution failed: {exc}")
        return r

    # All A/AAAA addresses
    try:
        all_ips = sorted({x[4][0] for x in socket.getaddrinfo(domain, None)})
        OUT.ok("All IPs", ", ".join(all_ips))
        r["all_ips"] = all_ips
    except Exception:
        pass

    # FQDN
    try:
        OUT.ok("FQDN", socket.getfqdn(domain))
    except Exception:
        pass

    # Reverse PTR
    try:
        ptr = socket.gethostbyaddr(r["ip"])[0]
        OUT.ok("Reverse DNS (PTR)", ptr)
        r["ptr"] = ptr
    except Exception:
        OUT.info("No PTR record found")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 2 — PORT SCAN  (nmap preferred → socket fallback)
# ══════════════════════════════════════════════════════════════════════
_COMMON_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP/TLS",
    993:   "IMAPS",
    995:   "POP3S",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "Jupyter/HTTP",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}


def port_scan(domain: str) -> dict[str, Any]:
    """Scan common TCP ports using nmap (if installed) or raw sockets."""
    OUT.section("Port Scanning — Common Ports")
    r: dict[str, Any] = {"open": [], "tool": ""}

    port_list = ",".join(str(p) for p in _COMMON_PORTS)

    # ── nmap branch ───────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-T4", "-p", port_list, domain],
            capture_output=True, text=True, timeout=90,
        )
        if result.returncode == 0:
            r["tool"] = "nmap"
            OUT.ok("Scanner", "nmap  (service version detection enabled)")
            for line in result.stdout.splitlines():
                if "/tcp" in line and ("open" in line or "filtered" in line):
                    parts        = line.split()
                    port_proto   = parts[0]
                    state        = parts[1]
                    service_info = " ".join(parts[2:]) if len(parts) > 2 else ""
                    tag          = "ok" if "open" in state else "warn"
                    OUT.raw(f"  [{state.upper():8}]  {port_proto:20}  {service_info}", tag)
                    r["open"].append({"port": port_proto, "state": state, "service": service_info})
            return r
    except FileNotFoundError:
        OUT.warn("nmap not installed — falling back to socket scan")
    except subprocess.TimeoutExpired:
        OUT.warn("nmap timed out — falling back to socket scan")
    except Exception as exc:
        OUT.warn(f"nmap error ({exc}) — falling back to socket scan")

    # ── socket fallback ───────────────────────────────────────────
    r["tool"] = "socket"
    try:
        ip = socket.gethostbyname(domain)
    except Exception as exc:
        OUT.bad(f"Cannot resolve domain for port scan: {exc}")
        return r

    OUT.info(f"Socket scanning {len(_COMMON_PORTS)} ports on {ip} …")
    for port, name in _COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((ip, port)) == 0:
                    OUT.raw(f"  [OPEN]   {port:5}/{name}", "ok")
                    r["open"].append({"port": port, "service": name})
        except Exception:
            pass

    if not r["open"]:
        OUT.info("No open ports found (or filtered by upstream firewall)")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 3 — HTTP HEADERS & SECURITY HEADER AUDIT
# ══════════════════════════════════════════════════════════════════════
_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy":   "CSP",
    "X-Content-Type-Options":    "X-Content-Type-Options",
    "X-Frame-Options":           "X-Frame-Options",
    "Referrer-Policy":           "Referrer-Policy",
    "Permissions-Policy":        "Permissions-Policy",
}

_SERVER_HEADERS: list[str] = [
    "Server", "X-Powered-By", "Via", "X-Generator",
    "X-Drupal-Cache", "X-Varnish", "X-Backend", "X-Application-Context",
]


def http_headers(domain: str) -> dict[str, Any]:
    """Fetch HTTP headers and audit for security header presence."""
    OUT.section("HTTP Headers & Security Audit")
    r: dict[str, Any] = {}

    for scheme in ("https", "http"):
        try:
            resp, html, headers = fetch(f"{scheme}://{domain}")
            r = {
                "scheme":  scheme,
                "status":  resp.status,
                "headers": headers,
                "url":     resp.url,
            }
            OUT.ok("Status", resp.status)
            OUT.ok("Final URL", resp.url)

            # Server / tech disclosure
            for h in _SERVER_HEADERS:
                val = headers.get(h) or headers.get(h.lower())
                if val:
                    OUT.ok(h, val)

            # Security headers audit
            OUT.raw("\n  Security Header Audit:", "sec_title")
            sec_results: dict[str, bool] = {}
            h_lower = {k.lower(): v for k, v in headers.items()}
            for hdr, label in _SECURITY_HEADERS.items():
                present = hdr.lower() in h_lower
                sec_results[label] = present
                tag = "ok" if present else "warn"
                icon = "✓" if present else "✗"
                OUT.raw(f"  [{icon}]  {label}", tag)

            r["security_headers"] = sec_results
            score = sum(1 for v in sec_results.values() if v)
            OUT.ok("Security Score", f"{score}/{len(sec_results)} headers present")
            break

        except urllib_error.HTTPError as exc:
            OUT.warn(f"{scheme}: HTTP {exc.code} {exc.reason}")
            r["status"] = exc.code
            break
        except Exception as exc:
            OUT.bad(f"{scheme}: {exc}")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 4 — SSL / TLS ANALYSIS
# ══════════════════════════════════════════════════════════════════════
def ssl_tls(domain: str) -> dict[str, Any]:
    """Probe TLS version support and extract full certificate details."""
    OUT.section("SSL/TLS Certificate Analysis")
    r: dict[str, Any] = {}

    # ── TLS version probing ───────────────────────────────────────
    probes: list[tuple[Any, str]] = []
    for attr, label in (("TLSv1_2", "TLS 1.2"), ("TLSv1_3", "TLS 1.3")):
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver:
            probes.append((ver, label))

    supported: list[str] = []
    for ver, name in probes:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            ctx.check_hostname  = False
            ctx.verify_mode     = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(6)
                s.connect((domain, 443))
                supported.append(name)
        except Exception:
            pass

    if supported:
        OUT.ok("Supported TLS", ", ".join(supported))
        r["tls_versions"] = supported
    else:
        OUT.warn("Could not probe TLS versions (port 443 may be filtered)")

    # ── Certificate details ───────────────────────────────────────
    try:
        ctx = _ssl_ctx(strict=False)
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert   = s.getpeercert()
            cipher = s.cipher()

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer",  []))

            OUT.ok("Common Name",  subject.get("commonName",       "N/A"))
            OUT.ok("Organization", subject.get("organizationName", "N/A"))
            OUT.ok("Issued By",    issuer.get("organizationName",  "N/A"))
            OUT.ok("Valid From",   cert.get("notBefore", "N/A"))
            OUT.ok("Valid Until",  cert.get("notAfter",  "N/A"))
            OUT.ok("TLS Version",  s.version())
            OUT.ok("Cipher Suite", cipher[0] if cipher else "N/A")
            OUT.ok("Key Bits",     cipher[2] if cipher else "N/A")

            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            OUT.ok("SAN Count", len(sans))
            for sn in sorted(sans)[:20]:
                OUT.item(sn)
            if len(sans) > 20:
                OUT.info(f"… and {len(sans) - 20} more SANs")

            r.update({
                "subject":     subject,
                "issuer":      issuer,
                "valid_until": cert.get("notAfter"),
                "sans":        sans,
                "cipher":      cipher,
            })

    except ssl.SSLCertVerificationError:
        OUT.warn("Certificate verification failed (self-signed or expired)")
    except ConnectionRefusedError:
        OUT.bad("Port 443 refused — HTTPS not available on this host")
    except Exception as exc:
        OUT.bad(f"SSL analysis: {exc}")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 5 — WAF / CDN DETECTION
# ══════════════════════════════════════════════════════════════════════
_WAF_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid", "cf-connecting-ip"],
        "body":    ["cloudflare", "Attention Required! | Cloudflare", "DDoS protection by Cloudflare"],
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-request-id", "x-amzn-requestid", "x-amzn-trace-id"],
        "body":    ["aws", "AmazonS3", "cloudfront.net"],
    },
    "AWS ALB": {
        "headers": ["x-amzn-trace-id"],
        "body":    [],
    },
    "Akamai": {
        "headers": ["akamai-grn", "x-check-cacheable", "x-akamai-transformed"],
        "body":    ["akamai"],
    },
    "Fastly": {
        "headers": ["fastly-restarts", "x-fastly-request-id", "x-served-by"],
        "body":    ["fastly"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body":    ["sucuri"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "incap_ses", "visid_incap"],
        "body":    ["incapsula", "Imperva"],
    },
    "F5 BIG-IP": {
        "headers": ["x-wa-info", "bigipserver"],
        "body":    ["BIG-IP", "F5"],
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "body":    ["barracuda"],
    },
    "ModSecurity": {
        "headers": ["mod_security", "x-modsecurity"],
        "body":    ["ModSecurity", "NOYB"],
    },
    "Azure Front Door": {
        "headers": ["x-azure-ref", "x-fd-healthprobe"],
        "body":    ["microsoft", "azure"],
    },
    "Google Cloud Armor": {
        "headers": ["x-goog-request-id", "server: gws", "via: 1.1 google"],
        "body":    ["google", "gcp"],
    },
}


def detect_waf(domain: str) -> dict[str, Any]:
    """Detect WAF/CDN providers via HTTP headers and response body analysis."""
    OUT.section("WAF / CDN Detection")
    r: dict[str, Any] = {"detected": []}

    try:
        resp, html, headers = fetch(f"https://{domain}")
        h_lower   = {k.lower(): v.lower() for k, v in headers.items()}
        html_low  = html.lower()
        detected: list[str] = []

        for waf, sigs in _WAF_SIGNATURES.items():
            hit = (
                any(h.lower() in h_lower for h in sigs["headers"])
                or any(b.lower() in html_low for b in sigs["body"])
            )
            if hit:
                detected.append(waf)
                OUT.ok("Detected", f"✓  {waf}")

        if ray := h_lower.get("cf-ray"):
            OUT.ok("Cloudflare Ray-ID", ray)

        if not detected:
            OUT.info("No common WAF/CDN signatures found — site may be unprotected")
            # Light probe with a suspicious payload
            probe_url = f"https://{domain}/?id=1'%20OR%20'1'='1"
            try:
                urllib_request.urlopen(
                    urllib_request.Request(probe_url, headers={"User-Agent": "curl/7.88"}),
                    timeout=5,
                )
            except urllib_error.HTTPError as exc:
                if exc.code in (403, 406, 429, 503):
                    OUT.warn(f"HTTP {exc.code} on injection probe — WAF likely active (no fingerprint matched)")

        r["detected"] = detected
    except Exception as exc:
        OUT.bad(f"WAF detection failed: {exc}")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 6 — AWS INFRASTRUCTURE DETECTION
# ══════════════════════════════════════════════════════════════════════
_AWS_INDICATORS: dict[str, list[str]] = {
    "CloudFront":  ["cloudfront.net", "x-amz-cf-id", "x-amz-cf-pop"],
    "S3":          ["s3.amazonaws.com", "AmazonS3", "x-amz-bucket"],
    "ALB/ELB":     ["x-amzn-trace-id", "awselb", "x-amzn-requestid"],
    "API Gateway": ["x-amzn-requestid", "x-amz-apigw-id"],
    "WAF":         ["awswaf"],
    "EC2":         ["ec2", "amazonaws.com"],
}

# AWS IP prefix ranges (simplified — for heuristic only)
_AWS_IP_PREFIXES = ("13.", "18.", "34.", "35.", "44.", "52.", "54.")


def detect_aws(domain: str) -> dict[str, Any]:
    """Detect AWS services via headers, body, and IP range heuristics."""
    OUT.section("AWS Infrastructure Detection")
    r: dict[str, Any] = {}

    try:
        _, html, headers = fetch(f"https://{domain}")
        h_str      = json.dumps(headers).lower()
        html_lower = html.lower()
        found: dict[str, list[str]] = {}

        for service, indicators in _AWS_INDICATORS.items():
            matches = [i for i in indicators if i.lower() in h_str or i.lower() in html_lower]
            if matches:
                found[service] = matches
                OUT.ok(f"AWS {service}", f"✓  {', '.join(matches)}")

        try:
            ip = socket.gethostbyname(domain)
            OUT.ok("Resolved IP", ip)
            if ip.startswith(_AWS_IP_PREFIXES):
                OUT.warn(f"IP {ip} falls in a common AWS range (heuristic — not guaranteed)")
                r["possible_aws_ip"] = ip
        except Exception:
            pass

        if not found:
            OUT.info("No AWS indicators detected")

        r["aws_services"] = found
    except Exception as exc:
        OUT.bad(f"AWS detection: {exc}")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 7 — CLOUDFLARE DETECTION
# ══════════════════════════════════════════════════════════════════════
_CF_HEADERS = [
    "cf-ray", "cf-cache-status", "cf-request-id",
    "cf-connecting-ip", "cf-ipcountry", "cf-visitor",
]
_CF_IP_PREFIXES = (
    "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "172.64.", "172.65.",
    "172.66.", "172.67.", "198.41.",
)


def detect_cloudflare(domain: str) -> dict[str, Any]:
    """Deep Cloudflare fingerprint via headers and IP range check."""
    OUT.section("Cloudflare Detection")
    r: dict[str, Any] = {"cloudflare": False}

    try:
        _, _, headers = fetch(f"https://{domain}")
        h_lower = {k.lower(): v for k, v in headers.items()}

        found_hdrs = [h for h in _CF_HEADERS if h in h_lower]
        if found_hdrs:
            for h in found_hdrs:
                OUT.ok(f"Header: {h}", h_lower[h])
            OUT.ok("Cloudflare", "✓  CONFIRMED via response headers")
            r.update({"cloudflare": True, "cf_headers": found_hdrs})
        else:
            try:
                ip = socket.gethostbyname(domain)
                if ip.startswith(_CF_IP_PREFIXES):
                    OUT.ok("Cloudflare", f"✓  IP {ip} in Cloudflare ASN range")
                    r.update({"cloudflare": True, "cf_ip": ip})
                else:
                    OUT.info("No Cloudflare signature detected")
            except Exception:
                pass

    except Exception as exc:
        OUT.bad(f"Cloudflare check: {exc}")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 8 — WEB SERVER DETECTION  (Nginx / Apache / etc.)
# ══════════════════════════════════════════════════════════════════════
_SENSITIVE_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/nginx.conf",
    "/.env",
    "/.htaccess",
    "/config.php",
    "/wp-config.php",
    "/server-status",
]


def detect_nginx(domain: str) -> dict[str, Any]:
    """Identify web server and probe for accidentally exposed sensitive paths."""
    OUT.section("Web Server Fingerprinting")
    r: dict[str, Any] = {}

    try:
        _, _, headers = fetch(f"https://{domain}")
        server = headers.get("Server") or headers.get("server") or ""
        r["server"] = server

        if server:
            OUT.ok("Server Header", server)
        powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered:
            OUT.ok("X-Powered-By", powered)
            r["powered_by"] = powered

        # Sensitive path probing
        OUT.raw("\n  Sensitive Path Probe:", "sec_title")
        exposed: list[str] = []
        for path in _SENSITIVE_PATHS:
            try:
                req = urllib_request.Request(
                    f"https://{domain}{path}",
                    headers={"User-Agent": _CHROME_HEADERS["User-Agent"]},
                )
                ctx = _ssl_ctx()
                opener = urllib_request.build_opener(urllib_request.HTTPSHandler(context=ctx))
                with opener.open(req, timeout=5) as tr:
                    if tr.status == 200:
                        OUT.warn(f"EXPOSED (200):  {path}")
                        exposed.append(path)
            except urllib_error.HTTPError as exc:
                tag = "warn" if exc.code == 403 else "normal"
                OUT.raw(f"  [{exc.code}]  {path}", tag)
            except Exception:
                pass

        if exposed:
            OUT.warn(f"{len(exposed)} sensitive path(s) are publicly accessible!")
        else:
            OUT.ok("Sensitive Paths", "None exposed (or all returning 404/403)")
        r["exposed_paths"] = exposed

    except Exception as exc:
        OUT.bad(f"Server fingerprinting: {exc}")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 9 — SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════════════
_WORDLIST = [
    "www", "mail", "smtp", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "cdn", "static", "media", "blog", "shop", "app", "vpn", "remote",
    "portal", "internal", "mx", "ns1", "ns2", "ssh", "git", "jenkins", "ci",
    "grafana", "prometheus", "dashboard", "auth", "login", "secure", "docs",
    "help", "support", "status", "monitor", "backup", "storage", "vault",
]


def subdomains(domain: str) -> dict[str, Any]:
    """
    Enumerate subdomains via:
      1. crt.sh certificate transparency logs
      2. DNS brute-force with a curated wordlist
    """
    OUT.section("Subdomain Enumeration")
    r: dict[str, Any] = {"ct_log": [], "brute_force": []}

    # ── Certificate Transparency (crt.sh) ────────────────────────
    try:
        OUT.info("Querying crt.sh certificate transparency …")
        _, data_str, _ = fetch(
            f"https://crt.sh/?q=%.{domain}&output=json", timeout=25
        )
        data = json.loads(data_str)
        subs: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.")
                if name and domain in name and name != domain:
                    subs.add(name.lower())

        OUT.ok("crt.sh subdomains", len(subs))
        for sn in sorted(subs)[:30]:
            OUT.item(sn)
        if len(subs) > 30:
            OUT.info(f"… and {len(subs) - 30} more (see JSON output)")
        r["ct_log"] = sorted(subs)
    except json.JSONDecodeError:
        OUT.warn("crt.sh returned non-JSON (may be rate-limited)")
    except Exception as exc:
        OUT.bad(f"crt.sh query failed: {exc}")

    # ── DNS Brute-Force ───────────────────────────────────────────
    OUT.info(f"Brute-forcing {len(_WORDLIST)} common subdomain prefixes …")
    brute_found: list[dict[str, str]] = []
    for prefix in _WORDLIST:
        fqdn = f"{prefix}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            OUT.raw(f"  [FOUND]  {fqdn}  →  {ip}", "ok")
            brute_found.append({"subdomain": fqdn, "ip": ip})
        except socket.gaierror:
            pass
        except Exception:
            pass

    OUT.ok("Brute-force hits", len(brute_found))
    r["brute_force"] = brute_found
    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 10 — EMAIL HARVESTING & LINK ANALYSIS
# ══════════════════════════════════════════════════════════════════════
_SOCIAL_PATTERNS: dict[str, str] = {
    "Twitter/X":  r"(?:twitter|x)\.com/([^/\"'?\s@]{2,30})",
    "LinkedIn":   r"linkedin\.com/(?:in|company)/([^/\"'?\s]{2,50})",
    "Facebook":   r"facebook\.com/([^/\"'?\s]{2,50})",
    "Instagram":  r"instagram\.com/([^/\"'?\s@]{2,30})",
    "GitHub":     r"github\.com/([^/\"'?\s]{2,39})",
    "YouTube":    r"youtube\.com/(?:c/|channel/|@)([^/\"'?\s]{2,50})",
    "TikTok":     r"tiktok\.com/@([^/\"'?\s]{2,30})",
    "Telegram":   r"t\.me/([^/\"'?\s]{2,30})",
}

_EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".woff"}


def harvest(domain: str) -> dict[str, Any]:
    """Scrape homepage for emails, external domains, and social media handles."""
    OUT.section("Email Harvesting & Link Analysis")
    r: dict[str, Any] = {}

    try:
        _, html, _ = fetch(f"https://{domain}")

        # Emails
        emails = [
            e for e in set(_EMAIL_REGEX.findall(html))
            if not any(e.endswith(ext) for ext in _SKIP_EXT)
        ]
        OUT.ok("Emails found", len(emails))
        for email in sorted(emails)[:15]:
            OUT.item(email)
        r["emails"] = sorted(emails)

        # External domains
        ext_domains = sorted({
            d for d in re.findall(r"https?://([^/\"'\s>]+)", html)
            if domain not in d
        })
        OUT.ok("External domains", len(ext_domains))
        for d in ext_domains[:15]:
            OUT.item(d)
        r["external_domains"] = ext_domains

        # Social profiles
        OUT.raw("\n  Social Media Profiles:", "sec_title")
        socials: dict[str, str] = {}
        for platform, pattern in _SOCIAL_PATTERNS.items():
            matches = [
                m for m in set(re.findall(pattern, html, re.I)) if len(m) > 1
            ]
            if matches:
                OUT.ok(platform, matches[0])
                socials[platform] = matches[0]
        r["social_media"] = socials

    except Exception as exc:
        OUT.bad(f"Harvesting failed: {exc}")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 11 — WHOIS
# ══════════════════════════════════════════════════════════════════════
def whois_info(domain: str) -> dict[str, Any]:
    """Query WHOIS registration data via a public JSON API."""
    OUT.section("WHOIS Information")
    r: dict[str, Any] = {}

    try:
        _, data_str, _ = fetch(f"https://api.whois.vu/?q={domain}&json", timeout=14)
        data = json.loads(data_str)
        for key, label in [
            ("registrar",    "Registrar"),
            ("created",      "Created"),
            ("updated",      "Updated"),
            ("expires",      "Expires"),
            ("nameservers",  "Nameservers"),
            ("status",       "Status"),
        ]:
            val = data.get(key)
            if val:
                display = ", ".join(val) if isinstance(val, list) else str(val)[:120]
                OUT.ok(label, display)
        r = data
    except Exception as exc:
        OUT.bad(f"WHOIS failed: {exc}")
        OUT.info("Fallback: https://who.is")

    return r


# ══════════════════════════════════════════════════════════════════════
# MODULE 12 — ROBOTS.TXT, SITEMAP & SECURITY.TXT
# ══════════════════════════════════════════════════════════════════════
_DISCOVERY_PATHS: list[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/humans.txt",
]


def robots_sitemap(domain: str) -> dict[str, Any]:
    """Discover robots.txt, sitemap, and well-known files."""
    OUT.section("Discovery — Robots / Sitemap / Security.txt")
    r: dict[str, Any] = {"found": []}

    for path in _DISCOVERY_PATHS:
        try:
            resp_obj, content, _ = fetch(f"https://{domain}{path}", timeout=10)
            OUT.ok(f"Found ({resp_obj.status})", f"https://{domain}{path}")
            r["found"].append(path)

            if "robots" in path:
                disallowed = re.findall(r"Disallow:\s*(.+)", content)
                sitemaps   = re.findall(r"Sitemap:\s*(.+)",  content)
                if disallowed:
                    OUT.ok("Disallowed paths", len(disallowed))
                    for d in disallowed[:10]:
                        OUT.item(d.strip())
                for sm in sitemaps:
                    OUT.ok("Sitemap referenced", sm.strip())

            elif "security.txt" in path:
                OUT.ok("security.txt", "Present — security contact policy published")

        except urllib_error.HTTPError as exc:
            if exc.code == 403:
                OUT.warn(f"{path}  →  403 Forbidden (exists but restricted)")
        except Exception:
            pass

    return r


# ══════════════════════════════════════════════════════════════════════
# RESULT SERIALISATION
# ══════════════════════════════════════════════════════════════════════
def save_results(
    domain: str,
    results: dict[str, Any],
    filepath: Optional[str] = None,
) -> Path:
    """Serialise scan results to a timestamped JSON file."""
    if not filepath:
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"osint_{domain.replace('.', '_')}_{ts}.json"

    out_path = Path(filepath)
    payload  = {
        "meta": {
            "target":     domain,
            "tool":       "OSINT Pro v4.0",
            "scan_time":  datetime.now().isoformat(),
            "python":     sys.version,
        },
        "results": results,
    }
    out_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return out_path


# ══════════════════════════════════════════════════════════════════════
# MODULE REGISTRY
# ══════════════════════════════════════════════════════════════════════
MODULES: list[tuple[str, Callable[[str], dict[str, Any]]]] = [
    ("DNS & Host",        dns_host),
    ("Port Scan",         port_scan),
    ("HTTP Headers",      http_headers),
    ("SSL / TLS",         ssl_tls),
    ("WAF Detection",     detect_waf),
    ("AWS Detection",     detect_aws),
    ("Cloudflare",        detect_cloudflare),
    ("Web Server",        detect_nginx),
    ("Subdomains",        subdomains),
    ("Emails & Links",    harvest),
    ("WHOIS",             whois_info),
    ("Robots & Sitemap",  robots_sitemap),
]

MODULE_MAP: dict[str, Callable[[str], dict[str, Any]]] = dict(MODULES)


# ══════════════════════════════════════════════════════════════════════
# CLI MODE
# ══════════════════════════════════════════════════════════════════════
def run_cli(domain: str, module_names: list[str]) -> None:
    """Run selected modules headlessly and print results to stdout."""
    print(f"\n{'═'*64}")
    print(f"  OSINT Pro v4.0  |  Target: {domain}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*64}\n")

    results: dict[str, Any] = {}
    for name in module_names:
        fn = MODULE_MAP.get(name)
        if not fn:
            print(f"[!] Unknown module: {name}")
            continue
        try:
            results[name] = fn(domain)
        except Exception as exc:
            print(f"  [-]  Module '{name}' crashed: {exc}")
            results[name] = {"error": str(exc)}

    path = save_results(domain, results)
    print(f"\n  ✓  Saved  →  {path}\n")


# ══════════════════════════════════════════════════════════════════════
# GUI — OSINT Pro App
# ══════════════════════════════════════════════════════════════════════
class OSINTApp(tk.Tk):
    """Dark-theme Tkinter GUI for OSINT Pro."""

    APP_TITLE = "OSINT Pro — Reconnaissance Tool  v4.0"

    def __init__(self) -> None:
        super().__init__()
        self.title(self.APP_TITLE)
        self.geometry("1260x840")
        self.minsize(980, 660)
        self.configure(bg=C.BG)

        self._scanning:    bool              = False
        self._stop_event:  Event             = Event()
        self._scan_thread: Optional[Thread]  = None
        self._results:     dict[str, Any]    = {}
        self._domain:      str               = ""

        self._build_styles()
        self._build_ui()
        OUT.attach(self.output_text, self.status_var)

        self.bind("<Control-Return>", lambda _: self._start_scan())
        self.bind("<F5>",             lambda _: self._start_scan())
        self.bind("<Escape>",         lambda _: self._stop_scan())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── styles ─────────────────────────────────────────────────────
    def _build_styles(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")

        # Frames
        for name, bg in [("TFrame", C.BG), ("Side.TFrame", C.BG2), ("Foot.TFrame", C.BG3)]:
            s.configure(name, background=bg)

        # Labels
        for name, bg, fg, font in [
            ("TLabel",       C.BG,  C.WHITE,  ("Consolas", 10)),
            ("H1.TLabel",    C.BG,  C.ACCENT, ("Consolas", 17, "bold")),
            ("Sub.TLabel",   C.BG,  C.MUTED,  ("Consolas",  9)),
            ("Side.TLabel",  C.BG2, C.WHITE,  ("Consolas", 10)),
            ("SideH.TLabel", C.BG2, C.CYAN,   ("Consolas", 11, "bold")),
            ("Foot.TLabel",  C.BG3, C.MUTED,  ("Consolas",  9)),
            ("Stat.TLabel",  C.BG2, C.MUTED,  ("Consolas",  9)),
        ]:
            s.configure(name, background=bg, foreground=fg, font=font)

        # Buttons
        for bname, bg, fg, abg in [
            ("Scan", C.ACCENT, C.BG,    C.CYAN),
            ("Stop", C.RED,    C.WHITE, "#ff7b72"),
            ("Save", C.BG3,    C.WHITE, C.BORDER),
            ("Util", C.BG3,    C.MUTED, C.BORDER),
        ]:
            s.configure(
                f"{bname}.TButton",
                background=bg, foreground=fg,
                font=("Consolas", 10, "bold"),
                borderwidth=0, focusthickness=0, padding=(14, 7),
            )
            s.map(
                f"{bname}.TButton",
                background=[("active", abg), ("disabled", C.BG2)],
                foreground=[("disabled", C.MUTED)],
            )

        # Entry
        s.configure(
            "TEntry",
            fieldbackground=C.BG3, background=C.BG3,
            foreground=C.WHITE, insertcolor=C.ACCENT,
            bordercolor=C.BORDER, lightcolor=C.BORDER, darkcolor=C.BORDER,
            font=("Consolas", 12), padding=(8, 6),
        )
        s.map("TEntry", bordercolor=[("focus", C.ACCENT)])

        # Checkbutton
        s.configure(
            "Mod.TCheckbutton",
            background=C.BG2, foreground=C.WHITE,
            font=("Consolas", 10), indicatorcolor=C.BG3,
        )
        s.map(
            "Mod.TCheckbutton",
            background=[("active", C.BG2)],
            indicatorcolor=[("selected", C.ACCENT)],
        )

        # Progressbar
        s.configure(
            "TProgressbar",
            background=C.ACCENT, troughcolor=C.BG3,
            borderwidth=0, thickness=4,
        )

    # ── UI build ────────────────────────────────────────────────────
    def _build_ui(self) -> None:

        # Header
        hdr = ttk.Frame(self)
        hdr.pack(fill="x")
        ttk.Label(hdr, text="  ◈  OSINT Pro  Reconnaissance Tool  v4.0",
                  style="H1.TLabel").pack(side="left", pady=12)
        ttk.Label(hdr, text="DNS · Ports · WAF · SSL · CDN · Subdomains  ",
                  style="Sub.TLabel").pack(side="right", pady=16)
        tk.Frame(self, bg=C.ACCENT, height=2).pack(fill="x")

        # Target bar
        tbar = ttk.Frame(self)
        tbar.pack(fill="x", padx=14, pady=(12, 6))

        ttk.Label(tbar, text="Target:").pack(side="left", padx=(0, 6))
        self.domain_var = tk.StringVar()
        self.entry = ttk.Entry(tbar, textvariable=self.domain_var, width=38)
        self.entry.pack(side="left", padx=(0, 10))
        self.entry.bind("<Return>", lambda _: self._start_scan())
        self.entry.focus_set()

        self.scan_btn = ttk.Button(tbar, text="▶  Scan",
                                   style="Scan.TButton", command=self._start_scan)
        self.scan_btn.pack(side="left", padx=(0, 5))

        self.stop_btn = ttk.Button(tbar, text="■  Stop",
                                   style="Stop.TButton", command=self._stop_scan,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 5))

        self.save_btn = ttk.Button(tbar, text="💾  Save JSON",
                                   style="Save.TButton", command=self._save_results,
                                   state="disabled")
        self.save_btn.pack(side="left", padx=(0, 5))

        ttk.Button(tbar, text="⊗  Clear",
                   style="Util.TButton", command=self._clear).pack(side="left")

        self.time_lbl = ttk.Label(tbar, text="", style="Sub.TLabel")
        self.time_lbl.pack(side="right")

        # Progress bar
        self.prog_var = tk.DoubleVar(value=0)
        self.prog = ttk.Progressbar(self, variable=self.prog_var,
                                    maximum=len(MODULES))
        self.prog.pack(fill="x", padx=14, pady=(0, 6))

        # Main area (sidebar + output)
        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=14, pady=(0, 6))

        # Sidebar
        side = ttk.Frame(main, style="Side.TFrame", width=195)
        side.pack(side="left", fill="y", padx=(0, 10))
        side.pack_propagate(False)

        ttk.Label(side, text="  MODULES", style="SideH.TLabel").pack(
            anchor="w", pady=(12, 4), padx=8)

        self._mod_vars:   dict[str, tk.BooleanVar] = {}
        self._mod_labels: dict[str, tk.Label]       = {}

        for name, _ in MODULES:
            var = tk.BooleanVar(value=True)
            self._mod_vars[name] = var

            row = ttk.Frame(side, style="Side.TFrame")
            row.pack(fill="x", padx=4, pady=1)

            ttk.Checkbutton(row, text=f"  {name}", variable=var,
                            style="Mod.TCheckbutton").pack(side="left", fill="x", expand=True)

            dot = tk.Label(row, text="●", fg=C.MUTED, bg=C.BG2,
                           font=("Consolas", 10), width=2)
            dot.pack(side="right", padx=4)
            self._mod_labels[name] = dot

        # Select All / None
        tk.Frame(side, bg=C.BORDER, height=1).pack(fill="x", padx=8, pady=8)
        btn_row = ttk.Frame(side, style="Side.TFrame")
        btn_row.pack(anchor="w", padx=8, pady=(0, 6))
        ttk.Button(btn_row, text="All",  style="Util.TButton",
                   command=self._all).pack(side="left", padx=(0, 4))
        ttk.Button(btn_row, text="None", style="Util.TButton",
                   command=self._none).pack(side="left")

        # Mini stats
        self.stats_lbl = tk.Label(side, text="", fg=C.MUTED, bg=C.BG2,
                                  font=("Consolas", 9), justify="left", wraplength=165)
        self.stats_lbl.pack(anchor="w", padx=10, pady=(4, 0))

        # Output text
        out_wrap = ttk.Frame(main)
        out_wrap.pack(side="left", fill="both", expand=True)

        self.output_text = tk.Text(
            out_wrap,
            state="disabled",
            bg=C.BG2, fg=C.WHITE,
            font=("Consolas", 10),
            wrap="word",
            borderwidth=0, highlightthickness=0,
            padx=12, pady=10,
            cursor="arrow",
            selectbackground=C.BG3, selectforeground=C.WHITE,
        )
        vsb = ttk.Scrollbar(out_wrap, command=self.output_text.yview)
        vsb.pack(side="right", fill="y")
        self.output_text.configure(yscrollcommand=vsb.set)
        self.output_text.pack(fill="both", expand=True)

        # Colour tags
        tag_cfg = {
            "section":   (C.ACCENT,  False),
            "sec_title": (C.CYAN,    True),
            "ok":        (C.GREEN,   False),
            "bad":       (C.RED,     False),
            "info":      (C.CYAN,    False),
            "warn":      (C.YELLOW,  False),
            "item":      (C.WHITE,   False),
            "normal":    (C.WHITE,   False),
            "purple":    (C.PURPLE,  False),
            "orange":    (C.ORANGE,  False),
        }
        for tag, (colour, bold) in tag_cfg.items():
            font = ("Consolas", 10, "bold") if bold else ("Consolas", 10)
            self.output_text.tag_configure(tag, foreground=colour, font=font)

        # Status bar
        foot = ttk.Frame(self, style="Foot.TFrame", height=26)
        foot.pack(fill="x", side="bottom")
        foot.pack_propagate(False)

        self.status_var = tk.StringVar(
            value="Ready — enter a domain and press Scan  (Ctrl+Enter / F5)"
        )
        ttk.Label(foot, textvariable=self.status_var,
                  style="Foot.TLabel").pack(side="left", padx=10, pady=4)
        self.clock_lbl = ttk.Label(foot, text="", style="Foot.TLabel")
        self.clock_lbl.pack(side="right", padx=10)
        self._tick()

    # ── helpers ─────────────────────────────────────────────────────
    def _tick(self) -> None:
        self.clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick)

    def _set_dot(self, name: str, state: str) -> None:
        colour = {"idle": C.MUTED, "run": C.YELLOW, "ok": C.GREEN, "err": C.RED}.get(state, C.MUTED)
        if lbl := self._mod_labels.get(name):
            self.after(0, lbl.config, {"fg": colour})

    def _all(self)  -> None:
        for v in self._mod_vars.values(): v.set(True)

    def _none(self) -> None:
        for v in self._mod_vars.values(): v.set(False)

    def _clear_text(self) -> None:
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")

    def _clear(self) -> None:
        self._clear_text()
        self.prog_var.set(0)
        self.status_var.set("Ready")
        self.stats_lbl.config(text="")
        self._results = {}
        self.save_btn.configure(state="disabled")
        for name in self._mod_labels:
            self._set_dot(name, "idle")

    def _on_close(self) -> None:
        self._stop_event.set()
        self.destroy()

    # ── scan control ────────────────────────────────────────────────
    def _start_scan(self) -> None:
        if self._scanning:
            return

        raw = self.domain_var.get().strip()
        if not raw:
            messagebox.showerror("Missing Target", "Enter a domain to scan.", parent=self)
            return

        # Normalise
        domain = raw.replace("https://", "").replace("http://", "").split("/")[0].strip()
        self.domain_var.set(domain)
        self._domain = domain

        selected = [name for name, _ in MODULES if self._mod_vars[name].get()]
        if not selected:
            messagebox.showerror("No Modules", "Select at least one module.", parent=self)
            return

        for name in self._mod_labels:
            self._set_dot(name, "idle")

        self._scanning = True
        self._stop_event.clear()
        self._results = {}
        self.prog_var.set(0)
        self.prog.configure(maximum=len(selected))
        self.save_btn.configure(state="disabled")
        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._clear_text()

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_lbl.config(text=f"Started: {ts}")
        OUT.raw(f"  Target  : {domain}",        "sec_title")
        OUT.raw(f"  Time    : {ts}",             "info")
        OUT.raw(f"  Modules : {len(selected)}",  "info")

        self._scan_thread = Thread(
            target=self._run_scan, args=(domain, selected), daemon=True
        )
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        self._stop_event.set()
        self._scanning = False
        self.status_var.set("Stopping …")
        OUT.warn("Scan interrupted by user")

    def _run_scan(self, domain: str, names: list[str]) -> None:
        total = len(names)
        for idx, name in enumerate(names, 1):
            if self._stop_event.is_set():
                break

            self._set_dot(name, "run")
            self.after(0, self.status_var.set, f"⟳  Running: {name} …")
            try:
                result = MODULE_MAP[name](domain)
                self._results[name] = result
                self._set_dot(name, "ok")
            except Exception as exc:
                log.exception("Module %s crashed", name)
                OUT.bad(f"Module '{name}' failed: {exc}")
                self._results[name] = {"error": str(exc)}
                self._set_dot(name, "err")

            self.after(0, self.prog_var.set, idx)
            self.after(
                0, self.stats_lbl.config,
                {"text": f"{idx} / {total}  modules\ncomplete"},
            )

        self.after(0, self._scan_done)

    def _scan_done(self) -> None:
        self._scanning = False
        self.scan_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.save_btn.configure(state="normal")

        ok_count  = sum(1 for v in self._results.values() if "error" not in v)
        err_count = len(self._results) - ok_count

        OUT.raw(f"\n{'═'*64}", "section")
        OUT.raw(f"  ✓  Scan Complete  |  {ok_count} OK   {err_count} error(s)", "sec_title")
        OUT.raw("═" * 64, "section")
        self.status_var.set(f"✓  Scan complete — {ok_count}/{len(self._results)} modules succeeded")

    # ── save ────────────────────────────────────────────────────────
    def _save_results(self) -> None:
        if not self._results:
            messagebox.showinfo("Nothing to Save", "Run a scan first.", parent=self)
            return

        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = f"osint_{self._domain.replace('.', '_')}_{ts}.json"

        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".json",
            initialfile=default,
            filetypes=[("JSON Report", "*.json"), ("All files", "*.*")],
        )
        if path:
            saved = save_results(self._domain, self._results, path)
            messagebox.showinfo("Saved", f"Report saved:\n{saved}", parent=self)
            self.status_var.set(f"Saved  →  {saved}")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="OSINT Pro v4.0 — open-source reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            ["Available modules:"] + [f"  {n}" for n, _ in MODULES]
        ),
    )
    p.add_argument("--cli",     metavar="DOMAIN",  help="Headless CLI scan (no GUI)")
    p.add_argument("--modules", metavar="MOD", nargs="+",
                   default=[n for n, _ in MODULES],
                   help="Module names to run (default: all)")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.cli:
        run_cli(args.cli, args.modules)
    else:
        if not _HAS_TK:
            sys.exit(
                "Tkinter is not available.  "
                "Use --cli <domain> for headless mode."
            )
        OSINTApp().mainloop()


if __name__ == "__main__":
    main()
