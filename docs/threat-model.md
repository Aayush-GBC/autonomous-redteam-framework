# Threat Model

> ARTASF is an **authorised penetration testing tool** designed for controlled lab environments. This document describes the attack techniques it automates so defenders and operators understand its scope.

---

## Scope

| In Scope | Out of Scope |
|---|---|
| Single isolated lab network (VirtualBox host-only) | Production networks |
| DVWA (intentionally vulnerable web application) | Real external systems |
| Known CVE exploitation via Metasploit | Zero-day development |
| Web application attacks (SQLi, XSS, file upload) | Social engineering |
| Local privilege escalation on the target VM | Lateral movement beyond the lab |

---

## Attack Techniques Used

### Reconnaissance
- **Nmap TCP scan** (`-sV -sC`) — service version and script detection
- **DNS enumeration** — reverse DNS and A-record lookups
- **HTTP banner grabbing** — `HEAD` requests to enumerate web server headers and page titles

### Vulnerability Mapping
- **Offline CVE matching** — service/version strings matched against a static CPE-mapped CVE list
- **CVSS v3 scoring** — base score used to rank findings

### Exploitation

| Attack | Target | Technique |
|---|---|---|
| SQLi | DVWA `/vulnerabilities/sqli/` | `' OR 1=1 --` blind/union injection via HTTP |
| XSS | DVWA `/vulnerabilities/xss_r/` | Reflected payload injection via HTTP |
| File upload | DVWA `/vulnerabilities/upload/` | PHP web-shell upload with spoofed MIME type |
| Metasploit modules | Any CVE with an MSF reference | RPC call to `exploit/multi/handler` or specific module |

### Post-Exploitation
- **System enumeration** — OS version, users, network interfaces, running processes
- **Privilege escalation checks** — `sudo -l`, GTFOBins patterns, docker group membership
- **Loot harvesting** — `/etc/passwd`, `/etc/shadow`, SSH private keys, environment variables
- **Web-shell command execution** — HTTP POST to uploaded PHP shell as a Metasploit session fallback

### Reporting
- Findings, exploit attempts, and harvested loot are rendered into an HTML/PDF report

---

## Trust Boundaries

```
[Attacker Host (Windows 11)]
  │  Anthropic API (HTTPS)
  │  Metasploit RPC (localhost:55553)
  │
  ╔══════════════════════════╗
  ║   Host-Only Network      ║
  ║   192.168.56.0/24        ║
  ║                          ║
  ║  [Target VM — DVWA]      ║
  ╚══════════════════════════╝
```

The framework only communicates outbound to the Anthropic API (for planning) and inbound to the isolated lab VM. No data leaves the host-only network except the API call payload (target/vuln summary — no raw loot).

---

## Mitigations Expected in a Real Environment

| Technique | Detection / Prevention |
|---|---|
| Nmap scan | IDS alert on port sweep; firewall block |
| SQLi | WAF rule; parameterised queries |
| File upload | Whitelist extensions; AV scan on upload |
| Reverse shell | Egress filtering; endpoint EDR |
| Privilege escalation | Least-privilege, no sudo for www-data |
| Web-shell | File integrity monitoring |
