# Usage Reference

## Prerequisites

1. `.env` file configured (copy `.env.example` → `.env` and fill in values)
2. Metasploit RPC running: `msfrpcd -P msf -S -a 127.0.0.1`
3. Target VM reachable on the configured `TARGET_NETWORK`
4. `ANTHROPIC_API_KEY` set (required for `plan` / `run`)

---

## Commands

### `artasf run` — Full Autonomous Pipeline

Runs recon → vuln-map → AI planning → exploitation → post-exploitation → reporting.

```
artasf run [OPTIONS]

Options:
  -t, --target TEXT    Override TARGET_NETWORK from .env (e.g. 192.168.56.0/24)
  -n, --name TEXT      Engagement name (overrides ENGAGEMENT_NAME)
  -o, --output PATH    Artifacts output directory
  --dry-run            Recon + planning only, no exploits launched
  -v, --verbose        Enable DEBUG logging
```

**Example:**
```bash
artasf run --target 192.168.56.0/24 --name dvwa-test
artasf run --dry-run --verbose
```

---

### `artasf scan` — Recon + Vuln-Map Only

Safe mode — discovers targets and maps vulnerabilities, no exploitation.

```
artasf scan [OPTIONS]

Options:
  -t, --target TEXT    CIDR to scan
  -v, --verbose        Enable DEBUG logging
```

**Example:**
```bash
artasf scan -t 192.168.56.0/24
```

Output: session JSON saved to `artifacts/sessions/`.

---

### `artasf plan` — Generate AI Attack Plan

Loads a saved session JSON and calls Claude to produce an `AttackPlan`.

```
artasf plan SESSION_FILE [OPTIONS]

Arguments:
  SESSION_FILE  Path to session JSON (from artasf scan)

Options:
  -v, --verbose
```

**Example:**
```bash
artasf plan artifacts/sessions/dvwa-lab_abc12345.json
```

The updated session (with plan attached) is re-saved to the same directory.

---

### `artasf report` — Regenerate Report

Re-renders the HTML and PDF report from a saved session.

```
artasf report SESSION_FILE [OPTIONS]

Arguments:
  SESSION_FILE  Path to session JSON

Options:
  -o, --out PATH   Output directory (default: artifacts/reports/)
```

**Example:**
```bash
artasf report artifacts/sessions/dvwa-lab_abc12345.json --out /tmp/reports
```

---

### `artasf version`

Prints the installed version and exits.

---

## Environment Variables

All variables can be set in `.env` (loaded automatically) or exported in the shell.

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | _(required)_ | Anthropic API key |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model for planning |
| `PLANNER_MAX_TOKENS` | `4096` | Max tokens for Claude response |
| `MSF_HOST` | `127.0.0.1` | Metasploit RPC host |
| `MSF_PORT` | `55553` | Metasploit RPC port |
| `MSF_PASSWORD` | `msf` | Metasploit RPC password |
| `MSF_SSL` | `true` | Use SSL for RPC connection |
| `TARGET_NETWORK` | `192.168.56.0/24` | CIDR range to scan |
| `ENGAGEMENT_NAME` | `lab-engagement` | Name tag for reports/artifacts |
| `LHOST` | _(empty)_ | Attacker IP for reverse shell callbacks |
| `MAX_EXPLOIT_ATTEMPTS` | `3` | Max attempts per exploit step |
| `EXPLOIT_TIMEOUT_SEC` | `60` | Seconds before an exploit step times out |
| `DRY_RUN` | `false` | Skip exploitation when `true` |
| `NMAP_FLAGS` | `-sV -sC --open -T4` | Flags passed to nmap (appended to `-oX`) |
| `ARTIFACTS_DIR` | `artifacts` | Root directory for all generated files |

---

## Artifacts Layout

```
artifacts/
├── sessions/     ─ JSON session snapshots (one per run/scan/plan)
├── reports/      ─ HTML and PDF engagement reports
├── scans/        ─ Raw nmap XML output files
├── loot/         ─ Harvested files, credentials, hashes
│   └── <target-ip>/
└── logs/         ─ Loguru log files
```

---

## Programmatic Use

```python
import asyncio
from artasf.core.orchestrator import Orchestrator

async def main():
    async with Orchestrator.from_settings() as orch:
        session = await orch.run()
    print(session.phase, len(session.vulns))

asyncio.run(main())
```
