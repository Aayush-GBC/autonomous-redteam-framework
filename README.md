# ARTASF — Autonomous Red Team Assessment Framework

[![CI](https://github.com/Aayush-GBC/autonomous-redteam-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Aayush-GBC/autonomous-redteam-framework/actions/workflows/ci.yml)

A Python CLI tool that runs a full autonomous penetration-testing pipeline against a controlled lab target using Claude AI for attack planning.

> **For authorised lab use only.** Never run against systems you do not own or have explicit written permission to test.

## Architecture

```
INIT → RECON → VULN_MAP → PLANNING (Claude) → EXPLOITING → POST_EXPLOIT → REPORTING → DONE
```

| Phase | What happens |
|---|---|
| RECON | Nmap scan, DNS enumeration, HTTP banner enrichment |
| VULN_MAP | Offline CVE matching + CVSS scoring |
| PLANNING | Claude (`claude-sonnet-4-6`) generates a ranked `AttackPlan` |
| EXPLOITING | Metasploit RPC + custom web-attack handlers (SQLi, XSS, file-upload) |
| POST_EXPLOIT | Session enumeration, privilege escalation (GTFOBins/sudo/docker), loot harvest |
| REPORTING | Jinja2 HTML + WeasyPrint PDF dark-theme report |

## Lab Setup

See [docs/lab-setup.md](docs/lab-setup.md) for the full VirtualBox + DVWA guide.

**Quick summary:**
- Target: Ubuntu Server with DVWA on a VirtualBox host-only network (`192.168.56.x`)
- Attacker: Windows 11 host running Metasploit RPC (`msfrpcd`)

## Installation

```bash
# Editable install (recommended for development)
pip install -e .

# With dev extras (pytest, ruff, mypy)
pip install -e ".[dev]"
```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Key variables:

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |
| `TARGET_NETWORK` | CIDR of the lab network (e.g. `192.168.56.0/24`) |
| `LHOST` | Your attacker IP for reverse shell callbacks |
| `MSF_PASSWORD` | Metasploit RPC password (set when starting `msfrpcd`) |
| `DRY_RUN` | `true` runs recon + planning only, no exploits |

## Usage

```bash
# Full autonomous pipeline
artasf run --target 192.168.56.0/24

# Recon + vuln-map only (safe, no exploitation)
artasf scan -t 192.168.56.0/24

# Generate AI attack plan from a saved scan
artasf plan artifacts/sessions/dvwa-lab_abc12345.json

# Regenerate report from a saved session
artasf report artifacts/sessions/dvwa-lab_abc12345.json

# Dry-run (no exploits launched)
artasf run --dry-run
```

See [docs/usage.md](docs/usage.md) for full CLI reference.

## Development

```bash
make test        # run all tests
make lint        # ruff lint
make fmt         # ruff format
make typecheck   # mypy
make test-cov    # tests + coverage report
```

## Project Structure

```
src/artasf/
├── core/          # config, models, orchestrator, workflow state machine
├── recon/         # nmap runner/parser, HTTP enrichment, DNS enum
├── vulnmap/       # CVE mapper, CVSS scoring, offline sources
├── planner/       # Claude AI planner, attack plan types, ranking
├── exploit/       # Metasploit RPC wrapper, executor, web attack handlers
├── post/          # session shell, enumeration, privilege escalation, loot
├── reporting/     # Jinja2 HTML + WeasyPrint PDF renderer
├── storage/       # aiosqlite database, file store, repositories
└── ui/            # Typer CLI, Rich console views
```

## Author

**Aayush Patel** — creator and maintainer of ARTASF.

- GitHub: [@Aayush-GBC](https://github.com/Aayush-GBC)
- Repository: [Aayush-GBC/autonomous-redteam-framework](https://github.com/Aayush-GBC/autonomous-redteam-framework)

## License

MIT — see [LICENSE](LICENSE).
