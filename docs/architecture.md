# Architecture

## Pipeline Overview

```
INIT → RECON → VULN_MAP → PLANNING → EXPLOITING → POST_EXPLOIT → REPORTING → DONE
```

The `WorkflowStateMachine` (`core/workflow.py`) enforces legal phase transitions. The `Orchestrator` (`core/orchestrator.py`) drives the pipeline end-to-end using an `EngagementSession` as the shared state object.

---

## Module Map

### `core/`

| File | Responsibility |
|---|---|
| `config.py` | `ARTASFSettings` — pydantic-settings, loads `.env` |
| `models.py` | All Pydantic domain models (`EngagementSession`, `Target`, `Vulnerability`, `AttackPlan`, `LootItem`, …) |
| `orchestrator.py` | Async pipeline driver; one phase per method |
| `workflow.py` | State machine with allowed-transition map |
| `logging.py` | Loguru setup — call `configure_logging()` once at startup |
| `exceptions.py` | `ARTASFError` hierarchy |

### `recon/`

Nmap runner → XML parse → HTTP enrichment → DNS enum.

- `nmap_runner.py` — spawns nmap as a subprocess, returns raw XML
- `nmap_parser.py` — parses XML into `list[Target]`
- `http_enrich.py` — HEAD request to each open HTTP/HTTPS port; captures title and server header
- `dns_enum.py` — reverse DNS + A-record lookups for all IPs in the CIDR

### `vulnmap/`

Offline CVE matching + CVSS scoring.

- `mapper.py` — `VulnMapper.map(target)` iterates services and queries sources
- `scoring.py` — CVSS v3 base-score → `Severity` enum
- `sources/offline_cve.py` — static list of 21 common CVEs mapped to CPE patterns
- `sources/exploit_refs.py` — CVE → Metasploit module mapping

### `planner/`

Sends recon + vuln data to Claude and parses the structured `AttackPlan` response.

- `planner.py` — `AIPlanner.plan(session)` — builds the Claude prompt, calls the API with `tool_use`, deserialises the response
- `plan_types.py` — `AttackPlan`, `AttackStep` data models
- `ranking.py` — re-ranks steps by CVSS score and exploitability

### `exploit/`

- `executor.py` — `ExploitExecutor` iterates `AttackPlan.steps`, dispatches to MSF or custom handlers
- `msf_rpc.py` — thin async wrapper around `pymetasploit3` (MsfRpcClient)
- `web_attacks/sqli.py` — DVWA SQLi exploitation via HTTP
- `web_attacks/xss.py` — DVWA XSS via HTTP
- `web_attacks/file_upload.py` — DVWA file-upload PHP web-shell upload + trigger

### `post/`

- `session.py` — `SessionShell` wraps a Metasploit session for command execution
- `enum.py` — system enumeration (OS, users, network, processes)
- `privesc.py` — GTFOBins, sudo -l, docker group checks
- `loot.py` — harvest `/etc/passwd`, `/etc/shadow`, SSH keys, env vars
- `webshell.py` — post-exploitation via uploaded PHP web-shell (when MSF session unavailable)

### `reporting/`

- `render.py` — `ReportRenderer.render_html/render_pdf(session)`
- `report_html.py` — Jinja2 render of `templates/report.html`
- `report_pdf.py` — WeasyPrint HTML → PDF conversion
- `templates/report.html` + `styles.css` — dark-theme report template

### `storage/`

- `db.py` — `Database` async context manager (aiosqlite, WAL mode)
- `repos.py` — `SessionRepository`, `VulnRepository`, `LootRepository`
- `file_store.py` — `FileStore` manages `artifacts/scans/`, `loot/`, `reports/`, `sessions/`
- `schema.sql` — canonical DDL reference

### `ui/`

- `cli.py` — Typer CLI (`run`, `scan`, `plan`, `report`, `version`)
- `console_views.py` — Rich tables and panels for each pipeline phase

---

## Data Flow

```
NmapRunner  ──XML──►  nmap_parser  ──[Target]──►  EngagementSession.targets
                                                        │
                                                   VulnMapper
                                                        │
                                                  [Vulnerability]
                                                        │
                                                    AIPlanner  ◄──── Claude API
                                                        │
                                                    AttackPlan
                                                        │
                                                 ExploitExecutor
                                                        │
                                          ┌─────────────┴──────────────┐
                                       MsfRpc                  WebAttackHandler
                                          │                             │
                                    SessionShell               loot / privesc
                                          │
                                      LootItem[]
                                          │
                                    ReportRenderer  ──►  HTML / PDF
```
