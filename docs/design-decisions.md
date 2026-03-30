# Design Decisions

## 1. Pydantic for all domain models

All data objects — `Target`, `Vulnerability`, `AttackPlan`, `LootItem`, `EngagementSession` — are Pydantic v2 models.
**Why:** Serialisation to/from JSON (for session persistence) and validation come for free. `model_dump_json()` / `model_validate_json()` eliminate manual marshalling.

---

## 2. Claude `tool_use` for structured attack planning

The planner sends a `tool_use` message to Claude and registers a `create_attack_plan` tool whose schema matches `AttackPlan`. Claude is forced to return structured data rather than freeform text.
**Why:** Parsing unstructured LLM output is fragile. Tool-use gives us type-safe, validated plans every time.

---

## 3. Single `EngagementSession` as shared state

The orchestrator holds one `EngagementSession` and mutates it in-place across phases.
**Why:** Simplifies async coordination — no message bus, no dependency injection. Each phase reads and appends to the same object. The session is serialised to JSON after every phase for crash-recovery.

---

## 4. `WorkflowStateMachine` for phase transitions

Valid next-phases are declared in a dict; `advance()` raises `InvalidTransitionError` on illegal moves.
**Why:** Without this guard it is easy to accidentally skip or repeat phases when debugging or extending the pipeline.

---

## 5. Custom web-attack handlers alongside Metasploit

`ExploitExecutor` first checks whether a step has a matching custom handler (`dvwa_sqli`, `dvwa_xss`, `dvwa_file_upload`) before falling back to MSF.
**Why:** DVWA is an intentionally vulnerable web app — its attack surface is HTTP, not native exploits. MSF modules don't exist for DVWA-style web challenges, so bespoke HTTP handlers are the only way to automate them.

---

## 6. aiosqlite + JSON blob storage

Each domain object is stored as a JSON blob alongside a small number of indexed scalar columns (id, phase, severity, etc.).
**Why:** Avoids a complex relational schema that would need to be kept in sync with evolving Pydantic models. Blobs let the model evolve freely; indexed columns provide cheap filtering. SQLite is zero-config for a single-user CLI tool.

---

## 7. Loguru over stdlib `logging`

**Why:** Structured, coloured output out of the box with zero configuration. `logger.bind()` enables per-context metadata without handler boilerplate.

---

## 8. Windows-safe signal handling

The asyncio `ProactorEventLoop` on Windows does not support `loop.add_signal_handler()`. The orchestrator detects this at runtime and falls back to `signal.signal()` with a two-argument callback.
**Why:** The tool must work on Windows (attacker machine) without requiring WSL.

---

## 9. Post-exploitation via web-shell fallback

When Metasploit fails to obtain a session, `PostExploitPhase` checks for an uploaded PHP web-shell and uses it to execute enumeration commands over HTTP.
**Why:** DVWA Low security allows file uploads; even without a reverse shell we can enumerate the target and harvest loot through the web-shell.

---

## 10. Offline CVE source as primary vuln data

`offline_cve.py` ships 21 common CVEs with CPE patterns. There is no live NVD API call.
**Why:** Lab environments typically have no internet access. An offline source keeps the tool self-contained and fast; it is intended as a starting point — the mapper is pluggable for richer sources.
