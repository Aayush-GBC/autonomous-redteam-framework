"""
AIPlanner — autonomous attack planning via Claude.

Workflow:
  1. build_context()  — convert EngagementSession → PlannerContext
  2. _render_prompt() — serialise PlannerContext into a structured text block
  3. _call_claude()   — send to Claude with a tool_use schema, get JSON back
  4. _parse_plan()    — validate + convert JSON → AttackPlan domain model

Claude is given a single tool "submit_attack_plan" and instructed to call it
exactly once.  This guarantees structured, machine-parseable output every time.
"""

from __future__ import annotations

import json
from typing import Any

import anthropic
from loguru import logger

from artasf.core.config import settings
from artasf.core.exceptions import AIResponseError, ConfigError, PlannerError
from artasf.core.models import AttackPlan, AttackStep, EngagementSession, Severity
from artasf.planner.plan_types import PlannerContext, VulnSummary
from artasf.planner.ranking import build_context

# ---------------------------------------------------------------------------
# Tool schema — Claude must call this exactly once with the attack plan
# ---------------------------------------------------------------------------

_SUBMIT_PLAN_TOOL: dict[str, Any] = {
    "name": "submit_attack_plan",
    "description": (
        "Submit the complete, ordered attack plan for this engagement. "
        "Call this tool exactly once with every exploitation step."
    ),
    "input_schema": {
        "type": "object",
        "required": ["rationale", "steps"],
        "properties": {
            "rationale": {
                "type": "string",
                "description": "High-level reasoning: why this attack order, what is the intended kill-chain.",
            },
            "steps": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["step", "vuln_id", "target_id", "rationale", "module"],
                    "properties": {
                        "step": {
                            "type": "integer",
                            "description": "Execution order (1-based, ascending).",
                        },
                        "vuln_id": {
                            "type": "string",
                            "description": "ID of the Vulnerability this step targets.",
                        },
                        "target_id": {
                            "type": "string",
                            "description": "ID of the Target host.",
                        },
                        "rationale": {
                            "type": "string",
                            "description": "Why this step at this position.",
                        },
                        "module": {
                            "type": "string",
                            "description": (
                                "Metasploit module path (e.g. exploit/multi/http/apache_normalize_path_rce) "
                                "or a custom tag like 'custom/sqli' or 'custom/file_upload'."
                            ),
                        },
                        "params": {
                            "type": "object",
                            "description": (
                                "Metasploit options to set. "
                                "Always include RHOSTS and RPORT where applicable."
                            ),
                            "additionalProperties": {"type": "string"},
                        },
                        "risk_level": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Operator risk assessment for this step.",
                        },
                        "requires_step": {
                            "type": "integer",
                            "description": "Step number that must succeed before this one runs (optional).",
                        },
                    },
                },
            },
        },
    },
}

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

def _build_system_prompt() -> str:
    lhost = settings.lhost or "127.0.0.1"
    return f"""\
You are a senior red team operator conducting an authorised penetration test \
against a controlled lab environment. Your task is to analyse the provided \
reconnaissance and vulnerability data, then produce a complete, ordered \
attack plan by calling the submit_attack_plan tool.

Guidelines:
- Order steps to maximise impact: prioritise unauthenticated RCE and \
  credential access before privilege escalation.
- Respect dependencies: if step B requires a shell obtained in step A, \
  set requires_step accordingly.  Do NOT set requires_step from INFO/LOW \
  recon steps to HIGH/CRITICAL attack steps — recon steps are best-effort \
  and must not block the attack chain if they are unavailable.
- Be specific with Metasploit params: always set RHOSTS, RPORT, and any \
  payload options (e.g. LHOST, LPORT for reverse shells).
- For LHOST always use {lhost}.
- For web attacks and recon on DVWA, use ONLY these custom/ handlers \
  (they are implemented in the framework — do not invent others): \
  custom/sqli, custom/xss, custom/http_put_upload, custom/cmd_inject. \
  Do NOT use auxiliary/scanner/http/* modules for web recon — they are \
  unreliable and often not present.
- The only Metasploit modules you may use are: exploit/multi/handler, \
  and any exploit/* or auxiliary/scanner/portscan/* module you are \
  certain exists. When in doubt, use a custom/ handler instead.
- Keep rationale concise but actionable — the operator will read it.
- Do not include steps for vulnerabilities that have no realistic exploit \
  path (e.g. info-disclosure-only entries with no follow-on action).
- Call submit_attack_plan exactly once.
"""


# ---------------------------------------------------------------------------
# AIPlanner
# ---------------------------------------------------------------------------

class AIPlanner:
    """Calls Claude to generate an AttackPlan from an EngagementSession."""

    def __init__(self, client: anthropic.AsyncAnthropic | None = None) -> None:
        self._client = client  # injected in tests; created lazily in production

    async def plan(self, session: EngagementSession) -> AttackPlan:
        """
        Build an attack plan for *session* using Claude.

        Raises:
            ConfigError:     ANTHROPIC_API_KEY not set.
            PlannerError:    No vulnerabilities to plan against.
            AIResponseError: Claude didn't call the tool or returned bad JSON.
        """
        if not settings.anthropic_api_key:
            raise ConfigError(
                "ANTHROPIC_API_KEY is required for the planning phase. "
                "Set it in your .env file."
            )

        if not session.vulns:
            raise PlannerError("No vulnerabilities found — nothing to plan against.")

        ctx = build_context(session)
        user_msg = _render_prompt(ctx)

        logger.debug("Sending {} vulns across {} targets to Claude", len(ctx.vulns), len(ctx.targets))

        raw = await self._call_claude(user_msg)
        plan = _parse_plan(raw, session.id, settings.claude_model)

        return plan

    async def _call_claude(self, user_message: str) -> dict[str, Any]:
        """Call Claude and return the tool input dict."""
        client = self._client or anthropic.AsyncAnthropic(
            api_key=settings.anthropic_api_key
        )

        response = await client.messages.create(
            model=settings.claude_model,
            max_tokens=settings.planner_max_tokens,
            system=_build_system_prompt(),
            tools=[_SUBMIT_PLAN_TOOL],
            tool_choice={"type": "any"},   # force tool use
            messages=[{"role": "user", "content": user_message}],
        )

        # Find the tool_use block
        for block in response.content:
            if block.type == "tool_use" and block.name == "submit_attack_plan":
                logger.debug(
                    "Claude used {} input_tokens / {} output_tokens",
                    response.usage.input_tokens,
                    response.usage.output_tokens,
                )
                return dict(block.input)  # type: ignore[arg-type]

        raise AIResponseError(
            f"Claude did not call submit_attack_plan. "
            f"Stop reason: {response.stop_reason}. "
            f"Content types: {[b.type for b in response.content]}"
        )


# ---------------------------------------------------------------------------
# Prompt renderer
# ---------------------------------------------------------------------------

def _render_prompt(ctx: PlannerContext) -> str:
    lines: list[str] = [
        f"# Engagement: {ctx.engagement_name}",
        f"Network: {ctx.network}",
        f"Lab context: {ctx.lab_notes}",
        "",
        "## Targets",
    ]

    for t in ctx.targets:
        lines.append(
            f"- [{t.target_id[:8]}] {t.ip}"
            + (f" ({t.hostname})" if t.hostname else "")
            + (f" — {t.os_guess}" if t.os_guess else "")
        )
        for p in t.open_ports:
            ver = f" [{p.version}]" if p.version else ""
            banner = f" | {p.banner}" if p.banner else ""
            lines.append(f"    port {p.number}/{p.service}{ver}{banner}")

    lines += ["", "## Vulnerabilities (ranked by priority, highest first)"]

    for i, v in enumerate(ctx.vulns, 1):
        msf = ", ".join(v.msf_modules) if v.msf_modules else "none"
        cve = f" [{v.cve}]" if v.cve else ""
        lines.append(
            f"{i}. [{v.vuln_id[:8]}] {v.title}{cve}"
            f" | host={v.target_ip}:{v.port}"
            f" | severity={v.severity} cvss={v.cvss}"
            f" | msf={msf}"
        )
        lines.append(f"   {v.description}")

    lines += [
        "",
        "Call submit_attack_plan with your complete ordered attack plan.",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_plan(raw: dict[str, Any], session_id: str, model: str) -> AttackPlan:
    """Validate the tool input dict and convert it to an AttackPlan."""
    try:
        rationale: str = raw["rationale"]
        raw_steps: list[dict[str, Any]] = raw["steps"]
    except KeyError as exc:
        raise AIResponseError(f"Missing key in Claude response: {exc}") from exc

    steps: list[AttackStep] = []
    for s in raw_steps:
        try:
            risk_raw = s.get("risk_level", "medium")
            try:
                risk = Severity(risk_raw)
            except ValueError:
                risk = Severity.MEDIUM

            steps.append(AttackStep(
                step=int(s["step"]),
                vuln_id=s["vuln_id"],
                target_id=s["target_id"],
                rationale=s["rationale"],
                module=s["module"],
                params=s.get("params") or {},
                risk_level=risk,
                requires_step=s.get("requires_step"),
            ))
        except (KeyError, TypeError, ValueError) as exc:
            raise AIResponseError(f"Malformed step in Claude response: {s!r} — {exc}") from exc

    if not steps:
        raise AIResponseError("Claude returned an empty steps list.")

    # Sort by step number (Claude should already do this, but be defensive)
    steps.sort(key=lambda x: x.step)

    return AttackPlan(
        session_id=session_id,
        steps=steps,
        rationale=rationale,
        model_used=model,
    )
