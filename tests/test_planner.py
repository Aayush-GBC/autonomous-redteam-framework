"""
Tests for planner/ — ranking, prompt rendering, and plan parsing.

Claude is never called in tests.  The AIPlanner._call_claude method is
replaced with a mock that returns a pre-baked tool response so we can test
the full parse-and-validate pipeline without an API key.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from artasf.core.exceptions import AIResponseError, PlannerError
from artasf.core.models import (
    AttackPlan,
    EngagementSession,
    Port,
    PortState,
    Severity,
    Target,
    Vulnerability,
)
from artasf.planner.planner import AIPlanner, _parse_plan, _render_prompt
from artasf.planner.ranking import build_context


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_session() -> EngagementSession:
    port_http = Port(number=80, protocol="tcp", state=PortState.OPEN,
                     service="http", version="Apache/2.4.29",
                     banner="DVWA - Damn Vulnerable Web Application")
    port_ssh  = Port(number=22, protocol="tcp", state=PortState.OPEN,
                     service="ssh", version="OpenSSH 7.6p1")
    target = Target(ip="192.168.56.101", hostname="dvwa.lab",
                    os_guess="Ubuntu 18.04", ports=[port_http, port_ssh])

    vuln_sqli = Vulnerability(
        target_id=target.id,
        port=80,
        service="http",
        title="DVWA SQL Injection (GET/POST)",
        description="SQL injection in DVWA.",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
    )
    vuln_ssh = Vulnerability(
        target_id=target.id,
        port=22,
        service="ssh",
        title="OpenSSH User Enumeration",
        description="User enum via timing.",
        severity=Severity.MEDIUM,
        cvss_score=5.3,
        cve="CVE-2018-15473",
    )

    session = EngagementSession(
        name="test-lab",
        target_network="192.168.56.0/24",
    )
    session.targets = [target]
    session.vulns   = [vuln_sqli, vuln_ssh]
    return session


def _mock_tool_response(session: EngagementSession) -> dict[str, Any]:
    """A valid submit_attack_plan tool input matching the session above."""
    t_id = session.targets[0].id
    v_sqli = next(v for v in session.vulns if "SQL" in v.title)
    v_ssh  = next(v for v in session.vulns if "SSH" in v.title)
    return {
        "rationale": "Start with SQLi to dump credentials, then enumerate SSH users.",
        "steps": [
            {
                "step": 1,
                "vuln_id": v_sqli.id,
                "target_id": t_id,
                "rationale": "SQLi gives us DB access and potential credential dump.",
                "module": "custom/sqli",
                "params": {"RHOSTS": "192.168.56.101", "RPORT": "80"},
                "risk_level": "critical",
            },
            {
                "step": 2,
                "vuln_id": v_ssh.id,
                "target_id": t_id,
                "rationale": "Enumerate valid SSH users for follow-on brute-force.",
                "module": "auxiliary/scanner/ssh/ssh_enumusers",
                "params": {"RHOSTS": "192.168.56.101", "RPORT": "22"},
                "risk_level": "medium",
                "requires_step": 1,
            },
        ],
    }


# ---------------------------------------------------------------------------
# build_context / ranking
# ---------------------------------------------------------------------------

def test_build_context_target_count():
    session = _make_session()
    ctx = build_context(session)
    assert len(ctx.targets) == 1


def test_build_context_vuln_count():
    session = _make_session()
    ctx = build_context(session)
    assert len(ctx.vulns) == 2


def test_build_context_ranked_by_priority():
    """Higher CVSS / severity should appear first."""
    session = _make_session()
    ctx = build_context(session)
    severities = [v.severity for v in ctx.vulns]
    # critical should come before medium
    assert severities.index("critical") < severities.index("medium")


def test_build_context_target_has_open_ports():
    session = _make_session()
    ctx = build_context(session)
    ports = ctx.targets[0].open_ports
    assert any(p.number == 80 for p in ports)
    assert any(p.number == 22 for p in ports)


# ---------------------------------------------------------------------------
# _render_prompt
# ---------------------------------------------------------------------------

def test_render_prompt_contains_target_ip():
    session = _make_session()
    ctx = build_context(session)
    prompt = _render_prompt(ctx)
    assert "192.168.56.101" in prompt


def test_render_prompt_contains_vuln_title():
    session = _make_session()
    ctx = build_context(session)
    prompt = _render_prompt(ctx)
    assert "SQL Injection" in prompt


def test_render_prompt_contains_msf_instruction():
    session = _make_session()
    ctx = build_context(session)
    prompt = _render_prompt(ctx)
    assert "submit_attack_plan" in prompt


# ---------------------------------------------------------------------------
# _parse_plan
# ---------------------------------------------------------------------------

def test_parse_plan_returns_attack_plan():
    session  = _make_session()
    raw      = _mock_tool_response(session)
    plan     = _parse_plan(raw, session.id, "claude-test")
    assert isinstance(plan, AttackPlan)
    assert len(plan.steps) == 2


def test_parse_plan_steps_ordered():
    session = _make_session()
    raw     = _mock_tool_response(session)
    plan    = _parse_plan(raw, session.id, "claude-test")
    assert [s.step for s in plan.steps] == [1, 2]


def test_parse_plan_severity_parsed():
    session = _make_session()
    raw     = _mock_tool_response(session)
    plan    = _parse_plan(raw, session.id, "claude-test")
    assert plan.steps[0].risk_level == Severity.CRITICAL
    assert plan.steps[1].risk_level == Severity.MEDIUM


def test_parse_plan_requires_step():
    session = _make_session()
    raw     = _mock_tool_response(session)
    plan    = _parse_plan(raw, session.id, "claude-test")
    assert plan.steps[1].requires_step == 1


def test_parse_plan_params_present():
    session = _make_session()
    raw     = _mock_tool_response(session)
    plan    = _parse_plan(raw, session.id, "claude-test")
    assert plan.steps[0].params["RHOSTS"] == "192.168.56.101"


def test_parse_plan_invalid_missing_rationale():
    with pytest.raises(AIResponseError):
        _parse_plan({"steps": []}, "sid", "model")


def test_parse_plan_empty_steps_raises():
    with pytest.raises(AIResponseError):
        _parse_plan({"rationale": "ok", "steps": []}, "sid", "model")


def test_parse_plan_bad_step_raises():
    with pytest.raises(AIResponseError):
        _parse_plan(
            {"rationale": "ok", "steps": [{"step": 1}]},  # missing required fields
            "sid", "model"
        )


def test_parse_plan_unknown_risk_level_defaults_to_medium():
    session = _make_session()
    raw = _mock_tool_response(session)
    raw["steps"][0]["risk_level"] = "bogus"
    plan = _parse_plan(raw, session.id, "claude-test")
    assert plan.steps[0].risk_level == Severity.MEDIUM


# ---------------------------------------------------------------------------
# AIPlanner.plan — mocked Claude
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_planner_plan_returns_attack_plan(monkeypatch):
    session  = _make_session()
    raw_resp = _mock_tool_response(session)

    planner = AIPlanner()
    monkeypatch.setattr(planner, "_call_claude", AsyncMock(return_value=raw_resp))
    monkeypatch.setattr("artasf.planner.planner.settings.anthropic_api_key", "sk-test")

    plan = await planner.plan(session)
    assert isinstance(plan, AttackPlan)
    assert len(plan.steps) == 2


@pytest.mark.asyncio
async def test_planner_raises_when_no_vulns(monkeypatch):
    session       = _make_session()
    session.vulns = []
    monkeypatch.setattr("artasf.planner.planner.settings.anthropic_api_key", "sk-test")

    planner = AIPlanner()
    with pytest.raises(PlannerError):
        await planner.plan(session)


@pytest.mark.asyncio
async def test_planner_raises_when_no_api_key(monkeypatch):
    session = _make_session()
    monkeypatch.setattr("artasf.planner.planner.settings.anthropic_api_key", None)

    planner = AIPlanner()
    with pytest.raises(Exception):
        await planner.plan(session)
