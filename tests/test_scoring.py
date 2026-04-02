"""Tests for vulnmap scoring and mapper logic."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from artasf.core.models import Port, PortState, Severity, Target
from artasf.vulnmap.scoring import score, _severity_from_score
from artasf.vulnmap.vuln_types import KnownVuln
from artasf.vulnmap.mapper import VulnMapper, _matches, _detect_dvwa


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _make_vuln(**kwargs) -> KnownVuln:
    defaults = dict(id="TEST", title="Test", description="", cvss_score=5.0)
    defaults.update(kwargs)
    return KnownVuln(**defaults)


def test_msf_module_bonus():
    base = _make_vuln(cvss_score=5.0)
    with_msf = _make_vuln(cvss_score=5.0, msf_modules=["exploit/test/foo"])
    s_base, _ = score(base)
    s_msf, _ = score(with_msf)
    assert s_msf > s_base


def test_web_port_bonus():
    vuln = _make_vuln(cvss_score=5.0)
    s_web, _ = score(vuln, matched_port=80)
    s_other, _ = score(vuln, matched_port=22)
    assert s_web > s_other


def test_auth_required_penalty():
    no_auth = _make_vuln(cvss_score=7.0, requires_auth=False)
    needs_auth = _make_vuln(cvss_score=7.0, requires_auth=True)
    s_no, _ = score(no_auth)
    s_yes, _ = score(needs_auth)
    assert s_no > s_yes


def test_score_clamped_to_ten():
    vuln = _make_vuln(
        cvss_score=10.0,
        msf_modules=["exploit/x"],
        requires_auth=False,
    )
    s, _ = score(vuln, matched_port=80)
    assert s <= 10.0


def test_score_never_negative():
    vuln = _make_vuln(cvss_score=0.0, requires_auth=True, tags=["information-disclosure"])
    s, _ = score(vuln)
    assert s >= 0.0


def test_severity_from_score():
    assert _severity_from_score(9.5) == Severity.CRITICAL
    assert _severity_from_score(7.0) == Severity.HIGH
    assert _severity_from_score(5.0) == Severity.MEDIUM
    assert _severity_from_score(2.0) == Severity.LOW
    assert _severity_from_score(0.0) == Severity.INFO


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

def _make_port(**kwargs) -> Port:
    defaults = dict(number=80, protocol="tcp", state=PortState.OPEN, service="http")
    defaults.update(kwargs)
    return Port(**defaults)


def _make_target(ports: list[Port]) -> Target:
    return Target(ip="192.168.56.101", ports=ports)


def test_port_number_match():
    known = _make_vuln(port_numbers=[80], service_patterns=["http"])
    port = _make_port(number=80, service="http")
    assert _matches(known, port, _make_target([port]))


def test_port_number_no_match():
    known = _make_vuln(port_numbers=[443], service_patterns=["https"])
    port = _make_port(number=80, service="http")
    assert not _matches(known, port, _make_target([port]))


def test_version_pattern_match():
    known = _make_vuln(
        service_patterns=["http"],
        version_patterns=["Apache/2\\.4\\.49"],
    )
    port = _make_port(service="http", version="Apache/2.4.49 (Ubuntu)")
    assert _matches(known, port, _make_target([port]))


def test_version_pattern_no_match():
    known = _make_vuln(
        service_patterns=["http"],
        version_patterns=["Apache/2\\.4\\.49"],
    )
    port = _make_port(service="http", version="Apache/2.4.50 (Ubuntu)")
    assert not _matches(known, port, _make_target([port]))


def test_cpe_fallback_match():
    known = _make_vuln(
        service_patterns=["http"],
        cpe_patterns=["apache:http_server:2\\.4\\.29"],
    )
    port = _make_port(service="http", cpe="cpe:/a:apache:http_server:2.4.29")
    assert _matches(known, port, _make_target([port]))


# ---------------------------------------------------------------------------
# DVWA detection
# ---------------------------------------------------------------------------

def test_dvwa_detected_via_banner():
    port = _make_port(number=80, service="http", banner="DVWA Login :: Damn Vulnerable Web App")
    target = _make_target([port])
    assert _detect_dvwa(target)


def test_dvwa_not_detected_on_generic_http():
    port = _make_port(number=80, service="http", banner="Apache/2.4.29")
    target = _make_target([port])
    assert not _detect_dvwa(target)


# ---------------------------------------------------------------------------
# VulnMapper integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mapper_returns_vulns_for_dvwa_host():
    port = Port(
        number=80, protocol="tcp", state=PortState.OPEN,
        service="http", version="Apache/2.4.29",
        banner="DVWA - Damn Vulnerable Web Application",
    )
    target = Target(ip="192.168.56.101", ports=[port])
    mapper = VulnMapper()
    vulns = await mapper.map(target)
    assert len(vulns) > 0
    titles = [v.title for v in vulns]
    assert any("DVWA" in t for t in titles)


@pytest.mark.asyncio
async def test_mapper_no_dvwa_vulns_without_fingerprint():
    port = Port(
        number=80, protocol="tcp", state=PortState.OPEN,
        service="http", version="nginx/1.18",
    )
    target = Target(ip="192.168.56.10", ports=[port])
    mapper = VulnMapper()
    vulns = await mapper.map(target)
    dvwa_vulns = [v for v in vulns if "DVWA" in v.title]
    assert len(dvwa_vulns) == 0


@pytest.mark.asyncio
async def test_mapper_ssh_user_enum():
    port = Port(
        number=22, protocol="tcp", state=PortState.OPEN,
        service="ssh", version="OpenSSH 7.6p1 Ubuntu",
    )
    target = Target(ip="192.168.56.101", ports=[port])
    mapper = VulnMapper()
    vulns = await mapper.map(target)
    assert any("OpenSSH" in v.title or "SSH" in v.title for v in vulns)
