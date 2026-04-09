"""
Nmap XML parser.

Converts an nmap -oX output file into a list of Target domain models.
Handles both single-host and CIDR range scans.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import cast

from loguru import logger

from artasf.core.exceptions import NmapError
from artasf.core.models import Port, PortState, Target

# Service names nmap reports when a TCP proxy/wrapper intercepts the connection
_TCPWRAP_NAMES = {"tcpwrapped", "tcpwrap"}

# Number of filtered ports that triggers a "firewall likely" determination
_FILTER_THRESHOLD = 3


def parse_nmap_xml(xml_path: Path) -> list[Target]:
    """
    Parse *xml_path* and return one Target per host that was found up.

    Raises:
        NmapError: if the file cannot be parsed.
    """
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise NmapError(f"Cannot parse nmap XML {xml_path}: {exc}") from exc

    root = tree.getroot()
    targets: list[Target] = []

    for host_el in root.findall("host"):
        # Skip hosts that nmap reports as down
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        ip       = _extract_ip(host_el)
        hostname = _extract_hostname(host_el)
        os_guess, os_cpe = _extract_os(host_el)
        ports    = _extract_ports(host_el)

        target = Target(
            ip=ip,
            hostname=hostname,
            os_guess=os_guess,
            os_cpe=os_cpe,
            ports=ports,
        )
        logger.debug(
            "Host {} ({}) — {} open port(s)", ip, hostname or "?", len(target.open_ports())
        )
        targets.append(target)

    logger.info("Parsed {} live host(s) from {}", len(targets), xml_path.name)
    return targets


def detect_filtered_ports(targets: list[Target]) -> dict:
    """
    Analyse parsed scan results for firewall / WAF / TCP-wrapper indicators.

    Args:
        targets: List of Target objects from ``parse_nmap_xml``.

    Returns a dict with three keys:

        ``per_target``
            Mapping of ``{ip: {"open": int, "filtered": int, "tcpwrapped": int}}``.

        ``totals``
            Aggregate ``{"open": int, "filtered": int, "tcpwrapped": int}`` across
            all targets.

        ``firewall_likely``
            ``True`` when the aggregate filtered count exceeds
            ``_FILTER_THRESHOLD`` OR when at least one tcpwrapped port exists.
            Either condition indicates a stateful packet filter or application
            proxy in the path.
    """
    per_target: dict[str, dict[str, int]] = {}
    totals = {"open": 0, "filtered": 0, "tcpwrapped": 0}

    for target in targets:
        counts = {"open": 0, "filtered": 0, "tcpwrapped": 0}
        for port in target.ports:
            if port.state == PortState.OPEN:
                svc = (port.service or "").lower().strip()
                if svc in _TCPWRAP_NAMES:
                    counts["tcpwrapped"] += 1
                else:
                    counts["open"] += 1
            elif port.state == PortState.FILTERED:
                counts["filtered"] += 1
        per_target[target.ip] = counts
        for k in totals:
            totals[k] += counts[k]

    firewall_likely = (
        totals["filtered"] > _FILTER_THRESHOLD
        or totals["tcpwrapped"] > 0
    )

    if firewall_likely:
        logger.warning(
            "Firewall/filter indicators detected — "
            "filtered={} tcpwrapped={} open={} across {} host(s)",
            totals["filtered"], totals["tcpwrapped"], totals["open"], len(targets),
        )
    else:
        logger.debug(
            "No firewall indicators — filtered={} tcpwrapped={} open={}",
            totals["filtered"], totals["tcpwrapped"], totals["open"],
        )

    return {
        "per_target": per_target,
        "totals": totals,
        "firewall_likely": firewall_likely,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_ip(host_el: ET.Element) -> str:
    for addr in host_el.findall("address"):
        if addr.get("addrtype") == "ipv4":
            return addr.get("addr", "0.0.0.0")
    return "0.0.0.0"


def _extract_hostname(host_el: ET.Element) -> str | None:
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is None:
        return None
    for hn in hostnames_el.findall("hostname"):
        name = hn.get("name")
        if name:
            return name
    return None


def _extract_os(host_el: ET.Element) -> tuple[str | None, str | None]:
    os_el = host_el.find("os")
    if os_el is None:
        return None, None
    # Best match (highest accuracy)
    best = None
    best_acc = -1
    for match in os_el.findall("osmatch"):
        try:
            acc = int(match.get("accuracy", "0"))
        except ValueError:
            acc = 0
        if acc > best_acc:
            best_acc = acc
            best = match
    if best is None:
        return None, None

    matched = cast(ET.Element, best)
    os_name = matched.get("name")
    # Try to grab CPE from first osclass
    cpe: str | None = None
    osclass = matched.find("osclass")
    if osclass is not None:
        cpe_el = osclass.find("cpe")
        if cpe_el is not None:
            cpe = cpe_el.text
    return os_name, cpe


def _extract_ports(host_el: ET.Element) -> list[Port]:
    ports: list[Port] = []
    ports_el = host_el.find("ports")
    if ports_el is None:
        return ports

    for port_el in ports_el.findall("port"):
        number   = int(port_el.get("portid", "0"))
        protocol = port_el.get("protocol", "tcp")

        state_el = port_el.find("state")
        raw_state = state_el.get("state", "closed") if state_el is not None else "closed"
        try:
            state = PortState(raw_state)
        except ValueError:
            state = PortState.FILTERED

        service_el = port_el.find("service")
        service  = ""
        version  = None
        banner   = None
        cpe      = None
        if service_el is not None:
            service = service_el.get("name", "")
            product = service_el.get("product", "")
            ver     = service_el.get("version", "")
            extra   = service_el.get("extrainfo", "")
            parts   = [p for p in (product, ver, extra) if p]
            version = " ".join(parts) or None
            cpe_el  = service_el.find("cpe")
            if cpe_el is not None:
                cpe = cpe_el.text

        # Grab banner from script output (e.g. banner.nse)
        for script_el in port_el.findall("script"):
            if script_el.get("id") == "banner":
                banner = script_el.get("output")
                break

        ports.append(Port(
            number=number,
            protocol=protocol,
            state=state,
            service=service,
            version=version,
            banner=banner,
            cpe=cpe,
        ))

    return ports
