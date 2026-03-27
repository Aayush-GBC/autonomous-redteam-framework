"""
DNS enumeration for discovered hosts.

Performs reverse PTR lookups for every IP in the scanned range to resolve
hostnames, and optionally forward-confirms them.  Returns a mapping of
IP → hostname that the orchestrator merges back into Target objects.
"""

from __future__ import annotations

import ipaddress

import dns.resolver
import dns.reversename
from loguru import logger

from artasf.recon.recon_types import DnsResult


async def enumerate_dns(network: str) -> dict[str, str]:
    """
    Reverse-resolve every host address in *network*.

    Returns a ``{ip: hostname}`` dict for IPs that have a PTR record.
    Uses the system's default resolver (inherits /etc/resolv.conf or
    Windows DNS settings).

    Note: this is synchronous under the hood (dnspython doesn't expose
    a native asyncio API for simple queries), but it's fast enough for
    a /24 and is called once per engagement.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        logger.warning("Invalid network for DNS enum: {}", network)
        return {}

    resolved: list[DnsResult] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 2
    resolver.lifetime = 4

    for host in net.hosts():  # type: ignore[attr-defined]
        result = _reverse_lookup(resolver, str(host))
        if result.hostname:
            resolved.append(result)

    mapping = {r.ip: r.hostname for r in resolved if r.hostname}
    logger.info("DNS enum: {}/{} hosts resolved", len(mapping), net.num_addresses)  # type: ignore[attr-defined]
    return mapping


def _reverse_lookup(resolver: dns.resolver.Resolver, ip: str) -> DnsResult:
    result = DnsResult(ip=ip)
    try:
        rev_name = dns.reversename.from_address(ip)
        answers  = resolver.resolve(rev_name, "PTR")
        names: list[str] = [str(r).rstrip(".") for r in answers]
        for i, name in enumerate(names):
            if i == 0:
                result.hostname = name
            else:
                result.aliases.append(name)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    except Exception as exc:
        logger.debug("PTR lookup failed for {}: {}", ip, exc)
    return result
