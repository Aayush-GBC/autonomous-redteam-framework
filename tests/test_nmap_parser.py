"""Tests for recon/nmap_parser.py using a minimal XML fixture."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from artasf.core.models import PortState
from artasf.recon.nmap_parser import parse_nmap_xml


FIXTURE_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="192.168.56.101" addrtype="ipv4"/>
        <hostnames>
          <hostname name="dvwa.lab" type="PTR"/>
        </hostnames>
        <os>
          <osmatch name="Linux 4.15" accuracy="95">
            <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X">
              <cpe>cpe:/o:linux:linux_kernel:4.15</cpe>
            </osclass>
          </osmatch>
        </os>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.6p1"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4.29">
              <cpe>cpe:/a:apache:http_server:2.4.29</cpe>
            </service>
          </port>
          <port protocol="tcp" portid="3306">
            <state state="filtered"/>
            <service name="mysql"/>
          </port>
        </ports>
      </host>
      <host>
        <status state="down"/>
        <address addr="192.168.56.1" addrtype="ipv4"/>
        <ports/>
      </host>
    </nmaprun>
""")


@pytest.fixture()
def xml_file(tmp_path: Path) -> Path:
    p = tmp_path / "scan.xml"
    p.write_text(FIXTURE_XML)
    return p


def test_parse_returns_only_up_hosts(xml_file: Path) -> None:
    targets = parse_nmap_xml(xml_file)
    assert len(targets) == 1


def test_ip_and_hostname(xml_file: Path) -> None:
    target = parse_nmap_xml(xml_file)[0]
    assert target.ip == "192.168.56.101"
    assert target.hostname == "dvwa.lab"


def test_os_detection(xml_file: Path) -> None:
    target = parse_nmap_xml(xml_file)[0]
    assert target.os_guess is not None
    assert "Linux" in target.os_guess
    assert target.os_cpe == "cpe:/o:linux:linux_kernel:4.15"


def test_open_ports(xml_file: Path) -> None:
    target = parse_nmap_xml(xml_file)[0]
    open_ports = target.open_ports()
    assert len(open_ports) == 2
    port_numbers = {p.number for p in open_ports}
    assert port_numbers == {22, 80}


def test_filtered_port_excluded_from_open(xml_file: Path) -> None:
    target = parse_nmap_xml(xml_file)[0]
    assert all(p.number != 3306 for p in target.open_ports())


def test_port_service_fields(xml_file: Path) -> None:
    target = parse_nmap_xml(xml_file)[0]
    http = next(p for p in target.ports if p.number == 80)
    assert http.service == "http"
    assert http.version is not None
    assert "Apache" in http.version
    assert http.cpe == "cpe:/a:apache:http_server:2.4.29"


def test_has_service_helper(xml_file: Path) -> None:
    target = parse_nmap_xml(xml_file)[0]
    assert target.has_service("http")
    assert target.has_service("ssh")
    assert not target.has_service("ftp")
