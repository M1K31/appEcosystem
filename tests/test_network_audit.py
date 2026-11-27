"""Unit tests for LAN-only `scan.network_audit` capability."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from agents.scan_agent.network_audit import (
    NETWORK_AUDIT_CAPABILITY,
    build_network_audit_handler,
    parse_nmap_xml,
    run_network_audit,
    validate_lan_ip,
)
from ecosystem_policy import PolicyEngine


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="arp-response"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Apple SMB"/>
      </port>
      <port protocol="tcp" portid="5900">
        <state state="open"/>
        <service name="vnc" product="Apple remote desktop vnc"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _make_fake_nmap(tmp_path: Path, xml_body: str = SAMPLE_NMAP_XML, rc: int = 0) -> Path:
    script = tmp_path / "fake_nmap.py"
    script.write_text(
        f"""#!{sys.executable}
import sys
sys.stdout.write({xml_body!r})
sys.exit({rc})
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def test_validate_lan_ip_fail_closed():
    assert validate_lan_ip("192.168.50.61") == "192.168.50.61"
    assert validate_lan_ip("::ffff:192.168.50.61") == "192.168.50.61"
    assert validate_lan_ip("10.0.0.5") == "10.0.0.5"
    assert validate_lan_ip("127.0.0.1") == "127.0.0.1"
    assert validate_lan_ip("fe80::1") == "fe80::1"

    for bad in ("8.8.8.8", "1.1.1.1", "example.com", "192.168.50.0/24", "0.0.0.0", "224.0.0.1", "-sV", ""):
        with pytest.raises(ValueError):
            validate_lan_ip(bad)


def test_parse_nmap_xml_and_xxe_rejection():
    state, ports = parse_nmap_xml(SAMPLE_NMAP_XML)
    assert state == "up"
    assert [p.port for p in ports] == [22, 445, 5900]
    assert ports[0].product == "OpenSSH"

    with pytest.raises(ValueError, match="ENTITY"):
        parse_nmap_xml('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "bad">]><nmaprun/>')


def test_run_network_audit_findings_and_policy_freeze(tmp_path: Path):
    fake_nmap = _make_fake_nmap(tmp_path)
    policy = PolicyEngine(authority="standalone_local", persistence_path=tmp_path / "policy.json")

    res = asyncio.run(
        run_network_audit(
            "192.168.50.61",
            mac_address="5e:a7:49:18:14:8b",
            profile="quick",
            nmap_bin=str(fake_nmap),
            policy_engine=policy,
        )
    )
    assert res.status == "findings"
    assert res.host_state == "up"
    assert res.summary == {"open_port_count": 3, "high_count": 1, "medium_count": 1, "low_count": 1}
    assert res.mac_address == "5e:a7:49:18:14:8b"

    # Public IP is refused fail-closed before nmap runs
    denied = asyncio.run(run_network_audit("8.8.8.8", nmap_bin=str(fake_nmap), policy_engine=policy))
    assert denied.status == "denied"

    # Freeze suspends network audits
    policy.freeze(initiated_by="test", channel="test", reason="test freeze")
    frozen = asyncio.run(run_network_audit("192.168.50.61", nmap_bin=str(fake_nmap), policy_engine=policy))
    assert frozen.status == "denied"
    assert "Freeze" in (frozen.error_message or "")


def test_network_audit_handler_and_capability_manifest(tmp_path: Path):
    assert NETWORK_AUDIT_CAPABILITY["capability"] == "scan.network_audit"
    assert NETWORK_AUDIT_CAPABILITY["action_class"] == "investigate"

    published = []

    class FakeBus:
        async def publish(self, ev):
            published.append(ev)

    fake_nmap = _make_fake_nmap(tmp_path)
    handler = build_network_audit_handler(event_bus=FakeBus(), nmap_bin=str(fake_nmap))
    out = asyncio.run(
        handler(
            {
                "capability": "scan.network_audit",
                "target": {"scope": "local", "identifier": "192.168.50.61"},
                "parameters": {"ip": "192.168.50.61", "mac": "5e:a7:49:18:14:8b", "profile": "quick"},
            },
            None,
        )
    )
    assert out["status"] == "completed"
    assert out["result"]["summary"]["high_count"] == 1
    assert len(published) == 1
    assert published[0].type == "scan.network_audit.completed"
