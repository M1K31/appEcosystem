"""Authorized LAN-only network service & exposure audit capability (`scan.network_audit`).

Provides a fail-closed, bounded, non-destructive `nmap` TCP service/version audit
strictly confined to RFC 1918 / loopback / link-local / ULA addresses. Registered on
the hub under `ecosystem_scan_agent` with `action_class="investigate"` so every run
passes through `PolicyEngine` (operator approval or signed scoped Restrictions-Off
grant, Freeze preemption, and tamper-evident audit logging).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import shutil
import signal
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable

from .command_handler import SCAN_PROVIDER_APP

logger = logging.getLogger("ecosystem.network_audit")

MAX_STDOUT_BYTES = 2 * 1024 * 1024  # 2 MiB bounded XML read
MAX_STDERR_BYTES = 64 * 1024  # 64 KiB bounded stderr read
DEFAULT_TIMEOUT_SECONDS = 90.0
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

_LAN_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# Defensive exposure heuristics for common open LAN services
_HIGH_RISK_PORTS: dict[int, tuple[str, str]] = {
    21: ("Cleartext FTP service exposed", "Disable FTP or migrate to SFTP/FTPS."),
    23: ("Cleartext Telnet service exposed", "Disable Telnet immediately and use SSH."),
    513: ("Legacy rlogin service exposed", "Disable rlogin and use SSH."),
    514: ("Legacy rsh/syslog TCP port exposed", "Restrict remote shell/syslog to authorized hosts."),
    2375: ("Unauthenticated Docker daemon TCP API exposed", "Bind Docker to unix socket or require TLS mTLS."),
    3389: ("RDP remote desktop exposed on LAN", "Restrict RDP with firewall rules and NLA/MFA."),
    5900: ("VNC / Screen Sharing exposed on LAN", "Restrict VNC to loopback/SSH tunnel or disable if unused."),
    6379: ("Redis service exposed on LAN", "Bind Redis to 127.0.0.1 and require authentication."),
    9200: ("Elasticsearch HTTP API exposed on LAN", "Bind to localhost or enable TLS + RBAC."),
    27017: ("MongoDB service exposed on LAN", "Bind MongoDB to localhost and enforce authentication."),
}

_MEDIUM_RISK_PORTS: dict[int, tuple[str, str]] = {
    80: ("Unencrypted HTTP service exposed", "Verify whether TLS (HTTPS) should be enforced."),
    139: ("NetBIOS session service exposed", "Disable legacy NetBIOS if SMBv3-only is sufficient."),
    161: ("SNMP service exposed", "Use SNMPv3 with authPriv or disable if unused."),
    445: ("SMB file sharing exposed on LAN", "Ensure SMB signing is enabled and guest access is disabled."),
    1433: ("MSSQL database port exposed", "Restrict database port to authorized application hosts."),
    3306: ("MySQL/MariaDB database port exposed", "Bind database to localhost unless remote access is required."),
    5432: ("PostgreSQL database port exposed", "Restrict PostgreSQL via pg_hba.conf and firewall rules."),
    8080: ("Unencrypted HTTP-alt service exposed", "Verify service authentication and consider TLS."),
}

NETWORK_AUDIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "ip": {"type": "string", "minLength": 2, "maxLength": 64},
        "mac": {"type": "string", "pattern": "^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"},
        "profile": {"type": "string", "enum": ["quick", "standard"]},
    },
    "required": ["ip"],
    "additionalProperties": False,
}

NETWORK_AUDIT_CAPABILITY: dict[str, Any] = {
    "schema_version": 1,
    "capability": "scan.network_audit",
    "version": 1,
    "description": (
        "Run an authorized, non-destructive LAN service and exposure audit (nmap -sT -sV) "
        "against a private RFC 1918 / link-local IP address."
    ),
    "provider": {
        "app": SCAN_PROVIDER_APP,
        "device_id": "hub-local",
    },
    "action_class": "investigate",
    "required_grant": "scan:network_audit",
    "inputs_schema": NETWORK_AUDIT_SCHEMA,
    "timeout_seconds": 120,
    "cancellable": True,
    "idempotent": True,
    "offline_behavior": "run_local",
}


def validate_lan_ip(raw_ip: str) -> str:
    """Validate and canonicalize a strict LAN-only IP address (fail-closed)."""
    if not isinstance(raw_ip, str):
        raise ValueError("Target IP must be a string")
    text = raw_ip.strip()
    if not text or "/" in text or any(ch.isspace() for ch in text):
        raise ValueError(f"Invalid target IP address: {raw_ip!r}")
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"Invalid IP literal: {raw_ip!r}") from exc

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if addr.is_unspecified or addr.is_multicast:
        raise ValueError(f"Refusing non-unicast target IP: {addr}")

    if not any(addr.version == net.version and addr in net for net in _LAN_NETWORKS):
        raise ValueError(
            f"Refusing non-LAN target IP {addr}; scan.network_audit is restricted to private LAN addresses"
        )
    return str(addr)


@dataclass
class OpenPort:
    port: int
    protocol: str
    service: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExposureFinding:
    severity: str  # high | medium | low
    port: int
    service: str
    title: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkAuditResult:
    audit_id: str
    target_ip: str
    mac_address: str | None
    profile: str
    status: str  # clean | findings | unreachable | denied | failed
    host_state: str = "unknown"
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    duration_seconds: float = 0.0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_service_exposures(ports: list[OpenPort]) -> list[ExposureFinding]:
    """Classify open ports into defensive exposure findings."""
    findings: list[ExposureFinding] = []
    for p in ports:
        if p.port in _HIGH_RISK_PORTS:
            title, rec = _HIGH_RISK_PORTS[p.port]
            findings.append(
                ExposureFinding(
                    severity="high",
                    port=p.port,
                    service=p.service or "unknown",
                    title=title,
                    recommendation=rec,
                )
            )
        elif p.port in _MEDIUM_RISK_PORTS:
            title, rec = _MEDIUM_RISK_PORTS[p.port]
            findings.append(
                ExposureFinding(
                    severity="medium",
                    port=p.port,
                    service=p.service or "unknown",
                    title=title,
                    recommendation=rec,
                )
            )
        else:
            banner = " ".join(x for x in (p.product, p.version) if x).strip()
            detail = f" ({banner})" if banner else ""
            findings.append(
                ExposureFinding(
                    severity="low",
                    port=p.port,
                    service=p.service or "unknown",
                    title=f"Open TCP/{p.port} ({p.service or 'unknown'}){detail}",
                    recommendation="Confirm this service is intentionally exposed on the LAN.",
                )
            )
    return findings


def parse_nmap_xml(xml_text: str) -> tuple[str, list[OpenPort]]:
    """Safely parse nmap XML output into (host_state, open_ports)."""
    if not xml_text or not xml_text.strip():
        return "unknown", []
    # Reject XML DOCTYPE/ENTITY declarations (fail-closed against XXE)
    upper_head = xml_text[:4096].upper()
    if "<!ENTITY" in upper_head:
        raise ValueError("Refusing XML payload containing ENTITY declarations")
    cleaned_xml = re.sub(r"<!DOCTYPE[^>]*>", "", xml_text, count=1, flags=re.IGNORECASE)
    root = ET.fromstring(cleaned_xml)

    host_el = root.find("host")
    if host_el is None:
        return "down", []
    status_el = host_el.find("status")
    host_state = status_el.get("state", "unknown") if status_el is not None else "unknown"

    ports: list[OpenPort] = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                port_num = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            proto = str(port_el.get("protocol") or "tcp")
            svc_el = port_el.find("service")
            service_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""
            ports.append(
                OpenPort(
                    port=port_num,
                    protocol=proto,
                    service=service_name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                )
            )
    ports.sort(key=lambda item: item.port)
    return host_state, ports


async def _read_bounded(stream: asyncio.StreamReader | None, limit: int) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    total = 0
    overflow = False
    while True:
        chunk = await stream.read(16384)
        if not chunk:
            break
        remaining = limit - total
        if remaining > 0:
            chunks.append(chunk[:remaining])
            total += min(len(chunk), remaining)
        if len(chunk) > remaining:
            overflow = True
            break
    return b"".join(chunks), overflow


async def _terminate_proc(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except Exception:
        pass


def _is_frozen(policy_engine: Any) -> bool:
    if policy_engine is None:
        return False
    try:
        state = policy_engine.export_state()
        return bool(state.get("frozen", False))
    except Exception:
        # Fail closed if policy state cannot be inspected
        return True


async def run_network_audit(
    target_ip: str,
    *,
    mac_address: str | None = None,
    profile: str = "quick",
    nmap_bin: str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    policy_engine: Any = None,
) -> NetworkAuditResult:
    """Execute a bounded, LAN-only nmap TCP service/version audit."""
    audit_id = uuid.uuid4().hex
    t0 = time.monotonic()
    clean_profile = str(profile or "quick").strip().lower()
    if clean_profile not in ("quick", "standard"):
        clean_profile = "quick"
    clean_mac = str(mac_address).strip().lower() if mac_address and MAC_RE.match(str(mac_address).strip()) else None

    if _is_frozen(policy_engine):
        return NetworkAuditResult(
            audit_id=audit_id,
            target_ip=str(target_ip or ""),
            mac_address=clean_mac,
            profile=clean_profile,
            status="denied",
            duration_seconds=round(time.monotonic() - t0, 2),
            error_message="Ecosystem Freeze is active; network audits are suspended.",
        )

    try:
        canon_ip = validate_lan_ip(target_ip)
    except ValueError as exc:
        return NetworkAuditResult(
            audit_id=audit_id,
            target_ip=str(target_ip or ""),
            mac_address=clean_mac,
            profile=clean_profile,
            status="denied",
            duration_seconds=round(time.monotonic() - t0, 2),
            error_message=str(exc),
        )

    exe = nmap_bin or shutil.which("nmap")
    if not exe:
        return NetworkAuditResult(
            audit_id=audit_id,
            target_ip=canon_ip,
            mac_address=clean_mac,
            profile=clean_profile,
            status="failed",
            duration_seconds=round(time.monotonic() - t0, 2),
            error_message="nmap binary is not installed on this host.",
        )

    addr = ipaddress.ip_address(canon_ip)
    cmd = [exe]
    if addr.version == 6:
        cmd.append("-6")
    if clean_profile == "standard":
        cmd.extend(["-sT", "-Pn", "-sV", "--top-ports", "1000", "-T4", "--max-retries", "2"])
    else:
        cmd.extend(["-sT", "-Pn", "-sV", "--version-light", "--top-ports", "100", "-T4", "--max-retries", "1"])
    cmd.extend(["-oX", "-", "--", canon_ip])

    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
        stdout_task = asyncio.create_task(_read_bounded(proc.stdout, MAX_STDOUT_BYTES))
        stderr_task = asyncio.create_task(_read_bounded(proc.stderr, MAX_STDERR_BYTES))
        try:
            (out_bytes, out_overflow), (err_bytes, _err_overflow) = await asyncio.wait_for(
                asyncio.gather(stdout_task, stderr_task),
                timeout=max(5.0, float(timeout_seconds)),
            )
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            stdout_task.cancel()
            stderr_task.cancel()
            await _terminate_proc(proc)
            return NetworkAuditResult(
                audit_id=audit_id,
                target_ip=canon_ip,
                mac_address=clean_mac,
                profile=clean_profile,
                status="failed",
                duration_seconds=round(time.monotonic() - t0, 2),
                error_message=f"Network audit timed out after {int(timeout_seconds)}s.",
            )
        except asyncio.CancelledError:
            stdout_task.cancel()
            stderr_task.cancel()
            await _terminate_proc(proc)
            raise

        if out_overflow:
            return NetworkAuditResult(
                audit_id=audit_id,
                target_ip=canon_ip,
                mac_address=clean_mac,
                profile=clean_profile,
                status="failed",
                duration_seconds=round(time.monotonic() - t0, 2),
                error_message="nmap XML output exceeded maximum allowed size.",
            )

        if proc.returncode != 0:
            logger.warning("nmap exited with rc=%s for %s", proc.returncode, canon_ip)
            return NetworkAuditResult(
                audit_id=audit_id,
                target_ip=canon_ip,
                mac_address=clean_mac,
                profile=clean_profile,
                status="failed",
                duration_seconds=round(time.monotonic() - t0, 2),
                error_message=f"nmap exited with code {proc.returncode}.",
            )

        host_state, open_ports = parse_nmap_xml(out_bytes.decode("utf-8", errors="replace"))
        findings = assess_service_exposures(open_ports)
        high_cnt = sum(1 for f in findings if f.severity == "high")
        med_cnt = sum(1 for f in findings if f.severity == "medium")
        low_cnt = sum(1 for f in findings if f.severity == "low")
        if host_state == "down":
            res_status = "unreachable"
        elif high_cnt > 0 or med_cnt > 0:
            res_status = "findings"
        else:
            res_status = "clean"

        return NetworkAuditResult(
            audit_id=audit_id,
            target_ip=canon_ip,
            mac_address=clean_mac,
            profile=clean_profile,
            status=res_status,
            host_state=host_state,
            open_ports=[p.to_dict() for p in open_ports],
            findings=[f.to_dict() for f in findings],
            summary={
                "open_port_count": len(open_ports),
                "high_count": high_cnt,
                "medium_count": med_cnt,
                "low_count": low_cnt,
            },
            duration_seconds=round(time.monotonic() - t0, 2),
        )
    except Exception as exc:
        if proc is not None and proc.returncode is None:
            await _terminate_proc(proc)
        logger.warning("Network audit error for %s: %r", canon_ip, exc)
        return NetworkAuditResult(
            audit_id=audit_id,
            target_ip=canon_ip,
            mac_address=clean_mac,
            profile=clean_profile,
            status="failed",
            duration_seconds=round(time.monotonic() - t0, 2),
            error_message="Network audit failed while processing scan results.",
        )


def build_network_audit_handler(
    *,
    policy_engine: Any = None,
    event_bus: Any = None,
    nmap_bin: str | None = None,
) -> Callable[[dict[str, Any], str | None], Awaitable[dict[str, Any]]]:
    """Build an in-hub local command handler for `scan.network_audit`."""

    async def _handle(
        record: dict[str, Any],
        authorization_ref: str | None = None,
    ) -> dict[str, Any]:
        params = dict(record.get("parameters") or {})
        target = record.get("target") or {}
        ip = str(params.get("ip") or (target.get("identifier") if isinstance(target, dict) else "") or "").strip()
        mac = params.get("mac")
        profile = str(params.get("profile") or "quick").strip().lower()

        res = await run_network_audit(
            ip,
            mac_address=str(mac) if mac else None,
            profile=profile,
            nmap_bin=nmap_bin,
            policy_engine=policy_engine,
        )
        payload = res.to_dict()

        if event_bus is not None and res.status in ("clean", "findings", "unreachable"):
            try:
                from events.schemas import EventEnvelope

                await event_bus.publish(
                    EventEnvelope(
                        type="scan.network_audit.completed",
                        source=SCAN_PROVIDER_APP,
                        data=payload,
                    )
                )
            except Exception as exc:
                logger.debug("Failed to publish scan.network_audit.completed event: %s", exc)

        if res.status == "denied":
            return {"status": "denied", "error": res.error_message or "Network audit denied", "result": payload}
        if res.status == "failed":
            return {"status": "failed", "error": res.error_message or "Network audit failed", "result": payload}
        return {"status": "completed", "result": payload}

    return _handle
