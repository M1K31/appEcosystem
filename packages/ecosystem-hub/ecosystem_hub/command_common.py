"""Pure helpers shared by the hub's command dispatcher and the provider-side receiver."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

FINAL_STATUSES = frozenset({"completed", "denied", "failed", "provider_unavailable"})
OPEN_STATUSES = frozenset({"received", "dispatching", "accepted", "pending_approval"})
MAX_JSON_BYTES = 64 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request_digest(capability: str, target: dict[str, Any], parameters: dict[str, Any]) -> str:
    """SHA-256 of what a command asks for; identical requests share a digest whatever their key order."""
    body = {"capability": capability, "target": target or {}, "parameters": parameters or {}}
    return hashlib.sha256(_canonical(body)).hexdigest()


def json_too_large(value: Any) -> bool:
    """True when `value` serialises to more than MAX_JSON_BYTES of compact JSON."""
    try:
        size = len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return True
    return size > MAX_JSON_BYTES


# ---- policy mapping ---------------------------------------------------------

# Action classes that reach into the subject's own system. For these a subject
# that is not provably on the owner's network is an external target.
TOUCHES_SUBJECT = frozenset({"investigate", "remediate", "system_change"})

TRIGGER_BY_ACTOR_TYPE = {
    "operator": "operator",
    "service": "service",
    "automation": "automation",
    "voice_intent": "voice",
    "ai_proposal": "ai_proposal",
}

_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
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
_INTERNAL_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal")
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def is_internal_subject(identifier: str | None) -> bool:
    """True only when the subject is provably on the owner's own network.

    Accepted: no subject at all; a strictly written IP address or CIDR that lies
    wholly inside private, loopback, link-local or unique-local space; a hostname
    under .local, .lan, .home.arpa or .internal. Everything else — public
    addresses, other hostnames, bare names, and the integer, hex and
    leading-zero spellings some tools resolve as addresses — is external.
    """
    if identifier is None:
        return True
    if not isinstance(identifier, str):
        return False
    value = identifier.strip()
    if not value:
        return True
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.version == 6 and net.prefixlen >= 96:
            mapped = net.network_address.ipv4_mapped
            if mapped is not None:
                net = ipaddress.ip_network(f"{mapped}/{net.prefixlen - 96}", strict=False)
        return any(net.version == allowed.version and net.subnet_of(allowed) for allowed in _INTERNAL_NETWORKS)
    host = value.lower().rstrip(".")
    return bool(_HOSTNAME_RE.match(host)) and host.endswith(_INTERNAL_SUFFIXES)


# Parameter names under which a request commonly names the system it will touch.
SUBJECT_PARAMETER_KEYS = frozenset({
    "host", "hosts", "hostname", "hostnames", "ip", "ips", "ip_address", "address", "addresses", "addr",
    "indicator", "indicators", "target", "targets", "url", "urls", "uri", "domain", "domains",
    "cidr", "network", "networks", "subnet", "endpoint",
})


def _subject_values(parameters: dict[str, Any] | None) -> list[Any]:
    """Values of the top-level parameters that name a system, with URLs reduced to their host."""
    out: list[Any] = []
    for key, value in (parameters or {}).items():
        if str(key).lower() not in SUBJECT_PARAMETER_KEYS:
            continue
        for item in value if isinstance(value, (list, tuple)) else [value]:
            if isinstance(item, str) and "://" in item:
                try:
                    item = urlsplit(item).hostname or item
                except ValueError:
                    pass
            out.append(item)
    return out


def policy_target(
    target: dict[str, Any],
    action_class: str,
    parameters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Translate a CommandEnvelope target into the target the PolicyEngine evaluates.

    For the classes that reach into the subject's own system, the target is
    external unless everything the request names is provably the owner's: the
    `target.identifier`, and any host, address, URL or network in the
    parameters. A request of those classes that names no subject at all (no
    identifier, no device id, nothing in the parameters) is external too —
    what it would touch cannot be shown to be the owner's.
    """
    target = target or {}
    out = {k: target[k] for k in ("scope", "device_id", "service", "identifier") if target.get(k) is not None}
    identifier = target.get("identifier")
    external_subject = identifier
    external = target.get("scope") == "external"
    if not external and action_class in TOUCHES_SUBJECT:
        named = _subject_values(parameters)
        if not is_internal_subject(identifier):
            external = True
        else:
            for value in named:
                if not is_internal_subject(value):
                    external, external_subject = True, value
                    break
        if not external and not identifier and not target.get("device_id") and not named:
            external = True
    if external:
        out["is_external"] = True
        out["kind"] = "external_ip"
        out["host"] = external_subject if isinstance(external_subject, str) else None
    return out


def actor_string(actor: dict[str, Any]) -> str:
    """The `app/id` actor string the PolicyEngine and the audit log use."""
    return f"{actor.get('app', 'unknown')}/{actor.get('id', 'unknown')}"


def policy_action(capability: str) -> str:
    """The action name the PolicyEngine evaluates: the capability's last segment.

    Policy files list bare action names (`lookup_ioc`, `block_ip`), so
    `threat_intel.lookup_ioc` is evaluated as `lookup_ioc`.
    """
    return str(capability).rsplit(".", 1)[-1]
