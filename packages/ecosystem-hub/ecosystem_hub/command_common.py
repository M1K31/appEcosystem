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


_MAX_PARAMETER_DEPTH = 6
_UNINSPECTABLE = object()  # stands for "could not be shown to be internal"


def _url_host(value: str) -> str | None:
    """The host of a URL, or None when parsers could disagree about what the host is.

    Backslashes, whitespace, control characters and userinfo are how one parser
    is made to see an internal host while another connects to an external one;
    a URL carrying any of them is not trusted to name its own host.
    """
    if any(ch == "\\" or ch.isspace() or ord(ch) < 0x20 for ch in value):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if "@" in parts.netloc:
        return None
    return parts.hostname


def _is_address_literal(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


def _subject_values(parameters: Any, *, _key_is_subject: bool = False, _depth: int = 0) -> list[Any]:
    """Everything in the parameters that names a system the request could touch.

    Under a subject-bearing key (host, ip, url, indicator, ...) every value
    counts. Under any other key a value counts when it is itself an address or
    a URL. Nested objects and lists are walked; anything nested too deeply to
    inspect is reported as uninspectable, which callers treat as external.
    """
    if _depth > _MAX_PARAMETER_DEPTH:
        return [_UNINSPECTABLE]
    out: list[Any] = []
    if isinstance(parameters, dict):
        for key, value in parameters.items():
            subject_key = str(key).lower() in SUBJECT_PARAMETER_KEYS
            out.extend(_subject_values(value, _key_is_subject=subject_key, _depth=_depth + 1))
        return out
    if isinstance(parameters, (list, tuple)):
        for item in parameters:
            out.extend(_subject_values(item, _key_is_subject=_key_is_subject, _depth=_depth + 1))
        return out
    value = parameters
    if isinstance(value, str):
        if "://" in value or value.startswith("//"):
            host = _url_host(value)
            out.append(host if host else value)
        elif _key_is_subject or _is_address_literal(value):
            out.append(value)
    elif _key_is_subject and value is not None and not isinstance(value, bool):
        out.append(value)
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


# Passive lookups that policy files list by bare name. The alias applies only
# to exactly these capabilities, and only while they are registered as
# non-mutating; sharing a last segment with one earns nothing.
PASSIVE_LOOKUP_ALIASES = {"threat_intel.lookup_ioc": "lookup_ioc"}
NON_MUTATING_CLASSES = frozenset({"observe", "investigate"})


def policy_action(capability: str, action_class: str | None = None) -> str:
    """The action name the PolicyEngine evaluates for a capability.

    The capability id itself, so the engine's exact-name rules (its scan
    consent check matches "scan.request") see what they expect. The only
    exception is the explicit alias table above.
    """
    if action_class in NON_MUTATING_CLASSES and capability in PASSIVE_LOOKUP_ALIASES:
        return PASSIVE_LOOKUP_ALIASES[capability]
    return str(capability)
