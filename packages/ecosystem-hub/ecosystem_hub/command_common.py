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


_BRACKETED_PORT_RE = re.compile(r"^\[([0-9A-Fa-f:.]+)\]:\d{1,5}$")
_PLAIN_PORT_RE = re.compile(r"^([^:\s]+):\d{1,5}$")


def _strip_port(value: str) -> str:
    """`host:port` and `[v6]:port` reduced to the host; anything else unchanged."""
    text = value.strip()
    match = _BRACKETED_PORT_RE.match(text) or _PLAIN_PORT_RE.match(text)
    return match.group(1) if match else text


def _subject_values(parameters: Any, *, _key_is_subject: bool = False, _depth: int = 0) -> list[Any]:
    """Everything in the parameters that names a system the request could touch.

    Under a subject-bearing key (host, ip, url, indicator, ...) every value
    counts. Under any other key a value counts when it is itself an address
    (with or without a port) or a URL; a hostname under an arbitrary key cannot
    be told from ordinary text, which is why a handler must take the system it
    touches from `target.identifier` or from a subject-bearing key. Nested
    objects and lists are walked, and everything inside a subject-bearing key
    stays a subject however deeply it is nested; anything nested too deeply to
    inspect is reported as uninspectable, which callers treat as external.
    """
    if _depth > _MAX_PARAMETER_DEPTH:
        return [_UNINSPECTABLE]
    out: list[Any] = []
    if isinstance(parameters, dict):
        for key, value in parameters.items():
            subject_key = _key_is_subject or str(key).lower() in SUBJECT_PARAMETER_KEYS
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
        else:
            bare = _strip_port(value)
            if _key_is_subject or _is_address_literal(bare):
                out.append(bare)
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

    The engine authorises an external target by its single `host`. When a
    request names more than one distinct external subject, `host` is None, so
    authorising one of them never covers another: the engine then allows only
    passive actions.
    """
    target = target or {}
    out = {k: target[k] for k in ("scope", "device_id", "service", "identifier") if target.get(k) is not None}
    identifier = target.get("identifier")
    externals: list[Any] = []
    external = target.get("scope") == "external"
    if action_class in TOUCHES_SUBJECT:
        named = _subject_values(parameters)
        candidates = ([identifier] if identifier not in (None, "") else []) + named
        externals = [v for v in candidates if not is_internal_subject(v)]
        if externals:
            external = True
        elif not identifier and not target.get("device_id") and not named:
            external = True
    if external:
        distinct = {v if isinstance(v, str) else repr(v) for v in externals}
        if len(distinct) > 1:
            host = None
        elif externals:
            host = externals[0] if isinstance(externals[0], str) else None
        else:
            host = identifier if isinstance(identifier, str) else None
        out["is_external"] = True
        out["kind"] = "external_ip"
        out["host"] = host
    return out


# ---- policy context ------------------------------------------------------------

# The hub forwards the policy context it evaluated with in this reserved
# parameter, so the provider's gate evaluates the same request. Callers may not
# set it; the receiver removes it before the handler sees the parameters.
POLICY_PARAMETER_KEY = "_policy"
# The only caller-supplied context the policy may see. Anything that could grant
# something (an approved data release, a budget flag) is not here.
CALLER_CONTEXT_KEYS = ("incident_id", "profile")
# A caller may only declare a trigger that makes the evaluation stricter.
RESTRICTIVE_TRIGGERS = frozenset({"schedule", "automation"})
_MAX_CONTEXT_VALUE = 128

# How long a provider remembers a command, and how long after its creation a
# command may still be sent. The gap leaves room for clock differences between
# hub and provider: past the window nothing is sent or run, because the
# provider could no longer tell a retry from a first attempt.
REPLAY_RETENTION_SECONDS = 24 * 3600
RETRY_WINDOW_SECONDS = 20 * 3600


def policy_context(actor: dict[str, Any], supplied: dict[str, Any] | None) -> dict[str, Any]:
    """The context both gates evaluate: the trigger and the whitelisted caller keys."""
    ctx: dict[str, Any] = {}
    supplied = supplied if isinstance(supplied, dict) else {}
    for key in CALLER_CONTEXT_KEYS:
        value = supplied.get(key)
        if isinstance(value, str) and value and len(value) <= _MAX_CONTEXT_VALUE:
            ctx[key] = value
    trigger = TRIGGER_BY_ACTOR_TYPE.get(str((actor or {}).get("type")), "service")
    if supplied.get("trigger") in RESTRICTIVE_TRIGGERS:
        trigger = supplied["trigger"]
    ctx["trigger"] = trigger
    return ctx


def split_policy_parameters(parameters: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Separate the handler's parameters from the forwarded policy context."""
    params = dict(parameters or {})
    supplied = params.pop(POLICY_PARAMETER_KEY, None)
    return params, supplied if isinstance(supplied, dict) else {}


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
