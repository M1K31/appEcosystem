"""Deployment-topology resolution shared by every ecosystem app.

The same code base runs in two shapes:

* ``local`` (default) — every service runs on one machine. Services bind to and
  are advertised on loopback (``127.0.0.1``). Nothing is exposed on the network;
  health checks and peer calls stay on the host.
* ``lan`` — services are spread across devices on a trusted LAN. Services bind to
  all interfaces (``0.0.0.0``) and are *advertised* on this host's real LAN IP so
  peers and the registry can reach them.

The critical distinction is **bind host** (where a server listens) vs **advertise
host** (the address other services should use to reach it). Conflating the two is
what made MagicMirror register as ``192.168.50.73`` while actually listening on
IPv6 ``::1`` — health checks then failed. Mode is selected with
``ECOSYSTEM_MODE=local|lan`` and individual values can always be overridden.
"""
from __future__ import annotations

import logging
import os
import socket

logger = logging.getLogger(__name__)

LOCAL = "local"
LAN = "lan"
_VALID_MODES = (LOCAL, LAN)

_LOOPBACK = "127.0.0.1"
_ALL_INTERFACES = "0.0.0.0"


def get_mode() -> str:
    """Return the deployment mode (``local`` or ``lan``); defaults to ``local``."""
    mode = os.environ.get("ECOSYSTEM_MODE", LOCAL).strip().lower()
    if mode not in _VALID_MODES:
        logger.warning("Unknown ECOSYSTEM_MODE=%r — falling back to %r", mode, LOCAL)
        return LOCAL
    return mode


def is_lan() -> bool:
    return get_mode() == LAN


def detect_lan_ip() -> str:
    """Best-effort detection of this host's primary LAN IPv4 address.

    Opens a UDP socket toward a public address (no packets are actually sent) and
    reads back the local address the OS would route through. Falls back to
    loopback when there is no usable route, so this never raises.
    """
    override = os.environ.get("ECOSYSTEM_ADVERTISE_HOST", "").strip()
    if override:
        return override
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    finally:
        sock.close()
    # No route off-box — fall back to a resolvable hostname address, then loopback.
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return _LOOPBACK


def bind_host() -> str:
    """Address a server should bind/listen on for the current mode.

    ``ECOSYSTEM_BIND_HOST`` overrides; otherwise loopback in local mode and all
    interfaces in LAN mode."""
    override = os.environ.get("ECOSYSTEM_BIND_HOST", "").strip()
    if override:
        return override
    return _ALL_INTERFACES if is_lan() else _LOOPBACK


def advertise_host() -> str:
    """Address peers/registry should use to reach this service.

    ``ECOSYSTEM_ADVERTISE_HOST`` overrides; otherwise loopback in local mode and
    the detected LAN IP in LAN mode."""
    override = os.environ.get("ECOSYSTEM_ADVERTISE_HOST", "").strip()
    if override:
        return override
    return detect_lan_ip() if is_lan() else _LOOPBACK


def is_loopback(host: str) -> bool:
    """True when ``host`` names this machine's loopback interface."""
    h = (host or "").strip().lower()
    return h in ("localhost", "127.0.0.1", "::1", "ip6-localhost")


def resolve_static_host(host: str) -> str:
    """Resolve a host from static config (e.g. ecosystem.yaml) for the current mode.

    Loopback placeholders in committed config are single-host defaults; in LAN
    mode a co-located static service should be advertised on the real LAN IP so
    other devices can reach it. Non-loopback hosts (an explicit remote address)
    are returned unchanged."""
    if is_lan() and is_loopback(host):
        return advertise_host()
    return host or _LOOPBACK
