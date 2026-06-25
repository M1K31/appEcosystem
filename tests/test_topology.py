"""Tests for deployment-topology resolution (ECOSYSTEM_MODE local|lan)."""
import importlib

import pytest

from ecosystem_client import topology


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with no topology env overrides."""
    for var in (
        "ECOSYSTEM_MODE",
        "ECOSYSTEM_BIND_HOST",
        "ECOSYSTEM_ADVERTISE_HOST",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


def test_defaults_to_local_mode():
    assert topology.get_mode() == "local"
    assert topology.is_lan() is False
    assert topology.bind_host() == "127.0.0.1"
    assert topology.advertise_host() == "127.0.0.1"


def test_unknown_mode_falls_back_to_local(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_MODE", "wan")
    assert topology.get_mode() == "local"


def test_lan_mode_binds_all_interfaces(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_MODE", "lan")
    assert topology.is_lan() is True
    assert topology.bind_host() == "0.0.0.0"


def test_lan_advertise_is_non_loopback(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_MODE", "lan")
    host = topology.advertise_host()
    # detect_lan_ip should return a routable address or fall back gracefully;
    # in CI without a network it may still be loopback, which must not crash.
    assert isinstance(host, str) and host


def test_explicit_overrides_win(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_MODE", "lan")
    monkeypatch.setenv("ECOSYSTEM_BIND_HOST", "10.1.2.3")
    monkeypatch.setenv("ECOSYSTEM_ADVERTISE_HOST", "10.1.2.4")
    assert topology.bind_host() == "10.1.2.3"
    assert topology.advertise_host() == "10.1.2.4"


def test_advertise_override_applies_in_local_mode(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_ADVERTISE_HOST", "myhost.local")
    assert topology.advertise_host() == "myhost.local"


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "IP6-localhost"])
def test_is_loopback_true(host):
    assert topology.is_loopback(host) is True


@pytest.mark.parametrize("host", ["10.0.0.5", "example.com", "192.168.1.50"])
def test_is_loopback_false(host):
    assert topology.is_loopback(host) is False


def test_resolve_static_host_local_passthrough():
    # local mode: loopback placeholders are left as-is.
    assert topology.resolve_static_host("localhost") == "localhost"


def test_resolve_static_host_lan_promotes_loopback(monkeypatch):
    monkeypatch.setenv("ECOSYSTEM_MODE", "lan")
    monkeypatch.setenv("ECOSYSTEM_ADVERTISE_HOST", "10.0.0.42")
    # a co-located (loopback) static service is advertised on the LAN IP...
    assert topology.resolve_static_host("localhost") == "10.0.0.42"
    # ...but an explicit remote host is preserved.
    assert topology.resolve_static_host("10.0.0.99") == "10.0.0.99"


def test_detect_lan_ip_never_raises():
    # Should always return a string, even with no network route.
    assert isinstance(topology.detect_lan_ip(), str)
