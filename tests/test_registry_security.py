"""Tests for registry bind-host and CORS hardening."""

import pytest

from registry.app import _cors_origins
from cli.commands import _registry_host


class TestCorsOrigins:
    def test_default_is_wildcard(self, monkeypatch):
        monkeypatch.delenv("ECOSYSTEM_CORS_ORIGINS", raising=False)
        assert _cors_origins() == ["*"]

    def test_explicit_wildcard(self, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_CORS_ORIGINS", "*")
        assert _cors_origins() == ["*"]

    def test_comma_separated_origins(self, monkeypatch):
        monkeypatch.setenv(
            "ECOSYSTEM_CORS_ORIGINS",
            "https://a.example.com, https://b.example.com",
        )
        assert _cors_origins() == [
            "https://a.example.com",
            "https://b.example.com",
        ]

    def test_blank_falls_back_to_wildcard(self, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_CORS_ORIGINS", "  ")
        assert _cors_origins() == ["*"]


class TestRegistryHost:
    def test_default_is_loopback(self, monkeypatch):
        monkeypatch.delenv("ECOSYSTEM_REGISTRY_HOST", raising=False)
        assert _registry_host({}) == "127.0.0.1"

    def test_config_host_used(self, monkeypatch):
        monkeypatch.delenv("ECOSYSTEM_REGISTRY_HOST", raising=False)
        assert _registry_host({"registry": {"host": "10.0.0.5"}}) == "10.0.0.5"

    def test_env_overrides_config(self, monkeypatch):
        monkeypatch.setenv("ECOSYSTEM_REGISTRY_HOST", "0.0.0.0")
        assert _registry_host({"registry": {"host": "10.0.0.5"}}) == "0.0.0.0"
