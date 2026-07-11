"""Tests for ecosystem CLI commands."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestProjectResolver:
    def test_resolve_project_paths(self):
        from cli.commands import _resolve_projects

        config = {
            "ecosystem": {"base_path": "/tmp/test"},
            "projects": {
                "myapp": {
                    "name": "MyApp",
                    "path": "my-app/backend",
                    "port": 8000,
                    "health_endpoint": "/health",
                    "start_command": "python main.py",
                },
            },
        }

        projects = _resolve_projects(config)
        assert len(projects) == 1
        assert projects[0]["key"] == "myapp"
        assert projects[0]["abs_path"] == Path("/tmp/test/my-app/backend")
        assert projects[0]["start_command"] == "python main.py"

    def test_resolve_projects_empty(self):
        from cli.commands import _resolve_projects

        config = {"ecosystem": {"base_path": "/tmp"}, "projects": {}}
        assert _resolve_projects(config) == []

    def test_base_path_env_override(self, monkeypatch):
        from cli.commands import _resolve_projects

        monkeypatch.setenv("ECOSYSTEM_BASE_PATH", "/opt/eco")
        config = {
            "ecosystem": {"base_path": "/ignored"},
            "projects": {"a": {"path": "a/b", "port": 1}},
        }
        assert _resolve_projects(config)[0]["abs_path"] == Path("/opt/eco/a/b")

    def test_base_path_defaults_to_repo_parent(self, monkeypatch):
        from cli import commands

        monkeypatch.delenv("ECOSYSTEM_BASE_PATH", raising=False)
        config = {"ecosystem": {"base_path": ""}, "projects": {"a": {"path": "x", "port": 1}}}
        expected = commands.ECOSYSTEM_DIR.parent / "x"
        assert commands._resolve_projects(config)[0]["abs_path"] == expected


class TestDeviceApps:
    """Per-device enabled-apps record (cmd_apps): presence from disk."""

    def _config(self, base):
        return {
            "ecosystem": {"base_path": str(base)},
            "projects": {
                "here": {"path": "here_app", "port": 9101},
                "elsewhere": {"path": "elsewhere_app", "port": 9102},
            },
        }

    def test_device_apps_marks_present_by_disk(self, tmp_path, monkeypatch):
        from cli import commands

        monkeypatch.delenv("ECOSYSTEM_BASE_PATH", raising=False)
        (tmp_path / "here_app").mkdir()  # installed locally; elsewhere_app absent
        monkeypatch.setattr(commands, "_load_config", lambda: self._config(tmp_path))

        apps = {a["key"]: a for a in commands._device_apps()}
        assert apps["here"]["present"] is True
        assert apps["elsewhere"]["present"] is False
        assert apps["here"]["port"] == 9101

    def test_cmd_apps_json_output(self, tmp_path, monkeypatch, capsys):
        import json
        from cli import commands

        (tmp_path / "here_app").mkdir()
        monkeypatch.setattr(commands, "_load_config", lambda: self._config(tmp_path))

        rc = commands.cmd_apps(as_json=True)
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        present = {d["key"]: d["present"] for d in data}
        assert present == {"here": True, "elsewhere": False}

    def test_cmd_apps_human_output(self, tmp_path, monkeypatch, capsys):
        from cli import commands

        (tmp_path / "here_app").mkdir()
        monkeypatch.setattr(commands, "_load_config", lambda: self._config(tmp_path))

        rc = commands.cmd_apps()
        out = capsys.readouterr().out
        assert rc == 0
        assert "1/2 present" in out
        assert "not installed here are expected on other" in out


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_check_health_healthy(self):
        from cli.commands import _check_health

        with patch("cli.commands.httpx") as mock_httpx:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_httpx.get.return_value = mock_resp

            result = await _check_health("localhost", 8000, "/health")
            assert result is True

    @pytest.mark.asyncio
    async def test_check_health_down(self):
        from cli.commands import _check_health

        with patch("cli.commands.httpx") as mock_httpx:
            mock_httpx.get.side_effect = Exception("Connection refused")

            result = await _check_health("localhost", 9999, "/health")
            assert result is False


class TestTerminatePid:
    def test_graceful_sigterm(self):
        """A process that exits on SIGTERM is not escalated to SIGKILL."""
        from cli import commands

        sent = []
        # Alive until SIGTERM is observed, then dead.
        state = {"alive": True}

        def fake_kill(pid, sig):
            sent.append(sig)
            if sig == commands.signal.SIGTERM:
                state["alive"] = False

        with patch("cli.commands.os.kill", side_effect=fake_kill), \
             patch("cli.commands._pid_alive", side_effect=lambda pid: state["alive"]):
            result = commands._terminate_pid(1234, "Reg", grace=1.0)

        assert commands.signal.SIGTERM in sent
        assert commands.signal.SIGKILL not in sent
        assert "stopped" in result

    def test_escalates_to_sigkill(self):
        """A process that ignores SIGTERM is force-killed."""
        from cli import commands

        sent = []
        with patch("cli.commands.os.kill", side_effect=lambda pid, sig: sent.append(sig)), \
             patch("cli.commands._pid_alive", return_value=True), \
             patch("cli.commands.time.sleep"):
            result = commands._terminate_pid(1234, "Reg", grace=0.5)

        assert commands.signal.SIGTERM in sent
        assert commands.signal.SIGKILL in sent
        assert "force-killed" in result

    def test_already_dead(self):
        """A missing process reports a stale PID without error."""
        from cli import commands

        with patch("cli.commands.os.kill", side_effect=ProcessLookupError):
            result = commands._terminate_pid(1234, "Reg", grace=0.5)

        assert "stale PID" in result


class TestStatusOutput:
    def test_format_status_line(self):
        from cli.commands import _format_status_line

        line = _format_status_line("MyApp", 8000, True)
        assert "MyApp" in line
        assert "8000" in line
        assert "HEALTHY" in line or "UP" in line

    def test_format_status_line_down(self):
        from cli.commands import _format_status_line

        line = _format_status_line("MyApp", 8000, False)
        assert "DOWN" in line


def test_partner_add_and_list(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    rc = cmd_partner("add", app_id="org.acme", name="Acme", owner="dev@acme",
                     service_names="acme_thermostat")
    assert rc == 0
    out = capsys.readouterr().out
    assert "org.acme" in out and "key_id" in out.lower() and "secret" in out.lower()

    rc = cmd_partner("list")
    assert rc == 0
    out = capsys.readouterr().out
    assert "org.acme" in out and "acme_thermostat" in out


def test_partner_add_rejects_reserved_name(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    rc = cmd_partner("add", app_id="org.evil", name="Evil", owner="e@x",
                     service_names="openeye")
    assert rc == 1
    assert "reserved" in capsys.readouterr().out.lower()


def test_partner_list_and_show_never_print_secret(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    cmd_partner("add", app_id="org.acme", name="Acme", owner="dev@acme",
                service_names="acme_thermostat")
    secret_line = [l for l in capsys.readouterr().out.splitlines() if "secret" in l.lower()]
    printed_secret = secret_line[0].split()[-1] if secret_line else "UNSET"
    cmd_partner("show", app_id="org.acme")
    cmd_partner("list")
    out = capsys.readouterr().out
    assert printed_secret not in out


def test_partner_suspend(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ECOSYSTEM_APPS_FILE", str(tmp_path / "apps.json"))
    from cli.commands import cmd_partner
    cmd_partner("add", app_id="org.acme", name="Acme", owner="dev@acme",
                service_names="acme_thermostat")
    capsys.readouterr()
    rc = cmd_partner("suspend", app_id="org.acme")
    assert rc == 0
    cmd_partner("show", app_id="org.acme")
    assert "suspended" in capsys.readouterr().out.lower()
