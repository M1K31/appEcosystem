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
