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
