"""Tests for the CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import click
import pytest
from click.testing import CliRunner

from scantonomous_mcp import cli


def test_require_client_id_prefers_explicit_value(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = SimpleNamespace(obj={"client_id": "explicit-client", "stage": "beta"})
    get_default_client_id = MagicMock(return_value="default-client")
    monkeypatch.setattr(cli, "get_default_client_id", get_default_client_id)

    assert cli._require_client_id(ctx) == "explicit-client"
    get_default_client_id.assert_not_called()


def test_require_client_id_falls_back_to_stage_default(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = SimpleNamespace(obj={"client_id": None, "stage": "beta"})
    monkeypatch.setattr(cli, "get_default_client_id", lambda stage: f"{stage}-client")

    assert cli._require_client_id(ctx) == "beta-client"


def test_require_client_id_exits_when_missing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ctx = SimpleNamespace(obj={"client_id": None, "stage": "missing"})
    monkeypatch.setattr(cli, "get_default_client_id", lambda _stage: None)

    with pytest.raises(SystemExit) as exc_info:
        cli._require_client_id(ctx)

    assert exc_info.value.code == 1
    assert "No client ID configured for stage 'missing'" in capsys.readouterr().err


def test_kill_stale_servers_counts_killed_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.os, "getpid", lambda: 100)
    monkeypatch.setattr(
        cli.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout="100\n101\n102\n103\n"),
    )
    killed: list[int] = []

    def kill(pid: int, _signal: int) -> None:
        killed.append(pid)
        if pid == 102:
            raise ProcessLookupError("gone")
        if pid == 103:
            raise PermissionError("denied")

    monkeypatch.setattr(cli.os, "kill", kill)

    assert cli._kill_stale_servers() == 1
    assert killed == [101, 102, 103]


def test_kill_stale_servers_returns_zero_when_pgrep_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_pgrep(*_args, **_kwargs) -> None:
        raise FileNotFoundError("pgrep missing")

    monkeypatch.setattr(cli.subprocess, "run", missing_pgrep)

    assert cli._kill_stale_servers() == 0


def test_login_uses_default_prod_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    calls: dict[str, object] = {}

    class DummyManager:
        def __init__(self, client_id: str, stage: str) -> None:
            calls["init"] = {"client_id": client_id, "stage": stage}

        def login(self) -> None:
            calls["login"] = True

    monkeypatch.setattr(cli, "AuthManager", DummyManager)
    monkeypatch.setattr(cli, "_kill_stale_servers", lambda: 0)
    monkeypatch.setattr(cli, "get_default_client_id", lambda stage: f"{stage}-client")

    result = runner.invoke(cli.main, ["login"])

    assert result.exit_code == 0
    assert calls == {
        "init": {"client_id": "prod-client", "stage": "prod"},
        "login": True,
    }
    assert "Authenticated successfully." in result.output


def test_logout_constructs_auth_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    calls: dict[str, object] = {}

    class DummyManager:
        def __init__(self, client_id: str, stage: str) -> None:
            calls["init"] = {"client_id": client_id, "stage": stage}

        def logout(self) -> None:
            calls["logout"] = True

    monkeypatch.setattr(cli, "AuthManager", DummyManager)

    result = runner.invoke(cli.main, ["--stage", "beta", "--client-id", "explicit", "logout"])

    assert result.exit_code == 0
    assert calls == {
        "init": {"client_id": "explicit", "stage": "beta"},
        "logout": True,
    }
    assert "Logged out." in result.output


def test_status_reports_authenticated(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    class DummyManager:
        def __init__(self, client_id: str, stage: str) -> None:
            self.client_id = client_id
            self.stage = stage

        def get_access_token(self) -> str:
            return "token"

    monkeypatch.setattr(cli, "AuthManager", DummyManager)

    result = runner.invoke(cli.main, ["--client-id", "explicit", "status"])

    assert result.exit_code == 0
    assert "Authenticated." in result.output


def test_status_reports_auth_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()

    class DummyManager:
        def __init__(self, client_id: str, stage: str) -> None:
            self.client_id = client_id
            self.stage = stage

        def get_access_token(self) -> str:
            raise cli.AuthError("missing login")

    monkeypatch.setattr(cli, "AuthManager", DummyManager)

    result = runner.invoke(cli.main, ["--client-id", "explicit", "status"])

    assert result.exit_code == 1
    assert "Not authenticated: missing login" in result.output


def test_serve_creates_server_and_runs_stdio_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}

    class FakeServer:
        async def run(self, read_stream: str, write_stream: str, init_options: str) -> None:
            captured["run"] = {
                "read_stream": read_stream,
                "write_stream": write_stream,
                "init_options": init_options,
            }

        def create_initialization_options(self) -> str:
            return "init-options"

    class FakeStdioServer:
        async def __aenter__(self) -> tuple[str, str]:
            return ("read-stream", "write-stream")

        async def __aexit__(self, exc_type, exc, tb) -> bool:
            return False

    monkeypatch.setattr(cli, "get_default_client_id", lambda stage: f"{stage}-client")
    monkeypatch.setattr(
        "scantonomous_mcp.server.create_server",
        lambda client_id, stage: (
            captured.update({"create_server": {"client_id": client_id, "stage": stage}})
            or FakeServer()
        ),
    )
    monkeypatch.setattr("mcp.server.stdio.stdio_server", lambda: FakeStdioServer())

    result = runner.invoke(cli.main, ["serve"])

    assert result.exit_code == 0
    assert captured == {
        "create_server": {"client_id": "prod-client", "stage": "prod"},
        "run": {
            "read_stream": "read-stream",
            "write_stream": "write-stream",
            "init_options": "init-options",
        },
    }


def test_init_writes_global_config_without_explicit_client_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config_path = tmp_path / ".claude.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"existing": {"command": "existing", "args": ["serve"]}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_kill_stale_servers", lambda: 0)
    monkeypatch.setattr(cli, "get_default_client_id", lambda stage: f"{stage}-client")
    monkeypatch.setattr(cli.os.path, "expanduser", lambda _path: str(config_path))

    result = runner.invoke(cli.main, ["init"])

    assert result.exit_code == 0
    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert written == {
        "mcpServers": {
            "existing": {"command": "existing", "args": ["serve"]},
            "scantonomous": {
                "command": "scantonomous-mcp",
                "args": ["--stage", "prod", "serve"],
            },
        }
    }
    assert f"MCP server config written to {config_path}" in result.output
    assert "Restart Claude Code to pick up the new MCP server configuration." in result.output


def test_init_writes_local_config_with_explicit_client_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config_path = tmp_path / ".claude.json"
    config_path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_kill_stale_servers", lambda: 0)

    result = runner.invoke(
        cli.main,
        ["--stage", "beta", "--client-id", "explicit", "init", "--local"],
    )

    assert result.exit_code == 0
    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert written == {
        "foo": "bar",
        "mcpServers": {
            "scantonomous": {
                "command": "scantonomous-mcp",
                "args": ["--stage", "beta", "--client-id", "explicit", "serve"],
            }
        },
    }
