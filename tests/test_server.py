"""Tests for MCP server registration and dispatch."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

from mcp import types
from mcp.server.lowlevel.server import Server
import pytest

from scantonomous_mcp import server
from scantonomous_mcp.auth import AuthError
from scantonomous_mcp.client import ApiError


async def _list_tools(server_instance: Server) -> list[types.Tool]:
    handler = server_instance.request_handlers[types.ListToolsRequest]
    result = await handler(types.ListToolsRequest(method="tools/list"))
    return result.root.tools


async def _call_tool(
    server_instance: Server,
    name: str,
    arguments: dict[str, object],
) -> types.ServerResult:
    handler = server_instance.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    )
    return await handler(request)


def test_create_server_wires_auth_manager_and_client(monkeypatch) -> None:
    auth_instance = MagicMock()
    api_instance = MagicMock()
    auth_manager = MagicMock(return_value=auth_instance)
    client_ctor = MagicMock(return_value=api_instance)
    monkeypatch.setattr(server, "AuthManager", auth_manager)
    monkeypatch.setattr(server, "ScantonomousClient", client_ctor)

    result = server.create_server(client_id="client-123", stage="beta")

    auth_manager.assert_called_once_with(client_id="client-123", stage="beta")
    client_ctor.assert_called_once_with(auth_instance)
    assert isinstance(result, Server)


def test_create_server_registers_expected_tools_and_populates_cache() -> None:
    server_instance = server.create_server(client_id="client-123", stage="dev")

    tools = asyncio.run(_list_tools(server_instance))

    expected_names = [
        "list_assets",
        "create_scan",
        "get_scan",
        "watch_scan",
        "create_ai_scan",
        "get_ai_scan_report",
        "watch_ai_scan",
        "list_findings",
        "get_finding",
        "get_remediation",
        "triage_finding",
        "get_findings_summary",
    ]
    assert [tool.name for tool in tools] == expected_names
    assert sorted(server_instance._tool_cache) == sorted(expected_names)

    tools_by_name = {tool.name: tool for tool in tools}
    assert tools_by_name["create_scan"].inputSchema["required"] == ["asset_id"]
    assert tools_by_name["triage_finding"].inputSchema["required"] == ["state", "reason", "ai_model"]
    assert tools_by_name["triage_finding"].inputSchema["properties"]["finding_ids"]["maxItems"] == 25


def test_call_tool_returns_validation_error_for_missing_required_fields() -> None:
    server_instance = server.create_server(client_id="client-123", stage="dev")
    asyncio.run(_list_tools(server_instance))

    result = asyncio.run(_call_tool(server_instance, "create_scan", {}))

    assert result.root.isError is True
    assert result.root.content[0].text == "Input validation error: 'asset_id' is a required property"


def test_call_tool_formats_success_as_json(monkeypatch) -> None:
    server_instance = server.create_server(client_id="client-123", stage="dev")
    asyncio.run(_list_tools(server_instance))
    dispatch = AsyncMock(return_value={"status": "ok"})
    monkeypatch.setattr(server, "_dispatch_tool", dispatch)

    result = asyncio.run(_call_tool(server_instance, "get_scan", {"scan_id": "scan-1"}))

    assert result.root.isError is False
    assert result.root.content[0].text == json.dumps({"status": "ok"}, indent=2)
    assert dispatch.await_args.args[1:] == ("get_scan", {"scan_id": "scan-1"})


def test_call_tool_formats_auth_errors(monkeypatch) -> None:
    server_instance = server.create_server(client_id="client-123", stage="dev")
    asyncio.run(_list_tools(server_instance))
    monkeypatch.setattr(server, "_dispatch_tool", AsyncMock(side_effect=AuthError("expired")))

    result = asyncio.run(_call_tool(server_instance, "get_scan", {"scan_id": "scan-1"}))

    assert result.root.isError is False
    assert "Authentication required: expired" in result.root.content[0].text
    assert "scantonomous-mcp login" in result.root.content[0].text


def test_call_tool_formats_api_errors(monkeypatch) -> None:
    server_instance = server.create_server(client_id="client-123", stage="dev")
    asyncio.run(_list_tools(server_instance))
    monkeypatch.setattr(server, "_dispatch_tool", AsyncMock(side_effect=ApiError(403, "forbidden")))

    result = asyncio.run(_call_tool(server_instance, "get_scan", {"scan_id": "scan-1"}))

    assert result.root.isError is False
    assert result.root.content[0].text == "API error: API error 403: forbidden"


@pytest.mark.parametrize(
    ("tool_name", "target", "args", "expected_kwargs"),
    [
        ("list_assets", ("scans", "list_assets"), {"query": "repo"}, {"query": "repo", "limit": 25}),
        (
            "create_scan",
            ("scans", "create_scan"),
            {"asset_id": "asset-1"},
            {"asset_id": "asset-1", "ref": None},
        ),
        ("get_scan", ("scans", "get_scan"), {"scan_id": "scan-1"}, {"scan_id": "scan-1"}),
        (
            "watch_scan",
            ("scans", "watch_scan"),
            {"scan_id": "scan-1"},
            {"scan_id": "scan-1", "timeout_minutes": 30},
        ),
        (
            "create_ai_scan",
            ("ai_scans", "create_ai_scan"),
            {},
            {"asset_ids": None},
        ),
        (
            "get_ai_scan_report",
            ("ai_scans", "get_ai_scan_report"),
            {"ai_scan_id": "ai-1"},
            {"ai_scan_id": "ai-1"},
        ),
        (
            "watch_ai_scan",
            ("ai_scans", "watch_ai_scan"),
            {"ai_scan_id": "ai-1"},
            {"ai_scan_id": "ai-1", "timeout_minutes": 30},
        ),
        (
            "list_findings",
            ("findings", "list_findings"),
            {"severity": "high"},
            {
                "severity": "high",
                "state": None,
                "query": None,
                "scan_id": None,
                "asset_id": None,
                "limit": 25,
            },
        ),
        (
            "get_finding",
            ("findings", "get_finding"),
            {"finding_id": "finding-1"},
            {"finding_id": "finding-1"},
        ),
        (
            "get_remediation",
            ("findings", "get_remediation"),
            {"finding_id": "finding-1"},
            {"finding_id": "finding-1"},
        ),
        (
            "triage_finding",
            ("triage", "triage_finding"),
            {
                "state": "fixed",
                "reason": "done",
                "ai_model": "GPT-5.4",
                "finding_id": "finding-1",
            },
            {
                "state": "fixed",
                "reason": "done",
                "ai_model": "GPT-5.4",
                "finding_id": "finding-1",
                "finding_ids": None,
                "ecd": None,
                "approval_reference": None,
            },
        ),
        (
            "get_findings_summary",
            ("triage", "get_findings_summary"),
            {},
            {"scan_id": None},
        ),
    ],
)
def test_dispatch_tool_routes_to_correct_handler(
    monkeypatch,
    tool_name: str,
    target: tuple[str, str],
    args: dict[str, object],
    expected_kwargs: dict[str, object],
) -> None:
    api = MagicMock()
    module_name, function_name = target
    module = getattr(server, module_name)
    original = getattr(module, function_name)
    is_async = asyncio.iscoroutinefunction(original)
    mock = AsyncMock(return_value={"ok": True}) if is_async else MagicMock(return_value={"ok": True})
    monkeypatch.setattr(module, function_name, mock)

    result = asyncio.run(server._dispatch_tool(api, tool_name, args))

    assert result == {"ok": True}
    if is_async:
        mock.assert_awaited_once_with(api, **expected_kwargs)
    else:
        mock.assert_called_once_with(api, **expected_kwargs)


def test_dispatch_tool_returns_unknown_tool_error() -> None:
    api = MagicMock()

    result = asyncio.run(server._dispatch_tool(api, "unknown_tool", {}))

    assert result == {"error": "Unknown tool: unknown_tool"}
