"""SCA-514: a scanner observation id is refused before any API call.

A finding's ``evidence`` used to carry the scanner's per-detection id,
``scntnms:finding:<uuid4>``. An agent passed it to ``get_finding`` and the API refused
it for its length ("id must be at most 28 characters"), which named neither id. Every
tool that takes a finding id now says which id it wants instead.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import MagicMock

import pytest
from mcp import types
from mcp.server.lowlevel.server import Server

from scantonomous_mcp import server
from scantonomous_mcp.tools import findings, triage

FINDING_ID = "fnd_" + uuid.uuid4().hex[:24]
MESSAGE = "scanner observation id"


async def _call_tool(
    server_instance: Server, name: str, arguments: dict[str, object]
) -> types.CallToolResult:
    handler = server_instance.request_handlers[types.CallToolRequest]
    request = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    )
    result = await handler(request)
    assert isinstance(result.root, types.CallToolResult)
    return result.root


async def _list_tools(server_instance: Server) -> list[types.Tool]:
    handler = server_instance.request_handlers[types.ListToolsRequest]
    result = await handler(types.ListToolsRequest(method="tools/list"))
    assert isinstance(result.root, types.ListToolsResult)
    return result.root.tools


def _observation_id() -> str:
    return f"scntnms:finding:{uuid.uuid4()}"


def _client() -> MagicMock:
    client = MagicMock()
    client.get.return_value = {}
    client.patch.return_value = {}
    return client


def _assert_refused(client: MagicMock, excinfo: pytest.ExceptionInfo[ValueError]) -> None:
    message = str(excinfo.value)
    assert MESSAGE in message
    assert "finding_id field" in message
    assert "fnd_" in message
    client.get.assert_not_called()
    client.patch.assert_not_called()


def test_get_finding_refuses_an_observation_id() -> None:
    client = _client()
    with pytest.raises(ValueError, match=MESSAGE) as excinfo:
        findings.get_finding(client, finding_id=_observation_id())
    _assert_refused(client, excinfo)


def test_get_remediation_refuses_an_observation_id() -> None:
    client = _client()
    with pytest.raises(ValueError, match=MESSAGE) as excinfo:
        findings.get_remediation(client, finding_id=_observation_id())
    _assert_refused(client, excinfo)


def test_triage_finding_refuses_an_observation_id() -> None:
    client = _client()
    with pytest.raises(ValueError, match=MESSAGE) as excinfo:
        triage.triage_finding(
            client,
            state="fixed",
            reason="Fixed",
            ai_model="Claude Opus 4.7",
            finding_id=_observation_id(),
        )
    _assert_refused(client, excinfo)


def test_triage_finding_batch_refuses_an_observation_id_before_any_write() -> None:
    client = _client()
    with pytest.raises(ValueError, match=MESSAGE) as excinfo:
        triage.triage_finding(
            client,
            state="fixed",
            reason="Fixed",
            ai_model="Claude Opus 4.7",
            finding_ids=[FINDING_ID, _observation_id()],
        )
    _assert_refused(client, excinfo)
    assert "finding_ids[1]" in str(excinfo.value)


def test_set_finding_label_refuses_an_observation_id() -> None:
    client = _client()
    with pytest.raises(ValueError, match=MESSAGE) as excinfo:
        triage.set_finding_label(client, finding_id=_observation_id(), label="Exploitable")
    _assert_refused(client, excinfo)


def test_a_finding_id_still_reaches_the_api() -> None:
    client = _client()
    findings.get_finding(client, finding_id=FINDING_ID)
    client.get.assert_called_once_with(f"/findings/{FINDING_ID}")


def test_get_finding_tool_call_returns_the_error_to_the_agent(monkeypatch) -> None:
    api = _client()
    monkeypatch.setattr(server, "ScantonomousClient", MagicMock(return_value=api))
    monkeypatch.setattr(server, "AuthManager", MagicMock())
    server_instance = server.create_server(client_id="client-123", stage="dev")

    result = asyncio.run(
        _call_tool(server_instance, "get_finding", {"finding_id": _observation_id()})
    )

    assert result.isError is True
    content = result.content[0]
    assert isinstance(content, types.TextContent)
    text = content.text
    assert MESSAGE in text
    assert "fnd_" in text
    api.get.assert_not_called()


@pytest.mark.parametrize(
    ("tool", "properties"),
    [
        ("get_finding", ("finding_id",)),
        ("get_remediation", ("finding_id",)),
        ("triage_finding", ("finding_id", "finding_ids")),
        ("set_finding_label", ("finding_id",)),
    ],
)
def test_tool_schemas_name_the_finding_id_field(tool: str, properties: tuple[str, ...]) -> None:
    server_instance = server.create_server(client_id="client-123", stage="dev")
    listed = asyncio.run(_list_tools(server_instance))
    schema = {t.name: t for t in listed}[tool].inputSchema["properties"]
    for name in properties:
        description = schema[name]["description"]
        assert "finding_id field" in description
        assert "fnd_" in description
