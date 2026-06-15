"""Tests for scan tool helpers."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from scantonomous_mcp.client import ApiError
from scantonomous_mcp.tools import scans


def test_list_assets_builds_account_path_and_maps_repo_path() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "asset-1", "repo_path": "scantonomous/services"},
            {"asset_id": "asset-2", "name": "fallback-name"},
        ]
    }

    result = scans.list_assets(client, query="services", limit=10)

    client.get.assert_called_once_with(
        "/account/acct-123/assets",
        params={"limit": 10, "query": "services"},
    )
    assert result == {
        "assets": [
            {"asset_id": "asset-1", "repo_path": "scantonomous/services"},
            {"asset_id": "asset-2", "repo_path": "fallback-name"},
        ]
    }


def test_create_scan_sets_mcp_trigger_type() -> None:
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-1"}

    result = scans.create_scan(client, asset_id="asset-1")

    client.post.assert_called_once_with(
        "/scans",
        body={"asset_id": "asset-1", "trigger_type": "mcp"},
    )
    assert result == {"scan_id": "scan-1"}


def test_create_scan_includes_ref_when_provided() -> None:
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-1"}

    scans.create_scan(client, asset_id="asset-1", ref="feature/ref")

    client.post.assert_called_once_with(
        "/scans",
        body={"asset_id": "asset-1", "trigger_type": "mcp", "ref": "feature/ref"},
    )


def test_create_scan_with_scan_kind_dast_includes_scan_kind_in_body() -> None:
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-2"}

    result = scans.create_scan(client, asset_id="asset-1", scan_kind="dast")

    client.post.assert_called_once_with(
        "/scans",
        body={"asset_id": "asset-1", "trigger_type": "mcp", "scan_kind": "dast"},
    )
    assert result == {"scan_id": "scan-2"}


def test_create_scan_with_scan_kind_recon_includes_scan_kind_in_body() -> None:
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-3"}

    scans.create_scan(client, asset_id="asset-1", scan_kind="recon")

    client.post.assert_called_once_with(
        "/scans",
        body={"asset_id": "asset-1", "trigger_type": "mcp", "scan_kind": "recon"},
    )


def test_create_scan_with_scan_kind_standard_includes_scan_kind_in_body() -> None:
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-4"}

    scans.create_scan(client, asset_id="asset-1", scan_kind="standard")

    client.post.assert_called_once_with(
        "/scans",
        body={"asset_id": "asset-1", "trigger_type": "mcp", "scan_kind": "standard"},
    )


def test_create_scan_without_scan_kind_omits_scan_kind_from_body() -> None:
    """Back-compat: omitting scan_kind must produce the same body as before."""
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-1"}

    scans.create_scan(client, asset_id="asset-1")

    client.post.assert_called_once_with(
        "/scans",
        body={"asset_id": "asset-1", "trigger_type": "mcp"},
    )


def test_create_scan_invalid_scan_kind_raises_before_http_call() -> None:
    client = MagicMock()

    with pytest.raises(ValueError, match="bogus"):
        scans.create_scan(client, asset_id="asset-1", scan_kind="bogus")

    client.post.assert_not_called()


def test_create_scan_ai_scan_kind_rejected_before_http_call() -> None:
    """'ai' is not accepted by create_scan; callers must use create_ai_scan."""
    client = MagicMock()

    with pytest.raises(ValueError, match="ai"):
        scans.create_scan(client, asset_id="asset-1", scan_kind="ai")

    client.post.assert_not_called()


def test_get_scan_uses_scan_path() -> None:
    client = MagicMock()
    client.get.return_value = {"status": "completed"}

    result = scans.get_scan(client, scan_id="scan-1")

    client.get.assert_called_once_with("/scans/scan-1")
    assert result == {"status": "completed"}


def test_watch_scan_returns_immediately_for_terminal_status() -> None:
    client = MagicMock()
    client.get.return_value = {"status": "completed", "scan_id": "scan-1"}

    result = asyncio.run(scans.watch_scan(client, scan_id="scan-1"))

    client.get.assert_called_once_with("/scans/scan-1")
    assert result == {"status": "completed", "scan_id": "scan-1"}


def test_watch_scan_polls_until_terminal_status(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get.side_effect = [
        {"status": "queued"},
        {"status": "completed", "scan_id": "scan-1"},
    ]
    sleep = AsyncMock()
    monkeypatch.setattr(scans.asyncio, "sleep", sleep)
    monkeypatch.setattr(scans.random, "uniform", lambda _a, _b: 0.0)

    result = asyncio.run(scans.watch_scan(client, scan_id="scan-1", timeout_minutes=2))

    assert client.get.call_count == 2
    sleep.assert_awaited_once_with(30.0)
    assert result == {"status": "completed", "scan_id": "scan-1"}


def test_watch_scan_propagates_api_errors() -> None:
    client = MagicMock()
    client.get.side_effect = ApiError(500, "boom")

    with pytest.raises(ApiError, match="boom"):
        asyncio.run(scans.watch_scan(client, scan_id="scan-1"))


def test_watch_scan_returns_timeout_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get.side_effect = [{"status": "running"}, {"status": "running"}]
    sleep = AsyncMock()
    monkeypatch.setattr(scans.asyncio, "sleep", sleep)
    monkeypatch.setattr(scans.random, "uniform", lambda _a, _b: 0.0)

    result = asyncio.run(scans.watch_scan(client, scan_id="scan-1", timeout_minutes=1))

    assert sleep.await_count == 2
    assert result == {
        "status": "timeout",
        "message": "Scan did not complete within 1 minutes.",
        "last_known_status": "running",
        "scan_id": "scan-1",
    }
