"""Tests for AI scan tool helpers."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from scantonomous_mcp.client import ApiError
from scantonomous_mcp.tools import ai_scans


def test_create_ai_scan_omits_asset_ids_when_not_provided() -> None:
    client = MagicMock()
    client.post.return_value = {"ai_scan_id": "ai-1"}

    result = ai_scans.create_ai_scan(client)

    client.post.assert_called_once_with("/ai-scans", body={})
    assert result == {"ai_scan_id": "ai-1"}


def test_create_ai_scan_includes_asset_ids_when_provided() -> None:
    client = MagicMock()
    client.post.return_value = {"ai_scan_id": "ai-1"}

    ai_scans.create_ai_scan(client, asset_ids=["asset-1", "asset-2"])

    client.post.assert_called_once_with(
        "/ai-scans",
        body={"asset_ids": ["asset-1", "asset-2"]},
    )


def test_get_ai_scan_report_uses_report_path() -> None:
    client = MagicMock()
    client.get.return_value = {"report": "ok"}

    result = ai_scans.get_ai_scan_report(client, ai_scan_id="ai-1")

    client.get.assert_called_once_with("/ai-scans/ai-1/report")
    assert result == {"report": "ok"}


def test_watch_ai_scan_returns_immediately_for_terminal_status() -> None:
    client = MagicMock()
    client.get.return_value = {"status": "completed_partial", "ai_scan_id": "ai-1"}

    result = asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="ai-1"))

    client.get.assert_called_once_with("/ai-scans/ai-1")
    assert result == {"status": "completed_partial", "ai_scan_id": "ai-1"}


def test_watch_ai_scan_polls_until_terminal_status(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get.side_effect = [
        {"status": "queued"},
        {"status": "failed", "ai_scan_id": "ai-1"},
    ]
    sleep = AsyncMock()
    monkeypatch.setattr(ai_scans.asyncio, "sleep", sleep)
    monkeypatch.setattr(ai_scans.random, "uniform", lambda _a, _b: 0.0)

    result = asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="ai-1", timeout_minutes=2))

    assert client.get.call_count == 2
    sleep.assert_awaited_once_with(30.0)
    assert result == {"status": "failed", "ai_scan_id": "ai-1"}


def test_watch_ai_scan_propagates_api_errors() -> None:
    client = MagicMock()
    client.get.side_effect = ApiError(500, "boom")

    with pytest.raises(ApiError, match="boom"):
        asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="ai-1"))


def test_watch_ai_scan_returns_timeout_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get.side_effect = [{"status": "running"}, {"status": "running"}]
    sleep = AsyncMock()
    monkeypatch.setattr(ai_scans.asyncio, "sleep", sleep)
    monkeypatch.setattr(ai_scans.random, "uniform", lambda _a, _b: 0.0)

    result = asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="ai-1", timeout_minutes=1))

    assert sleep.await_count == 2
    assert result == {
        "status": "timeout",
        "message": "AI scan did not complete within 1 minutes.",
        "last_known_status": "running",
        "ai_scan_id": "ai-1",
    }
