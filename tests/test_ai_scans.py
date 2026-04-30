"""Tests for AI scan tool helpers (SCA-272 unified-API rewrite)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from scantonomous_mcp.client import ApiError
from scantonomous_mcp.tools import ai_scans


def test_create_ai_scan_raises_when_asset_ids_empty() -> None:
    client = MagicMock()

    with pytest.raises(ValueError, match="asset_ids"):
        ai_scans.create_ai_scan(client, asset_ids=[])

    client.post.assert_not_called()


def test_create_ai_scan_fans_out_per_asset() -> None:
    client = MagicMock()
    client.post.side_effect = [
        {"scan_id": "scan-1", "status": "queued"},
        {"scan_id": "scan-2", "status": "queued"},
    ]

    result = ai_scans.create_ai_scan(client, asset_ids=["asset-1", "asset-2"])

    assert client.post.call_count == 2
    client.post.assert_any_call(
        "/scans",
        body={"asset_id": "asset-1", "scan_kind": "ai", "trigger_type": "mcp"},
    )
    client.post.assert_any_call(
        "/scans",
        body={"asset_id": "asset-2", "scan_kind": "ai", "trigger_type": "mcp"},
    )
    assert result == {
        "ai_scans": [
            {"asset_id": "asset-1", "scan_id": "scan-1", "status": "queued"},
            {"asset_id": "asset-2", "scan_id": "scan-2", "status": "queued"},
        ],
        "count": 2,
    }


def test_create_ai_scan_propagates_api_error() -> None:
    client = MagicMock()
    client.post.side_effect = ApiError(503, "ai_scanner_unavailable")

    with pytest.raises(ApiError, match="ai_scanner_unavailable"):
        ai_scans.create_ai_scan(client, asset_ids=["asset-1"])


def test_get_ai_scan_report_synthesizes_from_unified_api() -> None:
    client = MagicMock()
    client.get.side_effect = [
        {
            "scan_id": "scan-1",
            "scan_kind": "ai",
            "status": "completed",
            "started_at": "2026-04-27T00:00:00Z",
            "ended_at": "2026-04-27T00:30:00Z",
            "findings_count": 3,
        },
        {
            "items": [
                {"finding_id": "f-1", "severity": "HIGH"},
                {"finding_id": "f-2", "severity": "high"},
                {"finding_id": "f-3", "severity": "medium"},
            ]
        },
    ]

    result = ai_scans.get_ai_scan_report(client, ai_scan_id="scan-1")

    assert client.get.call_count == 2
    client.get.assert_any_call("/scans/scan-1")
    client.get.assert_any_call(
        "/scans/scan-1/findings",
        params={"scanner_type": "ai", "limit": 50},
    )
    assert result["scan_id"] == "scan-1"
    assert result["scan_kind"] == "ai"
    assert result["status"] == "completed"
    assert result["started_at"] == "2026-04-27T00:00:00Z"
    assert result["ended_at"] == "2026-04-27T00:30:00Z"
    assert result["findings_count"] == 3
    assert result["severity_breakdown"] == {"high": 2, "medium": 1}
    assert len(result["key_findings"]) == 3


def test_get_ai_scan_report_handles_missing_findings_payload() -> None:
    client = MagicMock()
    client.get.side_effect = [
        {"scan_id": "scan-1", "status": "running"},
        {},
    ]

    result = ai_scans.get_ai_scan_report(client, ai_scan_id="scan-1")

    assert result["status"] == "running"
    assert result["severity_breakdown"] == {}
    assert result["key_findings"] == []


def test_watch_ai_scan_returns_immediately_for_terminal_status() -> None:
    client = MagicMock()
    client.get.return_value = {"status": "completed_partial", "scan_id": "scan-1"}

    result = asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="scan-1"))

    client.get.assert_called_once_with("/scans/scan-1")
    assert result == {"status": "completed_partial", "scan_id": "scan-1"}


def test_watch_ai_scan_treats_canceled_as_terminal() -> None:
    client = MagicMock()
    client.get.return_value = {"status": "canceled", "scan_id": "scan-1"}

    result = asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="scan-1"))

    client.get.assert_called_once_with("/scans/scan-1")
    assert result == {"status": "canceled", "scan_id": "scan-1"}


def test_watch_ai_scan_polls_until_terminal_status(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get.side_effect = [
        {"status": "queued"},
        {"status": "failed", "scan_id": "scan-1"},
    ]
    sleep = AsyncMock()
    monkeypatch.setattr(ai_scans.asyncio, "sleep", sleep)
    monkeypatch.setattr(ai_scans.random, "uniform", lambda _a, _b: 0.0)

    result = asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="scan-1", timeout_minutes=2))

    assert client.get.call_count == 2
    sleep.assert_awaited_once_with(30.0)
    assert result == {"status": "failed", "scan_id": "scan-1"}


def test_watch_ai_scan_propagates_api_errors() -> None:
    client = MagicMock()
    client.get.side_effect = ApiError(500, "boom")

    with pytest.raises(ApiError, match="boom"):
        asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="scan-1"))


def test_watch_ai_scan_returns_timeout_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get.side_effect = [{"status": "running"}, {"status": "running"}]
    sleep = AsyncMock()
    monkeypatch.setattr(ai_scans.asyncio, "sleep", sleep)
    monkeypatch.setattr(ai_scans.random, "uniform", lambda _a, _b: 0.0)

    result = asyncio.run(ai_scans.watch_ai_scan(client, ai_scan_id="scan-1", timeout_minutes=1))

    assert sleep.await_count == 2
    assert result == {
        "status": "timeout",
        "message": "AI scan did not complete within 1 minutes.",
        "last_known_status": "running",
        "scan_id": "scan-1",
    }
