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
        "failed": [],
        "count": 2,
    }


def test_create_ai_scan_continues_through_partial_failure() -> None:
    """SCA-272 #35 [P2]: a mid-fan-out ApiError must not lose earlier scan_ids.

    Earlier asset creates have already burned AI quota and queued real
    scans server-side. Raising on the first error would lose those
    references; the agent could not watch or cancel them and a naive
    retry would create duplicates and double-spend quota. The wrapper
    captures per-asset failures and returns them alongside successes.
    """
    client = MagicMock()
    err = ApiError(503, "ai_scanner_unavailable")
    client.post.side_effect = [
        {"scan_id": "scan-1", "status": "queued"},
        err,
        {"scan_id": "scan-3", "status": "queued"},
    ]

    result = ai_scans.create_ai_scan(
        client, asset_ids=["asset-1", "asset-2", "asset-3"]
    )

    assert result["count"] == 2
    assert [r["asset_id"] for r in result["ai_scans"]] == ["asset-1", "asset-3"]
    assert len(result["failed"]) == 1
    failed = result["failed"][0]
    assert failed["asset_id"] == "asset-2"
    assert failed["status_code"] == 503
    assert "ai_scanner_unavailable" in failed["message"]


def test_create_ai_scan_full_failure_returns_only_failed() -> None:
    """All assets fail → empty ai_scans, full failed list, count==0."""
    client = MagicMock()
    client.post.side_effect = [
        ApiError(403, "ai_scans_quota_exceeded"),
        ApiError(403, "ai_scans_quota_exceeded"),
    ]

    result = ai_scans.create_ai_scan(client, asset_ids=["asset-1", "asset-2"])

    assert result["count"] == 0
    assert result["ai_scans"] == []
    assert len(result["failed"]) == 2
    assert all(f["status_code"] == 403 for f in result["failed"])


def test_get_ai_scan_report_synthesizes_from_unified_api() -> None:
    """SCA-272 #35 [P3]: severity breakdown comes from /findings/summary
    (server aggregates across all findings) rather than counting the first
    page of /scans/{id}/findings."""
    client = MagicMock()
    client.get.side_effect = [
        # 1) GET /scans/{id}
        {
            "scan_id": "scan-1",
            "scan_kind": "ai",
            "status": "completed",
            "started_at": "2026-04-27T00:00:00Z",
            "ended_at": "2026-04-27T00:30:00Z",
            "findings_count": 73,  # exceeds default per-page limit
        },
        # 2) GET /findings/summary?scan_id=scan-1 -- full aggregate
        {
            "total": 73,
            "open": 70,
            "triaged": 1,
            "resolved": 2,
            "open_by_severity": {"high": 12, "medium": 38, "low": 20},
        },
        # 3) GET /scans/{id}/findings (truncated key_findings)
        {
            "items": [
                {"finding_id": "f-1", "severity": "high"},
                {"finding_id": "f-2", "severity": "high"},
            ]
        },
    ]

    result = ai_scans.get_ai_scan_report(client, ai_scan_id="scan-1")

    assert client.get.call_count == 3
    client.get.assert_any_call("/scans/scan-1")
    client.get.assert_any_call("/findings/summary", params={"scan_id": "scan-1"})
    client.get.assert_any_call(
        "/scans/scan-1/findings",
        params={"scanner_type": "ai", "limit": 10},
    )
    assert result["scan_id"] == "scan-1"
    assert result["scan_kind"] == "ai"
    assert result["status"] == "completed"
    assert result["findings_count"] == 73
    # The breakdown reflects ALL 70 open findings, not just the 2 in
    # key_findings -- this is the regression guard for the [P3] issue.
    assert result["severity_breakdown"] == {"high": 12, "medium": 38, "low": 20}
    assert result["open_count"] == 70
    assert result["triaged_count"] == 1
    assert result["resolved_count"] == 2
    assert len(result["key_findings"]) == 2


def test_get_ai_scan_report_handles_missing_summary_payload() -> None:
    client = MagicMock()
    client.get.side_effect = [
        {"scan_id": "scan-1", "status": "running"},
        {},  # /findings/summary returns empty dict
        {},  # /findings returns empty dict
    ]

    result = ai_scans.get_ai_scan_report(client, ai_scan_id="scan-1")

    assert result["status"] == "running"
    assert result["severity_breakdown"] == {}
    assert result["key_findings"] == []
    assert result["open_count"] is None
    assert result["triaged_count"] is None


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
