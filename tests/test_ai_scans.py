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


@pytest.mark.skip(
    reason="SCA-299: cap is 1 while SCA-298 (cross-repo LLM analysis) is in flight; "
    "the single-asset list shape is covered by "
    "test_create_ai_scan_single_asset_uses_list_shape. Re-enable when the cap returns to 5."
)
def test_create_ai_scan_sends_one_request_with_asset_ids_list() -> None:
    """SCA-280: a single multi-repo POST replaces the legacy per-asset fan-out.

    The server-side ``scan_authorize_consume_batch`` policy validates
    1..5 asset_ids atomically and consumes one quota slot total. The
    MCP wrapper sends one request and returns one scan_id.
    """
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-1", "status": "queued"}

    result = ai_scans.create_ai_scan(client, asset_ids=["asset-1", "asset-2", "asset-3"])

    # Single POST with full asset_ids list (not N POSTs).
    client.post.assert_called_once_with(
        "/scans",
        body={
            "asset_ids": ["asset-1", "asset-2", "asset-3"],
            "scan_kind": "ai",
            "trigger_type": "mcp",
        },
    )
    assert result == {
        "scan_id": "scan-1",
        "asset_ids": ["asset-1", "asset-2", "asset-3"],
        "status": "queued",
        "count": 3,
    }


def test_create_ai_scan_single_asset_uses_list_shape() -> None:
    """A single asset still goes through the asset_ids list shape.

    The server's discriminator routing requires ``asset_ids`` (not
    ``asset_id``) for AI scans. Wrapping the lone asset in a list keeps
    the contract uniform.
    """
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-solo", "status": "queued"}

    result = ai_scans.create_ai_scan(client, asset_ids=["only-asset"])

    client.post.assert_called_once_with(
        "/scans",
        body={
            "asset_ids": ["only-asset"],
            "scan_kind": "ai",
            "trigger_type": "mcp",
        },
    )
    assert result["scan_id"] == "scan-solo"
    assert result["asset_ids"] == ["only-asset"]
    assert result["count"] == 1


def test_create_ai_scan_rejects_more_than_one_asset() -> None:
    """SCA-299: cap is 1 while SCA-298 (cross-repo LLM analysis) is in flight.

    Server-side handler enforces the same cap; client-side validation
    saves a network round-trip for a deterministic-failure case.
    Returns to 5 once SCA-298 ships.
    """
    client = MagicMock()
    too_many = [f"asset-{i}" for i in range(2)]

    with pytest.raises(ValueError, match="at most 1"):
        ai_scans.create_ai_scan(client, asset_ids=too_many)

    client.post.assert_not_called()


def test_create_ai_scan_rejects_duplicate_asset_ids() -> None:
    """Duplicates are validated client-side."""
    client = MagicMock()

    with pytest.raises(ValueError, match="unique"):
        ai_scans.create_ai_scan(client, asset_ids=["asset-1", "asset-1", "asset-2"])

    client.post.assert_not_called()


def test_create_ai_scan_propagates_server_error() -> None:
    """ApiError from the server (e.g. tier denial, suspended account)
    bubbles up unchanged so the agent can show the user the precise
    reason. The legacy fan-out semantics that swallowed errors into a
    `failed` array no longer apply — there's only one server call.
    """
    client = MagicMock()
    client.post.side_effect = ApiError(403, "ai_scanner_not_in_tier")

    with pytest.raises(ApiError) as exc:
        ai_scans.create_ai_scan(client, asset_ids=["asset-1"])

    assert exc.value.status_code == 403
    assert "ai_scanner_not_in_tier" in str(exc.value)


def test_create_ai_scan_preserves_batch_policy_payload_on_denial() -> None:
    """SCA-280 review: structured fields from the batch policy denial
    response (denied_asset_id, quota) must survive the ApiError boundary.

    The batch action returns shapes like::

        {"message": "asset asset-2 is inactive",
         "denied_asset_id": "asset-2"}

    Without preserving the full payload, the agent only sees a generic
    text message and can't tell which asset to remove. With
    ``ApiError.payload`` populated, the agent can surface the precise
    failing asset.
    """
    client = MagicMock()
    denial_payload = {
        "message": "asset asset-1 is inactive",
        "denied_asset_id": "asset-1",
    }
    client.post.side_effect = ApiError(
        403,
        "asset asset-1 is inactive",
        payload=denial_payload,
    )

    with pytest.raises(ApiError) as exc:
        ai_scans.create_ai_scan(client, asset_ids=["asset-1"])

    assert exc.value.status_code == 403
    # Structured fields survive — the agent can read denied_asset_id.
    assert exc.value.payload == denial_payload
    assert exc.value.payload["denied_asset_id"] == "asset-1"


def test_create_ai_scan_preserves_quota_exceeded_payload() -> None:
    """Quota-exceeded denials carry a ``quota`` snapshot the agent can
    surface so the user knows their current usage."""
    client = MagicMock()
    quota_payload = {
        "message": "AI scan quota exceeded (10/10)",
        "quota": {
            "ai_scan_limit": 10,
            "ai_scans_used": 10,
            "subscription_period_end": "2026-06-01T00:00:00Z",
        },
    }
    client.post.side_effect = ApiError(
        403,
        "AI scan quota exceeded (10/10)",
        payload=quota_payload,
    )

    with pytest.raises(ApiError) as exc:
        ai_scans.create_ai_scan(client, asset_ids=["asset-1"])

    assert exc.value.payload == quota_payload
    assert exc.value.payload["quota"]["ai_scans_used"] == 10


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
