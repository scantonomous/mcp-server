"""Tests for web-scan tool helpers (SCA-422)."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from scantonomous_mcp.client import ApiError
from scantonomous_mcp.tools import web_scans


def test_create_dast_scan_posts_dast_kind() -> None:
    client = MagicMock()
    client.post.return_value = {"scan_id": "scan-1", "status": "queued"}

    result = web_scans.create_dast_scan(client, web_asset_id="web-1")

    client.post.assert_called_once_with(
        "/scans", body={"asset_id": "web-1", "scan_kind": "dast", "trigger_type": "mcp"}
    )
    assert result == {"scan_id": "scan-1", "status": "queued", "asset_id": "web-1"}


def test_create_dast_scan_empty_id_raises() -> None:
    client = MagicMock()
    with pytest.raises(ValueError, match="web_asset_id is required"):
        web_scans.create_dast_scan(client, web_asset_id="")
    client.post.assert_not_called()


@pytest.mark.parametrize(
    "message, status",
    [
        ("recon/dast scans require a web_endpoint asset", "wrong_asset_type"),
        ("web asset ownership must be verified before scanning", "not_verified"),
        ("DAST scanner is not available on this subscription tier", "tier_unavailable"),
    ],
)
def test_create_dast_scan_maps_policy_denials(message: str, status: str) -> None:
    client = MagicMock()
    client.post.side_effect = ApiError(403, message, payload={"message": message})

    result = web_scans.create_dast_scan(client, web_asset_id="web-1")

    assert result == web_scans._REJECTION_GUIDANCE[message]


def test_create_dast_scan_reraises_unknown_api_error() -> None:
    client = MagicMock()
    client.post.side_effect = ApiError(500, "boom", payload={"message": "boom"})

    with pytest.raises(ApiError, match="boom"):
        web_scans.create_dast_scan(client, web_asset_id="web-1")


def test_watch_dast_scan_returns_on_terminal() -> None:
    client = MagicMock()
    client.get.return_value = {"status": "completed", "scan_id": "scan-1"}

    result = asyncio.run(web_scans.watch_dast_scan(client, scan_id="scan-1"))

    client.get.assert_called_once_with("/scans/scan-1")
    assert result == {"status": "completed", "scan_id": "scan-1"}


def test_watch_dast_scan_surfaces_failure_error_code() -> None:
    client = MagicMock()
    client.get.return_value = {
        "status": "failed", "scan_id": "scan-1", "error_code": "dns_unresolved"
    }

    result = asyncio.run(web_scans.watch_dast_scan(client, scan_id="scan-1"))

    assert result["status"] == "failed"
    assert result["error_code"] == "dns_unresolved"


def test_watch_dast_scan_timeout_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.get.side_effect = [{"status": "running"}, {"status": "running"}]
    monkeypatch.setattr(web_scans.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(web_scans.random, "uniform", lambda _a, _b: 0.0)

    result = asyncio.run(web_scans.watch_dast_scan(client, scan_id="scan-1", timeout_minutes=1))

    assert result == {
        "status": "timeout",
        "message": "DAST scan did not complete within 1 minutes.",
        "last_known_status": "running",
        "scan_id": "scan-1",
    }
