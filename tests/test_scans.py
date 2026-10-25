"""Tests for scan tool helpers."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from scantonomous_mcp.client import ApiError
from scantonomous_mcp.tools import scans


def test_list_assets_maps_repo_path_and_asset_type() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "asset-1", "asset_type": "code_repository", "provider": "github",
             "repo_path": "scantonomous/services"},
            {"asset_id": "asset-2", "asset_type": "code_repository", "provider": "github",
             "name": "fallback-name"},
        ]
    }

    result = scans.list_assets(client, limit=10)

    client.get.assert_called_once_with("/account/acct-123/assets", params={"limit": 10})
    assert result == {
        "assets": [
            {"asset_id": "asset-1", "asset_type": "code_repository", "provider": "github",
             "repo_path": "scantonomous/services"},
            {"asset_id": "asset-2", "asset_type": "code_repository", "provider": "github",
             "repo_path": "fallback-name"},
        ]
    }


def test_list_assets_reports_provider_so_same_path_repos_are_distinguishable() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "gh-1", "asset_type": "code_repository", "provider": "github",
             "repo_path": "acme/app", "external_ref": "github:acme/app"},
            {"asset_id": "bb-1", "asset_type": "code_repository", "provider": "bitbucket",
             "repo_path": "acme/app",
             "external_ref": "bitbucket:b29b26c2-1a9f-4ea0-8e44-73fa0aa5f84c"},
        ]
    }

    result = scans.list_assets(client)

    assert [(a["asset_id"], a["provider"]) for a in result["assets"]] == [
        ("gh-1", "github"),
        ("bb-1", "bitbucket"),
    ]


def test_list_assets_derives_missing_provider_from_external_ref() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "legacy-1", "asset_type": "code_repository", "provider": "",
             "repo_path": "acme/old", "external_ref": "gitlab:acme/old"},
            {"asset_id": "legacy-2", "asset_type": "code_repository", "repo_path": "acme/odd"},
        ]
    }

    result = scans.list_assets(client)

    assert [a["provider"] for a in result["assets"]] == ["gitlab", ""]


def test_list_assets_omits_provider_for_web_endpoints() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "web-1", "asset_type": "web_endpoint", "provider": "",
             "external_ref": "web:https://shop.example.com:443", "scheme": "https",
             "fqdn": "shop.example.com", "port": 443},
        ]
    }

    result = scans.list_assets(client)

    assert "provider" not in result["assets"][0]


def test_list_assets_filters_by_query_because_the_api_returns_every_asset() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "bb-1", "asset_type": "code_repository", "provider": "bitbucket",
             "repo_path": "scntnms-demo/Space-Kitten-Mittens"},
            {"asset_id": "gh-1", "asset_type": "code_repository", "provider": "github",
             "repo_path": "acme/app"},
            {"asset_id": "named-1", "asset_type": "code_repository", "provider": "github",
             "name": "kitten-tools"},
            {"asset_id": "web-1", "asset_type": "web_endpoint", "scheme": "https",
             "fqdn": "kittens.example.com", "port": 443},
            {"asset_id": "web-2", "asset_type": "web_endpoint", "scheme": "https",
             "fqdn": "other.example.com", "port": 443},
        ]
    }

    result = scans.list_assets(client, query="KITTEN")

    client.get.assert_called_once_with(
        "/account/acct-123/assets", params={"limit": 25, "query": "KITTEN"}
    )
    assert [a["asset_id"] for a in result["assets"]] == ["bb-1", "named-1", "web-1"]


def test_list_assets_enforces_limit_after_filtering() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "web-1", "asset_type": "web_endpoint", "scheme": "https",
             "fqdn": "a.example.com", "port": 443},
            {"asset_id": "repo-1", "asset_type": "code_repository", "repo_path": "x/a"},
            {"asset_id": "repo-2", "asset_type": "code_repository", "repo_path": "x/b"},
            {"asset_id": "repo-3", "asset_type": "code_repository", "repo_path": "x/c"},
        ]
    }

    result = scans.list_assets(client, limit=2, kind="repo")

    assert [a["asset_id"] for a in result["assets"]] == ["repo-1", "repo-2"]


def test_list_assets_shapes_web_endpoint_fields() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "web-1", "asset_type": "web_endpoint", "scheme": "https",
             "fqdn": "shop.example.com", "port": 443,
             "effective_verification": "verified", "analysis_state": "analyzed"},
        ]
    }

    result = scans.list_assets(client)

    assert result == {
        "assets": [
            {"asset_id": "web-1", "asset_type": "web_endpoint", "repo_path": "",
             "origin": "https://shop.example.com:443",
             "verification_status": "verified", "analysis_state": "analyzed"},
        ]
    }


def test_list_assets_kind_filter_web_only() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "repo-1", "asset_type": "code_repository", "repo_path": "x/y"},
            {"asset_id": "web-1", "asset_type": "web_endpoint", "scheme": "https",
             "fqdn": "a.example.com", "port": 443,
             "effective_verification": "unverified", "analysis_state": "legacy"},
        ]
    }

    result = scans.list_assets(client, kind="web")

    assert [a["asset_id"] for a in result["assets"]] == ["web-1"]


def test_list_assets_kind_filter_repo_only() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "repo-1", "asset_type": "code_repository", "repo_path": "x/y"},
            {"asset_id": "web-1", "asset_type": "web_endpoint", "scheme": "https",
             "fqdn": "a.example.com", "port": 443,
             "effective_verification": "verified", "analysis_state": "analyzed"},
        ]
    }

    result = scans.list_assets(client, kind="repo")

    assert [a["asset_id"] for a in result["assets"]] == ["repo-1"]


def test_list_assets_kind_all_returns_both() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "repo-1", "asset_type": "code_repository", "repo_path": "x/y"},
            {"asset_id": "web-1", "asset_type": "web_endpoint", "scheme": "https",
             "fqdn": "a.example.com", "port": 443,
             "effective_verification": "verified", "analysis_state": "analyzed"},
        ]
    }

    result = scans.list_assets(client, kind="all")

    assert [a["asset_id"] for a in result["assets"]] == ["repo-1", "web-1"]


def test_list_assets_passes_instance_url_for_self_hosted_repositories() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "gl-com", "asset_type": "code_repository", "provider": "gitlab",
             "repo_path": "acme/app"},
            {"asset_id": "gl-self", "asset_type": "code_repository", "provider": "gitlab",
             "repo_path": "acme/app", "instance_url": "https://git.acme.example"},
        ]
    }

    result = scans.list_assets(client)

    assert "instance_url" not in result["assets"][0]
    assert result["assets"][1]["instance_url"] == "https://git.acme.example"


def test_list_assets_ignores_surrounding_whitespace_in_query() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "bb-1", "asset_type": "code_repository", "provider": "bitbucket",
             "repo_path": "scntnms-demo/space-kitten-mittens"},
        ]
    }

    result = scans.list_assets(client, query="  space-kitten-mittens\n")

    assert [a["asset_id"] for a in result["assets"]] == ["bb-1"]


def test_list_assets_falls_back_to_name_when_api_sends_empty_repo_path() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "legacy-1", "asset_type": "code_repository", "provider": "github",
             "repo_path": "", "name": "acme/old", "external_ref": "github:acme/old"},
            {"asset_id": "web-1", "asset_type": "web_endpoint", "repo_path": "",
             "name": "Old shop", "scheme": "https", "fqdn": "old.example.com", "port": 443},
        ]
    }

    result = scans.list_assets(client, query="old")

    assert [(a["asset_id"], a["repo_path"]) for a in result["assets"]] == [
        ("legacy-1", "acme/old"),
        ("web-1", ""),
    ]


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


def test_create_scan_with_scan_kind_dast_raises_not_yet_available() -> None:
    """dast scans are not yet executable (no consumer until SCA-422 Phase 3/4)."""
    client = MagicMock()

    with pytest.raises(ValueError, match="not yet available"):
        scans.create_scan(client, asset_id="asset-1", scan_kind="dast")

    client.post.assert_not_called()


def test_create_scan_with_scan_kind_recon_raises_not_yet_available() -> None:
    """recon scans are not yet executable (no consumer until SCA-422 Phase 3/4)."""
    client = MagicMock()

    with pytest.raises(ValueError, match="not yet available"):
        scans.create_scan(client, asset_id="asset-1", scan_kind="recon")

    client.post.assert_not_called()


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
