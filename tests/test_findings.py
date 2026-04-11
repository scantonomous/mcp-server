"""Tests for finding tool helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from scantonomous_mcp.tools import findings


def test_list_findings_defaults_to_untriaged_without_scan_id() -> None:
    client = MagicMock()
    client.get.return_value = {"items": []}

    findings.list_findings(client)

    client.get.assert_called_once_with(
        "/findings",
        params={"limit": 25, "state": "untriaged"},
    )


def test_list_findings_does_not_default_state_when_scan_id_is_present() -> None:
    client = MagicMock()
    client.get.return_value = {"items": []}

    findings.list_findings(client, scan_id="scan-1")

    client.get.assert_called_once_with("/scans/scan-1/findings", params={"limit": 25})


def test_list_findings_passes_filters_through_to_api() -> None:
    client = MagicMock()
    client.get.return_value = {"items": []}

    findings.list_findings(
        client,
        severity="high",
        state="fixed",
        query="sql injection",
        limit=10,
    )

    client.get.assert_called_once_with(
        "/findings",
        params={
            "limit": 10,
            "severity": "high",
            "state": "fixed",
            "query": "sql injection",
        },
    )


def test_list_findings_resolves_source_repository_from_asset_id(
    monkeypatch,
) -> None:
    client = MagicMock()
    client.get.return_value = {"items": []}
    monkeypatch.setattr(
        findings,
        "_resolve_source_repository",
        lambda _client, _asset_id: "github:scantonomous/services",
    )

    findings.list_findings(client, asset_id="asset-1")

    client.get.assert_called_once_with(
        "/findings",
        params={
            "limit": 25,
            "state": "untriaged",
            "source_repository": "github:scantonomous/services",
        },
    )


def test_list_findings_returns_empty_result_when_asset_is_missing(monkeypatch) -> None:
    client = MagicMock()
    monkeypatch.setattr(findings, "_resolve_source_repository", lambda _client, _asset_id: None)

    result = findings.list_findings(client, asset_id="asset-404")

    client.get.assert_not_called()
    assert result == {
        "items": [],
        "total": 0,
        "message": "Asset asset-404 not found",
    }


def test_list_findings_prefers_scan_id_over_asset_lookup(monkeypatch) -> None:
    client = MagicMock()
    client.get.return_value = {"items": []}
    resolver = MagicMock(return_value="github:should/not/run")
    monkeypatch.setattr(findings, "_resolve_source_repository", resolver)

    findings.list_findings(client, scan_id="scan-1", asset_id="asset-1")

    resolver.assert_not_called()
    client.get.assert_called_once_with("/scans/scan-1/findings", params={"limit": 25})


def test_resolve_source_repository_returns_external_ref() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {
        "items": [
            {"asset_id": "asset-1", "external_ref": "github:scantonomous/services"},
            {"asset_id": "asset-2", "external_ref": "github:scantonomous/other"},
        ]
    }

    result = findings._resolve_source_repository(client, "asset-1")

    client.get.assert_called_once_with("/account/acct-123/assets", params={"limit": 100})
    assert result == "github:scantonomous/services"


def test_resolve_source_repository_returns_none_when_asset_is_missing() -> None:
    client = MagicMock()
    client.get_account_id.return_value = "acct-123"
    client.get.return_value = {"items": [{"asset_id": "asset-1", "external_ref": "github:one"}]}

    result = findings._resolve_source_repository(client, "asset-404")

    assert result is None


def test_get_finding_uses_finding_path() -> None:
    client = MagicMock()
    client.get.return_value = {"finding_id": "finding-1"}

    result = findings.get_finding(client, finding_id="finding-1")

    client.get.assert_called_once_with("/findings/finding-1")
    assert result == {"finding_id": "finding-1"}


def test_get_remediation_uses_remediation_path() -> None:
    client = MagicMock()
    client.get.return_value = {"fix": "use parameterized queries"}

    result = findings.get_remediation(client, finding_id="finding-1")

    client.get.assert_called_once_with("/findings/finding-1/remediation")
    assert result == {"fix": "use parameterized queries"}
