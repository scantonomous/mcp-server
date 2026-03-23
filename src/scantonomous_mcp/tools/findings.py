"""Finding tools: list_findings, get_finding, get_remediation."""

from __future__ import annotations

from typing import Any

from ..client import ScantonomousClient


def list_findings(
    client: ScantonomousClient,
    severity: str | None = None,
    state: str | None = None,
    query: str | None = None,
    scan_id: str | None = None,
    asset_id: str | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    """Search and filter security findings.

    :param severity: Filter by severity (critical, high, medium, low, info).
    :param state: Filter by state (untriaged, fixed, false_positive, accepted_risk,
        will_fix, duplicate, reopened). Defaults to ``untriaged`` to show
        unresolved findings first.
    :param query: Free-text search query.
    :param scan_id: Filter to findings from a specific scan.
    :param asset_id: Filter to findings for this asset/repository. Resolves
        the asset to its ``source_repository`` and queries OpenSearch
        directly. Ignored if ``scan_id`` is provided.
    :param limit: Maximum number of results (default 25).
    :returns: List of findings with summary info.
    """
    source_repository: str | None = None
    if asset_id and not scan_id:
        source_repository = _resolve_source_repository(client, asset_id)
        if not source_repository:
            return {"items": [], "total": 0, "message": f"Asset {asset_id} not found"}

    params: dict[str, Any] = {"limit": limit}
    if severity:
        params["severity"] = severity
    if state:
        params["state"] = state
    elif not scan_id:
        params["state"] = "untriaged"
    if query:
        params["query"] = query
    if source_repository:
        params["source_repository"] = source_repository

    if scan_id:
        return client.get(f"/scans/{scan_id}/findings", params=params)
    return client.get("/findings", params=params)


def _resolve_source_repository(client: ScantonomousClient, asset_id: str) -> str | None:
    """Resolve an asset ID to its source_repository identifier.

    Fetches the asset list and returns the ``external_ref`` field
    (e.g. ``"github:scantonomous/services"``), which matches the
    ``source_repository`` field in the findings OpenSearch index.

    :param client: API client.
    :param asset_id: The asset ID to look up.
    :returns: The source_repository string, or None if not found.
    """
    account_id = client.get_account_id()
    resp = client.get(f"/account/{account_id}/assets", params={"limit": 100})
    for asset in resp.get("items", []):
        if asset.get("asset_id") == asset_id:
            return asset.get("external_ref", "")
    return None


def get_finding(
    client: ScantonomousClient,
    finding_id: str,
) -> dict[str, Any]:
    """Get full finding details including code evidence.

    :param finding_id: The finding ID.
    :returns: Finding with title, description, severity, code evidence,
        file path, line numbers, and remediation guidance.
    """
    return client.get(f"/findings/{finding_id}")


def get_remediation(
    client: ScantonomousClient,
    finding_id: str,
) -> dict[str, Any]:
    """Get AI-generated remediation suggestion for a finding.

    :param finding_id: The finding ID.
    :returns: Remediation with suggested code fix, explanation, and
        confidence score.
    """
    return client.get(f"/findings/{finding_id}/remediation")
