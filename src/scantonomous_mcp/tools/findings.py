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
    :param state: Filter by state (new, fixed, false_positive, accepted_risk).
        Defaults to ``new`` to show unresolved findings first.
    :param query: Free-text search query.
    :param scan_id: Filter to findings from a specific scan.
    :param asset_id: Filter to findings from the most recent completed scan
        of this asset. Ignored if ``scan_id`` is provided.
    :param limit: Maximum number of results (default 25).
    :returns: List of findings with summary info.
    """
    # If asset_id is provided (and no explicit scan_id), resolve to the
    # most recent completed scan for that asset.
    if asset_id and not scan_id:
        scan_id = _resolve_latest_scan(client, asset_id)
        if not scan_id:
            return {"findings": [], "message": f"No completed scans found for asset {asset_id}"}

    params: dict[str, Any] = {"limit": limit}
    if severity:
        params["severity"] = severity
    if state:
        params["state"] = state
    elif not scan_id:
        # Default to "new" only for account-wide queries. Scan-scoped
        # findings may not have a canonical state yet, so filtering by
        # state=new would hide them.
        params["state"] = "new"
    if query:
        params["query"] = query

    if scan_id:
        return client.get(f"/scans/{scan_id}/findings", params=params)
    return client.get("/findings", params=params)


def _resolve_latest_scan(client: ScantonomousClient, asset_id: str) -> str | None:
    """Find the most recent completed scan for an asset.

    :param client: API client.
    :param asset_id: The asset ID to look up.
    :returns: The scan_id of the most recent completed scan, or None.
    """
    resp = client.get("/scans", params={"limit": 50})
    scans = resp.get("scans", resp.get("items", []))
    for scan in scans:
        if scan.get("asset_id") == asset_id and scan.get("status") == "completed":
            return scan["scan_id"]
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
