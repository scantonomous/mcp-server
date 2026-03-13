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
    limit: int = 25,
) -> dict[str, Any]:
    """Search and filter security findings.

    :param severity: Filter by severity (critical, high, medium, low, info).
    :param state: Filter by state (new, fixed, false_positive, accepted_risk).
        Defaults to ``new`` to show unresolved findings first.
    :param query: Free-text search query.
    :param scan_id: Filter to findings from a specific scan.
    :param limit: Maximum number of results (default 25).
    :returns: List of findings with summary info.
    """
    params: dict[str, Any] = {"limit": limit}
    if severity:
        params["severity"] = severity
    if state:
        params["state"] = state
    else:
        params["state"] = "new"
    if query:
        params["query"] = query

    if scan_id:
        return client.get(f"/scans/{scan_id}/findings", params=params)
    return client.get("/findings", params=params)


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
