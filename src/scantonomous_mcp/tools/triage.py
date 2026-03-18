"""Triage tools: triage_finding, get_findings_summary."""

from __future__ import annotations

from typing import Any

from ..client import ScantonomousClient


def triage_finding(
    client: ScantonomousClient,
    finding_id: str,
    state: str,
    reason: str,
    ai_model: str,
) -> dict[str, Any]:
    """Record a triage decision on a finding.

    :param finding_id: The finding ID to triage.
    :param state: New state: ``fixed``, ``false_positive``, or ``accepted_risk``.
    :param reason: Explanation for the decision. Required for ``false_positive``
        and ``accepted_risk`` states.
    :param ai_model: The AI model performing the triage (e.g. "Claude Opus 4.6").
    :returns: Updated finding state.
    """
    body: dict[str, Any] = {
        "state": state,
        "reason": reason,
        "source": "mcp",
        "ai_model": ai_model,
    }
    return client.patch(f"/findings/{finding_id}/state", body=body)


def get_findings_summary(
    client: ScantonomousClient,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Get aggregate statistics for findings.

    :param scan_id: Optional scan ID to scope stats to a specific scan.
    :returns: Stats with severity and state breakdowns, total counts.
    """
    params: dict[str, Any] = {}
    if scan_id:
        params["scan_id"] = scan_id
    return client.get("/findings/stats", params=params)
