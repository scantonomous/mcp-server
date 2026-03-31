"""Triage tools: triage_finding, get_findings_summary."""

from __future__ import annotations

from typing import Any

from ..client import ApiError, ScantonomousClient

MAX_BATCH_SIZE = 25


def triage_finding(
    client: ScantonomousClient,
    state: str,
    reason: str,
    ai_model: str,
    finding_id: str | None = None,
    finding_ids: list[str] | None = None,
    ecd: str | None = None,
) -> dict[str, Any]:
    """Record a triage decision on one or more findings.

    Supply either ``finding_id`` (single) or ``finding_ids`` (batch, up to 25).

    :param state: New state: ``fixed``, ``false_positive``, ``accepted_risk``,
        ``will_fix``, or ``duplicate``.
    :param reason: Explanation for the decision.
    :param ai_model: The AI model performing the triage (e.g. "Claude Opus 4.6").
    :param finding_id: A single finding ID to triage.
    :param finding_ids: A list of finding IDs to triage with the same state/reason.
    :param ecd: Expected completion date (YYYY-MM-DD). Required when state is
        ``will_fix``. Must be a future date within the severity-based SLA limit.
    :returns: For single: the updated finding state. For batch: a summary with
        succeeded/failed counts and per-finding results.
    """
    ids = _resolve_finding_ids(finding_id, finding_ids)

    body: dict[str, Any] = {
        "state": state,
        "reason": reason,
        "source": "mcp",
        "ai_model": ai_model,
    }
    if ecd:
        if state == "accepted_risk":
            body["ecd_approved_until"] = ecd
        else:
            body["ecd"] = ecd

    if len(ids) == 1:
        return client.patch(f"/findings/{ids[0]}/state", body=body)

    results: list[dict[str, Any]] = []
    for fid in ids:
        try:
            client.patch(f"/findings/{fid}/state", body=body)
            results.append({"finding_id": fid, "status": "success"})
        except ApiError as e:
            results.append({"finding_id": fid, "status": "error", "error": str(e)})

    succeeded = sum(1 for r in results if r["status"] == "success")
    failed = len(results) - succeeded
    return {"succeeded": succeeded, "failed": failed, "results": results}


def _resolve_finding_ids(
    finding_id: str | None,
    finding_ids: list[str] | None,
) -> list[str]:
    """Validate and return the list of finding IDs to triage."""
    if finding_id and finding_ids:
        raise ValueError("Provide either finding_id or finding_ids, not both.")
    if finding_ids:
        if len(finding_ids) > MAX_BATCH_SIZE:
            raise ValueError(f"finding_ids cannot exceed {MAX_BATCH_SIZE} items.")
        if len(finding_ids) == 0:
            raise ValueError("finding_ids must not be empty.")
        return finding_ids
    if finding_id:
        return [finding_id]
    raise ValueError("Either finding_id or finding_ids is required.")


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
