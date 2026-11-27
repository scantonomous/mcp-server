"""Triage tools: triage_finding, set_finding_label, get_findings_summary."""

from __future__ import annotations

from typing import Any

from ..client import ApiError, ScantonomousClient

MAX_BATCH_SIZE = 25
#: Labels a person or agent may set (SCA-523); the API takes them capitalized.
FINDING_LABELS = ("Exploitable", "Hardening")


def triage_finding(
    client: ScantonomousClient,
    state: str,
    reason: str,
    ai_model: str,
    finding_id: str | None = None,
    finding_ids: list[str] | None = None,
    ecd: str | None = None,
    approval_reference: str | None = None,
) -> dict[str, Any]:
    """Record a triage decision on one or more findings.

    Supply either ``finding_id`` (single) or ``finding_ids`` (batch, up to 25).

    :param state: New state: ``fixed``, ``false_positive``, ``not_production``,
        ``accepted_risk``, ``will_fix``, or ``duplicate``.
    :param reason: Explanation for the decision.
    :param ai_model: The AI model performing the triage (e.g. "Claude Opus 4.6").
    :param finding_id: A single finding ID to triage.
    :param finding_ids: A list of finding IDs to triage with the same state/reason.
    :param ecd: Expected completion date (YYYY-MM-DD). Required when state is
        ``will_fix`` (within severity SLA) or ``accepted_risk`` (mapped to
        ``ecd_approved_until``, max 1 year).
    :param approval_reference: URL or reference to the approval document. Required
        when state is ``accepted_risk``. Max 2048 characters.
    :returns: A summary with succeeded/failed counts and per-finding results, for one
        finding as for several (SCA-545). It does not echo the findings it wrote;
        ``get_finding`` reads one.
    :raises ApiError: When the update of a ``finding_id`` fails, so the caller gets the
        API's structured error. ``finding_ids``, at any length, reports each failure in
        ``results`` instead.
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
    if approval_reference:
        body["approval_reference"] = approval_reference

    results: list[dict[str, Any]] = []
    for fid in ids:
        try:
            client.patch(f"/findings/{fid}/state", body=body)
            results.append({"finding_id": fid, "status": "success"})
        except ApiError as e:
            if finding_ids is None:
                raise
            results.append({"finding_id": fid, "status": "error", "error": str(e)})

    succeeded = sum(1 for r in results if r["status"] == "success")
    failed = len(results) - succeeded
    return {"succeeded": succeeded, "failed": failed, "results": results}


def set_finding_label(
    client: ScantonomousClient,
    finding_id: str,
    label: str,
    ai_model: str | None = None,
) -> dict[str, Any]:
    """Label a finding Exploitable or Hardening (SCA-523).

    The label overrides the Noise Reduction label and clears a Needs review
    block on the pull request.

    :param finding_id: The finding to label.
    :param label: ``Exploitable`` or ``Hardening``.
    :param ai_model: The AI model setting the label (e.g. "Claude Opus 4.7").
    :returns: The updated finding.
    :raises ValueError: If ``finding_id`` is empty or ``label`` is not one of
        :data:`FINDING_LABELS`.
    """
    if not finding_id:
        raise ValueError("finding_id is required.")
    if label not in FINDING_LABELS:
        raise ValueError(f"label must be one of {', '.join(FINDING_LABELS)}.")
    body: dict[str, Any] = {"label": label, "source": "mcp"}
    if ai_model:
        body["ai_model"] = ai_model
    return client.patch(f"/findings/{finding_id}/label", body=body)


def _resolve_finding_ids(
    finding_id: str | None,
    finding_ids: list[str] | None,
) -> list[str]:
    """Validate and return the list of finding IDs to triage."""
    if finding_id and finding_ids:
        raise ValueError("Provide either finding_id or finding_ids, not both.")
    if finding_ids is not None:
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
    """Get aggregate findings statistics, account-wide or for one scan.

    The two modes return DIFFERENT shapes:

    * Without ``scan_id``: ``GET /findings/stats`` -- account-wide severity
      and state breakdowns and totals.
    * With ``scan_id``: ``GET /findings/summary`` -- a scan-scoped summary
      with ``total``, ``open``, ``triaged``, ``resolved``,
      ``open_by_severity`` and, for scans that report it, ``actionable`` and
      ``actionable_by_severity``.

    :param scan_id: Optional scan ID to scope the summary to one scan.
    :returns: Account-wide stats, or the scan-scoped summary when ``scan_id``
        is given. Do not assume the same keys in both cases.
    """
    if scan_id:
        return client.get("/findings/summary", params={"scan_id": scan_id})
    return client.get("/findings/stats")
