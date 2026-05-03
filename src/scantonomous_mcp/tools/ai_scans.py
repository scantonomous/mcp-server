"""AI scan tools (SCA-272 unified-API rewrite).

Thin wrappers over the unified ``/v1/scans`` API: AI scans are now a
``scan_kind`` discriminator on the standard scan resource, not a
separate ``/v1/ai-scans`` collection. The orchestrator routes AI scans
to a dedicated state machine (Phase C) but the API surface a caller
sees is the same as a standard scan -- one create endpoint, one read
endpoint, one watch loop.

These wrappers stay in the MCP toolkit because:

* ``create_ai_scan(asset_ids)`` matches how agents already model "scan
  N assets with AI"; calling ``create_scan`` per asset and tagging
  ``scan_kind="ai"`` is a less ergonomic surface for the model.
* ``get_ai_scan_report`` synthesizes the report shape from the unified
  scan + findings endpoints so existing agent prompts that expect a
  report payload keep working without an additional model nudge.
* ``watch_ai_scan`` exists so the watch loop can use AI-appropriate
  defaults (longer timeout, richer terminal-state set) without
  changing the standard-scan watch tool.

Server prerequisites:

* Services PR #324 (B1) deployed -- ``POST /v1/scans`` accepts
  ``scan_kind``.
* ``AI_SCANNER_ENABLED`` env var set on the Scan Service Lambda.
  Until Phase C wires the AI orchestrator + flips the flag, the
  unified API rejects ``scan_kind="ai"`` with HTTP 503
  ``ai_scanner_unavailable``. This MCP rewrite must merge AFTER
  Phase C+G.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

from ..client import ApiError, ScantonomousClient

#: Terminal lifecycle statuses for the unified scan resource. Matches
#: ``services/lambda/scan/models.py::ScanStatus`` plus the historical
#: prototype's ``completed_partial`` so legacy agent expectations
#: continue to short-circuit out of the watch loop.
_AI_TERMINAL_STATUSES = {"completed", "completed_partial", "failed", "canceled"}
_POLL_BASE_SECONDS = 30
_POLL_JITTER_SECONDS = 5
_DEFAULT_TIMEOUT_MINUTES = 60


#: SCA-299: temporarily 1 while SCA-298 (cross-repo LLM analysis) is
#: in flight. Mirrors the server-side cap on
#: ``AiScanCreate.asset_ids`` (``maxItems: 1``) and the orchestrator
#: worker's ``len > 1`` reject. Returns to 5 once SCA-298 lands.
#: Surfaced client-side so the agent gets a clean ``ValueError``
#: instead of an HTTP 400 round-trip when it oversteps.
_MAX_AI_SCAN_ASSETS = 1


def create_ai_scan(
    client: ScantonomousClient,
    asset_ids: list[str],
) -> dict[str, Any]:
    """Create one AI-powered security scan over a single repository.

    SCA-280 introduced a single multi-repo analysis pass -- one Scan
    record covers ``asset_ids``, the orchestrator checks the repos
    out, and a single AI scanner session reasons over the full set.
    One quota slot is consumed per scan regardless of repo count.

    SCA-299 caps the request at 1 ``asset_id`` while SCA-298
    (cross-repo LLM analysis) is in flight; the cap returns to 5 once
    that lands. The list shape (``asset_ids: string[]``) is preserved
    end-to-end so callers do not have to re-plumb on flip.

    The previous implementation fanned out client-side (one POST per
    asset, each tagged ``scan_kind="ai"``); each POST produced an
    independent single-repo AI scan and the agent had to stitch them
    back together. That gave N scans with N quota slots and no actual
    cross-repo signal. This wrapper now sends a single ``POST /v1/scans``
    with the full ``asset_ids`` list and the server-side batch policy
    consumes one slot atomically.

    :param asset_ids: Currently capped at 1 unique asset id per scan
        (SCA-299, while SCA-298 is in flight). Order is preserved
        end-to-end (agent selection → checkout Map → AI scanner LLM
        session). Returns to 1-5 once SCA-298 ships.
    :returns: ``{"scan_id": "...", "asset_ids": [...], "status": "...",
        "count": N}`` where ``count`` is the number of repos in the
        scan. Shape intentionally differs from the legacy multi-scan
        return because there is now only ever one scan per call;
        agent prompts that previously keyed off ``ai_scans[*].scan_id``
        should switch to the top-level ``scan_id``.
    :raises ValueError: If ``asset_ids`` is empty, exceeds the
        ``_MAX_AI_SCAN_ASSETS`` cap, or contains duplicates. Validated
        client-side so the agent gets a clear error before burning a
        network round-trip.
    :raises ApiError: If the server-side batch policy rejects the
        request (e.g. tier doesn't include AI, account suspended,
        asset inactive, quota exceeded). ``ApiError.payload`` carries
        the full structured server response so the agent can read
        ``denied_asset_id`` (the offending asset for inactive /
        unowned / no-credentials denials), ``quota`` (current usage on
        quota_exceeded denials), and the human-readable ``message``
        — important now that one request can fail because of one
        selected repo.
    """
    if not asset_ids:
        raise ValueError("asset_ids is required: pass the assets to scan")
    # SCA-299: dup check must precede the cap check -- under the
    # tightened cap (1) a duplicate input of length 2 would otherwise
    # hit the cap message and mask the more-specific "asset_ids must
    # be unique" feedback. Reorder is safe: dups are always invalid
    # regardless of cap.
    if len(set(asset_ids)) != len(asset_ids):
        raise ValueError("asset_ids must be unique")
    if len(asset_ids) > _MAX_AI_SCAN_ASSETS:
        raise ValueError(
            f"AI scans support at most {_MAX_AI_SCAN_ASSETS} repositories "
            f"per scan (got {len(asset_ids)})"
        )

    body = {
        "asset_ids": list(asset_ids),
        "scan_kind": "ai",
        "trigger_type": "mcp",
    }
    scan = client.post("/scans", body=body)
    return {
        "scan_id": scan.get("scan_id", ""),
        "asset_ids": list(asset_ids),
        "status": scan.get("status", "queued"),
        "count": len(asset_ids),
    }


def get_ai_scan_report(
    client: ScantonomousClient,
    ai_scan_id: str,
) -> dict[str, Any]:
    """Synthesize the executive-summary report for an AI scan.

    The unified scan API does not expose a ``/report`` endpoint;
    instead this wrapper composes one from three reads:

    * ``GET /v1/scans/{id}`` for status, timestamps, scan_kind.
    * ``GET /v1/findings/summary?scan_id=...`` for the *full*
      severity breakdown -- this endpoint aggregates over every
      finding for the scan (max_items=10_000 server-side), so the
      counts are accurate even when the scan has more than the per-
      page findings limit. AI scans only emit AI findings, so no
      ``scanner_type`` filter is needed; if a future change ever
      mixes scanner types on a single scan, the breakdown stays a
      faithful per-scan total either way.
    * ``GET /v1/scans/{id}/findings`` for the truncated ``key_findings``
      list rendered in the report's body. Callers that need the full
      finding set should use ``list_findings`` directly.

    The shape mirrors what the prototype's ``/ai-scans/{id}/report``
    used to return so agent prompts that expect a "report" payload
    keep working.

    :param ai_scan_id: The scan ID (no longer prefixed differently
        from a standard scan; ``scan_kind`` on the canonical record
        identifies it as AI).
    :returns: Report dict with ``scan_id``, ``status``, ``severity``
        breakdown, and a truncated list of key findings.
    """
    scan = client.get(f"/scans/{ai_scan_id}")
    summary = client.get("/findings/summary", params={"scan_id": ai_scan_id})
    findings_resp = client.get(
        f"/scans/{ai_scan_id}/findings",
        params={"scanner_type": "ai", "limit": 10},
    )
    items = findings_resp.get("items", []) if isinstance(findings_resp, dict) else []

    # ``/findings/summary`` returns ``open_by_severity`` for the open
    # bucket only. Surface that as ``severity_breakdown`` so the agent
    # sees a count consistent with the report's emphasis on actionable
    # findings; total / open / triaged / resolved are exposed verbatim
    # for callers that want the fuller picture.
    severity_breakdown = summary.get("open_by_severity", {}) if isinstance(summary, dict) else {}

    return {
        "scan_id": ai_scan_id,
        "scan_kind": scan.get("scan_kind", "ai"),
        "status": scan.get("status", "unknown"),
        "started_at": scan.get("started_at"),
        "ended_at": scan.get("ended_at"),
        "findings_count": scan.get("findings_count"),
        "severity_breakdown": severity_breakdown,
        "open_count": summary.get("open") if isinstance(summary, dict) else None,
        "triaged_count": summary.get("triaged") if isinstance(summary, dict) else None,
        "resolved_count": summary.get("resolved") if isinstance(summary, dict) else None,
        # Truncated -- callers should use list_findings
        # (scanner_type=ai) for the full set.
        "key_findings": items,
    }


async def watch_ai_scan(
    client: ScantonomousClient,
    ai_scan_id: str,
    timeout_minutes: int = _DEFAULT_TIMEOUT_MINUTES,
) -> dict[str, Any]:
    """Poll an AI scan until it reaches a terminal status.

    AI scans run on a separate orchestrator state machine with a longer
    end-to-end runtime than the standard pipeline, so the default
    timeout here (60 min) is double the standard ``watch_scan`` default.
    The poll interval (25-35s with jitter) matches the standard tool.

    :param ai_scan_id: The scan ID to watch.
    :param timeout_minutes: Maximum time to wait in minutes (default 60).
    :returns: Final scan object on terminal status, or a structured
        timeout dict with the last known status.
    """
    timeout_seconds = timeout_minutes * 60
    elapsed = 0.0
    last_known_status = "unknown"

    while elapsed < timeout_seconds:
        try:
            scan = client.get(f"/scans/{ai_scan_id}")
        except ApiError:
            raise

        last_known_status = str(scan.get("status", ""))
        if last_known_status in _AI_TERMINAL_STATUSES:
            return scan

        delay = _POLL_BASE_SECONDS + random.uniform(  # noqa: S311  # nosec B311
            -_POLL_JITTER_SECONDS, _POLL_JITTER_SECONDS
        )
        remaining = timeout_seconds - elapsed
        delay = min(delay, remaining)
        if delay <= 0:
            break

        await asyncio.sleep(delay)
        elapsed += delay

    return {
        "status": "timeout",
        "message": f"AI scan did not complete within {timeout_minutes} minutes.",
        "last_known_status": last_known_status,
        "scan_id": ai_scan_id,
    }
