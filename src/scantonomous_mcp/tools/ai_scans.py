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


def create_ai_scan(
    client: ScantonomousClient,
    asset_ids: list[str],
) -> dict[str, Any]:
    """Create one or more AI-powered security scans.

    Per the SCA-272 plan the unified scan API is single-asset
    (``one canonical scan per asset``). For multi-asset agent prompts
    this wrapper fans out client-side: one ``POST /v1/scans`` per asset,
    each tagged ``scan_kind="ai"``. Returns a dict with the per-asset
    scan IDs so the agent can watch them in parallel.

    :param asset_ids: One or more asset IDs to scan. Required (the
        prototype's "scan everything" default is gone with the unified
        API; agents must pick assets explicitly).
    :returns: ``{"ai_scans": [{"asset_id": ..., "scan_id": ...,
        "status": ...}, ...], "count": N}``. On a tier without AI
        scanner access OR before the AI scanner flag flips, the
        per-asset call raises ``ApiError`` with HTTP 503 / 403 -- the
        wrapper surfaces the first such error rather than half-creating.
    :raises ValueError: If ``asset_ids`` is empty.
    :raises ApiError: From the underlying ``POST /v1/scans`` calls.
    """
    if not asset_ids:
        raise ValueError("asset_ids is required: pass the assets to scan")

    results: list[dict[str, Any]] = []
    for asset_id in asset_ids:
        body = {
            "asset_id": asset_id,
            "scan_kind": "ai",
            "trigger_type": "mcp",
        }
        scan = client.post("/scans", body=body)
        results.append(
            {
                "asset_id": asset_id,
                "scan_id": scan.get("scan_id", ""),
                "status": scan.get("status", "queued"),
            }
        )
    return {"ai_scans": results, "count": len(results)}


def get_ai_scan_report(
    client: ScantonomousClient,
    ai_scan_id: str,
) -> dict[str, Any]:
    """Synthesize the executive-summary report for an AI scan.

    The unified scan API does not expose a ``/report`` endpoint;
    instead this wrapper composes one from the standard scan and
    findings reads:

    * ``GET /v1/scans/{id}`` for status, timestamps, finding count.
    * ``GET /v1/scans/{id}/findings?scanner_type=ai`` for the
      AI-scanner findings the report describes.

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
    findings_resp = client.get(
        f"/scans/{ai_scan_id}/findings",
        params={"scanner_type": "ai", "limit": 50},
    )
    items = findings_resp.get("items", []) if isinstance(findings_resp, dict) else []
    severity_counts: dict[str, int] = {}
    for f in items:
        sev = str(f.get("severity", "")).lower() or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "scan_id": ai_scan_id,
        "scan_kind": scan.get("scan_kind", "ai"),
        "status": scan.get("status", "unknown"),
        "started_at": scan.get("started_at"),
        "ended_at": scan.get("ended_at"),
        "findings_count": scan.get("findings_count"),
        "severity_breakdown": severity_counts,
        # Truncated list -- callers should use list_findings
        # (scanner_type=ai) for the full set.
        "key_findings": items[:10],
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
