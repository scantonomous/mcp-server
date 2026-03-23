"""AI scan tools: create_ai_scan, get_ai_scan_report, watch_ai_scan."""

from __future__ import annotations

import asyncio
import random
from typing import Any

from ..client import ApiError, ScantonomousClient

_AI_TERMINAL_STATUSES = {"completed", "completed_partial", "failed"}
_POLL_BASE_SECONDS = 30
_POLL_JITTER_SECONDS = 5
_DEFAULT_TIMEOUT_MINUTES = 30


def create_ai_scan(
    client: ScantonomousClient,
    asset_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Create a quick AI-powered security scan.

    :param asset_ids: Optional list of asset IDs to scan. If not provided,
        scans all connected assets.
    :returns: AI scan object with id and status.
    """
    body: dict[str, Any] = {}
    if asset_ids:
        body["asset_ids"] = asset_ids
    return client.post("/ai-scans", body=body)


def get_ai_scan_report(
    client: ScantonomousClient,
    ai_scan_id: str,
) -> dict[str, Any]:
    """Get the executive summary report for an AI scan.

    :param ai_scan_id: The AI scan ID.
    :returns: Report with executive summary, severity breakdown, and
        key findings.
    """
    return client.get(f"/ai-scans/{ai_scan_id}/report")


async def watch_ai_scan(
    client: ScantonomousClient,
    ai_scan_id: str,
    timeout_minutes: int = _DEFAULT_TIMEOUT_MINUTES,
) -> dict[str, Any]:
    """Poll an AI scan until it reaches a terminal status.

    Checks every 25–35 seconds (30s base ± 5s jitter) until the scan
    completes, fails, or the timeout is reached.

    :param ai_scan_id: The AI scan ID to watch.
    :param timeout_minutes: Maximum time to wait in minutes (default 30).
    :returns: Final AI scan object with status and results.
    """
    timeout_seconds = timeout_minutes * 60
    elapsed = 0.0

    while elapsed < timeout_seconds:
        try:
            scan = client.get(f"/ai-scans/{ai_scan_id}")
        except ApiError:
            raise

        status = scan.get("status", "")
        if status in _AI_TERMINAL_STATUSES:
            return scan

        delay = _POLL_BASE_SECONDS + random.uniform(  # noqa: S311
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
        "last_known_status": scan.get("status", "unknown"),  # type: ignore[possibly-undefined]
        "ai_scan_id": ai_scan_id,
    }
