"""AI scan tools: create_ai_scan, get_ai_scan_report."""

from __future__ import annotations

from typing import Any

from ..client import ScantonomousClient


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
