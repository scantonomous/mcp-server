"""Scan operation tools: list_assets, create_scan, get_scan, watch_scan."""

from __future__ import annotations

import asyncio
import random
from typing import Any

from ..client import ApiError, ScantonomousClient

TERMINAL_STATUSES = {"completed", "failed", "canceled"}
_ALLOWED_SCAN_KINDS = {"standard", "dast", "recon"}
_POLL_BASE_SECONDS = 30
_POLL_JITTER_SECONDS = 5
_DEFAULT_TIMEOUT_MINUTES = 30


def list_assets(
    client: ScantonomousClient,
    query: str | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    """List connected repositories/assets.

    :param query: Optional search query to filter assets.
    :param limit: Maximum number of results (default 25).
    :returns: Slim list of assets with id and repo path for easy matching.
    """
    account_id = client.get_account_id()
    params: dict[str, Any] = {"limit": limit}
    if query:
        params["query"] = query
    data = client.get(f"/account/{account_id}/assets", params=params)
    items = data.get("items", [])
    return {
        "assets": [
            {
                "asset_id": a["asset_id"],
                "repo_path": a.get("repo_path", a.get("name", "")),
            }
            for a in items
        ],
    }


def create_scan(
    client: ScantonomousClient,
    asset_id: str,
    ref: str | None = None,
    scan_kind: str | None = None,
) -> dict[str, Any]:
    """Trigger a security scan on an asset.

    :param asset_id: The asset (repository) to scan.
    :param ref: Optional git ref (branch, tag, commit) to scan. Defaults to the
        default branch.
    :param scan_kind: Optional scan kind: ``"standard"`` (code analysis),
        ``"dast"`` (web app security), or ``"recon"`` (web reconnaissance).
        Omit for a standard scan.  AI scans must use ``create_ai_scan``.
    :returns: Scan object with id and status.
    :raises ValueError: If *scan_kind* is not in the allowed set.
    """
    if scan_kind is not None and scan_kind not in _ALLOWED_SCAN_KINDS:
        raise ValueError(
            f"Invalid scan_kind {scan_kind!r}. "
            f"Allowed values: {sorted(_ALLOWED_SCAN_KINDS)}. "
            "AI scans must use create_ai_scan."
        )
    body: dict[str, Any] = {"asset_id": asset_id, "trigger_type": "mcp"}
    if ref:
        body["ref"] = ref
    if scan_kind is not None:
        body["scan_kind"] = scan_kind
    return client.post("/scans", body=body)


def get_scan(
    client: ScantonomousClient,
    scan_id: str,
) -> dict[str, Any]:
    """Get scan status and details.

    :param scan_id: The scan ID to look up.
    :returns: Scan object with id, status, timestamps, and finding counts.
    """
    return client.get(f"/scans/{scan_id}")


async def watch_scan(
    client: ScantonomousClient,
    scan_id: str,
    timeout_minutes: int = _DEFAULT_TIMEOUT_MINUTES,
) -> dict[str, Any]:
    """Poll a scan until it reaches a terminal status.

    Checks every 25–35 seconds (30s base ± 5s jitter) until the scan
    completes, fails, is canceled, or the timeout is reached.

    :param scan_id: The scan ID to watch.
    :param timeout_minutes: Maximum time to wait in minutes (default 30).
    :returns: Final scan object with status, timestamps, and finding counts.
    """
    timeout_seconds = timeout_minutes * 60
    elapsed = 0.0

    while elapsed < timeout_seconds:
        try:
            scan = client.get(f"/scans/{scan_id}")
        except ApiError:
            raise

        status = scan.get("status", "")
        if status in TERMINAL_STATUSES:
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
        "message": f"Scan did not complete within {timeout_minutes} minutes.",
        "last_known_status": scan.get("status", "unknown"),  # type: ignore[possibly-undefined]
        "scan_id": scan_id,
    }
