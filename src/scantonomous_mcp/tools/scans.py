"""Scan operation tools: list_assets, create_scan, get_scan."""

from __future__ import annotations

from typing import Any

from ..client import ScantonomousClient


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
) -> dict[str, Any]:
    """Trigger a security scan on an asset.

    :param asset_id: The asset (repository) to scan.
    :param ref: Optional git ref (branch, tag, commit) to scan. Defaults to the
        default branch.
    :returns: Scan object with id and status.
    """
    body: dict[str, Any] = {"asset_id": asset_id, "trigger_type": "mcp"}
    if ref:
        body["ref"] = ref
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
