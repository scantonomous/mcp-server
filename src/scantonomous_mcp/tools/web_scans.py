"""Web-asset DAST tools (SCA-422).

Thin wrappers over the unified ``/v1/scans`` API for web (DAST) scans.

Server prerequisites:

* ``POST /v1/scans`` accepts ``scan_kind="dast"`` (SCA-422; live on dev, not
  beta/prod yet). The server's DAST policy gates on only (1) a ``web_endpoint``
  asset and (2) live domain-ownership verification — it does **not** require an
  analyzed site-map. The DAST state machine runs recon internally (create-or-reuse,
  quota-exempt), so this tool never pre-gates on recon.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

from ..client import ApiError, ScantonomousClient

_TERMINAL_STATUSES = {"completed", "failed", "canceled"}
_POLL_BASE_SECONDS = 30
_POLL_JITTER_SECONDS = 5
_DEFAULT_TIMEOUT_MINUTES = 60

#: Exact server policy-denial messages (serialized under ``ApiError.payload["message"]``
#: by the scan handler — there is no ``reason`` key) mapped to friendly guidance.
_REJECTION_GUIDANCE: dict[str, dict[str, str]] = {
    "recon/dast scans require a web_endpoint asset": {
        "status": "wrong_asset_type",
        "next": "This isn't a web app — use create_scan for a repository.",
    },
    "web asset ownership must be verified before scanning": {
        "status": "not_verified",
        "next": (
            "Verify domain ownership for this web app in the Scantonomous web UI, then retry."
        ),
    },
    "DAST scanner is not available on this subscription tier": {
        "status": "tier_unavailable",
        "next": "DAST requires a Startup tier or higher.",
    },
}


def _web_scan_rejection(err: ApiError) -> dict[str, str] | None:
    """Map a server policy-denial to friendly guidance, or ``None`` if unrecognized.

    The scan handler serializes the policy reason under ``payload["message"]``
    (there is no ``reason`` key), so we match on that exact string.

    :param err: The ``ApiError`` raised by the create call.
    :returns: A ``{"status", "next"}`` guidance dict, or ``None`` to re-raise.
    """
    if err.payload is None:
        return None
    message = err.payload.get("message")
    if not isinstance(message, str):
        return None
    return _REJECTION_GUIDANCE.get(message)


def create_dast_scan(
    client: ScantonomousClient,
    web_asset_id: str,
) -> dict[str, Any]:
    """Create a DAST (dynamic web application) scan over a verified web asset.

    Posts once the asset is a verified ``web_endpoint`` and lets the server decide.
    It deliberately does NOT pre-check verification (the server recomputes ownership
    live; the asset's ``effective_verification`` snapshot is stale) and does NOT gate
    on recon readiness (the DAST state machine runs recon internally, quota-exempt).

    :param web_asset_id: The ``web_endpoint`` asset to scan.
    :returns: ``{"scan_id", "status", "asset_id"}`` on success, or a
        ``{"status", "next"}`` guidance dict for a recognized policy denial
        (``wrong_asset_type`` / ``not_verified`` / ``tier_unavailable``).
    :raises ValueError: If ``web_asset_id`` is empty.
    :raises ApiError: For server rejections that are not recognized policy denials.
    """
    if not web_asset_id:
        raise ValueError("web_asset_id is required: pass the web app's asset_id")

    body = {"asset_id": web_asset_id, "scan_kind": "dast", "trigger_type": "mcp"}
    try:
        scan = client.post("/scans", body=body)
    except ApiError as err:
        guidance = _web_scan_rejection(err)
        if guidance is not None:
            return guidance
        raise
    return {
        "scan_id": scan.get("scan_id", ""),
        "status": scan.get("status", "queued"),
        "asset_id": web_asset_id,
    }


async def watch_dast_scan(
    client: ScantonomousClient,
    scan_id: str,
    timeout_minutes: int = _DEFAULT_TIMEOUT_MINUTES,
) -> dict[str, Any]:
    """Poll a DAST scan until it reaches a terminal status.

    Polls every 25–35 s (30 s ± 5 s jitter). DAST runs on its own state machine
    (recon then the scanner), so the default timeout is 60 min. On ``failed``, the
    returned scan object carries the server ``error_code`` / ``error_message`` (the
    web-scan failure taxonomy, incl. a terminal recon failure), so the agent can
    explain the cause.

    :param scan_id: The DAST scan ID to watch.
    :param timeout_minutes: Maximum time to wait in minutes (default 60).
    :returns: The final scan object on terminal status, or a structured timeout dict.
    """
    timeout_seconds = timeout_minutes * 60
    elapsed = 0.0
    last_known_status = "unknown"

    while elapsed < timeout_seconds:
        scan = client.get(f"/scans/{scan_id}")
        last_known_status = str(scan.get("status", ""))
        if last_known_status in _TERMINAL_STATUSES:
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
        "message": f"DAST scan did not complete within {timeout_minutes} minutes.",
        "last_known_status": last_known_status,
        "scan_id": scan_id,
    }
