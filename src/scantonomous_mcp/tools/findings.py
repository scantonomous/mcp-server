"""Finding tools: list_findings, get_finding, get_remediation."""

from __future__ import annotations

from typing import Any

from ..client import ScantonomousClient

#: SCA-514: the prefix of the id a scanner mints for each detection. Finding detail
#: responses used to carry it inside ``evidence``, where agents mistook it for the
#: finding's id. No API accepts it.
SCANNER_OBSERVATION_ID_PREFIX = "scntnms:finding:"


def check_finding_id(finding_id: str, field: str = "finding_id") -> str:
    """Refuse a scanner observation id before it reaches the API (SCA-514).

    The API rejects one only for its length, which names neither id.

    :param finding_id: The id an agent passed.
    :param field: The argument it came in, named in the error.
    :returns: ``finding_id``, unchanged.
    :raises ValueError: If ``finding_id`` is a ``scntnms:finding:`` id.
    """
    if isinstance(finding_id, str) and finding_id.startswith(SCANNER_OBSERVATION_ID_PREFIX):
        raise ValueError(
            f"{field}: that is a scanner observation id from evidence, not a finding id; "
            "use the finding_id field (fnd_ and 24 hex characters) that list_findings "
            "and get_finding return."
        )
    return finding_id


def list_findings(
    client: ScantonomousClient,
    severity: str | None = None,
    state: str | None = None,
    query: str | None = None,
    scan_id: str | None = None,
    asset_id: str | None = None,
    scanner_type: str | None = None,
    limit: int = 25,
    cursor: str | None = None,
    offset: int | None = None,
) -> dict[str, Any]:
    """Search and filter security findings.

    :param severity: Filter by severity (critical, high, medium, low, info).
    :param state: Filter by state (untriaged, fixed, false_positive, not_production,
        accepted_risk, will_fix, duplicate, reopened). Defaults to ``untriaged`` to show
        unresolved findings first.
    :param query: Free-text search query.
    :param scan_id: Filter to findings from a specific scan.
    :param asset_id: Filter to findings for this asset/repository. Resolves
        the asset to its ``source_repository`` and queries OpenSearch
        directly. Ignored if ``scan_id`` is provided.
    :param scanner_type: Filter by the kind of scan that produced the finding
        (``standard``, ``ai`` or ``dast``). Both findings endpoints accept it.
    :param limit: Maximum number of results (default 25, API maximum 200).
    :param cursor: Opaque pagination cursor returned as ``next_cursor`` by a
        previous response. Use either ``cursor`` or ``offset``, not both.
    :param offset: Numeric pagination offset for endpoints and filter
        combinations that use offset-based pagination. Use either ``offset``
        or ``cursor``, not both.
    :returns: List of findings with summary info.
    """
    source_repository: str | None = None
    if asset_id and not scan_id:
        source_repository = _resolve_source_repository(client, asset_id)
        if not source_repository:
            return {"items": [], "total": 0, "message": f"Asset {asset_id} not found"}

    params: dict[str, Any] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    if offset is not None:
        params["offset"] = offset
    if severity:
        params["severity"] = severity
    if state:
        params["state"] = state
    elif not scan_id:
        params["state"] = "untriaged"
    if query:
        params["query"] = query
    if scanner_type:
        params["scanner_type"] = scanner_type
    if source_repository:
        params["source_repository"] = source_repository

    if scan_id:
        return client.get(f"/scans/{scan_id}/findings", params=params)
    return client.get("/findings", params=params)


def _resolve_source_repository(client: ScantonomousClient, asset_id: str) -> str | None:
    """Resolve an asset ID to its source_repository identifier.

    Fetches the asset list and returns the ``external_ref`` field
    (e.g. ``"github:scantonomous/services"``), which matches the
    ``source_repository`` field in the findings OpenSearch index.

    :param client: API client.
    :param asset_id: The asset ID to look up.
    :returns: The source_repository string, or None if not found.
    """
    account_id = client.get_account_id()
    resp = client.get(f"/account/{account_id}/assets", params={"limit": 100})
    for asset in resp.get("items", []):
        if asset.get("asset_id") == asset_id:
            return asset.get("external_ref", "")
    return None


def get_finding(
    client: ScantonomousClient,
    finding_id: str,
) -> dict[str, Any]:
    """Get full finding details including code evidence.

    :param finding_id: The finding's ``finding_id`` field, ``fnd_`` and 24 hex characters.
    :returns: Finding with title, description, severity, code evidence,
        file path, line numbers, and remediation guidance.
    :raises ValueError: If ``finding_id`` is a scanner observation id
        (``scntnms:finding:...``); see :func:`check_finding_id`.
    """
    return client.get(f"/findings/{check_finding_id(finding_id)}")


def get_remediation(
    client: ScantonomousClient,
    finding_id: str,
) -> dict[str, Any]:
    """Get AI-generated remediation suggestion for a finding.

    :param finding_id: The finding's ``finding_id`` field, ``fnd_`` and 24 hex characters.
    :returns: Remediation with suggested code fix, explanation, and
        confidence score.
    :raises ValueError: If ``finding_id`` is a scanner observation id
        (``scntnms:finding:...``); see :func:`check_finding_id`.
    """
    return client.get(f"/findings/{check_finding_id(finding_id)}/remediation")
