"""Tests for triage tool helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from scantonomous_mcp.client import ApiError
from scantonomous_mcp.tools import triage


def test_resolve_finding_ids_accepts_single_finding_id() -> None:
    assert triage._resolve_finding_ids("finding-1", None) == ["finding-1"]


def test_resolve_finding_ids_accepts_batch_ids() -> None:
    assert triage._resolve_finding_ids(None, ["finding-1", "finding-2"]) == [
        "finding-1",
        "finding-2",
    ]


@pytest.mark.parametrize(
    ("finding_id", "finding_ids", "message"),
    [
        ("finding-1", ["finding-2"], "Provide either finding_id or finding_ids"),
        (None, [], "finding_ids must not be empty."),
        (None, [f"finding-{n}" for n in range(26)], "finding_ids cannot exceed 25 items."),
        (None, None, "Either finding_id or finding_ids is required."),
    ],
)
def test_resolve_finding_ids_rejects_invalid_inputs(
    finding_id: str | None,
    finding_ids: list[str] | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        triage._resolve_finding_ids(finding_id, finding_ids)


def test_triage_finding_updates_single_finding() -> None:
    client = MagicMock()
    client.patch.return_value = {"status": "ok"}

    result = triage.triage_finding(
        client,
        state="fixed",
        reason="Applied the patch",
        ai_model="GPT-5.4",
        finding_id="finding-1",
    )

    client.patch.assert_called_once_with(
        "/findings/finding-1/state",
        body={
            "state": "fixed",
            "reason": "Applied the patch",
            "source": "mcp",
            "ai_model": "GPT-5.4",
        },
    )
    assert result == {"status": "ok"}


def test_triage_finding_maps_accepted_risk_ecd_and_approval_reference() -> None:
    client = MagicMock()
    client.patch.return_value = {"status": "ok"}

    triage.triage_finding(
        client,
        state="accepted_risk",
        reason="Approved by risk committee",
        ai_model="GPT-5.4",
        finding_id="finding-1",
        ecd="2027-01-01",
        approval_reference="https://example.com/ticket/123",
    )

    client.patch.assert_called_once_with(
        "/findings/finding-1/state",
        body={
            "state": "accepted_risk",
            "reason": "Approved by risk committee",
            "source": "mcp",
            "ai_model": "GPT-5.4",
            "ecd_approved_until": "2027-01-01",
            "approval_reference": "https://example.com/ticket/123",
        },
    )


def test_triage_finding_maps_non_accepted_risk_ecd() -> None:
    client = MagicMock()
    client.patch.return_value = {"status": "ok"}

    triage.triage_finding(
        client,
        state="will_fix",
        reason="Fix planned for next sprint",
        ai_model="GPT-5.4",
        finding_id="finding-1",
        ecd="2026-05-01",
    )

    client.patch.assert_called_once_with(
        "/findings/finding-1/state",
        body={
            "state": "will_fix",
            "reason": "Fix planned for next sprint",
            "source": "mcp",
            "ai_model": "GPT-5.4",
            "ecd": "2026-05-01",
        },
    )


def test_triage_finding_batches_results_and_continues_on_errors() -> None:
    client = MagicMock()
    client.patch.side_effect = [
        {"status": "ok"},
        ApiError(500, "failed"),
        {"status": "ok"},
    ]

    result = triage.triage_finding(
        client,
        state="fixed",
        reason="Applied the fix",
        ai_model="GPT-5.4",
        finding_ids=["finding-1", "finding-2", "finding-3"],
    )

    assert client.patch.call_count == 3
    assert result == {
        "succeeded": 2,
        "failed": 1,
        "results": [
            {"finding_id": "finding-1", "status": "success"},
            {
                "finding_id": "finding-2",
                "status": "error",
                "error": "API error 500: failed",
            },
            {"finding_id": "finding-3", "status": "success"},
        ],
    }


def test_get_findings_summary_without_scan_id() -> None:
    client = MagicMock()
    client.get.return_value = {"total": 1}

    result = triage.get_findings_summary(client)

    client.get.assert_called_once_with("/findings/stats", params={})
    assert result == {"total": 1}


def test_get_findings_summary_with_scan_id() -> None:
    client = MagicMock()
    client.get.return_value = {"total": 1}

    result = triage.get_findings_summary(client, scan_id="scan-1")

    client.get.assert_called_once_with("/findings/stats", params={"scan_id": "scan-1"})
    assert result == {"total": 1}


def test_set_finding_label_patches_label_with_mcp_source() -> None:
    client = MagicMock()
    client.patch.return_value = {"finding_id": "finding-1", "label": "exploitable"}

    result = triage.set_finding_label(
        client, finding_id="finding-1", label="Exploitable", ai_model="Claude Opus 4.7"
    )

    client.patch.assert_called_once_with(
        "/findings/finding-1/label",
        body={"label": "Exploitable", "source": "mcp", "ai_model": "Claude Opus 4.7"},
    )
    assert result == {"finding_id": "finding-1", "label": "exploitable"}


def test_set_finding_label_omits_ai_model_when_not_given() -> None:
    client = MagicMock()
    client.patch.return_value = {}

    triage.set_finding_label(client, finding_id="finding-1", label="Hardening")

    client.patch.assert_called_once_with(
        "/findings/finding-1/label",
        body={"label": "Hardening", "source": "mcp"},
    )


@pytest.mark.parametrize("label", ["exploitable", "Needs review", "needs_review", ""])
def test_set_finding_label_rejects_other_labels(label: str) -> None:
    client = MagicMock()

    with pytest.raises(ValueError, match="label must be one of Exploitable, Hardening"):
        triage.set_finding_label(client, finding_id="finding-1", label=label)

    client.patch.assert_not_called()


def test_set_finding_label_requires_finding_id() -> None:
    client = MagicMock()

    with pytest.raises(ValueError, match="finding_id is required"):
        triage.set_finding_label(client, finding_id="", label="Hardening")

    client.patch.assert_not_called()


def test_triage_finding_sends_not_production_state() -> None:
    client = MagicMock()
    client.patch.return_value = {"status": "ok"}

    triage.triage_finding(
        client,
        state="not_production",
        reason="Test fixture only",
        ai_model="GPT-5.4",
        finding_id="finding-1",
    )

    client.patch.assert_called_once_with(
        "/findings/finding-1/state",
        body={
            "state": "not_production",
            "reason": "Test fixture only",
            "source": "mcp",
            "ai_model": "GPT-5.4",
        },
    )
