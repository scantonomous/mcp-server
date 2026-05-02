"""Tests for the Scantonomous API client."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from scantonomous_mcp.client import ApiError, ScantonomousClient


class TestApiError:
    def test_stores_status_code(self) -> None:
        err = ApiError(404, "not found")
        assert err.status_code == 404

    def test_message_format(self) -> None:
        err = ApiError(500, "internal error")
        assert str(err) == "API error 500: internal error"


class TestScantonomousClient:
    def _make_client(self) -> ScantonomousClient:
        auth = MagicMock()
        auth.api_base_url = "https://api.dev.scantonomous.ai/v1"
        auth.get_id_token.return_value = "fake-token"
        return ScantonomousClient(auth)

    def test_base_url_from_auth(self) -> None:
        client = self._make_client()
        assert client.base_url == "https://api.dev.scantonomous.ai/v1"

    def test_get_sends_auth_header(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": "ok"}

        with patch.object(client._http, "request", return_value=mock_resp) as mock_req:
            result = client.get("/test")

        mock_req.assert_called_once()
        call_kwargs = mock_req.call_args
        assert call_kwargs[1]["headers"]["Authorization"] == "Bearer fake-token"
        assert result == {"data": "ok"}

    def test_post_sends_json_body(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": "123"}

        with patch.object(client._http, "request", return_value=mock_resp) as mock_req:
            result = client.post("/scans", body={"asset_id": "abc"})

        call_kwargs = mock_req.call_args
        assert call_kwargs[1]["json"] == {"asset_id": "abc"}
        assert result == {"id": "123"}

    def test_raises_api_error_on_4xx(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {"message": "forbidden"}

        with patch.object(client._http, "request", return_value=mock_resp):
            with pytest.raises(ApiError) as exc_info:
                client.get("/secret")

        assert exc_info.value.status_code == 403
        assert "forbidden" in str(exc_info.value)

    def test_api_error_preserves_full_payload_for_structured_denials(self) -> None:
        """SCA-280 review: structured server response fields like
        ``denied_asset_id`` and ``quota`` must survive the ApiError
        boundary so callers (e.g. create_ai_scan) can surface them."""
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "message": "asset asset-2 is inactive",
            "denied_asset_id": "asset-2",
            "quota": {"ai_scan_limit": 10, "ai_scans_used": 4},
        }

        with patch.object(client._http, "request", return_value=mock_resp):
            with pytest.raises(ApiError) as exc_info:
                client.post("/scans", body={"asset_ids": ["asset-1", "asset-2"]})

        # Legacy text summary still in the exception args.
        assert "asset asset-2 is inactive" in str(exc_info.value)
        # Full payload available on the exception for callers that
        # need structured fields.
        assert exc_info.value.payload == {
            "message": "asset asset-2 is inactive",
            "denied_asset_id": "asset-2",
            "quota": {"ai_scan_limit": 10, "ai_scans_used": 4},
        }

    def test_api_error_payload_is_none_when_response_not_json(self) -> None:
        """A non-JSON error response (HTML 502 from a load balancer,
        plain text 504, etc.) leaves ``payload`` as None and the message
        falls back to the raw response text."""
        import json as _json  # noqa: PLC0415

        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 502
        mock_resp.json.side_effect = _json.JSONDecodeError("unexpected", "", 0)
        mock_resp.text = "<html>Bad Gateway</html>"

        with patch.object(client._http, "request", return_value=mock_resp):
            with pytest.raises(ApiError) as exc_info:
                client.get("/scans")

        assert exc_info.value.status_code == 502
        assert exc_info.value.payload is None
        assert "Bad Gateway" in str(exc_info.value)

    def test_204_returns_empty_dict(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 204

        with patch.object(client._http, "request", return_value=mock_resp):
            result = client.patch("/findings/123", body={"state": "fixed"})

        assert result == {}

    def test_get_account_id_caches(self) -> None:
        client = self._make_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"account_id": "acct-456"}

        with patch.object(client._http, "request", return_value=mock_resp) as mock_req:
            first = client.get_account_id()
            second = client.get_account_id()

        assert first == "acct-456"
        assert second == "acct-456"
        assert mock_req.call_count == 1  # only one HTTP call, second was cached
