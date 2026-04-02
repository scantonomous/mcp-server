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
