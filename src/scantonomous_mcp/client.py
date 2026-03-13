"""HTTP client for the Scantonomous REST API."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from .auth import AuthManager

logger = logging.getLogger(__name__)


class ApiError(Exception):
    """Raised when an API request fails."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"API error {status_code}: {message}")


class ScantonomousClient:
    """Authenticated HTTP client for the Scantonomous API.

    Uses the AuthManager for automatic token management and refresh.
    Extracts account_id from the JWT token claims.
    """

    def __init__(self, auth: AuthManager) -> None:
        self._auth = auth
        self._http = httpx.Client(timeout=60)
        self._account_id: str | None = None

    @property
    def base_url(self) -> str:
        return self._auth.api_base_url

    def get_account_id(self) -> str:
        """Get the current user's account_id, cached after first fetch."""
        if self._account_id:
            return self._account_id

        profile = self.get("/account/me")
        self._account_id = profile["account_id"]
        return self._account_id

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Make an authenticated GET request.

        :param path: API path (e.g. ``/scans/123``).
        :param params: Optional query parameters.
        :returns: Parsed JSON response.
        :raises ApiError: On non-2xx response.
        """
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """Make an authenticated POST request.

        :param path: API path.
        :param body: Optional JSON body.
        :returns: Parsed JSON response.
        :raises ApiError: On non-2xx response.
        """
        return self._request("POST", path, json_body=body)

    def patch(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """Make an authenticated PATCH request.

        :param path: API path.
        :param body: Optional JSON body.
        :returns: Parsed JSON response.
        :raises ApiError: On non-2xx response.
        """
        return self._request("PATCH", path, json_body=body)

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        token = self._auth.get_id_token()
        url = f"{self.base_url}{path}"

        kwargs: dict[str, Any] = {
            "headers": {"Authorization": f"Bearer {token}"},
        }
        if params:
            kwargs["params"] = params
        if json_body is not None:
            kwargs["json"] = json_body

        resp = self._http.request(method, url, **kwargs)

        if resp.status_code >= 400:
            try:
                detail = resp.json().get("message", resp.text)
            except (json.JSONDecodeError, ValueError):
                detail = resp.text
            raise ApiError(resp.status_code, detail)

        if resp.status_code == 204:
            return {}

        return resp.json()
