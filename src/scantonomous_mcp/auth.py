"""OAuth 2.0 Authorization Code + PKCE flow with keychain token storage."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import logging
import os
import secrets
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from typing import Any

import httpx
import keyring

logger = logging.getLogger(__name__)

KEYRING_SERVICE = "scantonomous-mcp"
KEYRING_REFRESH_KEY = "refresh-token"
KEYRING_CONFIG_KEY = "auth-config"

# Fixed ports to match Cognito callback URL registration
CALLBACK_PORTS = [19827, 19828, 19829]

STAGE_CONFIGS: dict[str, dict[str, str]] = {
    "dev": {
        "client_id": "41o0m0h3sk9akaj1q0sqeq2di6",
        "cognito_domain": "scntnms-dev.auth.us-west-2.amazoncognito.com",
        "api_base_url": "https://dev.scntnms.services/v1",
        "web_domain": "web.dev.scntnms.services",
    },
    "beta": {
        "client_id": "",  # Set after beta deploy
        "cognito_domain": "scntnms-beta.auth.us-west-2.amazoncognito.com",
        "api_base_url": "https://beta.scntnms.services/v1",
        "web_domain": "web.beta.scntnms.services",
    },
    "prod": {
        "client_id": "",  # Set after prod deploy
        "cognito_domain": "scntnms-prod.auth.us-west-2.amazoncognito.com",
        "api_base_url": "https://scntnms.services/v1",
        "web_domain": "web.scntnms.services",
    },
}


def get_default_client_id(stage: str) -> str | None:
    """Return the built-in client ID for a stage, or None if not configured."""
    client_id = STAGE_CONFIGS.get(stage, {}).get("client_id", "")
    return client_id if client_id else None


@dataclass
class TokenSet:
    """OAuth token set with expiry tracking."""

    access_token: str
    id_token: str
    refresh_token: str | None
    expires_at: float  # epoch seconds


class AuthManager:
    """Manages OAuth 2.0 Authorization Code + PKCE flow.

    Handles browser-based login, token exchange, keychain storage,
    and automatic token refresh.
    """

    def __init__(
        self,
        client_id: str,
        stage: str = "dev",
    ) -> None:
        self.client_id = client_id
        self.stage = stage
        stage_cfg = STAGE_CONFIGS.get(stage, STAGE_CONFIGS["dev"])
        self.cognito_domain = stage_cfg["cognito_domain"]
        self.web_domain = stage_cfg["web_domain"]
        self._tokens: TokenSet | None = None
        self._http = httpx.Client(timeout=30)

    @property
    def api_base_url(self) -> str:
        return STAGE_CONFIGS.get(self.stage, STAGE_CONFIGS["dev"])["api_base_url"]

    def get_access_token(self) -> str:
        """Return a valid access token, refreshing if needed.

        :returns: Bearer access token.
        :raises AuthError: If no valid tokens and re-auth is required.
        """
        if self._tokens and self._tokens.expires_at > time.time() + 60:
            return self._tokens.access_token

        # Try refresh from keychain
        refresh_token = self._tokens.refresh_token if self._tokens else None
        if not refresh_token:
            refresh_token = keyring.get_password(KEYRING_SERVICE, KEYRING_REFRESH_KEY)

        if refresh_token:
            try:
                self._tokens = self._refresh_tokens(refresh_token)
                return self._tokens.access_token
            except AuthError:
                logger.info("Refresh token expired, re-auth required")

        raise AuthError(
            "Not authenticated. Please run: scantonomous-mcp auth login"
        )

    def get_id_token(self) -> str:
        """Return a valid ID token, refreshing if needed."""
        # Calling get_access_token ensures tokens are fresh
        self.get_access_token()
        if self._tokens:
            return self._tokens.id_token
        raise AuthError("Not authenticated")

    def login(self) -> None:
        """Run the browser-based OAuth login flow."""
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        state = secrets.token_urlsafe(32)

        # Find an available port
        server = None
        port = None
        for p in CALLBACK_PORTS:
            try:
                server = _CallbackServer(("127.0.0.1", p), _CallbackHandler)
                port = p
                break
            except OSError:
                continue

        if server is None or port is None:
            raise AuthError(
                f"Could not bind to any callback port ({CALLBACK_PORTS}). "
                "Close other scantonomous-mcp processes and try again."
            )

        redirect_uri = f"http://localhost:{port}/callback"

        # Build the authorize URL — goes through productweb consent page
        auth_params = urllib.parse.urlencode({
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        })
        authorize_url = f"https://{self.web_domain}/authorize?{auth_params}"

        logger.info("Opening browser for authorization...")
        webbrowser.open(authorize_url)

        # Wait for the callback
        server.timeout = 120
        server_thread = threading.Thread(target=server.handle_request, daemon=True)
        server_thread.start()
        server_thread.join(timeout=120)

        if not server.auth_code:
            raise AuthError(
                server.auth_error or "Authorization timed out. Please try again."
            )

        if server.callback_state != state:
            raise AuthError("State mismatch — possible CSRF attack. Aborting.")

        # Exchange auth code for tokens
        self._tokens = self._exchange_code(
            server.auth_code, redirect_uri, code_verifier
        )

        # Store refresh token in keychain
        if self._tokens.refresh_token:
            keyring.set_password(
                KEYRING_SERVICE, KEYRING_REFRESH_KEY, self._tokens.refresh_token
            )

        # Store config for future sessions
        config_data = json.dumps({
            "client_id": self.client_id,
            "stage": self.stage,
        })
        keyring.set_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY, config_data)

        logger.info("Authentication successful")

    def logout(self) -> None:
        """Clear stored tokens."""
        self._tokens = None
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_KEY)
        except keyring.errors.PasswordDeleteError:
            pass
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
        except keyring.errors.PasswordDeleteError:
            pass
        logger.info("Logged out successfully")

    def _exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str
    ) -> TokenSet:
        """Exchange authorization code for tokens via Cognito token endpoint."""
        resp = self._http.post(
            f"https://{self.cognito_domain}/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            raise AuthError(f"Token exchange failed: {resp.status_code} {resp.text}")

        data = resp.json()
        return TokenSet(
            access_token=data["access_token"],
            id_token=data["id_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=time.time() + data.get("expires_in", 3600),
        )

    def _refresh_tokens(self, refresh_token: str) -> TokenSet:
        """Refresh tokens using a refresh token."""
        resp = self._http.post(
            f"https://{self.cognito_domain}/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            # Clear invalid refresh token
            try:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_KEY)
            except keyring.errors.PasswordDeleteError:
                pass
            raise AuthError("Refresh token expired. Please re-authenticate.")

        data = resp.json()
        return TokenSet(
            access_token=data["access_token"],
            id_token=data["id_token"],
            # Cognito doesn't return a new refresh token on refresh
            refresh_token=refresh_token,
            expires_at=time.time() + data.get("expires_in", 3600),
        )


class AuthError(Exception):
    """Raised when authentication fails or tokens are unavailable."""


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the OAuth callback."""

    server: _CallbackServer  # type: ignore[assignment]

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_error(404)
            return

        params = urllib.parse.parse_qs(parsed.query)

        if "error" in params:
            self.server.auth_error = params["error"][0]
            self._respond("Authorization denied. You can close this tab.")
            return

        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]

        if code:
            self.server.auth_code = code
            self.server.callback_state = state
            self._respond(
                "Authorization successful! You can close this tab and return to your terminal."
            )
        else:
            self.server.auth_error = "No authorization code received"
            self._respond("Authorization failed. Please try again.")

    def _respond(self, message: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        html = f"""<!DOCTYPE html>
<html><head><title>Scantonomous MCP</title>
<style>body{{font-family:system-ui;display:flex;justify-content:center;
align-items:center;height:100vh;margin:0;background:#f8f9fa}}
.card{{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);
text-align:center;max-width:400px}}</style></head>
<body><div class="card"><h2>Scantonomous</h2><p>{message}</p></div></body></html>"""
        self.wfile.write(html.encode())

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default HTTP server logging
        pass


class _CallbackServer(http.server.HTTPServer):
    """HTTP server that captures the OAuth callback."""

    auth_code: str | None = None
    auth_error: str | None = None
    callback_state: str | None = None
