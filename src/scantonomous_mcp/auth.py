"""Token relay auth flow with keychain token storage.

The MCP server authenticates by opening the user's browser to the productweb
consent page. After the user approves, productweb relays its Amplify session
tokens (access, ID, refresh) to a localhost callback via a hidden form POST.
The refresh token is stored in the system keychain for future sessions.
"""

from __future__ import annotations

import http.server
import json
import logging
import secrets
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
        "region": "us-west-2",
    },
    "beta": {
        "client_id": "",  # Set after beta deploy
        "cognito_domain": "scntnms-beta.auth.us-west-2.amazoncognito.com",
        "api_base_url": "https://beta.scntnms.services/v1",
        "web_domain": "web.beta.scntnms.services",
        "region": "us-west-2",
    },
    "prod": {
        "client_id": "",  # Set after prod deploy
        "cognito_domain": "scntnms-prod.auth.us-west-2.amazoncognito.com",
        "api_base_url": "https://scntnms.services/v1",
        "web_domain": "web.scntnms.services",
        "region": "us-west-2",
    },
}


def get_default_client_id(stage: str) -> str | None:
    """Return the built-in client ID for a stage, or None if not configured."""
    client_id = STAGE_CONFIGS.get(stage, {}).get("client_id", "")
    return client_id if client_id else None


@dataclass
class TokenSet:
    """Token set with expiry tracking."""

    access_token: str
    id_token: str
    refresh_token: str | None
    token_client_id: str | None  # Cognito client ID that issued the tokens
    expires_at: float  # epoch seconds


class AuthManager:
    """Manages token relay auth flow.

    Opens the browser to the productweb consent page, receives relayed Amplify
    tokens via localhost POST callback, and handles automatic token refresh.
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
        self.region = stage_cfg["region"]
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
        token_client_id = self._tokens.token_client_id if self._tokens else None

        if not refresh_token:
            stored = self._load_keychain_config()
            if stored:
                refresh_token = stored.get("refresh_token")
                token_client_id = stored.get("token_client_id")

        if refresh_token and token_client_id:
            try:
                self._tokens = self._refresh_tokens(refresh_token, token_client_id)
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
        """Run the browser-based token relay login flow."""
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

        # Build the authorize URL — goes to productweb consent page
        auth_params = urllib.parse.urlencode({
            "redirect_uri": redirect_uri,
            "state": state,
        })
        authorize_url = f"https://{self.web_domain}/authorize?{auth_params}"

        logger.info("Opening browser for authorization...")
        webbrowser.open(authorize_url)

        # Wait for the callback (GET redirect with tokens from productweb).
        # 5 minutes to allow time for login + consent.
        server.timeout = 300
        server.handle_request()

        if not server.access_token:
            raise AuthError(
                server.auth_error or "Authorization timed out. Please try again."
            )

        if server.callback_state != state:
            raise AuthError("State mismatch -- possible CSRF attack. Aborting.")

        self._tokens = TokenSet(
            access_token=server.access_token,
            id_token=server.id_token or "",
            refresh_token=server.refresh_token,
            token_client_id=server.token_client_id,
            expires_at=time.time() + 900,  # Productweb tokens: ~15 min
        )

        # Store refresh token and config in keychain
        if self._tokens.refresh_token:
            config_data = json.dumps({
                "refresh_token": self._tokens.refresh_token,
                "token_client_id": self._tokens.token_client_id,
                "stage": self.stage,
            })
            keyring.set_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY, config_data)

        logger.info("Authentication successful")

    def logout(self) -> None:
        """Clear stored tokens."""
        self._tokens = None
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
        except keyring.errors.PasswordDeleteError:
            pass
        # Also clean up legacy key
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_KEY)
        except keyring.errors.PasswordDeleteError:
            pass
        logger.info("Logged out successfully")

    def _load_keychain_config(self) -> dict[str, str] | None:
        """Load stored config from keychain."""
        raw = keyring.get_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None

    def _refresh_tokens(self, refresh_token: str, token_client_id: str) -> TokenSet:
        """Refresh tokens using Cognito InitiateAuth API.

        The refresh token was issued by Amplify (SRP flow), so we use the
        Cognito service API rather than the hosted UI /oauth2/token endpoint.
        """
        resp = self._http.post(
            f"https://cognito-idp.{self.region}.amazonaws.com/",
            json={
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "ClientId": token_client_id,
                "AuthParameters": {
                    "REFRESH_TOKEN": refresh_token,
                },
            },
            headers={
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
            },
        )
        if resp.status_code != 200:
            # Clear invalid config
            try:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
            except keyring.errors.PasswordDeleteError:
                pass
            raise AuthError("Refresh token expired. Please re-authenticate.")

        data = resp.json()
        result = data.get("AuthenticationResult", {})
        return TokenSet(
            access_token=result["AccessToken"],
            id_token=result["IdToken"],
            refresh_token=refresh_token,
            token_client_id=token_client_id,
            expires_at=time.time() + result.get("ExpiresIn", 900),
        )


class AuthError(Exception):
    """Raised when authentication fails or tokens are unavailable."""


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the token relay callback."""

    server: _CallbackServer  # type: ignore[assignment]

    def do_GET(self) -> None:
        """Handle GET — receives redirected tokens or deny/error."""
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_error(404)
            return

        params = urllib.parse.parse_qs(parsed.query)

        if "error" in params:
            self.server.auth_error = params["error"][0]
            self._respond("Authorization denied. You can close this tab.")
            return

        access_token = params.get("access_token", [None])[0]
        id_token = params.get("id_token", [None])[0]
        refresh_token = params.get("refresh_token", [None])[0]
        token_client_id = params.get("token_client_id", [None])[0]
        state = params.get("state", [None])[0]

        if access_token:
            self.server.access_token = access_token
            self.server.id_token = id_token
            self.server.refresh_token = refresh_token if refresh_token else None
            self.server.token_client_id = token_client_id
            self.server.callback_state = state
            self._respond(
                "Authorization successful! You can close this tab and return to your terminal."
            )
        else:
            self.server.auth_error = "No tokens received"
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
    """HTTP server that captures the token relay callback."""

    access_token: str | None = None
    id_token: str | None = None
    refresh_token: str | None = None
    token_client_id: str | None = None
    auth_error: str | None = None
    callback_state: str | None = None
