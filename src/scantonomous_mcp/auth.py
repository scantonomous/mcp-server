"""OAuth 2.0 Authorization Code + PKCE auth flow with keychain token storage.

The MCP server authenticates by opening the user's browser to the productweb
consent page, which redirects to Cognito /oauth2/authorize. Cognito issues an
authorization code to the localhost callback. The MCP server exchanges the code
for tokens using the Cognito /oauth2/token endpoint with PKCE verification.
The refresh token is stored in the system keychain for future sessions.
"""

from __future__ import annotations

import base64
import hashlib
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
import keyring.backends.fail
import keyring.backends.null

logger = logging.getLogger(__name__)

# Insecure keyring backends that should not be trusted with refresh tokens.
_INSECURE_BACKENDS = (
    keyring.backends.fail.Keyring,
    keyring.backends.null.Keyring,
)


def _keyring_is_secure() -> bool:
    """Return True if the active keyring backend provides encrypted storage.

    Secure backends (macOS Keychain, Windows Credential Manager, SecretService)
    have priority > 0. Insecure backends (null, fail, plaintext file) have
    priority <= 0 and should not be trusted with refresh tokens.
    """
    backend = keyring.get_keyring()
    if isinstance(backend, _INSECURE_BACKENDS):
        return False
    priority = getattr(backend, "priority", -1)
    return priority > 0


KEYRING_SERVICE = "scantonomous-mcp"
KEYRING_REFRESH_KEY = "refresh-token"
KEYRING_CONFIG_KEY = "auth-config"

# Fixed ports to match Cognito callback URL registration
CALLBACK_PORTS = [19827, 19828, 19829]

STAGE_CONFIGS: dict[str, dict[str, str]] = {
    "dev": {
        "client_id": "41o0m0h3sk9akaj1q0sqeq2di6",
        "cognito_domain": "auth.dev.scantonomous.ai",
        "api_base_url": "https://api.dev.scantonomous.ai/v1",
        "web_domain": "app.dev.scantonomous.ai",
        "region": "us-west-2",
    },
    "beta": {
        "client_id": "6sjum4hbdcrbktp10gb6pij2r3",
        "cognito_domain": "auth.beta.scantonomous.ai",
        "api_base_url": "https://api.beta.scantonomous.ai/v1",
        "web_domain": "app.beta.scantonomous.ai",
        "region": "us-west-2",
    },
    "prod": {
        "client_id": "2t0dt9q9mfcff1e2qk9eussrfq",
        "cognito_domain": "auth.scantonomous.ai",
        "api_base_url": "https://api.scantonomous.ai/v1",
        "web_domain": "app.scantonomous.ai",
        "region": "us-west-2",
    },
}


def get_default_client_id(stage: str) -> str | None:
    """Return the built-in client ID for a stage, or None if not configured."""
    client_id = STAGE_CONFIGS.get(stage, {}).get("client_id", "")
    return client_id if client_id else None


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256).

    :returns: (code_verifier, code_challenge) tuple.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


@dataclass
class TokenSet:
    """Token set with expiry tracking."""

    access_token: str
    id_token: str
    refresh_token: str | None
    expires_at: float  # epoch seconds


class AuthManager:
    """Manages OAuth 2.0 Authorization Code + PKCE auth flow.

    Opens the browser to the productweb consent page, which redirects to
    Cognito /oauth2/authorize. Cognito issues an auth code to the localhost
    callback. The code is exchanged for tokens via the /oauth2/token endpoint.
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

        if not refresh_token:
            stored = self._load_keychain_config()
            if stored:
                refresh_token = stored.get("refresh_token")

        if refresh_token:
            try:
                self._tokens = self._refresh_tokens(refresh_token)
                return self._tokens.access_token
            except AuthError:
                logger.info("Refresh token expired, re-auth required")

        raise AuthError("Not authenticated. Please run: scantonomous-mcp auth login")

    def get_id_token(self) -> str:
        """Return a valid ID token, refreshing if needed."""
        # Calling get_access_token ensures tokens are fresh
        self.get_access_token()
        if self._tokens:
            return self._tokens.id_token
        raise AuthError("Not authenticated")

    def login(self) -> None:
        """Run the browser-based OAuth 2.0 Authorization Code + PKCE login flow."""
        state = secrets.token_urlsafe(32)
        code_verifier, code_challenge = _generate_pkce()

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

        # Build the authorize URL — goes to productweb consent page, which
        # redirects to Cognito /oauth2/authorize after user approval.
        auth_params = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid profile",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        authorize_url = f"https://{self.cognito_domain}/oauth2/authorize?{auth_params}"

        logger.info("Opening browser for authorization...")
        webbrowser.open(authorize_url)

        # Wait for the callback (GET redirect with auth code from Cognito).
        # 5 minutes to allow time for login + consent.
        server.timeout = 300
        server.handle_request()

        if server.auth_error:
            raise AuthError(f"Authorization denied: {server.auth_error}")

        if not server.auth_code:
            raise AuthError("Authorization timed out. Please try again.")

        if server.callback_state != state:
            raise AuthError("State mismatch -- possible CSRF attack. Aborting.")

        # Exchange auth code for tokens via Cognito /oauth2/token
        self._tokens = self._exchange_code(
            code=server.auth_code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

        # Store refresh token in keychain (only if backend is secure)
        if self._tokens.refresh_token:
            if _keyring_is_secure():
                config_data = json.dumps(
                    {
                        "refresh_token": self._tokens.refresh_token,
                        "stage": self.stage,
                    }
                )
                keyring.set_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY, config_data)
            else:
                backend = type(keyring.get_keyring()).__name__
                logger.warning(
                    "Keyring backend '%s' is not secure — refresh token will "
                    "not be persisted. You will need to re-authenticate each "
                    "session. Install a secure keyring backend (e.g., "
                    "SecretService on Linux) to enable token persistence.",
                    backend,
                )

        logger.info("Authentication successful")

    def logout(self) -> None:
        """Clear stored tokens."""
        self._tokens = None
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
        except keyring.errors.PasswordDeleteError:  # type: ignore[attr-defined]
            pass
        # Also clean up legacy key
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_REFRESH_KEY)
        except keyring.errors.PasswordDeleteError:  # type: ignore[attr-defined]
            pass
        logger.info("Logged out successfully")

    def _load_keychain_config(self) -> dict[str, str] | None:
        """Load stored config from keychain.

        Returns None if the keyring backend is insecure.
        """
        if not _keyring_is_secure():
            return None
        raw = keyring.get_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return None

    def _exchange_code(self, code: str, redirect_uri: str, code_verifier: str) -> TokenSet:
        """Exchange authorization code for tokens via Cognito /oauth2/token.

        :param code: Authorization code from Cognito callback.
        :param redirect_uri: The redirect_uri used in the authorize request.
        :param code_verifier: PKCE code_verifier for proof.
        :returns: TokenSet with access, ID, and refresh tokens.
        :raises AuthError: If the token exchange fails.
        """
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
            raise AuthError(f"Token exchange failed: {resp.text}")

        data = resp.json()
        return TokenSet(
            access_token=data["access_token"],
            id_token=data["id_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=time.time() + data.get("expires_in", 3600),
        )

    def _refresh_tokens(self, refresh_token: str) -> TokenSet:
        """Refresh tokens using Cognito /oauth2/token endpoint.

        :param refresh_token: The stored refresh token.
        :returns: New TokenSet with refreshed access and ID tokens.
        :raises AuthError: If the refresh fails (token expired).
        """
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
            # Clear invalid config
            try:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_CONFIG_KEY)
            except keyring.errors.PasswordDeleteError:  # type: ignore[attr-defined]
                pass
            raise AuthError("Refresh token expired. Please re-authenticate.")

        data = resp.json()
        return TokenSet(
            access_token=data["access_token"],
            id_token=data["id_token"],
            refresh_token=refresh_token,  # Cognito doesn't return a new refresh token
            expires_at=time.time() + data.get("expires_in", 3600),
        )


class AuthError(Exception):
    """Raised when authentication fails or tokens are unavailable."""


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the OAuth callback — receives auth code from Cognito."""

    server: _CallbackServer  # type: ignore[assignment]

    def do_GET(self) -> None:
        """Handle GET — receives authorization code or error from Cognito."""
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
