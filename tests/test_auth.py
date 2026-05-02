"""Tests for OAuth and keychain behavior."""

from __future__ import annotations

import json
import types
import urllib.parse
from unittest.mock import MagicMock

import keyring.backends.fail
import pytest

from scantonomous_mcp import auth


class FakeResponse:
    """Simple HTTP response stub for auth tests."""

    def __init__(
        self,
        status_code: int,
        data: dict[str, object] | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._data = data or {}
        self.text = text or json.dumps(self._data)

    def json(self) -> dict[str, object]:
        return self._data


class SecureKeyringBackend:
    """Keyring backend with positive priority."""

    priority = 1


def _make_manager(stage: str = "dev") -> auth.AuthManager:
    return auth.AuthManager(client_id="client-123", stage=stage)


def test_keyring_is_secure_rejects_insecure_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth.keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())

    assert auth._keyring_is_secure() is False


def test_keyring_is_secure_accepts_positive_priority_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auth.keyring, "get_keyring", lambda: SecureKeyringBackend())

    assert auth._keyring_is_secure() is True


@pytest.mark.parametrize(
    ("stage", "expected"),
    [
        ("dev", "41o0m0h3sk9akaj1q0sqeq2di6"),
        ("beta", "6sjum4hbdcrbktp10gb6pij2r3"),
        ("prod", "2t0dt9q9mfcff1e2qk9eussrfq"),
        ("missing", None),
    ],
)
def test_get_default_client_id(stage: str, expected: str | None) -> None:
    assert auth.get_default_client_id(stage) == expected


def test_api_base_url_uses_stage_and_falls_back_to_dev() -> None:
    assert _make_manager("beta").api_base_url == "https://api.beta.scantonomous.ai/v1"
    assert _make_manager("unknown").api_base_url == "https://api.dev.scantonomous.ai/v1"


def test_get_access_token_returns_fresh_in_memory_token(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager()
    manager._tokens = auth.TokenSet(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        expires_at=10**12,
    )
    refresh_tokens = MagicMock()
    monkeypatch.setattr(manager, "_refresh_tokens", refresh_tokens)

    assert manager.get_access_token() == "access-token"
    refresh_tokens.assert_not_called()


def test_get_access_token_refreshes_with_in_memory_refresh_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    manager._tokens = auth.TokenSet(
        access_token="expired",
        id_token="expired-id",
        refresh_token="refresh-token",
        expires_at=0,
    )
    monkeypatch.setattr(
        manager,
        "_refresh_tokens",
        MagicMock(
            return_value=auth.TokenSet(
                access_token="new-access",
                id_token="new-id",
                refresh_token="refresh-token",
                expires_at=10**12,
            )
        ),
    )

    assert manager.get_access_token() == "new-access"
    assert manager._tokens is not None
    assert manager._tokens.id_token == "new-id"


def test_get_access_token_loads_refresh_token_from_keychain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    monkeypatch.setattr(
        manager,
        "_load_keychain_config",
        MagicMock(return_value={"refresh_token": "refresh-token"}),
    )
    monkeypatch.setattr(
        manager,
        "_refresh_tokens",
        MagicMock(
            return_value=auth.TokenSet(
                access_token="new-access",
                id_token="new-id",
                refresh_token="refresh-token",
                expires_at=10**12,
            )
        ),
    )

    assert manager.get_access_token() == "new-access"
    assert manager._tokens is not None
    assert manager._tokens.id_token == "new-id"


def test_get_access_token_raises_when_refresh_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager()
    manager._tokens = auth.TokenSet(
        access_token="expired",
        id_token="expired-id",
        refresh_token="refresh-token",
        expires_at=0,
    )
    monkeypatch.setattr(
        manager,
        "_refresh_tokens",
        MagicMock(side_effect=auth.AuthError("expired")),
    )

    with pytest.raises(auth.AuthError, match="scantonomous-mcp login"):
        manager.get_access_token()


def test_get_id_token_returns_refreshed_id_token(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager()
    manager._tokens = auth.TokenSet(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        expires_at=10**12,
    )
    get_access_token = MagicMock(return_value="access-token")
    monkeypatch.setattr(manager, "get_access_token", get_access_token)

    assert manager.get_id_token() == "id-token"
    get_access_token.assert_called_once_with()


def test_get_id_token_raises_when_no_tokens_are_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    monkeypatch.setattr(manager, "get_access_token", MagicMock(return_value="access-token"))

    with pytest.raises(auth.AuthError, match="Not authenticated"):
        manager.get_id_token()


def test_load_keychain_config_returns_none_for_insecure_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    monkeypatch.setattr(auth, "_keyring_is_secure", lambda: False)

    assert manager._load_keychain_config() is None


def test_load_keychain_config_returns_none_when_entry_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    monkeypatch.setattr(auth, "_keyring_is_secure", lambda: True)
    monkeypatch.setattr(auth.keyring, "get_password", lambda _service, _key: None)

    assert manager._load_keychain_config() is None


def test_load_keychain_config_returns_none_for_invalid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    monkeypatch.setattr(auth, "_keyring_is_secure", lambda: True)
    monkeypatch.setattr(auth.keyring, "get_password", lambda _service, _key: "{bad json")

    assert manager._load_keychain_config() is None


def test_load_keychain_config_ignores_other_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager("dev")
    monkeypatch.setattr(auth, "_keyring_is_secure", lambda: True)
    monkeypatch.setattr(
        auth.keyring,
        "get_password",
        lambda _service, _key: json.dumps({"refresh_token": "refresh", "stage": "beta"}),
    )

    assert manager._load_keychain_config() is None


def test_load_keychain_config_returns_valid_data(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager("dev")
    monkeypatch.setattr(auth, "_keyring_is_secure", lambda: True)
    monkeypatch.setattr(
        auth.keyring,
        "get_password",
        lambda _service, _key: json.dumps({"refresh_token": "refresh", "stage": "dev"}),
    )

    assert manager._load_keychain_config() == {"refresh_token": "refresh", "stage": "dev"}


def test_exchange_code_posts_to_cognito_and_returns_token_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager("dev")
    monkeypatch.setattr(auth.time, "time", lambda: 1000.0)
    response = FakeResponse(
        200,
        {
            "access_token": "access-token",
            "id_token": "id-token",
            "refresh_token": "refresh-token",
            "expires_in": 1800,
        },
    )
    post = MagicMock(return_value=response)
    monkeypatch.setattr(manager._http, "post", post)

    tokens = manager._exchange_code(
        code="auth-code",
        redirect_uri="http://localhost:19827/callback",
        code_verifier="code-verifier",
    )

    post.assert_called_once_with(
        "https://auth.dev.scantonomous.ai/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "client-123",
            "code": "auth-code",
            "redirect_uri": "http://localhost:19827/callback",
            "code_verifier": "code-verifier",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert tokens == auth.TokenSet(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        expires_at=2800.0,
    )


def test_exchange_code_raises_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager("dev")
    monkeypatch.setattr(
        manager._http, "post", MagicMock(return_value=FakeResponse(400, text="bad"))
    )

    with pytest.raises(auth.AuthError, match="Token exchange failed: bad"):
        manager._exchange_code("auth-code", "http://localhost/callback", "verifier")


def test_refresh_tokens_posts_to_cognito_and_preserves_refresh_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager("beta")
    monkeypatch.setattr(auth.time, "time", lambda: 2000.0)
    response = FakeResponse(
        200,
        {
            "access_token": "access-token",
            "id_token": "id-token",
            "expires_in": 900,
        },
    )
    post = MagicMock(return_value=response)
    monkeypatch.setattr(manager._http, "post", post)

    tokens = manager._refresh_tokens("refresh-token")

    post.assert_called_once_with(
        "https://auth.beta.scantonomous.ai/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "client-123",
            "refresh_token": "refresh-token",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert tokens == auth.TokenSet(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        expires_at=2900.0,
    )


def test_refresh_tokens_clears_keychain_and_raises_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    delete_password = MagicMock()
    monkeypatch.setattr(auth.keyring, "delete_password", delete_password)
    monkeypatch.setattr(
        manager._http,
        "post",
        MagicMock(return_value=FakeResponse(401, text="expired")),
    )

    with pytest.raises(auth.AuthError, match="Refresh token expired"):
        manager._refresh_tokens("refresh-token")

    delete_password.assert_called_once_with(auth.KEYRING_SERVICE, auth.KEYRING_CONFIG_KEY)


def test_login_uses_first_available_port_and_persists_refresh_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager("dev")
    attempted_ports: list[int] = []
    opened_urls: list[str] = []
    saved_keyring: dict[str, str] = {}

    class FakeCallbackServer:
        def __init__(self) -> None:
            self.auth_code = "auth-code"
            self.auth_error = None
            self.callback_state = "expected-state"
            self.timeout: int | None = None

        def handle_request(self) -> None:
            return None

    def fake_callback_server(
        address: tuple[str, int],
        _handler: type[auth._CallbackHandler],
    ) -> FakeCallbackServer:
        attempted_ports.append(address[1])
        if address[1] == auth.CALLBACK_PORTS[0]:
            raise OSError("busy")
        return FakeCallbackServer()

    exchanged_tokens = auth.TokenSet(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        expires_at=10**12,
    )
    exchange_code = MagicMock(return_value=exchanged_tokens)

    monkeypatch.setattr(auth.secrets, "token_urlsafe", lambda _size: "expected-state")
    monkeypatch.setattr(auth, "_generate_pkce", lambda: ("code-verifier", "code-challenge"))
    monkeypatch.setattr(auth, "_CallbackServer", fake_callback_server)
    monkeypatch.setattr(auth.webbrowser, "open", opened_urls.append)
    monkeypatch.setattr(manager, "_exchange_code", exchange_code)
    monkeypatch.setattr(auth, "_keyring_is_secure", lambda: True)
    monkeypatch.setattr(
        auth.keyring,
        "set_password",
        lambda service, key, value: saved_keyring.update(
            {"service": service, "key": key, "value": value}
        ),
    )

    manager.login()

    assert attempted_ports == [auth.CALLBACK_PORTS[0], auth.CALLBACK_PORTS[1]]
    assert manager._tokens == exchanged_tokens
    parsed = urllib.parse.urlparse(opened_urls[0])
    params = urllib.parse.parse_qs(parsed.query)
    assert parsed.netloc == "app.dev.scantonomous.ai"
    assert parsed.path == "/authorize"
    assert params == {
        "client_id": ["client-123"],
        "redirect_uri": [f"http://localhost:{auth.CALLBACK_PORTS[1]}/callback"],
        "response_type": ["code"],
        "scope": ["openid profile"],
        "state": ["expected-state"],
        "code_challenge": ["code-challenge"],
        "code_challenge_method": ["S256"],
    }
    exchange_code.assert_called_once_with(
        code="auth-code",
        redirect_uri=f"http://localhost:{auth.CALLBACK_PORTS[1]}/callback",
        code_verifier="code-verifier",
    )
    assert saved_keyring["service"] == auth.KEYRING_SERVICE
    assert saved_keyring["key"] == auth.KEYRING_CONFIG_KEY
    assert json.loads(saved_keyring["value"]) == {
        "refresh_token": "refresh-token",
        "stage": "dev",
    }


def test_login_raises_when_no_callback_port_is_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()

    def always_busy(
        _address: tuple[str, int],
        _handler: type[auth._CallbackHandler],
    ) -> object:
        raise OSError("busy")

    monkeypatch.setattr(auth, "_CallbackServer", always_busy)

    with pytest.raises(auth.AuthError, match="Could not bind to any callback port"):
        manager.login()


def test_login_raises_on_provider_error(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager()

    class FakeCallbackServer:
        def __init__(self) -> None:
            self.auth_code = None
            self.auth_error = "access_denied"
            self.callback_state = None
            self.timeout: int | None = None

        def handle_request(self) -> None:
            return None

    monkeypatch.setattr(auth, "_CallbackServer", lambda _address, _handler: FakeCallbackServer())
    monkeypatch.setattr(auth.webbrowser, "open", lambda _url: True)

    with pytest.raises(auth.AuthError, match="Authorization denied: access_denied"):
        manager.login()


def test_login_raises_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager()

    class FakeCallbackServer:
        def __init__(self) -> None:
            self.auth_code = None
            self.auth_error = None
            self.callback_state = None
            self.timeout: int | None = None

        def handle_request(self) -> None:
            return None

    monkeypatch.setattr(auth, "_CallbackServer", lambda _address, _handler: FakeCallbackServer())
    monkeypatch.setattr(auth.webbrowser, "open", lambda _url: True)

    with pytest.raises(auth.AuthError, match="Authorization timed out"):
        manager.login()


def test_login_raises_on_state_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _make_manager()

    class FakeCallbackServer:
        def __init__(self) -> None:
            self.auth_code = "auth-code"
            self.auth_error = None
            self.callback_state = "unexpected-state"
            self.timeout: int | None = None

        def handle_request(self) -> None:
            return None

    monkeypatch.setattr(auth.secrets, "token_urlsafe", lambda _size: "expected-state")
    monkeypatch.setattr(auth, "_generate_pkce", lambda: ("code-verifier", "code-challenge"))
    monkeypatch.setattr(auth, "_CallbackServer", lambda _address, _handler: FakeCallbackServer())
    monkeypatch.setattr(auth.webbrowser, "open", lambda _url: True)

    with pytest.raises(auth.AuthError, match="State mismatch"):
        manager.login()


def test_logout_clears_tokens_and_swallows_delete_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _make_manager()
    manager._tokens = auth.TokenSet(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        expires_at=10**12,
    )
    delete_calls: list[tuple[str, str]] = []

    def delete_password(service: str, key: str) -> None:
        delete_calls.append((service, key))
        raise auth.keyring.errors.PasswordDeleteError("missing")

    monkeypatch.setattr(auth.keyring, "delete_password", delete_password)

    manager.logout()

    assert manager._tokens is None
    assert delete_calls == [
        (auth.KEYRING_SERVICE, auth.KEYRING_CONFIG_KEY),
        (auth.KEYRING_SERVICE, auth.KEYRING_REFRESH_KEY),
    ]
