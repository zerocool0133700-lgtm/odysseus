"""Unit tests for the IdP delegation helpers (Phase 1c)."""
import time

import httpx
import jwt
import pytest

from src import idp

SECRET = "test-shared-secret"


def _token(claims=None, secret=SECRET, **over):
    base = {
        "userId": "uuid-123",
        "email": "dave@example.com",
        "role": "admin",
        "iss": "ellie-idp",
        "aud": "odysseus",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    if claims:
        base.update(claims)
    base.update(over)
    return jwt.encode(base, secret, algorithm="HS256")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setenv("IDP_AUD", "odysseus")
    monkeypatch.setenv("IDP_BASE_URL", "http://idp.test:3006")


def test_idp_login_url_has_redirect_state_and_aud():
    url = idp.idp_login_url("abc123", "http://localhost:7000")
    assert url.startswith("http://idp.test:3006/login?")
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A7000%2Fapi%2Fauth%2Fcallback" in url
    assert "state=abc123" in url
    assert "aud=odysseus" in url


def test_verify_idp_token_accepts_valid():
    claims = idp.verify_idp_token(_token())
    assert claims["userId"] == "uuid-123"
    assert claims["email"] == "dave@example.com"
    assert claims["role"] == "admin"


def test_verify_idp_token_within_leeway():
    # expired 20s ago — inside the 30s leeway
    claims = idp.verify_idp_token(_token(exp=int(time.time()) - 20))
    assert claims["userId"] == "uuid-123"


def test_verify_idp_token_rejects_expired_beyond_leeway():
    with pytest.raises(jwt.ExpiredSignatureError):
        idp.verify_idp_token(_token(exp=int(time.time()) - 120))


def test_verify_idp_token_rejects_wrong_aud():
    with pytest.raises(jwt.InvalidAudienceError):
        idp.verify_idp_token(_token(aud="proving-ground"))


def test_verify_idp_token_rejects_wrong_iss():
    with pytest.raises(jwt.InvalidIssuerError):
        idp.verify_idp_token(_token(iss="someone-else"))


def test_verify_idp_token_rejects_wrong_secret():
    with pytest.raises(jwt.InvalidSignatureError):
        idp.verify_idp_token(_token(secret="not-the-secret"))


def test_verify_idp_token_raises_without_secret(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        idp.verify_idp_token(_token())


def test_exchange_code_returns_access_token(monkeypatch):
    def fake_post(url, json, timeout):
        assert url == "http://idp.test:3006/auth/exchange"
        assert json == {"code": "one-time"}
        assert timeout == 5.0
        return httpx.Response(200, json={"access_token": "jwt-here"})
    monkeypatch.setattr(idp.httpx, "post", fake_post)
    assert idp.exchange_code("one-time") == "jwt-here"


def test_exchange_code_retries_once_on_5xx(monkeypatch):
    calls = {"n": 0}
    def fake_post(url, json, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={})
        return httpx.Response(200, json={"access_token": "jwt-2"})
    monkeypatch.setattr(idp.httpx, "post", fake_post)
    assert idp.exchange_code("c") == "jwt-2"
    assert calls["n"] == 2


def test_exchange_code_retries_once_on_network_error(monkeypatch):
    calls = {"n": 0}
    def fake_post(url, json, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom")
        return httpx.Response(200, json={"access_token": "jwt-3"})
    monkeypatch.setattr(idp.httpx, "post", fake_post)
    assert idp.exchange_code("c") == "jwt-3"
    assert calls["n"] == 2


def test_exchange_code_no_retry_on_4xx(monkeypatch):
    calls = {"n": 0}
    def fake_post(url, json, timeout):
        calls["n"] += 1
        return httpx.Response(400, json={"error": "bad"})
    monkeypatch.setattr(idp.httpx, "post", fake_post)
    with pytest.raises(RuntimeError):
        idp.exchange_code("c")
    assert calls["n"] == 1


def test_exchange_code_raises_on_missing_token(monkeypatch):
    monkeypatch.setattr(idp.httpx, "post",
                        lambda url, json, timeout: httpx.Response(200, json={}))
    with pytest.raises(RuntimeError):
        idp.exchange_code("c")
