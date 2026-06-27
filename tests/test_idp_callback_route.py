"""TestClient tests for GET /api/auth/callback (Phase 1c)."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.idp_routes as idp_routes
from core.auth import AuthManager
from routes.idp_routes import setup_idp_routes, IDP_STATE_COOKIE


def _setup(tmp_path, monkeypatch, claims=None, exchange=None, verify=None):
    monkeypatch.setenv("IDP_AUD", "odysseus")
    monkeypatch.delenv("ODYSSEUS_IDP_OWNER", raising=False)
    mgr = AuthManager(str(tmp_path / "auth.json"))
    mgr.create_user("dave", "password1", is_admin=True)
    monkeypatch.setattr(idp_routes, "exchange_code",
                        exchange or (lambda code: "fake-jwt"))
    monkeypatch.setattr(idp_routes, "verify_idp_token",
                        verify or (lambda token: claims or
                                   {"userId": "uuid-7", "email": "dave@example.com", "role": "admin"}))
    app = FastAPI()
    app.include_router(setup_idp_routes(mgr))
    client = TestClient(app)
    return client, mgr


def test_callback_happy_path_mints_session_and_records_identity(tmp_path, monkeypatch):
    client, mgr = _setup(tmp_path, monkeypatch)
    client.cookies.set(IDP_STATE_COOKIE, "st8", path="/api/auth/callback")
    resp = client.get("/api/auth/callback?code=c&state=st8", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    set_cookie = resp.headers["set-cookie"]
    assert "odysseus_session=" in set_cookie
    # the minted session resolves to the configured owner
    token = set_cookie.split("odysseus_session=")[1].split(";")[0]
    assert mgr.get_username_for_token(token) == "dave"
    # identity recorded on the user
    assert mgr._config["users"]["dave"]["idp_user_id"] == "uuid-7"
    assert mgr._config["users"]["dave"]["email"] == "dave@example.com"


def test_callback_rejects_bad_state(tmp_path, monkeypatch):
    client, mgr = _setup(tmp_path, monkeypatch)
    client.cookies.set(IDP_STATE_COOKIE, "real", path="/api/auth/callback")
    resp = client.get("/api/auth/callback?code=c&state=forged", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/?login_error=idp_state"
    assert "odysseus_session=" not in resp.headers.get("set-cookie", "")


def test_callback_missing_state_cookie(tmp_path, monkeypatch):
    client, mgr = _setup(tmp_path, monkeypatch)
    resp = client.get("/api/auth/callback?code=c&state=st8", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/?login_error=idp_state"


def test_callback_exchange_failure_no_session(tmp_path, monkeypatch):
    def boom(code):
        raise RuntimeError("exchange down")
    client, mgr = _setup(tmp_path, monkeypatch, exchange=boom)
    client.cookies.set(IDP_STATE_COOKIE, "st8", path="/api/auth/callback")
    resp = client.get("/api/auth/callback?code=c&state=st8", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/?login_error=idp"
    assert "odysseus_session=" not in resp.headers.get("set-cookie", "")


def test_callback_verify_failure_no_session(tmp_path, monkeypatch):
    def bad(token):
        raise RuntimeError("bad token")
    client, mgr = _setup(tmp_path, monkeypatch, verify=bad)
    client.cookies.set(IDP_STATE_COOKIE, "st8", path="/api/auth/callback")
    resp = client.get("/api/auth/callback?code=c&state=st8", follow_redirects=False)
    assert resp.headers["location"] == "/?login_error=idp"


def test_callback_owner_resolution_failure(tmp_path, monkeypatch):
    # add a second user so sole-user fallback fails and no owner is configured
    client, mgr = _setup(tmp_path, monkeypatch)
    mgr.create_user("alice", "password2", is_admin=False)
    client.cookies.set(IDP_STATE_COOKIE, "st8", path="/api/auth/callback")
    resp = client.get("/api/auth/callback?code=c&state=st8", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/?login_error=idp_owner"
    assert "odysseus_session=" not in resp.headers.get("set-cookie", "")
