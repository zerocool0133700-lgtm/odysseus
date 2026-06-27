"""Flag-gate tests: AUTH_IDP_ENABLED disables password login (Phase 1c)."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.auth import AuthManager
from routes.auth_routes import setup_auth_routes


def _client(tmp_path):
    mgr = AuthManager(str(tmp_path / "auth.json"))
    mgr.create_user("dave", "password1", is_admin=True)
    app = FastAPI()
    app.include_router(setup_auth_routes(mgr))
    return TestClient(app)


def test_status_reports_idp_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTH_IDP_ENABLED", raising=False)
    resp = _client(tmp_path).get("/api/auth/status")
    assert resp.status_code == 200
    assert resp.json()["idp_enabled"] is False


def test_status_reports_idp_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_IDP_ENABLED", "true")
    resp = _client(tmp_path).get("/api/auth/status")
    assert resp.json()["idp_enabled"] is True


def test_login_403_when_idp_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_IDP_ENABLED", "true")
    resp = _client(tmp_path).post(
        "/api/auth/login", json={"username": "dave", "password": "password1"}
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body["ok"] is False
    assert "IdP" in body["error"]


def test_signup_403_when_idp_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_IDP_ENABLED", "true")
    resp = _client(tmp_path).post(
        "/api/auth/signup", json={"username": "x", "password": "password123"}
    )
    assert resp.status_code == 403


def test_login_works_when_idp_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTH_IDP_ENABLED", raising=False)
    resp = _client(tmp_path).post(
        "/api/auth/login", json={"username": "dave", "password": "password1"}
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
