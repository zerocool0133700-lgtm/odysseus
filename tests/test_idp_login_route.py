"""TestClient tests for GET /api/auth/idp-login (Phase 1c)."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.auth import AuthManager
from routes.idp_routes import setup_idp_routes, IDP_STATE_COOKIE


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("IDP_BASE_URL", "http://idp.test:3006")
    monkeypatch.setenv("IDP_AUD", "odysseus")
    mgr = AuthManager(str(tmp_path / "auth.json"))
    mgr.create_user("dave", "password1", is_admin=True)
    app = FastAPI()
    app.include_router(setup_idp_routes(mgr))
    return TestClient(app)


def test_idp_login_redirects_to_idp_with_state_cookie(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    resp = client.get("/api/auth/idp-login", follow_redirects=False)
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert loc.startswith("http://idp.test:3006/login?")
    assert "aud=odysseus" in loc
    assert "%2Fapi%2Fauth%2Fcallback" in loc
    # state cookie set, scoped to the callback path, lax
    set_cookie = resp.headers["set-cookie"]
    assert f"{IDP_STATE_COOKIE}=" in set_cookie
    assert "Path=/api/auth/callback" in set_cookie
    assert "samesite=lax" in set_cookie.lower()
    assert "httponly" in set_cookie.lower()
    # the state value in the cookie must match the state in the redirect URL
    state_in_cookie = set_cookie.split(f"{IDP_STATE_COOKIE}=")[1].split(";")[0]
    assert f"state={state_in_cookie}" in loc
