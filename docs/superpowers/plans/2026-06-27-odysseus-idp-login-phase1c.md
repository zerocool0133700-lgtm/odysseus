# Odysseus → Central IdP Login Delegation (Phase 1c) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Odysseus delegate interactive login to the central Ellie IdP (`ellie-idp`, `:3006`) while keeping its own opaque server-side session — swap the password gate for an IdP redirect+callback that maps the IdP identity onto one configured Odysseus owner.

**Architecture:** Login-only delegation. A new `src/idp.py` (PyJWT + httpx helpers) and `routes/idp_routes.py` (two GET routes: `/api/auth/idp-login`, `/api/auth/callback`) sit in front of the unchanged `AuthMiddleware`/opaque-session machinery. The callback exchanges the one-time code, verifies the HS256 JWT, resolves a single configured owner (`ODYSSEUS_IDP_OWNER`), records the IdP identity on that user's `auth.json` entry for audit, and mints the existing `odysseus_session`. Per-request auth is untouched (no per-request JWT → no confused-deputy).

**Tech Stack:** Python 3 / FastAPI / Starlette, PyJWT (new dep), httpx (present), pytest + Starlette `TestClient`, bcrypt file-based auth (`data/auth.json`, `data/sessions.json`).

## Global Constraints

- **Login only.** Do not touch `AuthMiddleware` (`app.py:272-386`), `validate_token`, `get_username_for_token`, `create_session_trusted`, the `odysseus_session` cookie mechanics, the `ody_…` bearer-token path, or owner-scoped data models.
- **Feature flag `AUTH_IDP_ENABLED`** (default `false`). Everything new is inert when off; password login must still work unchanged when off (no regression).
- **Session cookie name is `odysseus_session`** — single-source it by importing `SESSION_COOKIE` from `routes.auth_routes`. Never hardcode the literal in new code.
- **State cookie `odysseus_idp_state`:** `httponly; samesite=lax; secure=(SECURE_COOKIES==true); path=/api/auth/callback; max_age=300`. Value = `secrets.token_hex(32)`. Compared with `secrets.compare_digest` against `?state=`; cleared (delete_cookie, same path) on **both** success and failure.
- **JWT verify:** `algorithms=["HS256"]`, `issuer="ellie-idp"`, `audience=IDP_AUD`, `leeway=30`. Verify before trusting; never persist the IdP JWT.
- **`aud=odysseus` end-to-end** (`IDP_AUD`, default `"odysseus"`).
- **Owner resolution is server-side only** (`ODYSSEUS_IDP_OWNER` env or sole-user fallback) — never derived from the JWT/user input.
- **Env defaults:** `IDP_BASE_URL` default `http://127.0.0.1:3006`; `IDP_AUD` default `odysseus`; `AUTH_IDP_ENABLED` default `false`; `JWT_SECRET` **required** (raise if unset when used) and must equal the IdP's `LIFE_JWT_SECRET`. Never commit a secret value.
- **Secure-cookie helper:** new code reads `os.getenv("SECURE_COOKIES", "false").lower() == "true"` (matches `routes/auth_routes.py:147`).
- **Fork discipline:** work on this worktree's `feat/idp-login` branch (off `fork/dev`). PRs target `zerocool0133700-lgtm/odysseus` `dev`. Never push to `origin` (read-only upstream).
- **No DB schema change.** Username stays the owner key. `idp_user_id`/`email` are additive optional fields on `auth.json` user records.
- Tests: `pytest tests/<file>::<test> -v` from the worktree root. Construct `AuthManager(str(tmp_path / "auth.json"))` for isolation.

---

### Task 1: `src/idp.py` — IdP helper functions + PyJWT dependency

**Files:**
- Create: `src/idp.py`
- Create: `tests/test_idp_helpers.py`
- Modify: `requirements.txt` (add `PyJWT`)

**Interfaces:**
- Consumes: env vars `IDP_BASE_URL`, `IDP_AUD`, `JWT_SECRET`; libraries `jwt` (PyJWT), `httpx`.
- Produces:
  - `idp_login_url(state: str, origin: str) -> str`
  - `verify_idp_token(token: str) -> dict` → `{"userId": str|None, "email": str|None, "role": str|None}`; raises `jwt.PyJWTError` subclasses on bad iss/aud/exp/sig or `RuntimeError` if `JWT_SECRET` unset.
  - `exchange_code(code: str) -> str` → access token string; raises `RuntimeError` on missing token / repeated failure.

- [ ] **Step 1: Add the dependency**

In `requirements.txt`, add a line (alphabetical-ish, near other libs):

```
PyJWT
```

- [ ] **Step 2: Install it**

Run: `pip install PyJWT`
Expected: `Successfully installed PyJWT-2.x`

- [ ] **Step 3: Write the failing tests**

Create `tests/test_idp_helpers.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `pytest tests/test_idp_helpers.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'src.idp'`

- [ ] **Step 5: Write `src/idp.py`**

```python
"""Central-IdP login delegation helpers (Phase 1c).

Login-only: these helpers build the IdP login URL, verify the HS256 access
JWT the IdP issues, and exchange the one-time code for that JWT. The verified
identity is mapped onto a single Odysseus owner by the callback route; the JWT
itself is never persisted.
"""
import os
from urllib.parse import urlencode

import httpx
import jwt


def _idp_base_url() -> str:
    return os.getenv("IDP_BASE_URL", "http://127.0.0.1:3006").rstrip("/")


def _idp_aud() -> str:
    return os.getenv("IDP_AUD", "odysseus")


def _jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError(
            "JWT_SECRET is not set (must equal the IdP's LIFE_JWT_SECRET)"
        )
    return secret


def idp_login_url(state: str, origin: str) -> str:
    """Build the IdP login URL for a top-level browser redirect."""
    redirect_uri = f"{origin.rstrip('/')}/api/auth/callback"
    query = urlencode(
        {"redirect_uri": redirect_uri, "state": state, "aud": _idp_aud()}
    )
    return f"{_idp_base_url()}/login?{query}"


def verify_idp_token(token: str) -> dict:
    """Verify the IdP's HS256 access JWT; return selected claims.

    Raises jwt.PyJWTError subclasses on bad iss/aud/exp/signature, or
    RuntimeError if JWT_SECRET is unset.
    """
    claims = jwt.decode(
        token,
        _jwt_secret(),
        algorithms=["HS256"],
        issuer="ellie-idp",
        audience=_idp_aud(),
        leeway=30,
    )
    return {
        "userId": claims.get("userId"),
        "email": claims.get("email"),
        "role": claims.get("role"),
    }


def exchange_code(code: str) -> str:
    """Exchange the IdP one-time code for an access token (server-to-server).

    5s timeout; one retry on network error or 5xx; no retry on 4xx.
    """
    url = f"{_idp_base_url()}/auth/exchange"
    last_error = None
    for attempt in range(2):
        try:
            resp = httpx.post(url, json={"code": code}, timeout=5.0)
        except httpx.RequestError as exc:
            last_error = exc
            continue  # retry once on network error
        if resp.status_code >= 500:
            last_error = RuntimeError(f"IdP exchange {resp.status_code}")
            continue  # retry once on 5xx
        if resp.status_code >= 400:
            raise RuntimeError(f"IdP exchange failed: {resp.status_code}")  # no retry on 4xx
        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError("IdP exchange response missing access_token")
        return token
    raise RuntimeError(f"IdP exchange failed after retry: {last_error}")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_idp_helpers.py -v`
Expected: PASS (14 passed)

- [ ] **Step 7: Commit**

```bash
git add src/idp.py tests/test_idp_helpers.py requirements.txt
git commit -m "feat(idp): add src/idp.py login/verify/exchange helpers + PyJWT"
```

---

### Task 2: Owner resolution + identity record in `core/auth.py`

**Files:**
- Modify: `core/auth.py` (add two methods to `AuthManager`)
- Create: `tests/test_idp_owner_resolution.py`

**Interfaces:**
- Consumes: `self._config["users"]` (the live user dict), `self._config_lock`, `self._save()`, env `ODYSSEUS_IDP_OWNER`.
- Produces:
  - `AuthManager.resolve_idp_owner(self) -> str` — raises `ValueError` when ambiguous/none/unknown configured user.
  - `AuthManager.record_idp_identity(self, username: str, idp_user_id: Optional[str], email: Optional[str]) -> None`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_idp_owner_resolution.py`:

```python
"""Tests for IdP owner resolution + identity record (Phase 1c)."""
import pytest

from core.auth import AuthManager


def _mgr(tmp_path):
    return AuthManager(str(tmp_path / "auth.json"))


def test_resolve_sole_user(tmp_path, monkeypatch):
    monkeypatch.delenv("ODYSSEUS_IDP_OWNER", raising=False)
    mgr = _mgr(tmp_path)
    assert mgr.create_user("dave", "password1", is_admin=True)
    assert mgr.resolve_idp_owner() == "dave"


def test_resolve_configured_owner(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    mgr.create_user("dave", "password1", is_admin=True)
    mgr.create_user("alice", "password2", is_admin=False)
    monkeypatch.setenv("ODYSSEUS_IDP_OWNER", "alice")
    assert mgr.resolve_idp_owner() == "alice"


def test_resolve_configured_owner_is_case_insensitive(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    mgr.create_user("dave", "password1", is_admin=True)
    monkeypatch.setenv("ODYSSEUS_IDP_OWNER", "DAVE")
    assert mgr.resolve_idp_owner() == "dave"


def test_resolve_raises_when_configured_user_missing(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path)
    mgr.create_user("dave", "password1", is_admin=True)
    monkeypatch.setenv("ODYSSEUS_IDP_OWNER", "ghost")
    with pytest.raises(ValueError):
        mgr.resolve_idp_owner()


def test_resolve_raises_when_ambiguous(tmp_path, monkeypatch):
    monkeypatch.delenv("ODYSSEUS_IDP_OWNER", raising=False)
    mgr = _mgr(tmp_path)
    mgr.create_user("dave", "password1", is_admin=True)
    mgr.create_user("alice", "password2", is_admin=False)
    with pytest.raises(ValueError):
        mgr.resolve_idp_owner()


def test_resolve_raises_when_no_users(tmp_path, monkeypatch):
    monkeypatch.delenv("ODYSSEUS_IDP_OWNER", raising=False)
    mgr = _mgr(tmp_path)
    with pytest.raises(ValueError):
        mgr.resolve_idp_owner()


def test_record_idp_identity_persists(tmp_path):
    mgr = _mgr(tmp_path)
    mgr.create_user("dave", "password1", is_admin=True)
    mgr.record_idp_identity("dave", "uuid-9", "dave@example.com")
    # reload from disk to prove it persisted
    mgr2 = AuthManager(str(tmp_path / "auth.json"))
    user = mgr2._config["users"]["dave"]
    assert user["idp_user_id"] == "uuid-9"
    assert user["email"] == "dave@example.com"
    # additive — existing fields untouched
    assert user["is_admin"] is True
    assert "password_hash" in user


def test_record_idp_identity_unknown_user_is_noop(tmp_path):
    mgr = _mgr(tmp_path)
    mgr.create_user("dave", "password1", is_admin=True)
    mgr.record_idp_identity("ghost", "uuid-9", "x@example.com")  # no raise
    assert "ghost" not in mgr._config["users"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_idp_owner_resolution.py -v`
Expected: FAIL — `AttributeError: 'AuthManager' object has no attribute 'resolve_idp_owner'`

- [ ] **Step 3: Add the two methods**

In `core/auth.py`, add these methods to the `AuthManager` class (place them just after `create_session_trusted`, around line 514 — `os`, `Optional`, and `Dict` are already imported at the top of the file):

```python
    def resolve_idp_owner(self) -> str:
        """Resolve the single Odysseus owner an IdP login maps to.

        Server-side only — never derived from the JWT. Returns
        ODYSSEUS_IDP_OWNER if set and that user exists; else the sole user
        when exactly one exists; else raises ValueError (ambiguous / none /
        unknown configured user). The caller redirects to /?login_error=idp_owner
        on ValueError.
        """
        configured = os.getenv("ODYSSEUS_IDP_OWNER", "").strip().lower()
        with self._config_lock:
            usernames = list(self._config.get("users", {}).keys())
        if configured:
            if configured in usernames:
                return configured
            raise ValueError(
                f"ODYSSEUS_IDP_OWNER='{configured}' is not an existing user"
            )
        if len(usernames) == 1:
            return usernames[0]
        raise ValueError(
            f"Cannot resolve IdP owner: {len(usernames)} users exist; "
            "set ODYSSEUS_IDP_OWNER"
        )

    def record_idp_identity(
        self, username: str, idp_user_id: Optional[str], email: Optional[str]
    ) -> None:
        """Record the IdP identity on the mapped user's auth.json entry.

        Additive (for audit/reconciliation only): does not change is_admin,
        privileges, or the owner key (username). No-op if the user is absent.
        """
        username = username.strip().lower()
        with self._config_lock:
            users = self._config.get("users", {})
            if username not in users:
                return
            if idp_user_id:
                users[username]["idp_user_id"] = idp_user_id
            if email:
                users[username]["email"] = email
            self._save()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_idp_owner_resolution.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add core/auth.py tests/test_idp_owner_resolution.py
git commit -m "feat(idp): owner resolution + identity record on auth.json users"
```

---

### Task 3: `routes/idp_routes.py` — `/api/auth/idp-login` + app wiring

**Files:**
- Create: `routes/idp_routes.py`
- Modify: `app.py` (import + `include_router`; add `/api/auth/idp-login` to `AUTH_EXEMPT_EXACT`)
- Create: `tests/test_idp_login_route.py`

**Interfaces:**
- Consumes: `idp_login_url` (Task 1); `SESSION_COOKIE` from `routes.auth_routes`; `RateLimiter` from `src.rate_limiter`; `AuthManager`.
- Produces: `setup_idp_routes(auth_manager: AuthManager) -> APIRouter` with `GET /api/auth/idp-login`. Module constant `IDP_STATE_COOKIE = "odysseus_idp_state"`. Helper `_request_origin(request) -> str`. (The callback route is added to this same router in Task 4.)

- [ ] **Step 1: Write the failing test**

Create `tests/test_idp_login_route.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_idp_login_route.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'routes.idp_routes'`

- [ ] **Step 3: Create `routes/idp_routes.py`**

```python
"""IdP login delegation routes — "Sign in with Ellie" (Phase 1c).

Login-only: these two routes front the unchanged opaque-session machinery.
/api/auth/idp-login starts the round-trip; /api/auth/callback (Task 4)
finishes it. Both are AUTH_EXEMPT (reachable before login).
"""
import asyncio
import logging
import os
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from core.auth import AuthManager
from routes.auth_routes import SESSION_COOKIE
from src.idp import exchange_code, idp_login_url, verify_idp_token
from src.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

IDP_STATE_COOKIE = "odysseus_idp_state"


def _secure_cookies() -> bool:
    return os.getenv("SECURE_COOKIES", "false").lower() == "true"


def _request_origin(request: Request) -> str:
    """Origin of the incoming request (single-origin app)."""
    host = request.headers.get("host", request.url.netloc)
    return f"{request.url.scheme}://{host}"


def setup_idp_routes(auth_manager: AuthManager) -> APIRouter:
    router = APIRouter(prefix="/api/auth", tags=["auth-idp"])
    _idp_limiter = RateLimiter(max_requests=10, window_seconds=60)

    @router.get("/idp-login")
    async def idp_login(request: Request):
        if not _idp_limiter.check(request.client.host):
            return RedirectResponse(url="/?login_error=rate_limited", status_code=302)
        state = secrets.token_hex(32)
        resp = RedirectResponse(
            url=idp_login_url(state, _request_origin(request)), status_code=302
        )
        resp.set_cookie(
            key=IDP_STATE_COOKIE,
            value=state,
            httponly=True,
            samesite="lax",
            secure=_secure_cookies(),
            path="/api/auth/callback",
            max_age=300,
        )
        return resp

    return router
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_idp_login_route.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Wire the router into `app.py`**

In `app.py`, add `/api/auth/idp-login` to the `AUTH_EXEMPT_EXACT` set (around line 173, alongside `/api/auth/login`):

```python
        "/api/auth/login",
        "/api/auth/idp-login",
        "/api/auth/logout",
```

Then register the router immediately after the existing `auth_router` include (after `app.include_router(auth_router)` at line 544):

```python
from routes.idp_routes import setup_idp_routes
app.include_router(setup_idp_routes(auth_manager))
```

- [ ] **Step 6: Verify the app imports cleanly**

Run: `python -c "import app"`
Expected: no traceback (the module imports and registers the router).

- [ ] **Step 7: Commit**

```bash
git add routes/idp_routes.py tests/test_idp_login_route.py app.py
git commit -m "feat(idp): /api/auth/idp-login route + app wiring + AUTH_EXEMPT"
```

---

### Task 4: `/api/auth/callback` — exchange → verify → resolve → mint session

**Files:**
- Modify: `routes/idp_routes.py` (add the `/api/auth/callback` route to the existing router)
- Modify: `app.py` (add `/api/auth/callback` to `AUTH_EXEMPT_EXACT`)
- Create: `tests/test_idp_callback_route.py`

**Interfaces:**
- Consumes: `exchange_code`, `verify_idp_token` (Task 1, imported into `routes.idp_routes` — tests monkeypatch them there); `auth_manager.resolve_idp_owner`, `record_idp_identity`, `create_session_trusted`, `get_username_for_token` (Task 2 + existing); `IDP_STATE_COOKIE`, `SESSION_COOKIE`, `_secure_cookies` (Task 3).
- Produces: `GET /api/auth/callback` on the same router. Success → 302 `/` + `odysseus_session` cookie + cleared state cookie + recorded identity. Failure → 302 `/?login_error=<reason>` (`idp_state` | `idp` | `idp_owner`) + cleared state cookie + no session.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_idp_callback_route.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_idp_callback_route.py -v`
Expected: FAIL — 404 on `/api/auth/callback` (route not defined yet).

- [ ] **Step 3: Add the callback route**

In `routes/idp_routes.py`, inside `setup_idp_routes` (after the `idp_login` handler, before `return router`), add:

```python
    @router.get("/callback")
    async def idp_callback(request: Request):
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        cookie_state = request.cookies.get(IDP_STATE_COOKIE)

        def _fail(reason: str) -> RedirectResponse:
            r = RedirectResponse(url=f"/?login_error={reason}", status_code=302)
            r.delete_cookie(IDP_STATE_COOKIE, path="/api/auth/callback")
            return r

        # CSRF: the state in the URL must match the short-lived state cookie.
        if (
            not code
            or not state
            or not cookie_state
            or not secrets.compare_digest(state, cookie_state)
        ):
            return _fail("idp_state")

        try:
            access_token = await asyncio.to_thread(exchange_code, code)
            claims = verify_idp_token(access_token)
        except Exception:
            logger.warning("IdP callback exchange/verify failed", exc_info=False)
            return _fail("idp")

        try:
            owner = auth_manager.resolve_idp_owner()
        except Exception:
            logger.warning("IdP owner resolution failed", exc_info=False)
            return _fail("idp_owner")

        # Audit record is best-effort — never block login on it.
        try:
            auth_manager.record_idp_identity(
                owner, claims.get("userId"), claims.get("email")
            )
        except Exception:
            logger.warning("record_idp_identity failed (non-fatal)", exc_info=False)

        token = await asyncio.to_thread(auth_manager.create_session_trusted, owner)
        resp = RedirectResponse(url="/", status_code=302)
        resp.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            httponly=True,
            samesite="lax",
            secure=_secure_cookies(),
            path="/",
            max_age=60 * 60 * 24 * 7,
        )
        resp.delete_cookie(IDP_STATE_COOKIE, path="/api/auth/callback")
        return resp
```

- [ ] **Step 4: Add the callback to `AUTH_EXEMPT_EXACT`**

In `app.py`, add `/api/auth/callback` to the set (next to `/api/auth/idp-login` from Task 3):

```python
        "/api/auth/idp-login",
        "/api/auth/callback",
        "/api/auth/logout",
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_idp_callback_route.py -v`
Expected: PASS (6 passed)

- [ ] **Step 6: Commit**

```bash
git add routes/idp_routes.py app.py tests/test_idp_callback_route.py
git commit -m "feat(idp): /api/auth/callback exchange+verify+resolve+mint session"
```

---

### Task 5: `/api/auth/status` (+`idp_enabled`) and password-login flag-gate

**Files:**
- Modify: `routes/auth_routes.py` (`_idp_enabled` helper; `status` adds `idp_enabled`; `login` + `signup` return 403 when on)
- Create: `tests/test_idp_flag_gate.py`

**Interfaces:**
- Consumes: env `AUTH_IDP_ENABLED`.
- Produces: `_idp_enabled() -> bool` (module-level in `routes/auth_routes.py`); `/api/auth/status` response gains `idp_enabled: bool`; `POST /api/auth/login` and `POST /api/auth/signup` short-circuit to a 403 JSON `{"ok": false, "error": "Password login disabled; use the IdP"}` when the flag is on.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_idp_flag_gate.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_idp_flag_gate.py -v`
Expected: FAIL — `test_status_reports_idp_disabled_by_default` KeyErrors on `idp_enabled`; the 403 tests fail (login returns 200 / signup proceeds).

- [ ] **Step 3: Add the `_idp_enabled` helper + import**

In `routes/auth_routes.py`, add `JSONResponse` to the imports and a module-level helper. Near the top (after the existing `from fastapi import ...` at line 3), add:

```python
from fastapi.responses import JSONResponse
```

After `SESSION_COOKIE = "odysseus_session"` (line 79), add:

```python
def _idp_enabled() -> bool:
    return os.getenv("AUTH_IDP_ENABLED", "false").lower() == "true"
```

- [ ] **Step 4: Gate `login` and `signup`, extend `status`**

In the `login` handler (line 125), make the first line of the body (before the rate-limit check):

```python
    @router.post("/login")
    async def login(body: LoginRequest, request: Request, response: Response):
        if _idp_enabled():
            return JSONResponse(
                status_code=403,
                content={"ok": False, "error": "Password login disabled; use the IdP"},
            )
        if not _login_limiter.check(request.client.host):
```

In the `signup` handler (line 107), add the same gate as its first body line:

```python
    @router.post("/signup")
    async def signup(body: SignupRequest, request: Request):
        if _idp_enabled():
            return JSONResponse(
                status_code=403,
                content={"ok": False, "error": "Password login disabled; use the IdP"},
            )
        if not _signup_limiter.check(request.client.host):
```

In the `status` handler (line 163), add `idp_enabled` to the result before returning (after the `result["signup_enabled"] = ...` line at 167):

```python
        result["signup_enabled"] = auth_manager.signup_enabled
        result["idp_enabled"] = _idp_enabled()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_idp_flag_gate.py -v`
Expected: PASS (5 passed)

- [ ] **Step 6: Commit**

```bash
git add routes/auth_routes.py tests/test_idp_flag_gate.py
git commit -m "feat(idp): status idp_enabled + 403 gate on password login/signup"
```

---

### Task 6: Login UI — "Sign in with Ellie" button

**Files:**
- Modify: `static/login.html` (markup: add hidden button; script: show it + hide form when `idp_enabled`)

**Interfaces:**
- Consumes: `idp_enabled` from `/api/auth/status` (Task 5); `GET /api/auth/idp-login` (Task 3).
- Produces: when `idp_enabled` is true, the password form is hidden and a single button navigates to `/api/auth/idp-login`; when false, today's form is unchanged.

- [ ] **Step 1: Add the button markup**

In `static/login.html`, after the `</form>` (line 288) and before the `toggleArea` div (line 290), add:

```html
  <button type="button" id="idpBtn" style="display:none">Sign in with Ellie</button>
```

- [ ] **Step 2: Branch on `idp_enabled` in the status handler**

In the `<script>` block, the status check currently reads (lines 361-373):

```javascript
    const res = await fetch('/api/auth/status', { credentials: 'same-origin' });
    const data = await res.json();
    if (data.authenticated) {
      window.location.replace('/');
      return;
    }
    signupAllowed = !!data.signup_enabled;
    if (!data.configured) {
      setMode('setup');
    } else {
      setMode('login');
    }
```

Insert the IdP branch immediately after the `data.authenticated` redirect block and before `signupAllowed = ...`:

```javascript
    if (data.authenticated) {
      window.location.replace('/');
      return;
    }
    if (data.idp_enabled) {
      form.style.display = 'none';
      toggleArea.style.display = 'none';
      const idpBtn = document.getElementById('idpBtn');
      idpBtn.style.display = '';
      idpBtn.addEventListener('click', () => {
        window.location.href = '/api/auth/idp-login';
      });
      return;
    }
    signupAllowed = !!data.signup_enabled;
```

- [ ] **Step 3: Verify the change is present**

Run: `grep -n "idpBtn\|idp_enabled\|/api/auth/idp-login" static/login.html`
Expected: shows the new button id, the `data.idp_enabled` branch, and the navigation target (3+ matches).

- [ ] **Step 4: Sanity-load the page (IdP on)**

Run:
```bash
AUTH_IDP_ENABLED=true JWT_SECRET=dummy ODYSSEUS_IDP_OWNER=dave python -c "
from fastapi.testclient import TestClient
import app
c = TestClient(app.app)
r = c.get('/login')
assert r.status_code == 200 and 'idpBtn' in r.text, r.status_code
print('login.html served with idpBtn present')
"
```
Expected: `login.html served with idpBtn present`
(If importing `app` requires other env/services and fails for reasons unrelated to this change, fall back to the Step 3 grep as the gate and note it in the report.)

- [ ] **Step 5: Commit**

```bash
git add static/login.html
git commit -m "feat(idp): Sign in with Ellie button on login page when IdP enabled"
```

---

### Task 7: Config docs + full-suite verification

**Files:**
- Modify: `.env.example` (document the five new vars) — create if absent
- Create: `tests/test_idp_session_roundtrip.py` (callback-minted session authenticates via `validate_token`)

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: documented config; a regression proving the minted session is a normal opaque session.

- [ ] **Step 1: Document the env vars**

Append to `.env.example` (create the file if it does not exist) — values are placeholders, never a real secret:

```bash
# --- Central IdP login delegation (Phase 1c) ---
# Turn on to replace password login with "Sign in with Ellie".
AUTH_IDP_ENABLED=false
# Ellie IdP base URL (ellie-idp / :3006).
IDP_BASE_URL=http://127.0.0.1:3006
# Audience this app requests/verifies. Must stay "odysseus".
IDP_AUD=odysseus
# Shared HS256 secret — MUST equal the IdP's LIFE_JWT_SECRET. Do not commit a real value.
JWT_SECRET=
# The existing Odysseus username every IdP login maps to.
# Optional when exactly one user exists (it is then used automatically).
ODYSSEUS_IDP_OWNER=
```

- [ ] **Step 2: Write the session round-trip test**

Create `tests/test_idp_session_roundtrip.py`:

```python
"""The callback-minted session is a normal opaque session (Phase 1c)."""
from core.auth import AuthManager


def test_minted_session_validates_like_any_other(tmp_path, monkeypatch):
    monkeypatch.delenv("ODYSSEUS_IDP_OWNER", raising=False)
    mgr = AuthManager(str(tmp_path / "auth.json"))
    mgr.create_user("dave", "password1", is_admin=True)
    owner = mgr.resolve_idp_owner()
    token = mgr.create_session_trusted(owner)
    # exactly what AuthMiddleware does per request:
    assert mgr.validate_token(token) is True
    assert mgr.get_username_for_token(token) == "dave"
```

- [ ] **Step 3: Run the round-trip test**

Run: `pytest tests/test_idp_session_roundtrip.py -v`
Expected: PASS (1 passed)

- [ ] **Step 4: Run the full Phase 1c test set**

Run:
```bash
pytest tests/test_idp_helpers.py tests/test_idp_owner_resolution.py \
       tests/test_idp_login_route.py tests/test_idp_callback_route.py \
       tests/test_idp_flag_gate.py tests/test_idp_session_roundtrip.py -v
```
Expected: PASS (35 passed total: 14 + 8 + 1 + 6 + 5 + 1).

- [ ] **Step 5: Confirm no regression in existing auth tests**

Run: `pytest tests/test_auth_regressions.py tests/test_auth_session_revocation.py -v`
Expected: PASS (same result as before this branch — these don't touch the IdP path).

- [ ] **Step 6: Commit**

```bash
git add .env.example tests/test_idp_session_roundtrip.py
git commit -m "docs(idp): document IdP env vars + session round-trip regression"
```

---

## Manual Verification Checklist (post-merge, with a running IdP)

Not automated — perform once against a live `ellie-idp` on `:3006`:

1. Set in Odysseus `.env`: `AUTH_IDP_ENABLED=true`, `JWT_SECRET=<the IdP's LIFE_JWT_SECRET>`, `ODYSSEUS_IDP_OWNER=<your username>`. Restart Odysseus.
2. Visit `/login` → only the "Sign in with Ellie" button shows (no password form).
3. Click it → redirected to the IdP `/login` (password + TOTP there).
4. Authenticate → bounced back to `/api/auth/callback?code=…&state=…` → land on `/` logged in as the mapped owner.
5. `data/auth.json` for that user now has `idp_user_id` + `email`.
6. `POST /api/auth/login` returns 403; flipping `AUTH_IDP_ENABLED=false` restores password login.
