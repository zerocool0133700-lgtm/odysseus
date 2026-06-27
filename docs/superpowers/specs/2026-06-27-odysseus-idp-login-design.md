# Odysseus → Central IdP — Login Delegation (Phase 1c)

**Date:** 2026-06-27
**Status:** Approved design — pending implementation plan
**Author:** Dave + Claude (brainstorming session)
**Scope:** Phase 1c (final app) of the consolidation: make **Odysseus** delegate interactive login to the central Ellie IdP (`ellie-idp`, `:3006`). **Login only** — keep Odysseus's opaque server-side session; swap the password gate for an IdP redirect+callback, and map the IdP identity onto a single configured Odysseus owner.

---

## 1. Context & Goal

The central IdP (Phase 1, Ellie Rust on `:3006`) issues HS256 access JWTs (claim `userId` = `life_users.id` UUID, plus `email,role,privileges,aud,jti,iss:"ellie-idp",iat,exp`) signed with the shared `LIFE_JWT_SECRET`, via a CSRF-safe one-time-code login (`GET /login?redirect_uri=&state=&aud=` → `POST /auth/exchange {code}` → `{access_token}`). Proving Ground (1a) and hermes-workspace (1b) already delegated login. Odysseus is the last and most multi-user-shaped of the three.

**Odysseus today** (Python/FastAPI, `:7000`, single-origin):
- **File-based users** `data/auth.json`: `username → { password_hash (bcrypt), is_admin, privileges, totp_secret/enabled, … }`. **No email, no UUID.** (`core/auth.py`)
- **Opaque server-side sessions** `data/sessions.json`: `token (secrets.token_hex(32)) → { username, expiry }`, 7-day TTL; cookie `odysseus_session` (httponly, samesite=lax, secure per `SECURE_COOKIES`, path=/, max_age=604800). (`core/auth.py`, `routes/auth_routes.py:142-152`)
- **Choke point:** `AuthMiddleware` (`app.py:272-386`) → `auth_manager.validate_token(token)` → `request.state.current_user = auth_manager.get_username_for_token(token)` (a **username string**). A separate `Bearer ody_…` path sets `request.state.api_token_owner`.
- **Owner key = username (string).** ~18 tables scope data by `owner: String` (`core/database.py`: Session, Document, GalleryImage, Note, Memory, ScheduledTask, ApiToken, …). There is **no email→user mapping**.
- Scoped `ody_…` API tokens (bcrypt-hashed, scoped) for integrations; independent of user login.
- `httpx` available; **`PyJWT` not yet** a dependency. Config via env + `data/settings.json`. `AUTH_ENABLED` (default true) gates the middleware; `LOCALHOST_BYPASS` (default off).

**Goal:** replace the password login with **delegated login** to the IdP, keeping Odysseus's opaque-session model. On callback, exchange the code, verify the IdP JWT, **map the IdP identity onto one configured Odysseus owner**, and mint Odysseus's existing session for that owner. Per-request auth is otherwise unchanged.

### Owner mapping decision (locked)
**Map to a single configured existing owner.** Odysseus is effectively a single-operator tool with existing username-owned data. Any IdP login resolves to **one** configured Odysseus username (`ODYSSEUS_IDP_OWNER`, defaulting to the sole admin user when exactly one exists). The IdP `idp_user_id`/`email` are recorded on that auth.json user for audit/future reconciliation. This **preserves all existing data**, is the simplest correct mapping, and gives "one identity" for the operator. Multi-user / JIT-by-email is explicitly deferred (the username→data coupling makes per-user provisioning a separate, larger project).

---

## 2. Decisions (locked)

1. **Login only:** keep the opaque session (`validate_token` / `create_session_trusted` / `odysseus_session` cookie) and per-request `AuthMiddleware`. Only the login entry-point changes.
2. **Single-owner mapping:** the IdP identity → `ODYSSEUS_IDP_OWNER` (existing username; default to the sole admin if unambiguous). Record `idp_user_id`/`email` on that user's auth.json entry. No DB schema change (username stays the owner key).
3. **Mint the existing session:** `create_session_trusted(owner)`; set the existing `odysseus_session` cookie. The IdP JWT is verified once (callback) then discarded.
4. **Server-side callback** `GET /api/auth/callback`; frontend change is just a "Sign in with Ellie" button.
5. **No per-request JWT validation** — per-request stays opaque-session. No confused-deputy (opaque token, not a JWT).
6. **Feature flag** `AUTH_IDP_ENABLED` (default false); password login retained for the off-state; when on, `POST /api/auth/login` returns 403.
7. **Shared secret in plain env** (`JWT_SECRET` = `LIFE_JWT_SECRET`) — Odysseus has no secret store.
8. **TOTP moves to the IdP.** When delegated, Odysseus's own 2FA path is bypassed (the IdP enforces TOTP). The mapped owner's local TOTP is irrelevant to the IdP flow.

---

## 3. Architecture & Flow

```
 Browser (Odysseus, :7000)                    IdP (:3006)          Odysseus server (same origin)
   │  "Sign in with Ellie" → GET /api/auth/idp-login ──────────────────────▶│ set odysseus_idp_state cookie
   │  ◀──────────────── 302 to IdP /login ─────────────────────────────────┤ (rate-limited, AUTH_EXEMPT)
   ├─ 302 ─────────────────────────────────▶ /login?redirect_uri=<cb>&state=&aud=odysseus
   │                                  (password + TOTP at IdP)               │
   │  ◀──────── 302 redirect_uri?code=&state= ────────┤                      │
   ├─ GET /api/auth/callback?code=&state= ───────────────────────────────────▶│ verify state cookie
   │                                                  │◀── POST /auth/exchange │ (httpx, server→server, 5s)
   │                                                  │ {code} → {access_token}│
   │                                                  │   verify_idp_token()   │ iss/aud/exp+leeway (PyJWT)
   │                                                  │   resolve owner +       │ record idp_user_id/email
   │                                                  │   create_session_trusted(owner)
   │  ◀──────── 302 "/" + Set-Cookie odysseus_session ───────────────────────┤ clear state cookie
   │  (from here: normal opaque-session — AuthMiddleware unchanged)           │
```

- `aud=odysseus` end-to-end. The `state` (CSRF on the callback) lives in a short-lived `odysseus_idp_state` cookie and complements the IdP's atomic one-time code.
- `redirect_uri` origin = Odysseus's own origin (single-port). `:7000` is already IdP-allowlisted.

---

## 4. Components & Changes

### 4.1 `src/idp.py` (new)
- `idp_login_url(state: str, origin: str) -> str` — `${IDP_BASE_URL}/login?redirect_uri=${origin}/api/auth/callback&state=${state}&aud=${IDP_AUD}`.
- `verify_idp_token(token: str) -> dict` — `jwt.decode(token, JWT_SECRET, algorithms=["HS256"], issuer="ellie-idp", audience=IDP_AUD, leeway=30)` (PyJWT); returns `{ userId, email, role }`; raises on invalid iss/aud/exp/sig.
- `exchange_code(code: str) -> str` — `httpx.post(f"{IDP_BASE_URL}/auth/exchange", json={"code": code}, timeout=5.0)`, one retry on network/5xx (not 4xx); returns `access_token`; raises on missing token.
- Reads `IDP_BASE_URL` (default `http://127.0.0.1:3006`), `IDP_AUD` (default `odysseus`), `JWT_SECRET` (raise if unset). Adds `PyJWT` to `requirements.txt`.

### 4.2 `routes/idp_routes.py` (new) + `app.py`
- `setup_idp_routes(auth_manager)` returning an `APIRouter`:
  - `GET /api/auth/idp-login` — mint `state = secrets.token_hex(32)`, set `odysseus_idp_state` cookie (§5), 302 to `idp_login_url(state, origin)`. Rate-limited (reuse the project's rate limiter, e.g. 10/min/IP).
  - `GET /api/auth/callback` — read `code`+`state` + the `odysseus_idp_state` cookie; if missing/mismatch → clear state + 302 `/?login_error=idp_state`. Else `exchange_code` → `verify_idp_token` → claims → resolve owner (§4.3) → `create_session_trusted(owner)` → set `odysseus_session` cookie + clear state cookie → 302 `/`. Any exchange/verify/resolve failure → clear state + 302 `/?login_error=idp`, no session.
- `app.py`: `app.include_router(setup_idp_routes(auth_manager))`; **add `/api/auth/idp-login` and `/api/auth/callback` to `AUTH_EXEMPT_EXACT`** (`app.py:173+`) so they're reachable before login.

### 4.3 Owner resolution + identity record (`core/auth.py`)
- `resolve_idp_owner() -> str` — return `ODYSSEUS_IDP_OWNER` if set and the user exists; else if exactly one user exists, return it; else raise a clear configuration error (logged; callback → `/?login_error=idp_owner`).
- `record_idp_identity(username, idp_user_id, email)` — set optional `idp_user_id`/`email` fields on that user's auth.json entry (additive; absent on legacy users). For audit/reconciliation only; the username stays the owner key. The user keeps its existing `is_admin`/`privileges`.

### 4.4 `/api/auth/status` (`routes/auth_routes.py`)
- Add `idp_enabled: bool` (from `AUTH_IDP_ENABLED`) to the existing status response. The login UI already calls this — no new endpoint.

### 4.5 `POST /api/auth/login` (`routes/auth_routes.py`)
- When `AUTH_IDP_ENABLED` is on, return **403** (`{ok: false, error: "Password login disabled; use the IdP"}`) before verifying the password. Code retained for the off-state. (Also gate `/api/auth/signup` similarly.)

### 4.6 Login UI (`static/login.html`)
- Read `idp_enabled` from `/api/auth/status`. When true, render a single **"Sign in with Ellie"** button → `window.location.href = "/api/auth/idp-login"`; hide the password form. When false → today's password form unchanged.

### 4.7 Config (env / settings)
- `AUTH_IDP_ENABLED` (default false), `IDP_BASE_URL` (default `http://127.0.0.1:3006`), `JWT_SECRET` (= the IdP's `LIFE_JWT_SECRET`), `IDP_AUD` (default `odysseus`), `ODYSSEUS_IDP_OWNER` (the mapped username). Read via the existing env/settings pattern. Document in `.env.example`.

---

## 5. Security

- **State cookie** `odysseus_idp_state`: `httponly; samesite=lax; secure(per SECURE_COOKIES); path=/api/auth/callback; max_age=300`. Value = `secrets.token_hex(32)`. Checked `cookie_state == query_state` at the callback; cleared (max_age=0) on success and failure. (The durable `odysseus_session` cookie keeps its current attributes; the state cookie must be `lax` to survive the IdP redirect.)
- **JWT verify:** `iss="ellie-idp"` + `aud=IDP_AUD` + signature + `exp` (30s leeway). Never trust before verify; never persist the IdP JWT (only the opaque session token is stored).
- **Code exchange** server-to-server via httpx (5s timeout); the one-time code is single-use at the IdP.
- **No token in any URL** beyond the one-time `code`.
- **Owner resolution is server-side config** (`ODYSSEUS_IDP_OWNER` / sole-admin), never user-controlled — a JWT cannot pick its Odysseus owner.
- **Opaque session unchanged:** per-request `AuthMiddleware`/`validate_token` is untouched → no new attack surface, no confused-deputy (opaque token, not a JWT).
- **`AUTH_ENABLED`** stays the gate (default true) — Odysseus already requires auth, so enabling the IdP doesn't create an open-app path (unlike hermes-workspace's password-empty case).
- **`ody_` API tokens** and **`LOCALHOST_BYPASS`** unchanged.
- **Rollback:** `AUTH_IDP_ENABLED=false` restores password login with no code removal.

---

## 6. Testing (pytest)

- `verify_idp_token`: accepts a correctly-signed `iss=ellie-idp`/`aud=odysseus` token; rejects wrong `aud`, wrong `iss`, wrong secret, expired-beyond-leeway; accepts within 30s leeway.
- `idp_login_url`: contains `redirect_uri=<origin>/api/auth/callback`, the `state`, and `aud=odysseus`.
- `exchange_code`: 5s timeout; one retry on 5xx/network; no retry on 4xx; raises on missing `access_token` (httpx mocked).
- `resolve_idp_owner`: returns `ODYSSEUS_IDP_OWNER` when set+exists; defaults to the sole user; raises when ambiguous/none.
- **callback** (FastAPI TestClient, stubbing exchange/verify): happy path (valid code → owner resolved → `odysseus_session` cookie set → `idp_user_id`/`email` recorded on the user → 302 `/`); bad/missing `state` → no session, redirect with error; exchange/verify throw → no session, redirect with error; owner-resolution failure → redirect `idp_owner`, no session.
- **flag gate:** `AUTH_IDP_ENABLED=true` → `POST /api/auth/login` returns 403; status reports `idp_enabled:true`.
- **session round-trip:** a session minted by the callback authenticates a subsequent request via `AuthMiddleware` (`request.state.current_user == owner`).
- **flag off:** password login still works (no regression).

---

## 7. File Touchpoints (current code)

- `core/auth.py` — `create_session_trusted` (reused), new `resolve_idp_owner`/`record_idp_identity`, optional `email`/`idp_user_id` on user records.
- `src/idp.py` (new) — IdP helpers; `routes/idp_routes.py` (new) — the two routes.
- `app.py` — register the router + `AUTH_EXEMPT_EXACT` additions.
- `routes/auth_routes.py` — `/api/auth/status` (+`idp_enabled`), `/api/auth/login` (flag-gate 403).
- `static/login.html` — "Sign in with Ellie" button.
- `requirements.txt` — add `PyJWT`. `.env.example` — new vars.
- Unchanged: `AuthMiddleware`/`validate_token`/`odysseus_session` mechanics, the `ody_` API-token path, owner-scoped data models.

---

## 8. Out of Scope (deferred)

Multi-user / JIT-by-email provisioning (the username→data coupling makes it a separate project); per-request JWT validation; removing password login; migrating `ody_` tokens to the IdP's service tokens; surfacing the IdP identity beyond the recorded `idp_user_id`/`email`.

---

## 9. Notes

1. **No IdP change required** — `:7000` is already allowlisted and per-`aud` emission exists. If Odysseus is deployed on a different origin, add it to the IdP's `IDP_REDIRECT_ALLOWLIST`.
2. **Secret distribution** — `JWT_SECRET` must equal the IdP's `LIFE_JWT_SECRET` (set in Odysseus's `.env`, which is gitignored).
3. **Fork** — work on `zerocool0133700-lgtm/odysseus` (`fork` remote; `origin` is the read-only upstream). PRs target the fork's `dev`.
4. **CORS** — the callback is a top-level browser navigation (302s), not an XHR, so the existing `ALLOWED_ORIGINS` CORS config is not on the critical path; confirm during implementation.
