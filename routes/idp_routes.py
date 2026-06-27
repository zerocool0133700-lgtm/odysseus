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
    """Origin of the incoming request (single-origin app).

    Derived from the Host request header. Callback-URL safety relies on the
    IdP's IDP_REDIRECT_ALLOWLIST rejecting any origin not explicitly permitted.
    """
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

    @router.get("/callback")
    async def idp_callback(request: Request):
        if not _idp_limiter.check(request.client.host):
            return RedirectResponse(url="/?login_error=rate_limited", status_code=302)
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

    return router
