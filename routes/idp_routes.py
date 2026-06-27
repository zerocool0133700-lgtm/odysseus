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
