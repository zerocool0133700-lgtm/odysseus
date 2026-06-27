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
