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
