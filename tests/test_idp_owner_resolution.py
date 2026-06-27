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
