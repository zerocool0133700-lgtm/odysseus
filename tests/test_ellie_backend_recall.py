"""Unit tests for the Ellie backend recall bridge.

Covers two layers in src.ellie_backend:
 - format_recall(used_memories): renders Odysseus's ctx.used_memories into the
   plain ``recall`` block sent to Ellie (one ``- <text>`` bullet per non-blank
   entry; None for an empty list so no empty block is sent).
 - stream_ellie_backend(..., recall=...): includes the ``recall`` key in the
   POSTed JSON when present and omits it when None.

The httpx fake mirrors tests/test_ellie_backend_forwarder.py so the captured
``json=`` payload can be asserted without a real network/DB stack.
"""
import httpx

from src.ellie_backend import format_recall, stream_ellie_backend


# ── format_recall ────────────────────────────────────────────────────────────


def test_format_recall_empty_is_none():
    assert format_recall([]) is None
    assert format_recall(None) is None


def test_format_recall_joins_texts():
    out = format_recall([
        {"text": "your wife's name is Wincy", "category": "fact", "type": "recalled"},
        {"text": "you like sailing", "category": "fact", "type": "pinned"},
    ])
    assert out is not None
    assert "your wife's name is Wincy" in out
    assert "you like sailing" in out


def test_format_recall_skips_blank_text():
    out = format_recall([{"text": "  ", "type": "pinned"}, {"text": "real", "type": "recalled"}])
    assert out == "- real"


# ── Fake httpx layer (mirrors tests/test_ellie_backend_forwarder.py) ──────────


class _FakeResp:
    def __init__(self, lines, status_code=200):
        self._lines = lines
        self.status_code = status_code
        self.request = httpx.Request("POST", "http://x/api/odysseus/turn")

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "boom", request=self.request,
                response=httpx.Response(self.status_code, request=self.request),
            )

    async def aiter_lines(self):
        for ln in self._lines:
            yield ln


class _FakeStreamCtx:
    def __init__(self, lines, status_code):
        self._lines = lines
        self._status = status_code

    async def __aenter__(self):
        return _FakeResp(self._lines, self._status)

    async def __aexit__(self, *a):
        return False


class _FakeClient:
    def __init__(self, capture, lines, status_code=200):
        self._capture = capture
        self._lines = lines
        self._status = status_code

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stream(self, method, url, **kw):
        self._capture["json"] = kw.get("json")
        return _FakeStreamCtx(self._lines, self._status)


def _patch_client(monkeypatch, capture, lines):
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(capture, lines),
    )


# ── recall key in the POSTed payload ─────────────────────────────────────────


async def test_payload_includes_recall_when_present(monkeypatch):
    capture = {}
    _patch_client(monkeypatch, capture, ["data: [DONE]"])
    async for _ in stream_ellie_backend(
        [{"role": "user", "content": "hi"}],
        "sess-recall",
        base_url="http://h",
        recall="- remember this",
    ):
        pass
    assert capture["json"]["recall"] == "- remember this"


async def test_payload_omits_recall_when_none(monkeypatch):
    capture = {}
    _patch_client(monkeypatch, capture, ["data: [DONE]"])
    async for _ in stream_ellie_backend(
        [{"role": "user", "content": "hi"}],
        "sess-norecall",
        base_url="http://h",
        recall=None,
    ):
        pass
    assert "recall" not in capture["json"]
