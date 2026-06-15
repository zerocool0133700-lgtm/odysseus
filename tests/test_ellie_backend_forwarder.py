"""Unit tests for the external Ellie agent backend forwarder.

Exercises src.ellie_backend.stream_ellie_backend in isolation (no FastAPI/DB):
 - POSTs to /api/odysseus/turn with {"messages": ..., "session_id": ...}
 - relays a scripted SSE stream (including [DONE]) through with Odysseus framing
 - accumulates assistant prose from {"delta": ...} events for persistence
 - fail-soft: an unreachable backend raises EllieBackendError (caller falls back),
   never a 500 / unhandled crash
"""
import json

import httpx
import pytest

from src.ellie_backend import (
    stream_ellie_backend,
    EllieBackendError,
    is_ellie_backend,
)


# ── Fake httpx layer mirroring tests/test_llm_core_streaming.py ──────────────


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
    def __init__(self, capture, lines, status_code):
        self._capture = capture
        self._lines = lines
        self._status = status_code

    async def __aenter__(self):
        return _FakeResp(self._lines, self._status)

    async def __aexit__(self, *a):
        return False


class _FakeClient:
    def __init__(self, capture, lines, status_code=200, raise_on_stream=None):
        self._capture = capture
        self._lines = lines
        self._status = status_code
        self._raise_on_stream = raise_on_stream

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stream(self, method, url, **kw):
        self._capture["method"] = method
        self._capture["url"] = url
        self._capture["json"] = kw.get("json")
        self._capture["headers"] = kw.get("headers")
        if self._raise_on_stream is not None:
            raise self._raise_on_stream
        return _FakeStreamCtx(self._capture, self._lines, self._status)


def _patch_client(monkeypatch, capture, lines, status_code=200, raise_on_stream=None):
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(capture, lines, status_code, raise_on_stream),
    )


# ── Tests ────────────────────────────────────────────────────────────────────


async def test_relays_scripted_sse_and_request_shape(monkeypatch):
    capture = {}
    lines = [
        'data: {"type": "model_info", "model": "ellie"}',
        "",
        'data: {"delta": "Hello"}',
        "",
        'data: {"delta": " world"}',
        "",
        "data: [DONE]",
        "",
    ]
    _patch_client(monkeypatch, capture, lines)

    prose = []
    out = []
    async for chunk in stream_ellie_backend(
        [{"role": "user", "content": "hi"}],
        "sess-123",
        base_url="http://127.0.0.1:8765",
        token="secret-tok",
        on_delta=prose.append,
    ):
        out.append(chunk)

    # Request shape: correct path, payload, bearer header.
    assert capture["method"] == "POST"
    assert capture["url"] == "http://127.0.0.1:8765/api/odysseus/turn"
    assert capture["json"] == {
        "messages": [{"role": "user", "content": "hi"}],
        "session_id": "sess-123",
    }
    assert capture["headers"]["Authorization"] == "Bearer secret-tok"

    body = "".join(out)
    # Relayed bytes appear, framed as SSE (data: ...\n\n).
    assert 'data: {"delta": "Hello"}\n\n' in out
    assert 'data: {"delta": " world"}\n\n' in out
    assert 'data: {"type": "model_info", "model": "ellie"}\n\n' in out
    # Every relayed event is properly terminated.
    for chunk in out:
        assert chunk.endswith("\n\n")
    # Exactly one DONE, and it is last.
    assert out.count("data: [DONE]\n\n") == 1
    assert out[-1] == "data: [DONE]\n\n"
    # Prose accumulated for persistence.
    assert "".join(prose) == "Hello world"


async def test_thinking_deltas_relayed_but_not_accumulated(monkeypatch):
    capture = {}
    lines = [
        'data: {"delta": "reasoning", "thinking": true}',
        "",
        'data: {"delta": "answer"}',
        "",
        "data: [DONE]",
    ]
    _patch_client(monkeypatch, capture, lines)

    prose = []
    out = []
    async for chunk in stream_ellie_backend(
        [], "s", base_url="http://h", on_delta=prose.append,
    ):
        out.append(chunk)

    # thinking delta is forwarded to the client...
    assert 'data: {"delta": "reasoning", "thinking": true}\n\n' in out
    # ...but kept out of the saved prose (matches the local loop).
    assert "".join(prose) == "answer"


async def test_no_token_omits_auth_header(monkeypatch):
    capture = {}
    _patch_client(monkeypatch, capture, ["data: [DONE]"])
    async for _ in stream_ellie_backend([], "s", base_url="http://h", token=""):
        pass
    assert "Authorization" not in (capture["headers"] or {})


async def test_synthesizes_done_when_backend_omits_it(monkeypatch):
    capture = {}
    _patch_client(monkeypatch, capture, ['data: {"delta": "hi"}'])
    out = [c async for c in stream_ellie_backend([], "s", base_url="http://h")]
    assert out[-1] == "data: [DONE]\n\n"


async def test_unreachable_raises_before_any_bytes(monkeypatch):
    # Connection blows up at stream() time, before any line is relayed → the
    # caller must be able to fall back to the local loop, so we raise (not 500).
    capture = {}
    _patch_client(
        monkeypatch, capture, [],
        raise_on_stream=httpx.ConnectError("refused"),
    )
    gen = stream_ellie_backend([], "s", base_url="http://127.0.0.1:9", token="t")
    with pytest.raises(EllieBackendError):
        await gen.__anext__()


async def test_http_error_status_before_bytes_raises(monkeypatch):
    capture = {}
    _patch_client(monkeypatch, capture, [], status_code=502)
    gen = stream_ellie_backend([], "s", base_url="http://h")
    with pytest.raises(EllieBackendError):
        await gen.__anext__()


async def test_midstream_failure_emits_clean_error_not_crash(monkeypatch):
    # Once relaying has started, an exception must NOT propagate — it is surfaced
    # in-band as a delta + DONE so the SSE stream closes cleanly.
    capture = {}

    class _BoomResp(_FakeResp):
        async def aiter_lines(self):
            yield 'data: {"delta": "partial"}'
            raise httpx.ReadError("dropped")

    class _BoomCtx:
        async def __aenter__(self):
            return _BoomResp([])

        async def __aexit__(self, *a):
            return False

    class _BoomClient(_FakeClient):
        def stream(self, method, url, **kw):
            return _BoomCtx()

    monkeypatch.setattr(
        httpx, "AsyncClient", lambda *a, **k: _BoomClient(capture, []),
    )

    out = [c async for c in stream_ellie_backend([], "s", base_url="http://h")]
    assert 'data: {"delta": "partial"}\n\n' in out
    assert any("[ellie backend error]" in c for c in out)
    assert out[-1] == "data: [DONE]\n\n"


def test_is_ellie_backend_reads_setting(monkeypatch):
    import src.settings as settings
    monkeypatch.setattr(settings, "get_setting", lambda k, d=None: "ellie" if k == "agent_backend" else d)
    assert is_ellie_backend() is True
    monkeypatch.setattr(settings, "get_setting", lambda k, d=None: "" if k == "agent_backend" else d)
    assert is_ellie_backend() is False
    monkeypatch.setattr(settings, "get_setting", lambda k, d=None: "odysseus" if k == "agent_backend" else d)
    assert is_ellie_backend() is False
