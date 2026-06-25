"""External "Ellie" agent backend forwarder.

When the ``agent_backend`` setting resolves to ``"ellie"``, the chat stream is
proxied to an external Ellie service instead of running the local agent loop.
Ellie exposes ``POST /api/odysseus/turn`` and emits Odysseus's EXACT SSE shapes
(``data: {json}\\n\\n`` ... ``data: [DONE]\\n\\n``), so the relay just re-frames
each line back into the same SSE envelope Odysseus's own generator yields.

Kept in its own tiny module (rather than inline in routes/chat_routes.py) so it
can be unit-tested in isolation without importing the full FastAPI/DB stack.
"""

import json
import logging
from typing import AsyncGenerator, Callable, Iterable, List, Optional

import httpx

logger = logging.getLogger(__name__)

# Marker sentinel so the caller can tell "Ellie was unreachable" apart from a
# normal completion and fall back to the local agent loop.
TURN_PATH = "/api/odysseus/turn"


def is_ellie_backend() -> bool:
    """True when the active settings route the agent turn to the Ellie backend.

    Reads the same ``get_setting`` mechanism the agent loop already uses for
    ``agent_max_rounds`` etc., so there is no parallel config system.
    """
    try:
        from src.settings import get_setting
        return str(get_setting("agent_backend", "") or "").strip().lower() == "ellie"
    except Exception:
        return False


class EllieBackendError(Exception):
    """Raised when the Ellie backend can't be reached or fails before output.

    The caller catches this to decide whether to fall back to the local agent
    loop. Once relaying has started (bytes yielded) we do NOT raise — a clean
    error + [DONE] is emitted instead so we never crash a half-sent SSE stream.
    """


def format_recall(used_memories) -> Optional[str]:
    """Render Odysseus's ``ctx.used_memories`` into a plain recall block for the
    Ellie backend's ``recall`` field. Each entry is ``{"text", "category",
    "type"}``; emit one ``- <text>`` bullet per non-blank entry. Returns ``None``
    for an empty/falsy list so no empty block is sent (Ellie then skips the
    preamble entirely).
    """
    if not used_memories:
        return None
    lines = [
        f"- {m['text'].strip()}"
        for m in used_memories
        if isinstance(m, dict) and (m.get("text") or "").strip()
    ]
    if not lines:
        return None
    return "\n".join(lines)


async def stream_ellie_backend(
    messages: List[dict],
    session_id: str,
    *,
    base_url: str,
    token: str = "",
    model: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    api_key: Optional[str] = None,
    disabled_tools: Optional[Iterable[str]] = None,
    recall: Optional[str] = None,
    on_delta: Optional[Callable[[str], None]] = None,
    timeout: float = 300.0,
    connect_timeout: float = 10.0,
) -> AsyncGenerator[str, None]:
    """Proxy a turn to the Ellie backend and relay its SSE bytes through.

    Yields SSE chunks framed EXACTLY like Odysseus's own generator
    (``"data: ...\\n\\n"``) so the browser SPA parses them identically.

    ``on_delta`` is invoked with the text of each ``{"delta": t}`` event so the
    caller can accumulate the assistant prose for post-turn persistence, mirroring
    the local loop's ``full_response += data["delta"]``.

    Raises :class:`EllieBackendError` if the connection fails BEFORE any bytes are
    relayed (so the caller can fall back). After relaying has begun, a failure is
    surfaced in-band as ``{"delta": "[ellie backend error]"}`` + ``[DONE]``.
    """
    url = base_url.rstrip("/") + TURN_PATH
    payload = {"messages": messages, "session_id": session_id}
    # Optional per-session overrides. When the session pins a model/endpoint/key,
    # forward them so Ellie drives the turn with the session's model + permissions
    # instead of falling back to her own. Omitted when empty so a plain session
    # keeps the old {messages, session_id} body (backward-compat).
    if model:
        payload["model"] = model
    if endpoint_url:
        payload["endpoint_url"] = endpoint_url
    if api_key:
        payload["api_key"] = api_key
    if disabled_tools:
        payload["disabled_tools"] = sorted(disabled_tools)
    if recall:
        payload["recall"] = recall
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    started = False
    saw_done = False
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=connect_timeout)
        ) as client:
            async with client.stream(
                "POST", url, json=payload, headers=headers
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line:
                        # aiter_lines() drops the blank separator line between
                        # SSE events; we re-add it on each data line below, so a
                        # bare empty line here is just that separator — skip it.
                        continue
                    if line.startswith("data: "):
                        body = line[6:]
                        if body == "[DONE]":
                            saw_done = True
                            started = True
                            # Re-frame and relay Ellie's terminator exactly once.
                            yield "data: [DONE]\n\n"
                            continue
                        # Accumulate assistant prose for post-turn persistence.
                        if on_delta is not None:
                            try:
                                data = json.loads(body)
                            except (ValueError, TypeError):
                                data = None
                            if isinstance(data, dict) and "delta" in data:
                                # Match the local loop: reasoning tokens flagged
                                # thinking:true are forwarded but NOT saved.
                                if not data.get("thinking"):
                                    delta = data.get("delta")
                                    if isinstance(delta, str):
                                        on_delta(delta)
                        started = True
                        # Re-frame as SSE; aiter_lines stripped the trailing \n\n.
                        yield line + "\n\n"
                    else:
                        # Non-data SSE line (e.g. ``event: ...`` / comment). Relay
                        # verbatim, re-adding the event separator.
                        started = True
                        yield line + "\n\n"
    except Exception as exc:
        if not started:
            # Nothing relayed yet — let the caller fall back to the local loop.
            raise EllieBackendError(str(exc)) from exc
        # Mid-stream failure: never crash the SSE. Emit a clean error + DONE.
        logger.warning("Ellie backend stream failed mid-relay (session %s): %s", session_id, exc)
        yield 'data: {"delta": "[ellie backend error]"}\n\n'
        if not saw_done:
            yield "data: [DONE]\n\n"
        return

    # Ellie never sent a terminator — synthesize one so the browser completes
    # and the caller's post-turn save (gated on the local loop's [DONE] handling)
    # still fires.
    if not saw_done:
        yield "data: [DONE]\n\n"
