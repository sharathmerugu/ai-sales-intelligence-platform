"""Provider-neutral model gateway.

The agent loop talks to `LLMClient.create`, which returns an `LLMResponse` of plain blocks plus the
provider's raw content (sent back unchanged on the next turn, so thinking blocks survive). One real
provider is implemented (Anthropic Messages API); `ScriptedClient` replays canned turns for tests and
`firmable.agent.mock.HeuristicModel` is a deterministic offline stand-in.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .config import AgentConfig

FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens + self.cache_read_tokens + self.cache_write_tokens


@dataclass
class LLMResponse:
    blocks: list[dict[str, Any]]          # {"type": "text"|"tool_use"|..., "text"?, "id"?, "name"?, "input"?}
    stop_reason: str | None
    usage: Usage
    model: str
    raw_content: Any = None               # provider content to append as the assistant turn
    request_id: str | None = None
    latency_ms: float = 0.0

    @property
    def tool_uses(self) -> list[dict[str, Any]]:
        return [b for b in self.blocks if b.get("type") == "tool_use"]

    @property
    def text(self) -> str:
        return "\n".join(b.get("text") or "" for b in self.blocks if b.get("type") == "text").strip()

    def assistant_content(self) -> Any:
        return self.raw_content if self.raw_content is not None else self.blocks


class TransientLLMError(Exception):
    """Rate limit, overload, timeout or connection failure: one bounded retry is allowed."""


class FatalLLMError(Exception):
    """Authentication, bad request, refusal or another error a retry cannot fix."""


class LLMClient(Protocol):
    model: str

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
               max_tokens: int, timeout: float) -> LLMResponse: ...


class AnthropicClient:
    """Claude through the official SDK. SDK retries are off: the agent loop owns retries and counts them."""

    def __init__(self, config: AgentConfig):
        import anthropic  # imported lazily so the app runs without the provider configured

        self._anthropic = anthropic
        self._client = anthropic.Anthropic(max_retries=0)
        self.model = config.model
        self.config = config

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
               max_tokens: int, timeout: float) -> LLMResponse:
        a = self._anthropic
        kwargs: dict[str, Any] = dict(
            model=self.model, max_tokens=max_tokens, messages=messages, tools=tools,
            # Stable prefix (tools, then system) is cached; the account-specific turn follows it.
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            thinking={"type": "adaptive"}, output_config={"effort": self.config.effort}, timeout=timeout,
        )
        if self.config.fallbacks == "default":
            kwargs.update(betas=[FALLBACK_BETA], fallbacks="default")
        started = time.perf_counter()
        try:
            msg = self._client.beta.messages.create(**kwargs)
        except (a.RateLimitError, a.APITimeoutError, a.APIConnectionError, a.InternalServerError) as e:
            raise TransientLLMError(f"{type(e).__name__}: {e}") from e
        except a.APIStatusError as e:
            if e.status_code >= 500 or e.status_code in (408, 409, 429, 529):
                raise TransientLLMError(f"{type(e).__name__} {e.status_code}") from e
            raise FatalLLMError(f"{type(e).__name__} {e.status_code}: {e.message}") from e
        latency = (time.perf_counter() - started) * 1000
        u = msg.usage
        usage = Usage(input_tokens=u.input_tokens or 0, output_tokens=u.output_tokens or 0,
                      cache_read_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
                      cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0)
        blocks: list[dict[str, Any]] = []
        for b in msg.content:
            if b.type == "text":
                blocks.append({"type": "text", "text": b.text})
            elif b.type == "tool_use":
                blocks.append({"type": "tool_use", "id": b.id, "name": b.name, "input": dict(b.input or {})})
            else:
                blocks.append({"type": b.type})
        return LLMResponse(blocks=blocks, stop_reason=msg.stop_reason, usage=usage, model=msg.model,
                           raw_content=msg.content, request_id=getattr(msg, "_request_id", None), latency_ms=latency)


@dataclass
class ScriptedClient:
    """Test double: each turn is a function of the messages so far, returning blocks (and an optional
    stop reason or exception). Records every request it receives."""

    turns: list[Callable[[list[dict[str, Any]]], Any]]
    model: str = "scripted"
    usage_per_call: Usage = field(default_factory=lambda: Usage(1000, 200, 0, 0))
    requests: list[dict[str, Any]] = field(default_factory=list)

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
               max_tokens: int, timeout: float) -> LLMResponse:
        self.requests.append({"system": system, "messages": [dict(m) for m in messages], "tools": tools,
                              "max_tokens": max_tokens})
        i = len(self.requests) - 1
        turn = self.turns[min(i, len(self.turns) - 1)]
        out = turn(messages)
        if isinstance(out, Exception):
            raise out
        stop = "tool_use"
        if isinstance(out, tuple):
            out, stop = out
        elif not any(b.get("type") == "tool_use" for b in out):
            stop = "end_turn"
        return LLMResponse(blocks=out, stop_reason=stop, usage=Usage(**vars(self.usage_per_call)), model=self.model)


def make_client(config: AgentConfig, semantic: Any = None) -> LLMClient | None:
    if config.provider == "anthropic":
        return AnthropicClient(config)
    if config.provider == "mock":
        from .mock import HeuristicModel
        return HeuristicModel()
    return None
