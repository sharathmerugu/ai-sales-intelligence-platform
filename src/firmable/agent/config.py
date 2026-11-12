"""Agent configuration, server-side only (environment variables; never sent to the browser).

| Variable | Default | Meaning |
|---|---|---|
| FIRMABLE_LLM_PROVIDER | `none` | `anthropic`, `mock` (deterministic test model, no network) or `none` (factual briefs only) |
| FIRMABLE_LLM_MODEL | `claude-opus-5-5` | model id |
| FIRMABLE_LLM_EFFORT | `medium` | `output_config.effort` |
| FIRMABLE_LLM_FALLBACKS | `default` | server-side refusal fallback (`default` or `off`) |
| FIRMABLE_LLM_PRICES | built in | JSON `{model: {input, output, cache_read, cache_write}}` in USD per million tokens |
| FIRMABLE_AGENT_MAX_MODEL_CALLS | 8 | model calls per run, repairs included |
| FIRMABLE_AGENT_MAX_TOOL_CALLS | 10 | retrieval tool calls per run |
| FIRMABLE_AGENT_MAX_TOKENS | 150000 | input + output tokens per run, summed over calls |
| FIRMABLE_AGENT_MAX_SECONDS | 90 | wall-clock budget per run |
| FIRMABLE_AGENT_MAX_REPAIRS | 2 | rejected submissions the model may fix |
| FIRMABLE_AGENT_RUNS_PER_HOUR | 60 | new runs per access scope per hour (cache hits are free) |
| FIRMABLE_AGENT_WORKERS | 2 | concurrent runs in this process |
| FIRMABLE_AGENT_RETRY_COOLDOWN | 600 | seconds before a failed brief may be generated again |
| FIRMABLE_AGENT_DAILY_USD | 20 | recorded spend over 24 h after which new runs are refused (fallback served) |
| FIRMABLE_LLM_ALLOW_INTERNAL | unset | `1` allows sending the internal (unsanitized) serving DB's records to the provider |
| FIRMABLE_APP_DB | `:memory:` | SQLite file for runs and briefs |

The provider credential (ANTHROPIC_API_KEY or an `ant auth` profile) is read by the SDK itself.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from typing import Any

# USD per million tokens. Source: Anthropic list prices as recorded in the claude-api reference
# (cached 2026-11-03). Cache writes use the 5-minute TTL rate (1.25 x input). Override with
# FIRMABLE_LLM_PRICES when billing rates differ; an unknown model is reported as unpriced, never guessed.
DEFAULT_PRICES: dict[str, dict[str, float]] = {
    "claude-opus-5-5": {"input": 4.00, "output": 20.00, "cache_read": 0.20, "cache_write": 5.00},
    "claude-opus-5": {"input": 5.00, "output": 25.00, "cache_read": 0.50, "cache_write": 6.25},
    "claude-opus-4-8": {"input": 5.00, "output": 25.00, "cache_read": 0.50, "cache_write": 6.25},
    "claude-sonnet-5-5": {"input": 2.00, "output": 10.00, "cache_read": 0.10, "cache_write": 2.50},
    "claude-haiku-5-5": {"input": 0.10, "output": 0.50, "cache_read": 0.01, "cache_write": 0.125},
}
PRICES_SOURCE = "Anthropic list prices recorded 2026-11-03 (override: FIRMABLE_LLM_PRICES)"
PROVIDERS = ("none", "anthropic", "mock")


@dataclass(frozen=True)
class AgentConfig:
    provider: str = "none"
    model: str = "claude-opus-5-5"
    effort: str = "medium"
    fallbacks: str = "default"
    max_model_calls: int = 8
    max_tool_calls: int = 10
    max_tokens_total: int = 150_000
    max_output_tokens_per_call: int = 16_000
    max_seconds: float = 90.0
    max_repairs: int = 2
    runs_per_hour: int = 60
    workers: int = 2
    retry_cooldown_s: float = 600.0
    max_transient_retries: int = 1
    app_db: str = ":memory:"
    daily_usd_cap: float = 20.0
    allow_internal_profile: bool = False
    prices: dict[str, dict[str, float]] = field(default_factory=lambda: dict(DEFAULT_PRICES))

    @property
    def enabled(self) -> bool:
        return self.provider != "none"

    @property
    def model_label(self) -> str:
        return "mock-heuristic" if self.provider == "mock" else self.model

    def with_(self, **kw: Any) -> "AgentConfig":
        return replace(self, **kw)

    def public(self) -> dict[str, Any]:
        """What the UI may see: no credentials, no prices beyond their source."""
        return {
            "enabled": self.enabled, "provider": self.provider, "model": self.model_label, "effort": self.effort,
            "budgets": {"model_calls": self.max_model_calls, "tool_calls": self.max_tool_calls,
                        "tokens": self.max_tokens_total, "seconds": self.max_seconds, "repairs": self.max_repairs},
            "runs_per_hour": self.runs_per_hour, "daily_usd_cap": self.daily_usd_cap,
        }

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "AgentConfig":
        env = dict(os.environ if env is None else env)
        provider = (env.get("FIRMABLE_LLM_PROVIDER") or "none").lower()
        if provider not in PROVIDERS:
            raise RuntimeError(f"FIRMABLE_LLM_PROVIDER must be one of {PROVIDERS}, not {provider!r}")
        prices = dict(DEFAULT_PRICES)
        if env.get("FIRMABLE_LLM_PRICES"):
            prices.update(json.loads(env["FIRMABLE_LLM_PRICES"]))

        def num(name: str, default: float, kind: type = int) -> Any:
            raw = env.get(name)
            return default if raw in (None, "") else kind(raw)

        return cls(
            provider=provider,
            model=env.get("FIRMABLE_LLM_MODEL") or cls.model,
            effort=env.get("FIRMABLE_LLM_EFFORT") or cls.effort,
            fallbacks=(env.get("FIRMABLE_LLM_FALLBACKS") or cls.fallbacks).lower(),
            max_model_calls=num("FIRMABLE_AGENT_MAX_MODEL_CALLS", cls.max_model_calls),
            max_tool_calls=num("FIRMABLE_AGENT_MAX_TOOL_CALLS", cls.max_tool_calls),
            max_tokens_total=num("FIRMABLE_AGENT_MAX_TOKENS", cls.max_tokens_total),
            max_seconds=num("FIRMABLE_AGENT_MAX_SECONDS", cls.max_seconds, float),
            max_repairs=num("FIRMABLE_AGENT_MAX_REPAIRS", cls.max_repairs),
            runs_per_hour=num("FIRMABLE_AGENT_RUNS_PER_HOUR", cls.runs_per_hour),
            workers=num("FIRMABLE_AGENT_WORKERS", cls.workers),
            retry_cooldown_s=num("FIRMABLE_AGENT_RETRY_COOLDOWN", cls.retry_cooldown_s, float),
            app_db=env.get("FIRMABLE_APP_DB") or ":memory:",
            daily_usd_cap=num("FIRMABLE_AGENT_DAILY_USD", cls.daily_usd_cap, float),
            allow_internal_profile=env.get("FIRMABLE_LLM_ALLOW_INTERNAL") == "1",
            prices=prices,
        )


def cost_usd(prices: dict[str, dict[str, float]], model: str, input_tokens: int, output_tokens: int,
             cache_read: int, cache_write: int) -> float | None:
    """Cost from actual token usage at the configured rates; None when the model has no rate."""
    p = prices.get(model)
    if p is None:
        return None
    return round((input_tokens * p["input"] + output_tokens * p["output"] + cache_read * p["cache_read"]
                  + cache_write * p["cache_write"]) / 1_000_000, 6)
