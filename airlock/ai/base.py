"""The one interface every AI backend implements.

Two jobs, deliberately narrow:

  * judge(ctx)  — on the hot path, for a *gray-zone* call the rules did not settle
                  outright, return allow | block | ask + a one-line reason. May
                  return None to mean "no opinion, use the caller's default".
  * summarize() — off the hot path, turn structured session facts into a short
                  human narrative.

Keeping the surface this small is what lets one adapter (OpenAI-compatible) cover
almost every provider and local runtime, plus a native Anthropic one, plus our
built-in mini model. See docs/AI-SPEC.md.

This module has no third-party dependencies so it imports cleanly in the `lite`
tier where no model is present.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

# The verdict vocabulary is the policy engine's own: allow | block | ask.
# (See policy.decide / audit "effective".) The judge speaks the same words so a
# verdict can flow straight back into the existing decision path.
ALLOW = "allow"
BLOCK = "block"
ASK = "ask"
_DECISIONS = (ALLOW, BLOCK, ASK)


@dataclass
class JudgeContext:
    """Everything the judge is allowed to see about one call.

    Populated from the enforcement point (mcp_proxy / cc_hook). Arguments are
    passed through secret redaction (see prompts.redact) before they ever reach
    a model, local or cloud.
    """
    tool: str                       # tool / method name, e.g. "Bash", "fs/write"
    server: str = ""                # MCP server or plane the call came from
    args: dict = field(default_factory=dict)   # already redacted
    plane: str = ""                 # "mcp" | "hook" | ...
    rule_verdict: str = ""          # what the deterministic rules said (context)
    reason_hint: str = ""           # why the rules escalated (e.g. "no matching grant")


@dataclass
class Verdict:
    """The judge's answer for one call."""
    decision: str                   # ALLOW | BLOCK | ASK
    reason: str = ""                # one line, human-readable, shown to the user
    source: str = "ai"              # "rules" | "mini" | "cloud" | "failsafe" | "cache"
    confidence: float = 0.0         # 0..1, backend's own estimate (optional)

    def __post_init__(self) -> None:
        if self.decision not in _DECISIONS:
            # Never trust a model to stay in-vocabulary. Anything off-menu is
            # treated as "ask" — the safe middle — not silently allowed.
            self.reason = self.reason or f"unrecognized verdict {self.decision!r}"
            self.decision = ASK
            self.source = "failsafe"

    @property
    def is_safe_relative_to(self) -> str:
        return self.decision


@runtime_checkable
class Backend(Protocol):
    """Protocol implemented by every backend (null, builtin, openai_compat, anthropic)."""

    def available(self) -> bool:
        """True if this backend can actually answer right now.

        False for lite, a missing/failed model, or cloud that is off/locked-off.
        Callers MUST check this and fall back to the non-AI path when False.
        """
        ...

    def judge(self, ctx: JudgeContext, *, timeout_ms: int) -> Optional[Verdict]:
        """Judge one gray-zone call within timeout_ms. None = no opinion.

        Must never raise on the hot path and must never exceed timeout_ms; on
        timeout or error the caller applies its fail-safe (default: ask).
        """
        ...

    def summarize(self, facts: dict, *, timeout_ms: int = 20000) -> str:
        """Narrative summary of a session from structured facts. "" if it can't."""
        ...


class NullBackend:
    """The no-AI backend. Used by the `lite` tier and as the universal fallback.

    Reports itself unavailable so every caller takes the deterministic path.
    """

    def available(self) -> bool:
        return False

    def judge(self, ctx: JudgeContext, *, timeout_ms: int) -> Optional[Verdict]:
        return None

    def summarize(self, facts: dict, *, timeout_ms: int = 20000) -> str:
        return ""
