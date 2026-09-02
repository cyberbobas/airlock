"""The inline judge: an AI overlay on the deterministic decision.

Wired into both enforcement points (mcp_proxy, cc_hook) right after the rules
resolve. It exists to make a call *safer* than the rules alone, never looser, and
to fail closed when the model cannot answer. Concretely:

  * A hard BLOCK is never touched. The judge cannot lift it.
  * By default the judge runs only on the gray zone the rules escalated (`ask`),
    not on every `allow` — so the hot path pays for the model only when the rules
    were already going to interrupt a human. `judge.check_allow: true` opts into
    scanning allows too (catch a dangerous allow at the cost of a call each time).
  * Tighten-only by default: it takes the stricter of (rules, judge). So it can
    turn an `ask` into a `block`. It will NOT turn an `ask` into an `allow`
    (which would skip the human) unless `judge.relax_ask: true` is set — off by
    default, because the core promise is fail-closed.
  * Any failure — no model, timeout, error, off-vocabulary — returns the rules'
    decision unchanged. Not consulting the judge is safe: the rules already
    vetted the call, and the judge only ever adds strictness on top.

This preserves the core invariant (ROADMAP: "Fail-closed").
"""
from __future__ import annotations

from ..policy import ALLOW, ASK, BLOCK, RANK, Decision
from . import get_backend
from .base import JudgeContext


def _cfg(cfg, local: bool = True):
    ai = getattr(cfg, "ai", {}) or {}
    j = ai.get("judge", {}) if isinstance(ai, dict) else {}
    # A local model answers in tens-to-hundreds of ms; a cloud model needs a
    # network round-trip (often 1-3s). With the local default a cloud judge would
    # silently time out on every call and do nothing, so the default scales with
    # where the model runs. An explicit latency_budget_ms always wins.
    default_budget = 800 if local else 6000
    return {
        "enabled": j.get("enabled", True) is not False,
        "budget": int(j.get("latency_budget_ms", default_budget) or default_budget),
        "relax_ask": bool(j.get("relax_ask", False)),
        "check_allow": bool(j.get("check_allow", False)),
    }


def consult(d: Decision, *, tool: str, args: dict | None = None, server: str = "",
            plane: str = "", cfg=None, backend=None) -> Decision:
    """Return a possibly-tightened decision. Never raises; never loosens by default."""
    if d.action == BLOCK:
        return d                                  # a hard block is final
    if getattr(cfg, "tier", "lite") not in ("standard", "pro"):
        return d

    b = backend or get_backend(cfg)
    if not b.available():
        return d                                  # no model -> rules stand
    opt = _cfg(cfg, local=getattr(b, "local", True))
    if not opt["enabled"]:
        return d
    if d.action == ALLOW and not opt["check_allow"]:
        return d                                  # gray zone only, by default
    try:
        v = b.judge(
            JudgeContext(tool=tool, server=server, args=args or {}, plane=plane,
                         rule_verdict=d.action, reason_hint=d.reason),
            timeout_ms=opt["budget"],
        )
    except Exception:
        return d                                  # fail safe to the rules
    if v is None:
        return d

    reason = f"AI: {v.reason}" if v.reason else d.reason
    if RANK[v.decision] > RANK[d.action]:         # tighten
        return Decision(v.decision, reason, d.rule)
    if opt["relax_ask"] and d.action == ASK and v.decision == ALLOW:
        return Decision(ALLOW, reason, d.rule)    # opt-in: auto-approve the ask
    return d
