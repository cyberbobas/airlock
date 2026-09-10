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

import time

from .. import audit
from ..policy import ALLOW, ASK, BLOCK, RANK, Decision
from . import get_backend
from .base import JudgeContext


def _note_noop(tool: str, server: str, d: Decision, why: str) -> None:
    """Record that the judge was consulted but gave no opinion, so the rules
    stand. Without this the failure is invisible: on CPU-only hardware the judge
    times out on every call and silently does nothing — a security control that
    is inert with no error and no log line. Fail-safe (rules already vetted the
    call), but the operator must be able to SEE that Feature B is not running."""
    try:
        audit.record("judge_noop", source="ai", tool=tool, server=server,
                     effective="observe", reason=f"judge gave no opinion ({why}); rules stand",
                     extra=f"rule_verdict={d.action}")
    except Exception:
        pass  # observability must never break the hot path


def _cfg(cfg, local: bool = True):
    ai = getattr(cfg, "ai", {}) or {}
    j = ai.get("judge", {}) if isinstance(ai, dict) else {}
    # A local model answers in tens-to-hundreds of ms; a cloud model needs a
    # network round-trip (often 1-3s), so the default scales with where the model
    # runs. An explicit latency_budget_ms always wins.
    #
    # The local default is 3000ms, not 800: the shipped builtin is a 3B Q4
    # llamafile, and on the hardware llamafile is FOR — CPU-only, no CUDA — one
    # judge call takes ~1.1s (measured, -ngl 0). At an 800ms ceiling every call
    # exceeded the budget and consult() fell back to the rules, so Feature B was
    # silently inert for the modal user (GPU boxes hid it: ~140ms offloaded).
    # 3000ms clears CPU latency with headroom while still bounding the hot path.
    default_budget = 3000 if local else 6000
    return {
        "enabled": j.get("enabled", True) is not False,
        "budget": int(j.get("latency_budget_ms", default_budget) or default_budget),
        "relax_ask": bool(j.get("relax_ask", False)),
        "check_allow": bool(j.get("check_allow", False)),
        # verdict cache: 0 disables. Only ever caches within one process, so the
        # per-call hook (fresh process each time) is unaffected; it saves the
        # repeated model round-trip on the long-lived MCP proxy.
        "cache_ttl_ms": int(j.get("cache_ttl_ms", 300000) or 0),
    }


# In-process, temperature-0 verdict cache. Keyed on EVERYTHING that can change a
# verdict (policy digest + model + the full redacted context), never on the tool
# name alone, so one cached answer can never stand in for a different call. Bound
# in size; entries expire by TTL. Deliberately NOT persisted to disk: a cached
# allow that outlived the reason it was safe would be a silent bypass, and the
# hot path should not grow a shared, stale, on-disk trust store.
_verdict_cache: dict = {}
_CACHE_MAX = 512


def _cache_key(cfg, backend, ctx: JudgeContext) -> str:
    import hashlib, json as _json
    payload = _json.dumps({
        "digest": getattr(cfg, "digest", ""),
        "model": getattr(backend, "model", "") or getattr(backend, "source", ""),
        "tool": ctx.tool, "server": ctx.server, "plane": ctx.plane,
        "rule": ctx.rule_verdict,
        "args": ctx.args,
    }, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


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

    ctx = JudgeContext(tool=tool, server=server, args=args or {}, plane=plane,
                       rule_verdict=d.action, reason_hint=d.reason)
    ttl = opt["cache_ttl_ms"]
    key = _cache_key(cfg, b, ctx) if ttl > 0 else None
    v = None
    if key is not None:
        hit = _verdict_cache.get(key)
        if hit is not None and hit[1] > time.monotonic():
            v = hit[0]                            # fresh cached verdict
        elif hit is not None:
            _verdict_cache.pop(key, None)         # expired
    if v is None:
        try:
            v = b.judge(ctx, timeout_ms=opt["budget"])
        except Exception:
            _note_noop(tool, server, d, "backend error")
            return d                              # fail safe to the rules
        if v is None:
            # available backend, but no answer within the budget (timeout) or an
            # unusable reply — the judge added nothing. Log it; do not fail.
            _note_noop(tool, server, d, "timeout or unusable reply")
            return d
        if key is not None:
            if len(_verdict_cache) >= _CACHE_MAX:
                _verdict_cache.clear()            # crude bound; correctness over hit-rate
            _verdict_cache[key] = (v, time.monotonic() + ttl / 1000.0)

    reason = f"AI: {v.reason}" if v.reason else d.reason
    if RANK[v.decision] > RANK[d.action]:         # tighten
        return Decision(v.decision, reason, d.rule)
    if opt["relax_ask"] and d.action == ASK and v.decision == ALLOW:
        return Decision(ALLOW, reason, d.rule)    # opt-in: auto-approve the ask
    return d
