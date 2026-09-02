"""Airlock AI ("AI in the Middle") — the optional runtime brain.

Airlock's value works with zero AI: rules gate calls, the audit log records them.
This package is the *optional* layer on top, in three tiers (see docs/AI-SPEC.md):

  * lite      — no model. Rules + a structured, non-LLM summary.
  * standard  — our small built-in model. Narrative summary + gray-zone judge.
  * pro       — standard, plus a bigger model you bring (local or a cloud key).

Everything degrades safely: if no backend is `available()` (lite, no model,
cloud locked off, or an error), callers fall back to the non-AI path. The AI can
only ever make a call *safer* than the rules alone — it never lifts a hard rule.
"""
from __future__ import annotations

from .base import Backend, JudgeContext, NullBackend, Verdict

__all__ = ["Backend", "JudgeContext", "NullBackend", "Verdict", "get_backend"]


def _resolve_cfg(cfg):
    """Return (tier, cloud) from a Policy-like cfg, the active policy, or safe
    defaults. Never raises — a config problem must not enable AI by surprise."""
    if cfg is None:
        try:
            from ..policy import Policy
            cfg = Policy.resolve()
        except Exception:
            return "lite", "off"
    return (getattr(cfg, "tier", "lite") or "lite"), (getattr(cfg, "cloud", "off") or "off")


def get_backend(cfg=None) -> Backend:
    """Return the AI backend for the current config.

    * lite            -> NullBackend (no model; callers use the non-AI path).
    * standard / pro  -> the built-in llamafile model if it is installed,
                         else NullBackend (degrade safely).

    Cloud/BYO provider selection for the `pro` tier lands in M4; it will honor
    `cloud: off | locked-off`. The built-in model is always local, so it runs
    regardless of the cloud setting.
    """
    tier, _cloud = _resolve_cfg(cfg)
    if tier not in ("standard", "pro"):
        return NullBackend()
    # pro: a configured bring-your-own model (local or cloud) wins, if allowed.
    if tier == "pro":
        try:
            from . import providers
            byo = providers.backend_for(cfg)
            if byo is not None and byo.available():
                return byo
        except Exception:
            pass
    # standard, or pro with no/unusable provider: the built-in local model.
    try:
        from .builtin import BuiltinBackend
        b = BuiltinBackend()
        if b.available():
            return b
    except Exception:
        pass
    return NullBackend()
