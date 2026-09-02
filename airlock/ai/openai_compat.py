"""One HTTP client for every OpenAI-compatible chat endpoint.

This single adapter covers our local llamafile (built-in tier), a user's own
local server (Ollama / LM Studio / vLLM / llama.cpp), and cloud providers whose
API is OpenAI-shaped (OpenAI, DeepSeek, Qwen/DashScope, Kimi/Moonshot, GLM/Zhipu,
Groq, OpenRouter). The only per-provider difference is base_url + model + key, so
we do not write one integration per vendor.

Stdlib only (urllib) — same discipline as ask.py / comment.py, and no new deps.

Two hard rules for the hot path (`judge`):
  * never exceed the caller's timeout (urllib timeout + our own ceiling);
  * never raise — any failure returns None ("no opinion"), so the caller applies
    its fail-safe (default: ask). A model that is slow, down, or off-vocabulary
    must never turn into a silent allow.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .base import ASK, Backend, JudgeContext, Verdict
from .prompts import (JUDGE_SYSTEM, SUMMARY_SYSTEM, judge_prompt, redact_obj,
                      summary_prompt)


class OpenAICompatBackend:
    """A Backend backed by any OpenAI-compatible /chat/completions endpoint."""

    def __init__(self, base_url: str, model: str, *, api_key: str = "",
                 source: str = "ai", local: bool = False):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.source = source        # "mini" | "cloud" | ...
        self.local = local          # True for the built-in / a localhost server

    # --- transport -------------------------------------------------------
    def _chat(self, system: str, user: str, *, timeout_ms: int,
              max_tokens: int = 256, temperature: float = 0.0) -> str | None:
        url = self.base_url + "/chat/completions"
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=max(0.05, timeout_ms / 1000)) as r:
                data = json.loads(r.read())
            return data["choices"][0]["message"]["content"]
        except Exception:
            # Timeout, connection refused, HTTP error, malformed response —
            # all the same to the caller: no answer.
            return None

    def available(self) -> bool:
        """Cheap reachability probe. Subclasses/builtin may override with a
        model-file check to avoid a network round-trip on every gate."""
        return bool(self.base_url and self.model)

    # --- judge (hot path) ------------------------------------------------
    def judge(self, ctx: JudgeContext, *, timeout_ms: int):
        payload = {
            "tool": ctx.tool, "server": ctx.server, "plane": ctx.plane,
            "rule_verdict": ctx.rule_verdict, "reason_hint": ctx.reason_hint,
            "args": redact_obj(ctx.args or {}),
        }
        out = self._chat(JUDGE_SYSTEM, judge_prompt(payload),
                         timeout_ms=timeout_ms, max_tokens=64)
        if not out:
            return None
        parsed = _parse_verdict(out)
        if parsed is None:
            return None
        decision, reason = parsed
        return Verdict(decision=decision, reason=reason, source=self.source)

    # --- summary (batch) -------------------------------------------------
    def summarize(self, facts: dict, *, timeout_ms: int = 20000) -> str:
        out = self._chat(SUMMARY_SYSTEM, summary_prompt(redact_obj(facts)),
                         timeout_ms=timeout_ms, max_tokens=400, temperature=0.2)
        return (out or "").strip()


def _parse_verdict(text: str):
    """Extract (decision, reason) from a model reply. None if unusable.

    Tolerant of models that wrap JSON in prose or code fences. If it cannot find
    a clean verdict it returns None so the caller fails closed rather than
    guessing an allow.
    """
    text = text.strip()
    # 1) first {...} block that parses as JSON
    start = text.find("{")
    while start != -1:
        depth, i = 0, start
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
        chunk = text[start:i + 1]
        try:
            obj = json.loads(chunk)
            dec = str(obj.get("decision", "")).strip().lower()
            if dec in ("allow", "block", "ask"):
                return dec, str(obj.get("reason", "")).strip()[:200]
        except Exception:
            pass
        start = text.find("{", start + 1)
    # 2) bare keyword fallback, strictest wins if several appear
    low = text.lower()
    for dec in ("block", "ask", "allow"):   # block first: safest to honor
        if dec in low:
            return dec, text[:120]
    return None
