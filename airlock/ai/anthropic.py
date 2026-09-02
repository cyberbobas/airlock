"""Native Anthropic (Claude) backend.

Claude is first-class, and its Messages API differs from the OpenAI shape (system
is a top-level field, auth is `x-api-key`, response is `content[].text`), so it
gets its own tiny adapter rather than being bent through the OpenAI one. Stdlib
only, same fail-safe rules as every backend: never raise on the hot path, an
unparseable reply is no opinion (None), never a silent allow.
"""
from __future__ import annotations

import json
import urllib.request

from .base import JudgeContext, Verdict
from .openai_compat import _parse_verdict
from .prompts import (JUDGE_SYSTEM, SUMMARY_SYSTEM, judge_prompt, redact_obj,
                      summary_prompt)

API_VERSION = "2023-06-01"


class AnthropicBackend:
    def __init__(self, base_url: str, model: str, *, api_key: str = "",
                 source: str = "cloud"):
        self.base_url = (base_url or "https://api.anthropic.com/v1").rstrip("/")
        self.model = model
        self.api_key = api_key
        self.source = source
        self.local = False        # Anthropic is always a cloud round-trip

    def _messages(self, system: str, user: str, *, timeout_ms: int,
                  max_tokens: int = 256, temperature: float = 0.0) -> str | None:
        body = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(self.base_url + "/messages", data=body, method="POST")
        req.add_header("content-type", "application/json")
        req.add_header("x-api-key", self.api_key)
        req.add_header("anthropic-version", API_VERSION)
        try:
            with urllib.request.urlopen(req, timeout=max(0.05, timeout_ms / 1000)) as r:
                data = json.loads(r.read())
            parts = data.get("content") or []
            return "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        except Exception:
            return None

    def available(self) -> bool:
        return bool(self.api_key and self.model)

    def judge(self, ctx: JudgeContext, *, timeout_ms: int):
        payload = {
            "tool": ctx.tool, "server": ctx.server, "plane": ctx.plane,
            "rule_verdict": ctx.rule_verdict, "reason_hint": ctx.reason_hint,
            "args": redact_obj(ctx.args or {}),
        }
        out = self._messages(JUDGE_SYSTEM, judge_prompt(payload),
                             timeout_ms=timeout_ms, max_tokens=64)
        if not out:
            return None
        parsed = _parse_verdict(out)
        if parsed is None:
            return None
        decision, reason = parsed
        return Verdict(decision=decision, reason=reason, source=self.source)

    def summarize(self, facts: dict, *, timeout_ms: int = 20000) -> str:
        out = self._messages(SUMMARY_SYSTEM, summary_prompt(redact_obj(facts)),
                            timeout_ms=timeout_ms, max_tokens=400, temperature=0.2)
        return (out or "").strip()
