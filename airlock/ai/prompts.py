"""Prompt templates and secret redaction for the AI layer.

Redaction runs before any call context or audit fact reaches a model — local or
cloud. Airlock exists to keep an agent away from secrets; it must not be the
thing that ships them to a model. The same patterns Airlock's siblings flag as
plaintext-credential leaks (agentpipe LOC-06) are the ones scrubbed here.

Pure stdlib (re only) so this imports in the `lite` tier.
"""
from __future__ import annotations

import re
from typing import Any

# High-confidence secret shapes. Conservative: better to redact a harmless token
# than to leak a real one into a prompt.
_SECRET_VALUE = re.compile(
    r"""(
        sk-[A-Za-z0-9_-]{16,}                 # OpenAI-style
      | sk-ant-[A-Za-z0-9_-]{16,}             # Anthropic
      | ghp_[A-Za-z0-9]{20,}                  # GitHub PAT
      | gho_[A-Za-z0-9]{20,}
      | github_pat_[A-Za-z0-9_]{20,}
      | AKIA[0-9A-Z]{16}                      # AWS access key id
      | xox[baprs]-[A-Za-z0-9-]{10,}          # Slack
      | AIza[0-9A-Za-z_-]{30,}                # Google API key
      | eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}  # JWT
      | -----BEGIN[ A-Z]+PRIVATE\ KEY-----    # PEM header
      | [A-Fa-f0-9]{40,}                      # long hex (tokens, hashes)
    )""",
    re.VERBOSE,
)

# key=value / "key": "value" where the key name looks sensitive.
_SECRET_KV = re.compile(
    r"""(?ix)
    \b([a-z0-9_.-]*(?:token|secret|passwd|password|api[_-]?key|auth|credential|bearer)[a-z0-9_.-]*)
    \s*[:=]\s*
    ['"]?([^\s'"]{4,})['"]?
    """,
)

REDACTED = "<redacted>"


def redact(text: str) -> str:
    """Replace anything that looks like a credential with <redacted>."""
    if not text:
        return text
    text = _SECRET_KV.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    text = _SECRET_VALUE.sub(REDACTED, text)
    return text


def redact_obj(obj: Any) -> Any:
    """Deep-redact strings inside dicts/lists (for tool-call arguments)."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact_obj(v) for v in obj)
    return obj


# --- judge ------------------------------------------------------------------

JUDGE_SYSTEM = (
    "You are the security judge inside Airlock, a firewall for AI coding agents. "
    "You see ONE tool call an agent wants to make. Deterministic rules already ran "
    "and left this call in the gray zone. Decide exactly one of: allow, block, ask. "
    "Prefer 'ask' when unsure. Block only clearly dangerous actions (destroying data, "
    "exfiltrating secrets, reaching untrusted networks, disabling safety). Reply with "
    "a single line of JSON: {\"decision\":\"allow|block|ask\",\"reason\":\"<=12 words\"}. "
    "The reason is shown to a human, so be concrete and short."
)


def judge_prompt(ctx: dict) -> str:
    """Build the user message for a judge call from a (already-redacted) context."""
    lines = [
        f"tool: {ctx.get('tool','')}",
        f"server/plane: {ctx.get('server','') or ctx.get('plane','')}",
        f"rules said: {ctx.get('rule_verdict','') or 'gray zone'}",
    ]
    if ctx.get("reason_hint"):
        lines.append(f"why escalated: {ctx['reason_hint']}")
    args = ctx.get("args")
    if args:
        lines.append(f"arguments: {args}")
    return "\n".join(lines)


# --- summary ----------------------------------------------------------------

SUMMARY_SYSTEM = (
    "You are summarizing one session of an AI coding agent for a human who may not "
    "read logs. You are given structured facts already computed by Airlock (counts, "
    "blocked actions, what was touched) — never raw secrets. Write a short, plain "
    "narrative: what the agent did, what was risky, what Airlock blocked, and one "
    "line of what to check. Be concrete, no fluff, no marketing. 4-8 sentences."
)


def summary_prompt(facts: dict) -> str:
    """Build the user message for a summary call from structured session facts."""
    import json

    return "Session facts (JSON):\n" + json.dumps(facts, ensure_ascii=False, indent=2)
