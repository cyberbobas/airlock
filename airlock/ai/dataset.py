"""Turn real usage into training data for our judge — the data flywheel.

Every time Airlock escalated a gray-zone call to a human and the human answered
allow/block, that is a labeled example: "given this action context, the right
verdict was X." Harvesting those (locally, redacted, opt-in) is how our built-in
judge gets smarter at *our* task than any generic model — see training/README.md.

We only learn from the GRAY ZONE the human actually resolved. Deterministic
rule hits are not training signal: rules run first and the model must defer to
them anyway. And we only count answers that came from a human channel, not from
an unattended fallback, so the labels are real decisions.

Output is chat-format JSONL (system / user / assistant), ready for SFT of a
Qwen2.5-Instruct-class model. Every field is redacted first.
"""
from __future__ import annotations

import json
import re

from .. import audit
from .prompts import JUDGE_SYSTEM, judge_prompt, redact, redact_obj

# ask backends that mean a human actually answered (see ask.py auto_backends)
_HUMAN_VIA = ("socket", "osascript", "zenity", "tty")
_VIA_RE = re.compile(r"\[ask:([a-z]+)\]")


def _via(reason: str) -> str:
    m = _VIA_RE.search(reason or "")
    return m.group(1) if m else ""


def _clean_reason(reason: str) -> str:
    """Drop the `[ask:...]`/`[guard:...]` provenance tag from a human reason."""
    return re.sub(r"\s*\[[a-z]+:[^\]]*\]\s*$", "", reason or "").strip()


def _events(days, session):
    out = []
    for p in audit.rotated_files():
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if session and r.get("session") != session:
                continue
            out.append(r)
    return out


def build_examples(days=None, session="", human_only=True) -> list[dict]:
    """SFT examples from human-resolved gray-zone decisions."""
    examples = []
    for r in _events(days, session):
        if r.get("event") != "decision":
            continue
        if r.get("decision") != "ask":          # only the gray zone
            continue
        final = r.get("effective")
        if final not in ("allow", "block"):     # must have been resolved
            continue
        reason = r.get("reason", "")
        if human_only and _via(reason) not in _HUMAN_VIA:
            continue
        ctx = {
            "tool": r.get("tool", ""),
            "server": r.get("server", ""),
            "plane": r.get("source", ""),
            "rule_verdict": "ask",
            "reason_hint": redact(_clean_reason(reason)),
            "args": {"resource": redact(r.get("resource", ""))},
        }
        assistant = json.dumps(
            {"decision": final, "reason": redact(_clean_reason(reason))[:120] or final},
            ensure_ascii=False,
        )
        examples.append({
            "messages": [
                {"role": "system", "content": JUDGE_SYSTEM},
                {"role": "user", "content": judge_prompt(redact_obj(ctx))},
                {"role": "assistant", "content": assistant},
            ]
        })
    return examples


def export(path, days=None, session="", human_only=True) -> int:
    """Write JSONL to `path`; return the number of examples."""
    ex = build_examples(days=days, session=session, human_only=human_only)
    from pathlib import Path
    p = Path(path)
    p.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in ex) + ("\n" if ex else ""),
                 encoding="utf-8")
    return len(ex)
