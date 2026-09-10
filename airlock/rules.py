"""`airlock rules` — add / list / remove policy rules without hand-editing YAML.

The shipped profiles are a heavily-commented YAML the user is invited to edit,
but editing YAML by hand is exactly the friction that makes the firewall feel
opaque. This owns a single marked block of *your* rules at the TOP of the
`rules:` list, so a rule you add is evaluated before the profile's — "my rule
wins" — while every profile comment and rule stays untouched.

    airlock rules list
    airlock rules block '*curl*ngrok*'         # refuse anything matching
    airlock rules allow '*/reports/*' --tool Write
    airlock rules ask   '*deploy*'
    airlock rules rm 2                          # remove your rule #2

A block rule added here is absolute (Airlock's block sweep checks every rule),
so it can never be undone by a grant — the same guarantee as a profile block.
Each change backs up the file and re-validates it; a change that would not load
is rolled back.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from . import config

BEGIN = "  # >>> airlock rules (managed by `airlock rules`) >>>"
END = "  # <<< airlock rules <<<"
_ACTIONS = ("allow", "ask", "block")


def _policy_path() -> Path:
    """The user policy we can edit. If only a bundled profile is active, copy it
    to the user policy first so we never mutate the shipped profile in place."""
    p, why = config.resolve_policy()
    if why == "user":
        return p
    up = config.user_policy()
    up.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(p, up)
    return up


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _escape(pattern: str) -> str:
    # rules live in a YAML flow mapping; keep the match a double-quoted scalar.
    return pattern.replace("\\", "\\\\").replace('"', '\\"')


def _rule_line(action: str, match: str, tool: str, reason: str) -> str:
    return (f'  - {{ tool: "{_escape(tool)}", match: "{_escape(match)}", '
            f'action: {action}, reason: "{_escape(reason)}" }}')


def _block_bounds(text: str):
    """(start_idx, end_idx) of the managed block's lines, or None."""
    lines = text.splitlines()
    b = e = None
    for i, ln in enumerate(lines):
        if ln.rstrip() == BEGIN.rstrip():
            b = i
        elif ln.rstrip() == END.rstrip():
            e = i
    if b is not None and e is not None and e > b:
        return b, e
    return None


def user_rules(text: str) -> list[dict]:
    """Parse the managed block into [{action, match, tool, reason}] in order."""
    bounds = _block_bounds(text)
    if not bounds:
        return []
    lines = text.splitlines()
    out = []
    rx = re.compile(r'tool:\s*"([^"]*)".*?match:\s*"([^"]*)".*?action:\s*(\w+)'
                    r'.*?reason:\s*"([^"]*)"')
    for ln in lines[bounds[0] + 1:bounds[1]]:
        m = rx.search(ln)
        if m:
            out.append({"tool": m.group(1), "match": m.group(2),
                        "action": m.group(3), "reason": m.group(4)})
    return out


def _validate(path: Path) -> tuple[bool, str]:
    try:
        from .policy import Policy
        pol = Policy.load(path)
        return True, f"{len(pol.rules)} rules, mode={pol.mode}"
    except Exception as e:
        return False, str(e)


def _write_checked(path: Path, new_text: str) -> tuple[bool, str]:
    bak = path.with_suffix(path.suffix + ".rules-bak")
    old = _read(path) if path.exists() else ""
    try:
        bak.write_text(old, encoding="utf-8")
    except Exception:
        pass
    path.write_text(new_text, encoding="utf-8")
    ok, msg = _validate(path)
    if not ok:
        path.write_text(old, encoding="utf-8")   # roll back a policy that won't load
        return False, f"change rejected — policy would not load ({msg})"
    return True, msg


def _ensure_block(text: str) -> str:
    """Return text with an (empty) managed block right after the `rules:` line."""
    if _block_bounds(text):
        return text
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if re.match(r"^rules:\s*(\[\s*\])?\s*$", ln.strip()) or ln.strip() == "rules:":
            # `rules: []` -> make it a real list so we can add entries
            if ln.strip() == "rules: []":
                lines[i] = "rules:"
            lines[i + 1:i + 1] = [BEGIN, END]
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    # no rules: line (shouldn't happen — load() requires it); append one
    lines += ["rules:", BEGIN, END]
    return "\n".join(lines) + "\n"


def add(action: str, match: str, *, tool: str = "*", reason: str = "") -> tuple[bool, str]:
    if action not in _ACTIONS:
        return False, f"action must be one of {', '.join(_ACTIONS)}"
    if not match:
        return False, "a match pattern is required (e.g. '*ngrok*')"
    path = _policy_path()
    text = _ensure_block(_read(path))
    bounds = _block_bounds(text)
    lines = text.splitlines()
    reason = reason or f"added by you ({action})"
    lines.insert(bounds[1], _rule_line(action, match, tool, reason))
    ok, msg = _write_checked(path, "\n".join(lines) + "\n")
    if not ok:
        return False, msg
    return True, f"{action} {match}" + (f" (tool {tool})" if tool != "*" else "")


def remove(index: int) -> tuple[bool, str]:
    path = _policy_path()
    text = _read(path)
    rules = user_rules(text)
    if not rules:
        return False, "you have no rules to remove (see `airlock rules list`)"
    if index < 1 or index > len(rules):
        return False, f"no rule #{index}; you have {len(rules)} (1-{len(rules)})"
    bounds = _block_bounds(text)
    lines = text.splitlines()
    # the index-th rule line within the block (skip non-rule lines defensively)
    rule_lines = [i for i in range(bounds[0] + 1, bounds[1])
                  if "action:" in lines[i]]
    target = rule_lines[index - 1]
    removed = rules[index - 1]
    del lines[target]
    ok, msg = _write_checked(path, "\n".join(lines) + "\n")
    if not ok:
        return False, msg
    return True, f"removed #{index}: {removed['action']} {removed['match']}"


def listing() -> dict:
    """Everything `airlock rules list` needs: your rules + a profile summary."""
    path, why = config.resolve_policy()
    text = _read(path) if path.exists() else ""
    mine = user_rules(text)
    from .policy import Policy
    pol = Policy.load(path)
    # profile rules = all rules minus ours (ours are dicts too; compare by match)
    mine_keys = {(r["action"], r["match"], r["tool"]) for r in mine}
    profile = []
    for r in pol.rules:
        if not isinstance(r, dict):
            continue
        key = (r.get("action", "ask"), str(r.get("match", "")), str(r.get("tool", "*")))
        if key in mine_keys:
            continue
        profile.append(r)
    return {"path": str(path), "profile_name": pol.profile or why,
            "mode": pol.mode, "mine": mine, "profile": profile}
