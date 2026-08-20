"""Claude Code PreToolUse hook (plane 2, for the agent's NATIVE tools).

Claude Code invokes this with the tool call as JSON on stdin. We apply the same
policy engine and answer via the stable hook contract:
  * allow -> exit 0
  * block -> exit 2, reason on stderr (shown to the model)  [enforce mode]
  * ask   -> print JSON permissionDecision "ask" so Claude Code prompts the human

FAILURE POSTURE
---------------
A firewall that fails open is decoration. If the policy cannot be loaded we
exit 2 (block) rather than 0, because "no policy" means "no boundary". Set
AIRLOCK_FAIL_OPEN=1 to invert that for a machine where a broken config must not
stop work — and know that you turned the gate off.

A payload we cannot parse is a different case: that is the harness changing
shape, not an attacker, so it is logged and allowed unless fail-closed is
explicitly demanded via AIRLOCK_STRICT=1.

Wired by `airlock init`, which writes the installed entry point into
~/.claude/settings.json:

  { "hooks": { "PreToolUse": [ { "matcher": "*", "hooks":
    [ { "type": "command", "command": "airlock-hook" } ] } ] } }
"""
from __future__ import annotations
import json
import os
import sys

from . import audit, config, contracts, notify, policy as policy_mod, scan
from .policy import ASK, BLOCK, Policy

EXIT_ALLOW, EXIT_BLOCK = 0, 2


def _flag(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes")


def _deny(reason: str) -> int:
    print(f"Airlock blocked this call: {reason}", file=sys.stderr)
    return EXIT_BLOCK


def _record_outcome(payload: dict) -> int:
    """PostToolUse: say what became of a call the gate only asked about.

    Airlock recorded `ask` and stopped. Claude Code then put its own prompt in
    front of the human, and whatever they answered never came back here — so a
    refused call and an approved one left an identical log. For exactly the
    calls that were worth interrupting somebody over, the record held the
    question and not the answer.

    PostToolUse fires only when the tool actually ran, so its arrival IS the
    answer. An `ask` with no outcome after it is one that never ran. This must
    never block: the call has already happened.
    """
    tool = payload.get("tool_name") or "?"
    args = payload.get("tool_input")
    if not isinstance(args, dict):
        args = {}
    _kind, resource = contracts.classify(tool, args)
    err = ""
    resp = payload.get("tool_response")
    if isinstance(resp, dict):
        if resp.get("error"):
            err = str(resp["error"])[:120]
        elif resp.get("is_error") or resp.get("isError"):
            err = "the tool reported an error"
    audit.record("outcome", source="hook", tool=tool,
                 effective="ran", reason=err or "the call ran",
                 args=args, session=payload.get("session_id", ""),
                 resource=resource)
    return EXIT_ALLOW


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("payload is not an object")
    except Exception as e:
        audit.record("hook_error", source="hook", effective="allow",
                     reason=f"unparseable hook payload: {e}")
        if _flag("AIRLOCK_STRICT"):
            return _deny(f"unparseable hook payload ({e}) and AIRLOCK_STRICT=1")
        return EXIT_ALLOW

    if ("--post" in sys.argv[1:]
            or payload.get("hook_event_name") == "PostToolUse"):
        try:
            return _record_outcome(payload)
        except Exception:
            return EXIT_ALLOW      # never let bookkeeping fail a call that ran

    tool = payload.get("tool_name") or "?"
    args = payload.get("tool_input")
    if not isinstance(args, dict):
        args = {}
    session = payload.get("session_id", "")

    try:
        policy = Policy.resolve()
    except Exception as e:
        ppath, _why = config.resolve_policy()
        audit.record("hook_error", source="hook", tool=tool,
                     effective="allow" if _flag("AIRLOCK_FAIL_OPEN") else "block",
                     reason=f"cannot load policy {ppath}: {e}",
                     session=session)
        if _flag("AIRLOCK_FAIL_OPEN"):
            return EXIT_ALLOW
        return _deny(f"policy could not be loaded ({e}). "
                     f"Fix it, or set AIRLOCK_FAIL_OPEN=1 to run without a gate.")

    try:
        audit.note_gate(*policy_mod.gate_fingerprint(policy))
    except Exception:
        pass                   # noticing must never be able to stop enforcing

    flags = scan.scan_text(json.dumps(args, ensure_ascii=False))
    d = policy.decide(tool, args)
    d = policy.apply_flags(d, flags)
    _, resource = contracts.classify(tool, args)

    # The hook HAS an interactive channel (Claude Code's own prompt), so unlike
    # the proxy it does NOT apply ask_fallback: `ask` stays `ask`. The mode
    # decides how much the unmatched middle is worth interrupting for.
    eff = policy.posture(d).action

    audit.record("decision", source="hook", tool=tool, decision=d.action,
                 effective=eff, reason=d.reason, args=args,
                 flags=flags, session=session, resource=resource)

    if eff == BLOCK:
        notify.blocked(tool=tool, reason=d.reason, resource=resource,
                       fix="airlock allow last")
        return _deny(f"{tool}: {d.reason}")
    if eff == ASK:
        # hand the decision to the human via Claude Code's own prompt
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": f"Airlock: {d.reason}",
        }}))
        return EXIT_ALLOW
    return EXIT_ALLOW


def guarded() -> int:
    """Any unexpected failure has to land on 2, not on a traceback.

    Claude Code blocks on exit 2 and *continues* on every other non-zero code.
    So an exception escaping main() — an unusable $AIRLOCK_HOME was the one
    that found this — printed a stack trace and let the call through ungated.
    A firewall that fails open when its own setup is broken is not one.
    """
    try:
        return main()
    except SystemExit:
        raise
    except Exception as e:
        if _flag("AIRLOCK_FAIL_OPEN"):
            print(f"Airlock could not run ({e}); AIRLOCK_FAIL_OPEN=1, allowing.",
                  file=sys.stderr)
            return EXIT_ALLOW
        return _deny(f"Airlock could not run ({type(e).__name__}: {e}). "
                     f"Fix it, or set AIRLOCK_FAIL_OPEN=1 to run without a gate.")


if __name__ == "__main__":
    raise SystemExit(guarded())
