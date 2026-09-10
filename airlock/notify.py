"""Desktop notification at the moment of a block (plane 2, human side).

When Airlock refuses a call the agent gets a JSON-RPC error and the human is
looking at the agent, not at audit.jsonl. Without a notification the experience
is "the agent broke"; with one it is "Airlock stopped something, and here is the
one command that allows it".

Best-effort and non-blocking by construction: never let notifying a human delay
or fail a security decision.
"""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import threading
import time

_LOCK = threading.Lock()
COOLDOWN = float(os.environ.get("AIRLOCK_NOTIFY_COOLDOWN", "20"))
# Global rate cap: the per-key cooldown stops one repeated block from spamming,
# but a burst of *different* blocks (an agent hitting a wall over and over on
# varied calls) still produced a wall of toasts. So at most CAP individual
# toasts fire per WINDOW; past that, blocks are folded into a single "N more
# blocked" summary, itself throttled. 0 disables the cap (every distinct block
# toasts, subject only to the per-key cooldown).
CAP = int(os.environ.get("AIRLOCK_NOTIFY_MAX", "5"))
WINDOW = float(os.environ.get("AIRLOCK_NOTIFY_WINDOW", "60"))


def _state_path():
    from . import config
    return config.home() / "notify.state"


def _admit(key: str, now: float):
    """Decide what to do with this block notification, across processes.

    The hook is a fresh process per tool call, so the debounce state has to live
    on disk, not in memory. Returns one of:
      ("send",  0)  -> emit the individual toast
      ("skip",  0)  -> the same block toasted within COOLDOWN; stay silent
      ("agg",   n)  -> the per-window cap is hit; emit one "n more blocked" toast
      ("hush",  0)  -> cap hit and a summary already went out this COOLDOWN; count only
    """
    p = _state_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    keys = data.get("keys") if isinstance(data.get("keys"), dict) else {}
    sent = [t for t in (data.get("sent") or []) if isinstance(t, (int, float))
            and now - t < WINDOW]
    result = ("send", 0)

    prev = keys.get(key)
    if isinstance(prev, (int, float)) and 0 <= now - prev < COOLDOWN:
        result = ("skip", 0)                     # identical block, still cooling
    elif CAP > 0 and len(sent) >= CAP:
        keys[key] = now
        data["suppressed"] = int(data.get("suppressed", 0)) + 1
        if now - float(data.get("agg_ts", 0) or 0) >= COOLDOWN:
            result = ("agg", data["suppressed"])
            data["suppressed"] = 0
            data["agg_ts"] = now
        else:
            result = ("hush", 0)
    else:
        keys[key] = now
        sent.append(now)

    if len(keys) > 256:                          # keep the file bounded
        keys = dict(sorted(keys.items(), key=lambda kv: -kv[1])[:128])
    data["keys"] = keys
    data["sent"] = sent
    try:
        tmp = p.with_suffix(".state.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:
        pass
    return result


def enabled() -> bool:
    v = os.environ.get("AIRLOCK_NOTIFY", "").lower()
    if v in ("0", "false", "no", "off"):
        return False
    if v in ("1", "true", "yes", "on"):
        return True
    return sys.platform in ("darwin", "linux")


def _backend() -> str | None:
    if sys.platform == "darwin":
        if shutil.which("terminal-notifier"):
            return "terminal-notifier"
        if shutil.which("osascript"):
            return "osascript"
        return None
    if shutil.which("notify-send"):
        return "notify-send"
    return None


def _spawn(argv: list[str]) -> None:
    try:
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass


_ns_actions = None


def _notify_send_has_actions() -> bool:
    """notify-send gained --action/--wait in libnotify 0.8. Older ones ignore
    them (and would show the literal flags), so probe once."""
    global _ns_actions
    if _ns_actions is None:
        try:
            h = subprocess.run(["notify-send", "--help"], capture_output=True,
                               text=True, timeout=2).stdout
            _ns_actions = ("--action" in h) and ("--wait" in h)
        except Exception:
            _ns_actions = False
    return _ns_actions


def _airlock_bin() -> str:
    return shutil.which("airlock") or "airlock"


def _emit(title: str, body: str, *, allow_cmd: str = "") -> None:
    """Show the toast. If `allow_cmd` is given and the backend supports buttons,
    add an 'Allow this' action that runs it on click; otherwise the command
    stays in the body text as before. Always non-blocking (a detached helper
    waits for the click, never the gate)."""
    b = _backend()
    if b == "notify-send":
        if allow_cmd and _notify_send_has_actions():
            # A detached helper shows the button and reacts to the click.
            # notify-send --wait prints the chosen action key on stdout.
            #   allow  -> run the allow command
            #   report -> write `airlock report` to a file and open it in the
            #             desktop's default viewer (a terminal is not assumed);
            #             a second toast confirms where it went.
            helper = (
                'k=$("$0" --wait -u critical -a Airlock '
                '--action=allow="Allow this" --action=report="Why?" '
                '"$1" "$2"); '
                'case "$k" in '
                'allow) sh -c "$3" ;; '
                'report) f="$HOME/.airlock/last-report.txt"; '
                '  sh -c "$4" > "$f" 2>&1; '
                '  (xdg-open "$f" >/dev/null 2>&1 || open "$f" >/dev/null 2>&1 '
                '   || x-terminal-emulator -e "less $f" >/dev/null 2>&1 '
                '   || "$0" -a Airlock "Airlock report saved" "$f") ;; '
                'esac')
            _spawn(["sh", "-c", helper, "notify-send", title, body,
                    allow_cmd, f"{_airlock_bin()} report"])
            return
        _spawn(["notify-send", "-u", "critical", "-a", "Airlock", title, body])
    elif b == "terminal-notifier":
        argv = ["terminal-notifier", "-title", title, "-message", body,
                "-group", "airlock"]
        if allow_cmd:
            # terminal-notifier runs -execute on click (whole notification).
            argv += ["-actions", "Allow this", "-execute", allow_cmd]
        _spawn(argv)
    elif b == "osascript":
        # osascript's `display notification` has no buttons; keep it
        # informational (the allow command is already in the body).
        safe = body.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " · ")
        _spawn(["osascript", "-e",
                f'display notification "{safe}" with title "{title}"'])


def blocked(*, tool: str, reason: str, resource: str = "",
            fix: str = "airlock allow last") -> None:
    """Tell the human what was refused and how to permit it. Never raises."""
    try:
        if not enabled():
            return
        key = f"{tool}|{reason}"
        now = time.time()       # wall clock: monotonic is meaningless across processes
        with _LOCK:
            action, n = _admit(key, now)
        if action in ("skip", "hush"):
            return              # a retry loop, or the burst summary already went out
        if action == "agg":
            _emit("Airlock blocked several calls",
                  f"{n} more call(s) blocked in the last {int(WINDOW)}s.\n"
                  f"See them all:  airlock report")
            return
        body = f"{tool}\n{reason}"
        if resource:
            body += f"\n{resource[:120]}"
        body += f"\n\nAllow it:  {fix}"
        # Pass the fix as a clickable action where the desktop supports buttons;
        # it stays in the body text as a fallback for those that don't.
        _emit("Airlock blocked a call", body,
              allow_cmd=f"{_airlock_bin()} {fix.split(' ', 1)[1]}"
              if fix.startswith("airlock ") else fix)
    except Exception:
        pass
