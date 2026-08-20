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

_last: dict[str, float] = {}
_LOCK = threading.Lock()
COOLDOWN = float(os.environ.get("AIRLOCK_NOTIFY_COOLDOWN", "20"))


def _state_path():
    from . import config
    return config.home() / "notify.state"


def _recently_sent(key: str, now: float) -> bool:
    """Debounce across processes, not just within one.

    The hook is a fresh process per tool call, so an in-memory dict debounced
    nothing there — and the hook is exactly where native-tool blocks arrive. An
    agent retrying in a loop would have produced forty popups.
    """
    p = _state_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    prev = data.get(key)
    if isinstance(prev, (int, float)) and 0 <= now - prev < COOLDOWN:
        return True
    data[key] = now
    if len(data) > 256:                       # keep the file bounded
        data = dict(sorted(data.items(), key=lambda kv: -kv[1])[:128])
    try:
        tmp = p.with_suffix(".state.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:
        pass
    return False


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


def blocked(*, tool: str, reason: str, resource: str = "",
            fix: str = "airlock allow last") -> None:
    """Tell the human what was refused and how to permit it. Never raises."""
    try:
        if not enabled():
            return
        key = f"{tool}|{reason}"
        now = time.time()       # wall clock: monotonic is meaningless across processes
        with _LOCK:
            if now - _last.get(key, 0.0) < COOLDOWN:
                return
            _last[key] = now
        if _recently_sent(key, now):
            return              # one agent retry loop must not become 40 popups

        title = "Airlock blocked a call"
        body = f"{tool}\n{reason}"
        if resource:
            body += f"\n{resource[:120]}"
        body += f"\n\nAllow it:  {fix}"

        b = _backend()
        if b == "notify-send":
            _spawn(["notify-send", "-u", "critical", "-a", "Airlock", title, body])
        elif b == "terminal-notifier":
            _spawn(["terminal-notifier", "-title", title, "-message", body,
                    "-group", "airlock"])
        elif b == "osascript":
            safe = body.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " · ")
            _spawn(["osascript", "-e",
                    f'display notification "{safe}" with title "{title}"'])
    except Exception:
        pass
