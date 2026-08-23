"""Ask resolver — turn an `ask` verdict into allow/block via a human, out of
band from the JSON-RPC stream the proxy is carrying.

Backends (env AIRLOCK_ASK_BACKEND, comma-separated; else auto):
  socket    -> ask the running daemon over $AIRLOCK_HOME/ask.sock
  osascript -> native macOS dialog (no daemon, no dependency)
  zenity    -> GTK yes/no dialog on Linux
  tty       -> prompt on /dev/tty
  fallback  -> return ask_fallback

auto picks: the daemon if it is running, else the platform's native dialog if
this process has a GUI to draw on, else a tty prompt, else fallback. So `ask`
reaches a human on macOS and Linux without anyone installing anything, and only
degrades to the fallback when there is genuinely nobody there.
"""
from __future__ import annotations
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from .audit import home
from .policy import ALLOW, BLOCK


def sock_path() -> Path:
    return home() / "ask.sock"


def daemon_listening(timeout: float = 0.5) -> bool:
    """Is anything actually accepting on the ask socket?

    A daemon killed with SIGKILL leaves the socket file behind. Treating its
    mere existence as "a human is reachable" made `doctor` report a channel
    that was not there, and made every `ask` pay a timeout before failing safe.
    """
    p = sock_path()
    if not p.exists():
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(str(p))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def auto_backends() -> list[str]:
    """The ask channels available right here, strongest first."""
    order: list[str] = []
    if daemon_listening():
        order.append("socket")
    if sys.platform == "darwin":
        if _which("osascript"):
            order.append("osascript")
    elif _which("zenity") and (os.environ.get("DISPLAY") or
                               os.environ.get("WAYLAND_DISPLAY")):
        order.append("zenity")
    # NOT tty by default: the proxy runs inside the agent's terminal, and a
    # readline prompt there would garble the agent's own UI and steal its input.
    # Opt in with AIRLOCK_ASK_TTY=1 when running the proxy from a plain shell.
    if os.environ.get("AIRLOCK_ASK_TTY", "").lower() in ("1", "true", "yes") \
            and os.path.exists("/dev/tty"):
        order.append("tty")
    order.append("fallback")
    return order


def describe_channel() -> str:
    """Human-readable answer to 'will an ask actually reach me?'"""
    b = [x for x in auto_backends() if x != "fallback"]
    return " -> ".join(b) if b else "none (ask resolves unattended)"


def _via_socket(req: dict, timeout: float) -> str | None:
    p = sock_path()
    if not p.exists():
        return None
    s = None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(str(p))
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        reply = json.loads(buf.decode().strip() or "{}")
        d = reply.get("decision")
        return d if d in (ALLOW, BLOCK) else None
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def _via_osascript(req: dict, timeout: float) -> str | None:
    """macOS native dialog. The purchase decision happens on a Mac."""
    if sys.platform != "darwin" or not _which("osascript"):
        return None
    text = _plain_text(req).replace("\\", "\\\\").replace('"', '\\"')
    script = (f'display dialog "{text}" with title "Airlock" '
              f'buttons {{"Block", "Allow"}} default button "Block" '
              f'with icon caution giving up after {int(timeout)}')
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True,
                           text=True, timeout=timeout + 5)
        out = (r.stdout or "").strip()
        if "gave up:true" in out.replace(" ", ""):
            return None                      # nobody answered -> fall through
        if "button returned:Allow" in out:
            return ALLOW
        if "button returned:Block" in out:
            return BLOCK
        return None
    except Exception:
        return None


def _via_zenity(req: dict, timeout: float) -> str | None:
    if sys.platform == "darwin" or not _which("zenity"):
        return None
    text = _prompt_text(req)
    try:
        rc = subprocess.run(
            ["zenity", "--question", "--title=Airlock",
             f"--text={text}", "--ok-label=Allow", "--cancel-label=Block",
             f"--timeout={int(timeout)}", "--width=460"],
            timeout=timeout + 5,
        ).returncode
        if rc == 0:
            return ALLOW
        if rc == 1:
            return BLOCK
        return None  # 5 = dialog timed out -> fall through to fallback
    except Exception:
        return None


def _via_tty(req: dict, timeout: float) -> str | None:
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(f"\n[airlock] ALLOW {req.get('tool')}? "
                      f"({req.get('reason')})  [y/N] ")
            tty.flush()
            ans = tty.readline().strip().lower()
        return ALLOW if ans in ("y", "yes") else BLOCK
    except Exception:
        return None


def _plain_text(req: dict) -> str:
    """Same content as the GTK prompt, without markup (osascript shows raw)."""
    lines = [f"{req.get('server','?')} wants to run {req.get('tool','?')}",
             "", f"reason: {req.get('reason','')}"]
    if req.get("resource"):
        lines.append(f"target: {req['resource']}")
    if req.get("flags"):
        lines.append("flags: " + ", ".join(f["id"] for f in req["flags"]))
    return "\n".join(lines)


def _prompt_text(req: dict) -> str:
    lines = [
        f"<b>{req.get('server','?')}</b> wants to run <b>{req.get('tool','?')}</b>",
        "",
        f"reason: {req.get('reason','')}",
    ]
    if req.get("resource"):
        lines.append(f"target: {req['resource']}")
    if req.get("flags"):
        lines.append("⚠ flags: " + ", ".join(f["id"] for f in req["flags"]))
    return "\n".join(lines)


def _which(cmd: str) -> bool:
    from shutil import which
    return which(cmd) is not None


# ---- remembered answers ------------------------------------------------
# A human who just answered "allow this tool on this target" does not want the
# same dialog again thirty seconds later when the agent retries — that is the
# fatigue that gets a security tool uninstalled. So an answer from a real human
# backend is remembered, briefly, keyed by exactly what was asked (server, tool,
# target). Like sudo's timestamp: a short window, tunable, and off if you set it
# to 0. Absolute blocks and scan escalations are decided BEFORE an ask is ever
# raised, so remembering an "allow" can never resurrect something the policy
# forbids outright — it only silences a repeat of the same reviewed question.
def _cache_path() -> Path:
    return home() / "ask_cache.json"


def _remember_ttl() -> float:
    try:
        return float(os.environ.get("AIRLOCK_ASK_REMEMBER", "300"))
    except ValueError:
        return 300.0


def _ask_key(req: dict) -> str:
    return "\x00".join([str(req.get("server", "")), str(req.get("tool", "")),
                        str(req.get("resource", ""))])


def recall(req: dict) -> str | None:
    """A still-valid remembered answer for this exact question, or None."""
    p = _cache_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    entry = data.get(_ask_key(req))
    if not isinstance(entry, dict):
        return None
    if entry.get("decision") in (ALLOW, BLOCK) and entry.get("expires", 0) > time.time():
        return entry["decision"]
    return None


def remember(req: dict, decision: str) -> None:
    """Store a human's answer for AIRLOCK_ASK_REMEMBER seconds; prune expired."""
    ttl = _remember_ttl()
    if ttl <= 0 or decision not in (ALLOW, BLOCK):
        return
    p = _cache_path()
    now = time.time()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    data = {k: v for k, v in data.items()
            if isinstance(v, dict) and v.get("expires", 0) > now}
    data[_ask_key(req)] = {"decision": decision, "expires": now + ttl,
                           "reason": req.get("reason", "")}
    tmp = p.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except OSError:
        pass


def resolve_ask(req: dict, *, ask_fallback: str = BLOCK,
                timeout: float = 60.0) -> tuple[str, str]:
    """Return (decision, via)."""
    if _remember_ttl() > 0:
        cached = recall(req)
        if cached is not None:
            return cached, "remembered"
    env = os.environ.get("AIRLOCK_ASK_BACKEND", "").strip()
    if env:
        backends = [b.strip() for b in env.split(",") if b.strip()]
    else:
        backends = auto_backends()
    resolvers = {"socket": _via_socket, "osascript": _via_osascript,
                 "zenity": _via_zenity, "tty": _via_tty}
    for b in backends:
        if b == "fallback":
            return ask_fallback, "fallback"
        fn = resolvers.get(b)
        if not fn:
            continue
        d = fn(req, timeout)
        if d in (ALLOW, BLOCK):
            remember(req, d)            # a real human answer — silence its repeats
            return d, b
    return ask_fallback, "fallback"
