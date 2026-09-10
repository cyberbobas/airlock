"""Schedule `airlock analyze` to run on its own — 6h / daily / weekly / monthly.

The mechanism is the user crontab, which exists on Linux and macOS without a
daemon of our own and survives reboots. We own exactly the lines between our
markers, mirroring the install-hook discipline: back up the crontab, add or
remove only our block, never touch a line we did not write.

A scheduled run is `airlock analyze --window <w> --save --quiet`: it writes a
Markdown review under $AIRLOCK_HOME/reports/ and, if the AI tier is on, an
analyst verdict. On a headless box that is the whole point — the review lands in
a file whether or not anyone is at the terminal.

Windows/other platforms without `crontab` fall back to the foreground
`airlock watch` loop (documented in the CLI); this module reports honestly when
it cannot install a system schedule.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

# interval -> (cron expression, analyze window label)
INTERVALS = {
    "6h":      ("0 */6 * * *", "6h"),
    "daily":   ("0 9 * * *",   "day"),
    "weekly":  ("0 9 * * 1",   "week"),
    "monthly": ("0 9 1 * *",   "month"),
}

_BEGIN = "# >>> airlock analyze (managed) >>>"
_END = "# <<< airlock analyze <<<"


def _airlock_cmd() -> str:
    """Absolute command to invoke the CLI from cron's minimal environment."""
    exe = shutil.which("airlock")
    if exe:
        return exe
    return f"{sys.executable} -m airlock.cli"


def cron_available() -> bool:
    return shutil.which("crontab") is not None


def _read_crontab() -> str:
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        # no crontab yet -> non-zero with a known message; treat as empty
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def _write_crontab(text: str) -> bool:
    try:
        r = subprocess.run(["crontab", "-"], input=text, text=True,
                           capture_output=True)
        return r.returncode == 0
    except Exception:
        return False


def _strip_block(text: str) -> str:
    """Remove our managed block (and a trailing blank line) if present."""
    if _BEGIN not in text:
        return text
    out, skipping = [], False
    for line in text.splitlines():
        if line.strip() == _BEGIN:
            skipping = True
            continue
        if line.strip() == _END:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    return "\n".join(out).rstrip("\n")


def _block(interval: str) -> str:
    cron_expr, window = INTERVALS[interval]
    home = os.environ.get("AIRLOCK_HOME", "")
    env = f"AIRLOCK_HOME={home} " if home else ""
    cmd = f"{env}{_airlock_cmd()} analyze --window {window} --save --quiet"
    return (f"{_BEGIN}\n"
            f"# every: {interval}. Edit with `airlock watch --install <interval>`.\n"
            f"{cron_expr} {cmd}\n"
            f"{_END}")


def status() -> dict:
    """What is scheduled right now, if anything."""
    text = _read_crontab()
    installed = _BEGIN in text
    interval = None
    if installed:
        for line in text.splitlines():
            if line.startswith("# every:"):
                interval = line.split(":", 1)[1].strip().split(".")[0].strip()
                break
    return {"installed": installed, "interval": interval,
            "cron_available": cron_available(),
            "cron_running": _cron_running()}


def _cron_running() -> bool:
    """Best-effort: is a cron daemon actually there to fire the entry? A crontab
    with no running daemon installs fine and never runs — worth warning about."""
    try:
        r = subprocess.run(["pgrep", "-x", "cron"], capture_output=True)
        if r.returncode == 0:
            return True
        r = subprocess.run(["pgrep", "-x", "crond"], capture_output=True)
        return r.returncode == 0
    except Exception:
        return False


def install(interval: str) -> tuple[bool, str]:
    if interval not in INTERVALS:
        return False, f"unknown interval {interval!r}; use {'/'.join(INTERVALS)}"
    if not cron_available():
        return False, ("no `crontab` on this system — use the foreground "
                       "`airlock watch --every " + interval + "` instead")
    current = _read_crontab()
    base = _strip_block(current)
    new = (base + ("\n" if base else "") + _block(interval)).rstrip("\n") + "\n"
    # back up what we are replacing
    try:
        bak = audit_home() / f"crontab.airlock-bak"
        bak.write_text(current, encoding="utf-8")
    except Exception:
        pass
    if not _write_crontab(new):
        return False, "could not write the crontab"
    warn = "" if _cron_running() else \
        "  (note: no cron daemon appears to be running — start it so this fires)"
    return True, f"scheduled `airlock analyze` {interval}{warn}"


def uninstall() -> tuple[bool, str]:
    if not cron_available():
        return True, "nothing to remove (no crontab on this system)"
    current = _read_crontab()
    if _BEGIN not in current:
        return True, "no airlock schedule was installed"
    new = _strip_block(current)
    new = (new.rstrip("\n") + "\n") if new.strip() else ""
    if not _write_crontab(new):
        return False, "could not write the crontab"
    return True, "removed the airlock schedule"


def audit_home() -> Path:
    from . import config
    return config.home()
