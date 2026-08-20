"""`airlock init` and `airlock uninstall` — wiring and, more importantly, unwiring.

A tool you cannot remove in one command does not get installed in the first
place, so uninstall is written first and tested as carefully as install.

What init touches, all of it reversible and all of it backed up:
  * $AIRLOCK_HOME/policy.yaml     copied from a profile (never overwritten)
  * ~/.claude/settings.json       adds the PreToolUse hook entry
  * <project>/.mcp.json           rewraps each server behind airlock-mcp

Everything Airlock adds carries an "airlock" marker so uninstall can find and
remove exactly its own edits and nothing else.
"""
from __future__ import annotations
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config

MARKER = "airlock"
HOOK_EVENTS = ("PreToolUse",)


@dataclass
class Change:
    path: str
    what: str
    applied: bool = True
    backup: str = ""


@dataclass
class Result:
    changes: list[Change] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, path, what, backup=""):
        self.changes.append(Change(str(path), what, backup=str(backup)))

    def note(self, s):
        self.notes.append(s)


def _console_script(name: str) -> str | None:
    """Find an installed entry point.

    PATH first, then next to the interpreter running us — a venv or pipx
    install is often invoked by absolute path with its bin dir off PATH, and
    writing a bare `python -m` line there would break the moment the user's
    cwd or PYTHONPATH changes.
    """
    exe = shutil.which(name)
    if exe:
        return exe
    sibling = Path(sys.executable).parent / name
    if sibling.exists() and os.access(sibling, os.X_OK):
        return str(sibling)
    return None


def hook_command() -> str:
    """The command to put in settings.json."""
    exe = _console_script("airlock-hook")
    if exe:
        return exe
    exe = _console_script("airlock")
    if exe:
        return f"{exe} hook"
    return f"{sys.executable} -m airlock.cc_hook"


def mcp_command() -> list[str]:
    exe = _console_script("airlock-mcp")
    if exe:
        return [exe]
    exe = _console_script("airlock")
    if exe:
        return [exe, "mcp"]
    return [sys.executable, "-m", "airlock.mcp_proxy"]


def _backup(p: Path) -> Path | None:
    """Copy a file aside before editing it, without ever clobbering an earlier
    copy.

    Second-resolution names collide when init and uninstall run in the same
    second — and the copy that got overwritten was the *original*, the only one
    worth keeping. Suffix until the name is free.
    """
    if not p.exists():
        return None
    stamp = time.strftime("%Y%m%d%H%M%S", time.localtime())
    b = p.with_suffix(p.suffix + f".airlock-bak-{stamp}")
    n = 1
    while b.exists():
        b = p.with_suffix(p.suffix + f".airlock-bak-{stamp}-{n}")
        n += 1
    shutil.copy2(p, b)
    return b


def _backups(p: Path) -> list[Path]:
    """Every backup Airlock has taken of this file, oldest first."""
    return sorted(p.parent.glob(p.name + ".airlock-bak-*"))


def _restore_verbatim(p: Path, unwrapped: dict) -> bool:
    """Put the file back exactly as it was, formatting included.

    Re-serialising JSON gives back the same *data* but not the same *file*: a
    one-line config comes back pretty-printed across fourteen lines, which shows
    up in someone's git diff and makes "uninstall put it back" feel untrue. So
    when the semantic unwrap matches a backup we took, we write that backup's
    bytes instead of our own serialisation.

    Only when it matches: if the user edited the file after `init`, their edits
    win and we fall back to the semantic unwrap.
    """
    for b in reversed(_backups(p)):
        try:
            if json.loads(b.read_text(encoding="utf-8")) == unwrapped:
                shutil.copyfile(b, p)
                return True
        except Exception:
            continue
    return False


def _load_json(p: Path) -> dict:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception as e:
        raise SystemExit(f"airlock: {p} is not valid JSON ({e}); fix it first")


def _save_json(p: Path, data: dict) -> None:
    """Atomic write that follows a symlink instead of eating it.

    Plenty of people keep ~/.claude/settings.json as a symlink into a dotfiles
    repo. os.replace() onto the link path replaced the *link* with a regular
    file: the real config never got the hook, the next dotfile sync would have
    dropped it anyway, and `airlock doctor` cheerfully reported the hook as
    wired. Resolve first, then replace the thing the link points at.
    """
    target = Path(os.path.realpath(p)) if p.is_symlink() else p
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    os.replace(tmp, target)


# ---- policy ------------------------------------------------------------
def install_policy(profile: str, res: Result, force: bool = False) -> Path:
    dst = config.user_policy()
    src = config.profile_path(profile)
    if dst.exists() and not force:
        res.note(f"kept your existing policy at {dst} (use --force to replace)")
        return dst
    b = _backup(dst)
    text = src.read_text(encoding="utf-8")
    banner = (f"# Written by `airlock init --profile {profile}` on "
              f"{time.strftime('%Y-%m-%d')}.\n"
              f"# Yours to edit. `airlock allow` appends to `grants:` below.\n"
              f"# Re-copy a fresh profile any time: airlock profile {profile} --force\n")
    dst.write_text(banner + text, encoding="utf-8")
    os.chmod(dst, 0o600)
    res.add(dst, f"policy written from profile '{profile}'", b or "")
    return dst


# ---- Claude Code hook --------------------------------------------------
def claude_settings() -> Path:
    return Path(os.environ.get("CLAUDE_SETTINGS",
                               Path.home() / ".claude" / "settings.json"))


def _hook_entry() -> dict:
    return {"matcher": "*", "hooks": [{"type": "command",
                                       "command": hook_command()}]}


def _is_airlock_hook(entry: dict) -> bool:
    return MARKER in json.dumps(entry).lower()


def install_hook(res: Result) -> None:
    p = claude_settings()
    data = _load_json(p)
    hooks = data.setdefault("hooks", {})
    changed = False
    for event in HOOK_EVENTS:
        groups = hooks.setdefault(event, [])
        if any(_is_airlock_hook(g) for g in groups):
            res.note(f"{event} hook already wired in {p}")
            continue
        groups.append(_hook_entry())
        changed = True
    if not changed:
        return
    b = _backup(p)
    _save_json(p, data)
    res.add(p, f"PreToolUse hook -> {hook_command()}", b or "")


def remove_hook(res: Result) -> None:
    p = claude_settings()
    if not p.exists():
        return
    data = _load_json(p)
    hooks = data.get("hooks") or {}
    removed = 0
    for event in list(hooks):
        groups = hooks.get(event) or []
        keep = [g for g in groups if not _is_airlock_hook(g)]
        removed += len(groups) - len(keep)
        if keep:
            hooks[event] = keep
        else:
            hooks.pop(event, None)
    if not hooks:
        data.pop("hooks", None)
    if removed:
        b = _backup(p)
        exact = _restore_verbatim(p, data)
        if not exact:
            _save_json(p, data)
        res.add(p, f"removed {removed} Airlock hook entr"
                   f"{'y' if removed == 1 else 'ies'}"
                   + (" (original file restored byte-for-byte)" if exact else ""),
                b or "")


# ---- .mcp.json ---------------------------------------------------------
def mcp_config_paths(project: Path) -> list[Path]:
    cands = [project / ".mcp.json",
             Path.home() / ".claude" / "mcp.json",
             Path.home() / ".cursor" / "mcp.json",
             Path.home() / "Library" / "Application Support" / "Claude"
             / "claude_desktop_config.json",
             Path.home() / ".config" / "Claude" / "claude_desktop_config.json"]
    return [p for p in cands if p.exists()]


def _is_wrapped(spec: dict) -> bool:
    """Is this server already behind Airlock?

    The marker can land in `command` (console script) or in `args` (the
    `python -m airlock.mcp_proxy` fallback), so check both — checking only the
    command double-wrapped a server on the second `init`.
    """
    if "_airlock_original" in spec:
        return True
    blob = json.dumps([spec.get("command", ""), *(spec.get("args") or [])]).lower()
    return MARKER in blob


def wrap_servers(path: Path, res: Result, unwrap: bool = False) -> int:
    data = _load_json(path)
    servers = data.get("mcpServers") or data.get("mcp_servers")
    if not isinstance(servers, dict) or not servers:
        return 0
    n = 0
    for name, spec in servers.items():
        if not isinstance(spec, dict) or not spec.get("command"):
            continue
        if unwrap:
            if not _is_wrapped(spec):
                continue
            orig = spec.pop("_airlock_original", None)
            if not orig:
                res.note(f"{path}: '{name}' is wrapped but has no saved original; "
                         f"left alone — edit it by hand")
                continue
            spec["command"] = orig.get("command")
            spec["args"] = orig.get("args", [])
            if not spec["args"]:
                spec.pop("args", None)
            n += 1
        else:
            if _is_wrapped(spec):
                continue
            spec["_airlock_original"] = {"command": spec["command"],
                                         "args": list(spec.get("args") or [])}
            inner = [spec["command"], *(spec.get("args") or [])]
            wrap = mcp_command()
            spec["command"] = wrap[0]
            spec["args"] = [*wrap[1:], "--server-id", name, "--", *inner]
            n += 1
    if n:
        b = _backup(path)
        if unwrap and _restore_verbatim(path, data):
            res.add(path, f"unwrapped {n} MCP server{'' if n == 1 else 's'} "
                          f"(restored the original file byte-for-byte)", b or "")
        else:
            _save_json(path, data)
            res.add(path, f"{'wrapped' if not unwrap else 'unwrapped'} {n} MCP "
                          f"server{'' if n == 1 else 's'}", b or "")
    return n


# ---- top level ---------------------------------------------------------
def init(profile: str = config.DEFAULT_PROFILE, *, project: Path | None = None,
         hook: bool = True, mcp: bool = True, force: bool = False) -> Result:
    res = Result()
    install_policy(profile, res, force=force)
    if hook:
        install_hook(res)
    if mcp:
        project = project or config.workspace()
        paths = mcp_config_paths(project)
        if not paths:
            res.note("no .mcp.json found — nothing to wrap yet. Re-run "
                     "`airlock init` after adding an MCP server.")
        for p in paths:
            wrap_servers(p, res)
    return res


def uninstall(*, project: Path | None = None, purge: bool = False) -> Result:
    res = Result()
    remove_hook(res)
    project = project or config.workspace()
    for p in mcp_config_paths(project):
        wrap_servers(p, res, unwrap=True)
    h = config.home()
    if purge:
        if h.exists():
            shutil.rmtree(h, ignore_errors=True)
            res.add(h, "removed $AIRLOCK_HOME (policy, pins, contracts, audit log)")
    else:
        res.note(f"kept your data in {h} — `airlock uninstall --purge` removes it")
    return res
