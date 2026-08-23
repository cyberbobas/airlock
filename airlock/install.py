"""`airlock init` and `airlock uninstall` — wiring and, more importantly, unwiring.

A tool you cannot remove in one command does not get installed in the first
place, so uninstall is written first and tested as carefully as install.

What init touches, all of it reversible and all of it backed up:
  * $AIRLOCK_HOME/policy.yaml     copied from a profile (never overwritten)
  * ~/.claude/settings.json       adds the PreToolUse hook entry
  * <project>/.mcp.json           rewraps each server behind airlock-mcp

Everything Airlock adds is recognised by the command it runs — not by a
substring — so uninstall removes exactly its own edits and never someone
else's tool that merely lives under a path containing the word "airlock".
"""
from __future__ import annotations
import json
import os
import shlex
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config

# PreToolUse decides; PostToolUse records what became of the ones it only
# asked about — without it a refused call and an approved one look the same
# in the log, for precisely the calls worth interrupting a human over.
HOOK_EVENTS = ("PreToolUse", "PostToolUse")


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
    config.write_atomic(dst, banner + text)
    os.chmod(dst, 0o600)
    res.add(dst, f"policy written from profile '{profile}'", b or "")
    return dst


# ---- Claude Code hook --------------------------------------------------
def claude_settings() -> Path:
    return Path(os.environ.get("CLAUDE_SETTINGS",
                               Path.home() / ".claude" / "settings.json"))


def _hook_entry(event: str = "PreToolUse") -> dict:
    cmd = hook_command()
    if event == "PostToolUse":
        cmd += " --post"
    return {"matcher": "*", "hooks": [{"type": "command", "command": cmd}]}


def _command_tokens(cmd) -> list[str]:
    """Split a hook command line into argv, tolerating an already-split list."""
    if isinstance(cmd, (list, tuple)):
        return [str(t) for t in cmd]
    try:
        return shlex.split(str(cmd))
    except ValueError:
        return str(cmd).split()


def _invokes_airlock(argv: list[str], *, script: str, subcommand: str,
                     module: str) -> bool:
    """Does this argv actually launch a specific Airlock component?

    Matched against exactly the three ways `hook_command()`/`mcp_command()`
    write these lines — the console script by *basename*, the `airlock
    <subcommand>` form, or `python -m <module>`. Never a substring scan of the
    whole command: a user's own MCP server or hook living under a path that
    merely contains "airlock" (say ~/src/airlock-labs/server.py) must not be
    mistaken for ours — silently left ungated on init, or ripped out of their
    settings on uninstall.
    """
    if not argv:
        return False
    base = os.path.basename(argv[0])
    if base == script:                                    # airlock-hook / airlock-mcp
        return True
    if base == "airlock" and len(argv) >= 2 and argv[1] == subcommand:
        return True                                       # airlock hook / airlock mcp
    if module in argv:                                    # python -m airlock.cc_hook
        return True
    return False


def _is_airlock_hook(entry: dict) -> bool:
    for h in entry.get("hooks") or []:
        if _invokes_airlock(_command_tokens(h.get("command", "")),
                            script="airlock-hook", subcommand="hook",
                            module="airlock.cc_hook"):
            return True
    return False


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
        groups.append(_hook_entry(event))
        changed = True
    if not changed:
        return
    b = _backup(p)
    _save_json(p, data)
    res.add(p, f"PreToolUse + PostToolUse hooks -> {hook_command()}", b or "")


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


# ---- MCP config stores -------------------------------------------------
# Every place an agent on this box actually keeps its MCP server list. "init
# closes your MCP servers" was only ever true for a project .mcp.json; the same
# person's Cursor, Windsurf and Cline servers sat wide open.
#
# Deliberately NOT here: Claude Code's global ~/.claude.json. Its MCP calls are
# already gated by the PreToolUse hook (cc_hook applies the full policy, plus
# holds and contracts, to every `mcp__server__tool`), so wrapping those servers
# through the proxy only double-gates them — and ~/.claude.json is a live file
# Claude Code rewrites on its own, which would race our edit and could strip the
# `_airlock_original` key uninstall needs to put it back. The hook covers Claude
# Code; the proxy covers the agents that have no hook.
def mcp_stores(project: Path) -> list[tuple[str, Path]]:
    """(label, path) for every known MCP config that exists on this box."""
    home = Path.home()
    cands = [
        ("Claude Code (project)", project / ".mcp.json"),
        ("Claude Code",           home / ".claude" / "mcp.json"),
        ("Cursor (project)",      project / ".cursor" / "mcp.json"),
        ("Cursor",                home / ".cursor" / "mcp.json"),
        ("Windsurf",              home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("Cline",                 home / ".config" / "Code" / "User" / "globalStorage"
                                  / "saoudrizwan.claude-dev" / "settings"
                                  / "cline_mcp_settings.json"),
        ("Cline (macOS)",         home / "Library" / "Application Support" / "Code"
                                  / "User" / "globalStorage" / "saoudrizwan.claude-dev"
                                  / "settings" / "cline_mcp_settings.json"),
        # Continue is deliberately NOT here yet: it keeps its servers under
        # experimental.modelContextProtocolServers as a LIST of {transport:{...}}
        # (and a newer YAML config), which _server_maps does not parse. Claiming
        # it while silently not wrapping it is worse than not claiming it. Real
        # support is a tracked backlog item.
        ("Claude Desktop (macOS)", home / "Library" / "Application Support" / "Claude"
                                   / "claude_desktop_config.json"),
        ("Claude Desktop",        home / ".config" / "Claude"
                                  / "claude_desktop_config.json"),
    ]
    return [(label, p) for label, p in cands if p.exists()]


def mcp_config_paths(project: Path) -> list[Path]:
    """Just the paths, for callers that do not need the store labels."""
    return [p for _, p in mcp_stores(project)]


def _server_maps(data: dict) -> list[dict]:
    """Every dict-of-servers inside a loaded config.

    Each known store keeps them at the top level under `mcpServers` (or the
    snake_case `mcp_servers` a few tools emit). Returned maps are live
    references into `data`, so mutating them and writing `data` back persists
    the edit.
    """
    maps: list[dict] = []
    for key in ("mcpServers", "mcp_servers"):
        m = data.get(key)
        if isinstance(m, dict):
            maps.append(m)
    return maps


def _is_wrapped(spec: dict) -> bool:
    """Is this server already behind Airlock?

    Our own wrap always leaves `_airlock_original` behind, so that is the
    primary signal. As a backstop (in case that key was hand-edited away) we
    also recognise the wrapper command itself — the console script by basename,
    `airlock mcp`, or `python -m airlock.mcp_proxy`. We do NOT scan for the
    substring "airlock" anywhere in the argv: a real server whose own path
    contains the word would otherwise be read as already-wrapped and silently
    left ungated.
    """
    if "_airlock_original" in spec:
        return True
    argv = [str(spec.get("command", "")), *(str(a) for a in spec.get("args") or [])]
    return _invokes_airlock(argv, script="airlock-mcp", subcommand="mcp",
                            module="airlock.mcp_proxy")


def wrap_servers(path: Path, res: Result, unwrap: bool = False, *,
                 label: str = "") -> int:
    # A store belongs to some other agent and may be malformed through no fault
    # of the user's. _load_json raises SystemExit on bad JSON (right for our own
    # policy/settings), but here it would abort the whole init/uninstall over one
    # stranger's broken config — leaving the hook half-wired. Skip it with a note.
    try:
        data = _load_json(path)
    except SystemExit:
        tag = f"{label}: " if label else ""
        res.note(f"{tag}{path} is not valid JSON — skipped (fix or remove it, "
                 f"then re-run)")
        return 0
    maps = _server_maps(data)
    if not maps:
        return 0
    n = 0
    for servers in maps:
        for name, spec in list(servers.items()):
            if not isinstance(spec, dict) or not spec.get("command"):
                continue
            if unwrap:
                if not _is_wrapped(spec):
                    continue
                orig = spec.pop("_airlock_original", None)
                if not orig:
                    res.note(f"{path}: '{name}' is wrapped but has no saved "
                             f"original; left alone — edit it by hand")
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
        tag = f"{label}: " if label else ""
        b = _backup(path)
        if unwrap and _restore_verbatim(path, data):
            res.add(path, f"{tag}unwrapped {n} MCP server{'' if n == 1 else 's'} "
                          f"(restored the original file byte-for-byte)", b or "")
        else:
            _save_json(path, data)
            res.add(path, f"{tag}{'wrapped' if not unwrap else 'unwrapped'} {n} MCP "
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
        stores = mcp_stores(project)
        if not stores:
            res.note("no MCP config found in any known store (Claude Code, "
                     "Cursor, Windsurf, Cline, Claude Desktop) — "
                     "nothing to wrap yet. Re-run `airlock init` once you have "
                     "added an MCP server.")
        for label, p in stores:
            wrap_servers(p, res, label=label)
    # If neither console script is on PATH we fall back to `python -m airlock.…`.
    # That works for THIS interpreter, but your agent launches these commands
    # with its own environment and will not have this module importable — the
    # hook and the MCP wrap would be dead on arrival. Say so loudly.
    if (hook or mcp) and " -m airlock" in hook_command():
        res.note("WARNING: 'airlock' is not on your PATH, so the wiring points at "
                 "`python -m airlock.…`. Your agents (Cursor, Claude Code, …) run "
                 "these with their own environment and will NOT find that module — "
                 "install Airlock first with `pipx install airlock-agent` (or "
                 "`pip install .`), then re-run `airlock init`.")
    return res


def fix(*, project: Path | None = None) -> Result:
    """What `airlock doctor --fix` runs: close the gaps doctor warns about —
    wire the PreToolUse/PostToolUse hook if it is missing, and wrap every
    ungated MCP server across every known store. It does NOT write policy;
    `airlock init` owns that, and doctor already reports a missing one.
    """
    res = Result()
    install_hook(res)
    project = project or config.workspace()
    for label, p in mcp_stores(project):
        wrap_servers(p, res, label=label)
    return res


def uninstall(*, project: Path | None = None, purge: bool = False) -> Result:
    res = Result()
    remove_hook(res)
    project = project or config.workspace()
    for label, p in mcp_stores(project):
        wrap_servers(p, res, unwrap=True, label=label)
    h = config.home()
    if purge:
        if h.exists():
            shutil.rmtree(h, ignore_errors=True)
            res.add(h, "removed $AIRLOCK_HOME (policy, pins, contracts, audit log)")
    else:
        res.note(f"kept your data in {h} — `airlock uninstall --purge` removes it")
    return res
