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
import base64
import json
import os
import re
import shlex
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib                     # 3.11+; read-only, used for grok's config
except ModuleNotFoundError:            # pragma: no cover
    tomllib = None

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
def _custom_stores() -> list[tuple[str, Path]]:
    """User-declared MCP configs from AIRLOCK_MCP_CONFIGS (os.pathsep-separated).

    The escape hatch for any agent Airlock does not auto-detect — point it at the
    config file and, if that file is a standard `mcpServers` JSON, it gets gated
    (and later unwrapped) exactly like a built-in store.
    """
    raw = os.environ.get("AIRLOCK_MCP_CONFIGS", "")
    return [("custom", Path(c.strip()).expanduser())
            for c in raw.split(os.pathsep) if c.strip()]


def mcp_stores(project: Path) -> list[tuple[str, Path]]:
    """(label, path) for every known MCP config that exists on this box.

    A store is auto-gated only if the file both EXISTS and holds a standard
    `mcpServers` object (checked later by _server_maps). That guard is what makes
    the best-effort entries for newer agents safe: a wrong path is a no-op, and a
    config with a different shape wraps nothing rather than being corrupted.
    """
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
        # Kimi CLI: standard `mcpServers` JSON at mcp.json (confirmed from the
        # binary), user- and project-scoped.
        ("Kimi CLI",              home / ".kimi-code" / "mcp.json"),
        ("Kimi CLI (project)",    project / ".kimi-code" / "mcp.json"),
        # grok: TOML, [mcp_servers.<name>] in config.toml (handled by _wrap_toml).
        ("grok",                  home / ".grok" / "config.toml"),
        ("grok (project)",        project / ".grok" / "config.toml"),
        # mimo: JSON under the `mcp` key, command-as-list, in mimocode.json
        # (user, project, and .mimocode/); handled by the JSON path + _wrap_spec.
        ("mimo",                  home / ".config" / "mimocode" / "mimocode.json"),
        ("mimo (project)",        project / "mimocode.json"),
        ("mimo (project)",        project / ".mimocode" / "mimocode.json"),
        # DeepSeek Harness: MCP servers are dsh-mcp-client entries in each
        # profile's cordis.patch.yml under $DSH_HOME (~/.dsh by default), handled
        # by _wrap_dsh. Added per-profile below.
    ]
    dsh_home = Path(os.environ.get("DSH_HOME") or (home / ".dsh"))
    profiles = dsh_home / "profiles"
    if profiles.is_dir():
        for prof in sorted(profiles.iterdir()):
            cands.append((f"DeepSeek Harness ({prof.name})",
                          prof / "cordis.patch.yml"))
    stores, seen = [], set()
    for label, p in cands + _custom_stores():
        if p.exists() and p not in seen:
            seen.add(p)
            stores.append((label, p))
    return stores


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
    for key in ("mcpServers", "mcp_servers", "mcp"):
        # `mcp` is mimo's key. Its value is a dict of server specs; a stray
        # `mcp` that is not (e.g. a scalar) is ignored here, and any entry that
        # is not a stdio server is skipped per-spec by the wrap loop.
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


def _wrap_spec(name: str, spec: dict) -> bool:
    """Rewrite one server dict to launch through airlock-mcp. Returns True if it
    changed. Handles both shapes: command-as-string + separate args (standard,
    Cursor, Cline, Kimi…) and command-as-list (mimo's `mcp` entries)."""
    if _is_wrapped(spec):
        return False
    cmd = spec.get("command")
    wrap = mcp_command()
    if isinstance(cmd, list):
        if not cmd:
            return False
        spec["_airlock_original"] = {"command": list(cmd)}      # no args field
        spec["command"] = [*wrap, "--server-id", name, "--", *cmd]
    else:
        spec["_airlock_original"] = {"command": cmd,
                                     "args": list(spec.get("args") or [])}
        inner = [cmd, *(spec.get("args") or [])]
        spec["command"] = wrap[0]
        spec["args"] = [*wrap[1:], "--server-id", name, "--", *inner]
    return True


def _unwrap_spec(name: str, spec: dict, res: Result, path: Path) -> bool:
    orig = spec.pop("_airlock_original", None)
    if not orig:
        res.note(f"{path}: '{name}' is wrapped but has no saved original; "
                 f"left alone — edit it by hand")
        return False
    if isinstance(orig.get("command"), list) and "args" not in orig:
        spec["command"] = orig["command"]                      # mimo list form
    else:
        spec["command"] = orig.get("command")
        spec["args"] = orig.get("args", [])
        if not spec["args"]:
            spec.pop("args", None)
    return True


# ---- TOML stores (grok) ------------------------------------------------
# grok keeps its MCP servers in TOML: `[mcp_servers.<name>]` tables with
# `command` / `args` / `enabled`, inside a config.toml that also holds unrelated
# sections. We edit ONLY those tables, line by line, and leave the rest of the
# file byte-identical — a whole-file TOML re-emit would drop comments and needs a
# writer the stdlib does not ship. The original command/args are stashed as a
# base64 JSON scalar so the wrap is fully reversible.
_TOML_HEADER = re.compile(r'^\s*\[mcp_servers\.(?P<name>"(?:[^"\\]|\\.)*"|[^\]]+)\]\s*(#.*)?$')
_TOML_ANY_HEADER = re.compile(r'^\s*\[')


def _toml_str(s) -> str:
    out = (str(s).replace("\\", "\\\\").replace('"', '\\"')
           .replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r"))
    return f'"{out}"'


def _toml_arr(items) -> str:
    return "[" + ", ".join(_toml_str(x) for x in items) + "]"


def _toml_edit_table(lines: list[str], start: int, end: int, ncmd: str,
                     nargs: list, stash: str | None, rm_stash: bool) -> bool:
    """Rewrite command/args (and add or drop the stash) within one table's line
    span. Returns False — changing nothing — for a shape we can't edit safely."""
    seg = lines[start:end]
    for ln in seg:                                   # bail on a multi-line array
        st = ln.strip()
        if re.match(r'^(args|command)\s*=', st):
            val = st.split("=", 1)[1].strip()
            if val.startswith("[") and "]" not in val:
                return False

    def find(pat):
        for k, ln in enumerate(seg):
            if re.match(pat, ln):
                return k
        return None

    ci = find(r'^\s*command\s*=')
    if ci is None:
        return False
    indent = re.match(r'^(\s*)', seg[ci]).group(1)
    seg[ci] = f"{indent}command = {_toml_str(ncmd)}\n"
    argline = f"{indent}args = {_toml_arr(nargs)}\n"
    ai = find(r'^\s*args\s*=')
    if ai is not None:
        seg[ai] = argline
    else:
        seg.insert(find(r'^\s*command\s*=') + 1, argline)
    if rm_stash:
        si = find(r'^\s*_airlock_original\s*=')
        if si is not None:
            del seg[si]
    elif stash is not None and find(r'^\s*_airlock_original\s*=') is None:
        seg.insert(find(r'^\s*command\s*=') + 1,
                   f"{indent}_airlock_original = {_toml_str(stash)}\n")
    lines[start:end] = seg
    return True


def _wrap_toml(path: Path, res: Result, unwrap: bool, *, label: str = "") -> int:
    tag = f"{label}: " if label else ""
    if tomllib is None:
        return 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    try:
        data = tomllib.loads(text)
    except Exception:
        res.note(f"{tag}{path} is not valid TOML — skipped (fix or remove it)")
        return 0
    servers = data.get("mcp_servers")
    if not isinstance(servers, dict) or not servers:
        return 0

    lines = text.splitlines(keepends=True)
    spans = []                                        # (name, start, end)
    i = 0
    while i < len(lines):
        m = _TOML_HEADER.match(lines[i])
        if m:
            raw = m.group("name").strip()
            try:
                name = json.loads(raw) if raw.startswith('"') else raw
            except Exception:
                name = raw
            j = i + 1
            while j < len(lines) and not _TOML_ANY_HEADER.match(lines[j]):
                j += 1
            spans.append((name, i, j))
            i = j
        else:
            i += 1

    n = 0
    for name, start, end in reversed(spans):          # bottom-up: indices stay valid
        spec = servers.get(name)
        if not isinstance(spec, dict):
            continue
        wrapped = "_airlock_original" in spec
        if unwrap:
            if not wrapped:
                continue
            try:
                orig = json.loads(base64.b64decode(spec["_airlock_original"]).decode())
                ncmd, nargs = orig["command"], orig.get("args") or []
            except Exception:
                res.note(f"{tag}{path}: '{name}' has an unreadable saved original; "
                         f"left alone")
                continue
            ok = _toml_edit_table(lines, start, end, ncmd, nargs, None, True)
        else:
            if wrapped:
                continue
            cmd = spec.get("command")
            args = spec.get("args") or []
            if not isinstance(cmd, str) or not cmd \
                    or not all(isinstance(a, str) for a in args):
                continue                              # only stdio string commands
            wrap = mcp_command()
            ncmd = wrap[0]
            nargs = [*wrap[1:], "--server-id", name, "--", cmd, *args]
            stash = base64.b64encode(
                json.dumps({"command": cmd, "args": list(args)}).encode()).decode()
            ok = _toml_edit_table(lines, start, end, ncmd, nargs, stash, False)
        if not ok:
            res.note(f"{tag}{path}: '{name}' has a shape airlock can't rewrite "
                     f"safely — left alone (edit it by hand)")
            continue
        n += 1

    if n:
        b = _backup(path)
        newtext = "".join(lines)
        restored = False
        if unwrap:                                    # byte-for-byte if a backup matches
            try:
                undata = tomllib.loads(newtext)
            except Exception:
                undata = None
            if undata is not None:
                for bak in reversed(_backups(path)):
                    try:
                        if tomllib.loads(bak.read_text(encoding="utf-8")) == undata:
                            shutil.copyfile(bak, path)
                            restored = True
                            break
                    except Exception:
                        continue
        if not restored:
            config.write_atomic(path, newtext)
        verb = "unwrapped" if unwrap else "wrapped"
        res.add(path, f"{tag}{verb} {n} MCP server{'' if n == 1 else 's'}"
                     + (" (restored the original file byte-for-byte)"
                        if restored else ""), b or "")
    return n


# ---- DeepSeek Harness (cordis loader-patch YAML) -----------------------
# DSH declares each MCP server as a `@deepseek-ai/dsh-mcp-client` plugin entry
# inside ~/.dsh/profiles/<name>/cordis.patch.yml — a YAML array of loader-patch
# entries (plain entries, `insert:` lists, id-targeted overrides). A stdio
# server's `config` is command-string + args-list, exactly the standard shape,
# so _wrap_spec/_unwrap_spec handle the `config` dict directly. The file may
# carry js-yaml `!!js` tags; if safe_load can't read it, we skip it (never guess).
_DSH_CLIENT = "dsh-mcp-client"


def _dsh_server_configs(node) -> list[tuple[str, dict]]:
    """(serverName, config) for every dsh-mcp-client entry, recursing through
    `insert:` lists and group configs."""
    out: list[tuple[str, dict]] = []
    if isinstance(node, list):
        for item in node:
            out += _dsh_server_configs(item)
    elif isinstance(node, dict):
        cfg = node.get("config")
        if str(node.get("name", "")).endswith(_DSH_CLIENT) and isinstance(cfg, dict):
            out.append((str(cfg.get("serverName") or node.get("id") or "server"), cfg))
        if isinstance(node.get("insert"), list):
            out += _dsh_server_configs(node["insert"])
        if node.get("group") and isinstance(cfg, list):
            out += _dsh_server_configs(cfg)
    return out


def _wrap_dsh(path: Path, res: Result, unwrap: bool, *, label: str = "") -> int:
    import yaml
    tag = f"{label}: " if label else ""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    try:
        data = yaml.safe_load(text)
    except Exception:
        res.note(f"{tag}{path}: not plain YAML (js-yaml tags?) — skipped")
        return 0
    if not isinstance(data, (list, dict)):
        return 0
    configs = _dsh_server_configs(data)
    if not configs:
        return 0
    n = 0
    for name, cfg in configs:
        if unwrap:
            if "_airlock_original" in cfg and _unwrap_spec(name, cfg, res, path):
                n += 1
        else:
            if cfg.get("transport", "stdio") == "stdio" and _wrap_spec(name, cfg):
                n += 1
    if n:
        b = _backup(path)
        newtext = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        restored = False
        if unwrap:
            try:
                undata = yaml.safe_load(newtext)
            except Exception:
                undata = None
            if undata is not None:
                for bak in reversed(_backups(path)):
                    try:
                        if yaml.safe_load(bak.read_text(encoding="utf-8")) == undata:
                            shutil.copyfile(bak, path)
                            restored = True
                            break
                    except Exception:
                        continue
        if not restored:
            config.write_atomic(path, newtext)
        verb = "unwrapped" if unwrap else "wrapped"
        res.add(path, f"{tag}{verb} {n} MCP server{'' if n == 1 else 's'}"
                     + (" (restored the original file byte-for-byte)"
                        if restored else ""), b or "")
    return n


def _is_dsh_store(path: Path) -> bool:
    return path.name in ("cordis.patch.yml", "cordis.yml")


def store_server_status(path: Path) -> list[tuple[str, bool]]:
    """(name, is_wrapped) for every stdio server in a store, JSON or TOML.

    Lets `doctor` report gated/ungated across every format without duplicating
    the per-format parsing. Tolerant: an unreadable store yields nothing.
    """
    out: list[tuple[str, bool]] = []
    try:
        if _is_dsh_store(path):
            import yaml
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            for name, cfg in _dsh_server_configs(data):
                if cfg.get("transport", "stdio") == "stdio" and cfg.get("command"):
                    out.append((name, "_airlock_original" in cfg))
        elif path.suffix == ".toml":
            if tomllib is None:
                return out
            servers = tomllib.loads(path.read_text(encoding="utf-8")).get("mcp_servers")
            if isinstance(servers, dict):
                for name, spec in servers.items():
                    if isinstance(spec, dict) and spec.get("command"):
                        out.append((name, "_airlock_original" in spec))
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
            for servers in _server_maps(data):
                for name, spec in servers.items():
                    if isinstance(spec, dict) and spec.get("command"):
                        out.append((name, _is_wrapped(spec)))
    except Exception:
        pass
    return out


def wrap_servers(path: Path, res: Result, unwrap: bool = False, *,
                 label: str = "") -> int:
    if _is_dsh_store(path):
        return _wrap_dsh(path, res, unwrap, label=label)
    if path.suffix == ".toml":
        return _wrap_toml(path, res, unwrap, label=label)
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
                if _unwrap_spec(name, spec, res, path):
                    n += 1
            else:
                if _wrap_spec(name, spec):
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
