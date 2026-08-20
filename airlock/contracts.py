"""Per-skill capability contracts (plane 4: the least-privilege grant).

Global policy says "may any skill do X?". A contract says "may THIS skill do X?"
— scoped to what it was pinned to do. A trusted-looking skill that global policy
would allow can still be stopped when it reaches outside its own contract
(e.g. `read_note` trying to read `../../etc/passwd`).

Contracts live in $AIRLOCK_HOME/contracts.yaml, one block per server-id:

    demo:
      enforced: true          # false = proposal only (observe/learn phase)
      tools: [read_note]      # allowed tool names (null = the pinned set)
      fs:   ["*/notes/*"]     # allowed filesystem path globs (read+write)
      net:  []                # allowed egress host globs (empty = deny all)
      shell: false            # may run a shell command?
      default: block          # verdict for in-scope tool touching out-of-scope resource

On first pin we AUTO-DERIVE a least-privilege starter with enforced:false, so the
operator has something concrete to review and promote.

Every string in the argument object is classified, not just the "primary" field
— a contract that only inspects one argument is trivially bypassed by putting
the real target in a second one.
"""
from __future__ import annotations
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from .audit import home
from .policy import ALLOW, BLOCK, RANK, iter_strings, render_action, _glob

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


def _path() -> Path:
    return home() / "contracts.yaml"


class _Lock:
    def __enter__(self):
        self.f = open(home() / "contracts.lock", "a+")
        if fcntl:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if fcntl:
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        self.f.close()
        return False


_cache: tuple | None = None


def _load() -> dict:
    """Read contracts.yaml, cached on (path, mtime, size).

    The proxy calls this on every single tools/call. Re-parsing the YAML each
    time cost more than the entire policy decision it was feeding. The mtime
    check keeps an `airlock contracts promote` in another process visible
    immediately, so the cache cannot go stale in a way that matters.
    """
    global _cache
    p = _path()
    try:
        st = p.stat()
    except OSError:
        _cache = None
        return {}
    key = (str(p), st.st_mtime, st.st_size)
    if _cache is not None and _cache[:3] == key:
        return _cache[3]
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except Exception:
        data = {}
    _cache = (*key, data)
    return data


def _save(data: dict) -> bool:
    """Atomic replace; False when it could not be written.

    Contracts are bookkeeping — a proposal and a learned footprint. Letting a
    full disk raise from here killed the proxy's pump thread and, in observe
    mode, turned every call into a fail-closed refusal. Neither is a proportionate
    response to being unable to save a suggestion.
    """
    global _cache
    _cache = None
    p = _path()
    tmp = p.with_suffix(".yaml.tmp")
    try:
        tmp.write_text(yaml.safe_dump(data, sort_keys=True, allow_unicode=True))
        os.replace(tmp, p)
        return True
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


# ---- resource classification ------------------------------------------
_SHELL_TOOLS = {"bash", "shell", "run_command", "exec", "execute", "spawn",
                "process", "terminal"}
_SHELL_KEYS = {"command", "cmd", "script", "argv", "shell"}
_PATHISH = ("/", "\\")


def _looks_like_path(s: str) -> bool:
    if not s or len(s) > 4096 or "://" in s:
        return False
    if s.startswith(("~", "/", "./", "../", ".\\", "..\\")):
        return True
    # a bare relative path: has a separator, no whitespace, not a sentence
    return any(c in s for c in _PATHISH) and " " not in s.strip()


def _url_host(s: str) -> str | None:
    if not s[:8].lower().startswith(("http://", "https:/", "ws://", "wss://",
                                     "ftp://")):
        return None
    try:
        return urlparse(s).hostname or None
    except Exception:
        return None


def classify_all(tool: str, args: dict) -> list[tuple[str, str]]:
    """Every resource this call touches, as (kind, value) pairs.

    kind in {shell, net, fs}. Values that look like none of those are dropped —
    an opaque string is not a capability.
    """
    base = tool.lower().split("__")[-1]
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str):
        item = (kind, value)
        if value and item not in seen:
            seen.add(item)
            out.append(item)

    shellish = base in _SHELL_TOOLS or any(k in args for k in _SHELL_KEYS)
    for k, v in args.items():
        if isinstance(v, str) and k.lower() in _SHELL_KEYS:
            add("shell", v)
    if shellish and not out:
        add("shell", render_action(tool, args))

    for s in iter_strings(args):
        host = _url_host(s)
        if host:
            add("net", host.lower())
        elif _looks_like_path(s):
            # Fold the spelling BEFORE collapsing `..`: normpath does nothing
            # for `%2e%2e`, so a percent-encoded traversal stayed inside a
            # contract scope that the plain `../` form escaped.
            from .policy import normalize
            add("fs", os.path.normpath(os.path.expanduser(normalize(s))))
    return out


def classify(tool: str, args: dict) -> tuple[str, str]:
    """The single most relevant resource — for display and the ask prompt."""
    found = classify_all(tool, args)
    for kind in ("shell", "net", "fs"):
        for k, v in found:
            if k == kind:
                return k, v
    return "other", render_action(tool, args)[:200]


@dataclass
class Contract:
    server_id: str
    enforced: bool = False
    tools: list | None = None
    fs: list = field(default_factory=list)
    net: list = field(default_factory=list)
    shell: bool = False
    default: str = BLOCK

    def check(self, tool: str, args: dict):
        """Return (action, reason) for the contract dimension, or (allow, '')."""
        base = tool.lower().split("__")[-1]
        if self.tools is not None and base not in self.tools:
            return BLOCK, f"tool '{base}' not in pinned contract"

        worst, why = ALLOW, ""
        for kind, value in classify_all(tool, args):
            if kind == "shell":
                act, reason = ((ALLOW, "") if self.shell
                               else (BLOCK, "shell not permitted by contract"))
            elif kind == "net":
                act, reason = ((ALLOW, "") if _in_scope(value, self.net)
                               else (self.default, f"egress to '{value}' outside contract"))
            else:  # fs
                act, reason = ((ALLOW, "") if _in_scope(value, self.fs)
                               else (self.default, f"path '{value}' outside contract scope"))
            if RANK[act] > RANK[worst]:
                worst, why = act, reason
        return worst, why


def _in_scope(value: str, globs: list) -> bool:
    """Scope check on the same normalised form the global rules use.

    Without it `/srv/notes/%2e%2e/%2e%2e/etc/passwd` counted as inside a
    contract scoped to `/srv/notes/*` — the plain `../` form was caught and the
    percent-encoded one was not, which is the worse half to miss.
    """
    from .policy import normalize
    v = normalize(value)          # idempotent; classify_all already folded fs paths
    return any(_glob(v, str(g).lower()) for g in globs)


def get(server_id: str) -> Contract | None:
    data = _load().get(server_id)
    if not data:
        return None
    return Contract(server_id=server_id,
                    enforced=bool(data.get("enforced", False)),
                    tools=data.get("tools"),
                    fs=data.get("fs") or [],
                    net=data.get("net") or [],
                    shell=bool(data.get("shell", False)),
                    default=data.get("default", BLOCK))


def ensure_default(server_id: str, tool_names: list[str]) -> None:
    """On first pin, write a least-privilege starter (proposal, not enforced)."""
    with _Lock():
        data = _load()
        if server_id in data:
            return
        data[server_id] = {
            "enforced": False,          # promote to true after review
            "tools": sorted(tool_names),
            "fs": [],                   # deny all fs by default
            "net": [],                  # deny all egress by default
            "shell": False,             # deny shell by default
            "default": "ask",
            "_note": "auto-derived least-privilege starter — review, then set enforced: true",
        }
        _save(data)


def observe(server_id: str, tool: str, args: dict) -> None:
    """Learn phase: record what a skill actually touches, as a promotion proposal."""
    with _Lock():
        data = _load()
        entry = data.setdefault(server_id, {"enforced": False, "tools": [], "fs": [],
                                            "net": [], "shell": False, "default": "ask"})
        seen = entry.setdefault("_observed", {"fs": [], "net": [], "shell": False,
                                              "tools": []})
        base = tool.lower().split("__")[-1]
        if base not in seen["tools"]:
            seen["tools"].append(base)
        for kind, value in classify_all(tool, args):
            if kind == "shell":
                seen["shell"] = True
            elif value not in seen[kind]:
                seen[kind].append(value)
        _save(data)


def promote(server_id: str) -> str:
    """Turn what was observed into an enforced contract (learn -> enforce)."""
    with _Lock():
        data = _load()
        entry = data.get(server_id)
        if not entry:
            return f"no contract for '{server_id}'"
        obs = entry.get("_observed") or {}
        if not obs:
            return (f"'{server_id}' has nothing observed yet — run it under "
                    f"AIRLOCK_MODE=observe first")
        entry["tools"] = sorted(set(entry.get("tools") or []) & set(obs.get("tools") or [])
                                or obs.get("tools") or [])
        entry["fs"] = sorted(_generalize(obs.get("fs") or []))
        entry["net"] = sorted(set(obs.get("net") or []))
        entry["shell"] = bool(obs.get("shell"))
        entry["enforced"] = True
        entry["_promoted_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _save(data)
        return (f"'{server_id}' promoted to enforced: {len(entry['tools'])} tools, "
                f"{len(entry['fs'])} fs globs, {len(entry['net'])} hosts, "
                f"shell={entry['shell']}")


def _generalize(paths: list[str]) -> set[str]:
    """Turn observed files into directory globs, so a promoted contract is
    usable without being a wildcard."""
    out = set()
    for p in paths:
        parent = os.path.dirname(p)
        out.add(f"{parent}/*" if parent and parent != "/" else p)
    return out
