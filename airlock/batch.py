"""Batch admission scan (plane 4, stage 1 at scale) — PLAN day 9.

Point Airlock at a directory (or a single file) and get a findings report over
everything an agent would load into its context or run on its behalf:

  * SKILL.md / AGENTS.md / CLAUDE.md and any markdown with skill frontmatter
  * MCP server definitions in .mcp.json / claude_desktop_config.json / settings.json
  * PreToolUse-style hook commands in settings.json  (a hook IS code execution)
  * the scripts a skill ships next to itself (.sh/.py/.js/.ts)

This is the "we scanned N public skills — here is what we found" engine. It is
static and deterministic: it produces evidence for a human, not a verdict.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import scan

SKILL_NAMES = {"skill.md", "agents.md", "claude.md", "readme.md"}
CONFIG_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json",
                "settings.json", "settings.local.json", "config.json"}
CODE_SUFFIXES = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1"}
DOC_SUFFIXES = {".md", ".markdown", ".mdc", ".txt"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", ".next", "target", ".mypy_cache", ".pytest_cache"}
MAX_BYTES = 2_000_000

# an MCP server command that fetches code at run time is a supply-chain risk
_UNPINNED = ("npx", "uvx", "bunx", "pnpx")


@dataclass
class Finding:
    path: str
    kind: str            # skill | mcp-config | mcp-server | hook | code
    subject: str         # tool name, server name, or ""
    flag: dict

    @property
    def severity(self) -> str:
        return self.flag.get("severity", "low")


@dataclass
class Report:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    servers: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def by_file(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.path, []).append(f)
        return out

    def counts(self) -> dict[str, int]:
        c = {"high": 0, "med": 0, "low": 0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "counts": self.counts(),
            "risk": scan.risk_score([f.flag for f in self.findings]),
            "servers": self.servers,
            "findings": [{"path": f.path, "kind": f.kind, "subject": f.subject,
                          **f.flag} for f in self.findings],
            "errors": self.errors,
        }


def _read(p: Path) -> tuple[str | None, str]:
    """(text, why it could not be read).

    Returning a bare None meant a file the scanner could not open vanished
    from the report: an unreadable directory, a file over the size cap and a
    genuinely clean file all produced the same output, and the risk score was
    computed over whatever happened to be readable. A scan that has not read
    something must not present the result as complete.
    """
    try:
        size = p.stat().st_size
        if size > MAX_BYTES:
            return None, f"{p}: skipped, {size // 1024} KB is over the {MAX_BYTES // 1024} KB cap"
        return p.read_text(encoding="utf-8", errors="replace"), ""
    except OSError as e:
        return None, f"{p}: not read ({e.strerror or e})"
    except Exception as e:
        return None, f"{p}: not read ({type(e).__name__})"


def _walk(root: Path, errors: list[str] | None = None):
    """Files under root. Directories we cannot enter are reported, not skipped
    in silence — os.walk swallows them by default.

    Symlinked directories are not followed (a loop would be unbounded), so a
    skill reachable only through one is out of scope; that is recorded too.
    """
    if root.is_file():
        yield root
        return

    def _oops(e: OSError):
        if errors is not None:
            errors.append(f"{getattr(e, 'filename', root)}: not scanned "
                          f"({e.strerror or e})")

    for dirpath, dirnames, filenames in os.walk(root, onerror=_oops):
        keep = []
        for d in dirnames:
            if d in SKIP_DIRS or d.startswith(".git"):
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                if errors is not None:
                    errors.append(f"{os.path.join(dirpath, d)}: not followed "
                                  f"(symlinked directory)")
                continue
            keep.append(d)
        dirnames[:] = keep
        for fn in filenames:
            yield Path(dirpath) / fn


def _classify_file(p: Path) -> str | None:
    n = p.name.lower()
    if n in CONFIG_NAMES:
        return "mcp-config"
    if n in SKILL_NAMES or (p.suffix.lower() in DOC_SUFFIXES and
                            "skill" in str(p.parent).lower()):
        return "skill"
    if p.suffix.lower() in DOC_SUFFIXES:
        return "skill"
    if p.suffix.lower() in CODE_SUFFIXES:
        return "code"
    return None


def _scan_config(rep: Report, p: Path, text: str) -> None:
    """MCP server definitions and hook commands hide executable intent in JSON."""
    try:
        data = json.loads(text)
    except Exception:
        return
    if not isinstance(data, dict):
        return
    rel = str(p)

    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    if isinstance(servers, dict):
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            cmd = spec.get("command", "")
            argv = spec.get("args") or []
            line = " ".join([str(cmd), *[str(a) for a in argv]])
            entry = {"file": rel, "name": name, "command": line,
                     "behind_airlock": "airlock" in str(cmd).lower(), "notes": []}
            if Path(str(cmd)).name in _UNPINNED and not any(
                    "@" in str(a) for a in argv):
                entry["notes"].append("unpinned version — fetches latest at each launch")
            if spec.get("env"):
                keys = [k for k in spec["env"] if isinstance(k, str)]
                if keys:
                    entry["notes"].append(f"passes env: {', '.join(sorted(keys)[:6])}")
            if not entry["behind_airlock"]:
                entry["notes"].append("not wrapped by airlock-mcp — calls are ungated")
            rep.servers.append(entry)
            for fl in scan.scan_text(line + "\n" + json.dumps(spec), all_hits=True):
                rep.findings.append(Finding(rel, "mcp-server", name, fl))

    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            for g in (groups if isinstance(groups, list) else []):
                for h in ((g or {}).get("hooks") or []) if isinstance(g, dict) else []:
                    cmd = str((h or {}).get("command", ""))
                    if not cmd:
                        continue
                    for fl in scan.scan_text(cmd, all_hits=True):
                        rep.findings.append(Finding(rel, "hook", event, fl))


def scan_path(root: str | Path, *, min_severity: str = "low") -> Report:
    root = Path(root).expanduser().resolve()
    rep = Report(root=str(root))
    if not root.exists():
        rep.errors.append(f"{root}: no such path")
        return rep
    order = {"high": 0, "med": 1, "low": 2}
    cutoff = order.get(min_severity, 2)

    for p in _walk(root, rep.errors):
        kind = _classify_file(p)
        if kind is None:
            continue
        text, why = _read(p)
        if text is None:
            if why:
                rep.errors.append(why)
            continue
        rep.files_scanned += 1
        rel = str(p)
        if kind == "mcp-config":
            _scan_config(rep, p, text)
        for fl in scan.scan_text(text, all_hits=True):
            rep.findings.append(Finding(rel, kind, "", fl))

    rep.findings = [f for f in rep.findings if order.get(f.severity, 2) <= cutoff]
    rep.findings.sort(key=lambda f: (order.get(f.severity, 2), f.path,
                                     f.flag.get("line", 0)))
    return rep


# ---- rendering ---------------------------------------------------------
_C = {"high": "\033[31m", "med": "\033[33m", "low": "\033[90m", "off": "\033[0m",
      "bold": "\033[1m", "dim": "\033[2m", "cyan": "\033[36m"}


def render(rep: Report, *, color: bool = True) -> str:
    c = _C if color else {k: "" for k in _C}
    out: list[str] = []
    counts = rep.counts()
    out.append(f"\n{c['bold']}AIRLOCK SCAN{c['off']}  {rep.root}")
    out.append(f"{c['dim']}{rep.files_scanned} files · "
               f"{len(rep.servers)} MCP server definitions{c['off']}\n")

    if rep.servers:
        out.append(f"{c['bold']}MCP servers{c['off']}")
        for s in rep.servers:
            mark = f"{c['low']}gated{c['off']}" if s["behind_airlock"] else \
                   f"{c['med']}UNGATED{c['off']}"
            out.append(f"  [{mark}] {c['cyan']}{s['name']}{c['off']}  {s['command'][:80]}")
            for n in s["notes"]:
                out.append(f"      {c['dim']}· {n}{c['off']}")
        out.append("")

    if not rep.findings:
        out.append(f"  {c['low']}no static indicators found{c['off']}\n")
    else:
        for path, fs in rep.by_file().items():
            head = os.path.relpath(path, rep.root) if path != rep.root else path
            out.append(f"{c['bold']}{head}{c['off']}  {c['dim']}({fs[0].kind}){c['off']}")
            for f in fs:
                loc = f":{f.flag['line']}" if "line" in f.flag else ""
                subj = f" [{f.subject}]" if f.subject else ""
                out.append(f"  {c[f.severity]}{f.severity.upper():4}{c['off']} "
                           f"{f.flag['id']:22}{loc:<6}{subj} {c['dim']}"
                           f"{f.flag['hit'][:70]}{c['off']}")
                why = scan.meaning(f.flag["id"])
                if why and f.severity == "high":
                    out.append(f"       {c['dim']}↳ {why}{c['off']}")
            out.append("")

    risk = scan.risk_score([f.flag for f in rep.findings])
    bar = "█" * (risk // 5) + "░" * (20 - risk // 5)
    tone = c["high"] if risk >= 50 else c["med"] if risk >= 20 else c["low"]
    out.append(f"  {tone}{bar}{c['off']}  risk {risk}/100   "
               f"{c['high']}{counts['high']} high{c['off']} · "
               f"{c['med']}{counts['med']} med{c['off']} · "
               f"{c['low']}{counts['low']} low{c['off']}")
    if rep.errors:
        # The score is only about what was read. Saying so next to the score is
        # the difference between a partial scan and a misleading one.
        out.append(f"  {c['med']}!{c['off']} {len(rep.errors)} path(s) were not "
                   f"read — this score covers the rest")
        for e in rep.errors[:8]:
            out.append(f"    {c['dim']}{e}{c['off']}")
        if len(rep.errors) > 8:
            out.append(f"    {c['dim']}...and {len(rep.errors) - 8} more{c['off']}")
    out.append(f"\n  {c['dim']}Static indicators only. They narrow the contract; "
               f"the runtime gate holds it.{c['off']}\n")
    return "\n".join(out)
