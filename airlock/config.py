"""Where things live, and how a policy finds its way onto someone else's machine.

Three resolution jobs, all of which the first prototype got wrong by hardcoding:

  workspace   the repo the agent is working in — what "in-workspace read" means
  policy      env -> per-project -> user -> bundled profile
  variables   ${workspace} / ${home} / ${user} / ${tmp} expanded at load time,
              so a shipped policy is portable instead of being one person's paths
"""
from __future__ import annotations
import os
import re
import sys
from pathlib import Path


def force_utf8() -> None:
    """Make stdout/stderr encode UTF-8 so the CLI does not crash on a Windows
    console (cp1252), which cannot encode the ✓ / ↳ / block-bar glyphs the output
    uses. Called from every entry point. No-op where the stream is already UTF-8.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            enc = (getattr(stream, "encoding", "") or "").lower()
            if enc not in ("utf-8", "utf8") and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

PKG = Path(__file__).resolve().parent
PROFILES = PKG / "profiles"
DEFAULT_PROFILE = "default"

# a per-project policy, looked for from the workspace root upward
PROJECT_POLICY_NAMES = (".airlock/policy.yaml", ".airlock.yaml", ".airlock.yml")


def home() -> Path:
    """$AIRLOCK_HOME, created 0700 (it records what an agent reached for)."""
    d = Path(os.environ.get("AIRLOCK_HOME", Path.home() / ".airlock")).expanduser()
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def write_atomic(path: Path, text: str) -> None:
    """Replace a file's contents in one step, or not at all.

    A plain write truncates first: for the length of one rewrite the policy on
    disk is a prefix of itself. A prefix of a YAML rule list is still valid
    YAML — 104 of the 118 line-boundary truncations of the shipped paranoid
    profile parse as a policy, one of them with a single block rule left of
    seventy-two — so a gate reading at that instant would enforce almost
    nothing and log the result as an ordinary decision. The window is
    microseconds and the consequence is total, which is the wrong trade to
    leave in a security tool when os.replace() is atomic and free.

    Writes through a symlink rather than replacing it, for the same reason
    `airlock init` does.
    """
    target = Path(os.path.realpath(path)) if path.is_symlink() else Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)


_WORKSPACE: dict = {}


def workspace() -> Path:
    """The project the agent is operating on.

    AIRLOCK_WORKSPACE wins; otherwise the enclosing git repo; otherwise cwd.
    An MCP server is launched with the project as cwd, so this is usually right
    without anyone configuring it.

    Found by walking up for a `.git`, NOT by running `git`. Shelling out meant
    the gate executed a binary resolved through the agent's own PATH on every
    single decision — and a `git` that answered `rev-parse` with a directory of
    its choosing moved `${workspace}`, turning a scoped allow rule into a wide
    one. A firewall must not run the caller's code to work out what the caller
    is allowed to do.

    A repository whose root is $HOME or / is not a project. A dotfiles repo at
    $HOME would otherwise make `${workspace}/*` mean the whole home directory,
    and `git init ~` is a command an agent can run.
    """
    # Cached on what it depends on, not globally: a long-lived process that
    # changes directory — or a test that moves between fixtures — must get the
    # answer for where it is now, not where it started.
    try:
        key = (os.environ.get("AIRLOCK_WORKSPACE", ""), os.getcwd())
    except OSError:
        key = (os.environ.get("AIRLOCK_WORKSPACE", ""), "")
    if key not in _WORKSPACE:
        _WORKSPACE.clear()
        _WORKSPACE[key] = _find_workspace()
    return _WORKSPACE[key]


def _find_workspace() -> Path:
    env = os.environ.get("AIRLOCK_WORKSPACE")
    if env:
        return Path(env).expanduser().resolve()
    try:
        cwd = Path.cwd().resolve()
    except OSError:            # the working directory was deleted under us
        return Path(os.environ.get("TMPDIR", "/tmp")).resolve()
    try:
        stop = {Path.home().resolve(), Path("/")}
    except (OSError, RuntimeError):
        stop = {Path("/")}
    for d in (cwd, *cwd.parents):
        if d in stop:
            break
        if (d / ".git").exists():
            return d
    return cwd


def user_policy() -> Path:
    return home() / "policy.yaml"


def profile_path(name: str) -> Path:
    p = PROFILES / f"{name}.yaml"
    if not p.exists():
        raise FileNotFoundError(
            f"no such profile: {name} (have: {', '.join(list_profiles())})")
    return p


def list_profiles() -> list[str]:
    return sorted(p.stem for p in PROFILES.glob("*.yaml"))


def project_policy(start: Path | None = None) -> Path | None:
    """Walk up from the workspace looking for a repo-local policy.

    A team keeps the strict policy in the repo it applies to; the personal
    machine-wide one is for everything else.
    """
    cur = (start or workspace()).resolve()
    for d in (cur, *cur.parents):
        for name in PROJECT_POLICY_NAMES:
            cand = d / name
            if cand.is_file():
                return cand
        if (d / ".git").exists():
            break        # do not escape the repo
    return None


def resolve_policy() -> tuple[Path, str]:
    """Return (path, why) for the policy that OWNS this machine's posture.

    Deliberately not the project policy. A `.airlock/policy.yaml` inside a
    repository is written by whoever wrote the repository, and the whole point
    of Airlock is that an agent works on code nobody has read. Letting that
    file win meant `git clone` was a way to turn the firewall off. It is still
    honoured — as an overlay that can only tighten — via resolve_policy_chain.
    """
    env = os.environ.get("AIRLOCK_POLICY")
    if env:
        return Path(env).expanduser(), "AIRLOCK_POLICY"
    up = user_policy()
    if up.is_file():
        return up, "user"
    name = os.environ.get("AIRLOCK_PROFILE", DEFAULT_PROFILE)
    return profile_path(name), f"bundled profile '{name}'"


def resolve_policy_chain() -> tuple[Path, str, Path | None]:
    """(base path, why, project overlay or None).

    An explicit AIRLOCK_POLICY is the user speaking, so it takes no overlay.
    """
    base, why = resolve_policy()
    if os.environ.get("AIRLOCK_POLICY"):
        return base, why, None
    proj = project_policy()
    if proj and proj.resolve() != base.resolve():
        return base, why, proj
    return base, why, None


# ---- variable expansion ------------------------------------------------
_VAR = re.compile(r"\$\{(\w+)\}")


def variables() -> dict[str, str]:
    return {
        "workspace": str(workspace()),
        "home": str(Path.home()),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "user",
        "tmp": os.environ.get("TMPDIR", "/tmp").rstrip("/"),
    }


def expand(value, vars_: dict[str, str] | None = None):
    """Expand ${...} through any nested structure a policy can contain."""
    vars_ = vars_ if vars_ is not None else variables()
    if isinstance(value, str):
        return _VAR.sub(lambda m: vars_.get(m.group(1), m.group(0)), value)
    if isinstance(value, list):
        return [expand(v, vars_) for v in value]
    if isinstance(value, dict):
        return {k: expand(v, vars_) for k, v in value.items()}
    return value
