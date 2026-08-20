"""Two boundaries: the policy file between a writer and a reader, and the hook
between Airlock's question and the agent's own answer."""
import json, os, pathlib, subprocess, sys, tempfile, threading, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite
from airlock import audit, config, report as R

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _atomic_writes(s):
    import yaml
    # A plain write truncates first, and a prefix of a YAML rule list is still
    # valid YAML — so a gate reading mid-rewrite could enforce a policy with
    # almost none of its block rules and log the result as an ordinary
    # decision.
    raw = config.profile_path("paranoid").read_text()
    lines = raw.splitlines(keepends=True)
    full = yaml.safe_load(raw)
    full_blocks = sum(1 for r in full["rules"] if r.get("action") == "block")
    weaker = 0
    for cut in range(1, len(lines)):
        try:
            d = yaml.safe_load("".join(lines[:cut]))
        except Exception:
            continue
        if not isinstance(d, dict) or not isinstance(d.get("rules"), list):
            continue
        if sum(1 for r in d["rules"]
               if isinstance(r, dict) and r.get("action") == "block") < full_blocks:
            weaker += 1
    s.check("a truncated policy can still parse as a weaker one — so writes "
            "must be atomic", weaker > 0, weaker)

    home = pathlib.Path(tempfile.mkdtemp(prefix="bd-"))
    (home / ".airlock").mkdir(parents=True)
    env = dict(os.environ, PYTHONPATH=str(ROOT), HOME=str(home),
               AIRLOCK_HOME=str(home / ".airlock"), AIRLOCK_QUIET="1", AIRLOCK_NOTIFY="0")
    env.pop("AIRLOCK_POLICY", None)
    subprocess.run([sys.executable, "-m", "airlock.cli", "profile", "paranoid"],
                   env=env, capture_output=True)
    pol = home / ".airlock" / "policy.yaml"
    d = yaml.safe_load(pol.read_text())
    d["rules"] += [{"tool": "*", "match": f"*f{i}*", "action": "ask", "reason": "x" * 200}
                   for i in range(1500)]
    d["grants"] = [{"tool": "Read", "match": f"/tmp/g{i}/*", "reason": "seed"}
                   for i in range(8)]
    pol.write_text(yaml.safe_dump(d, sort_keys=False))
    steady = pol.stat().st_size

    stop = []
    partial = []
    samples = [0]

    def watch():
        while not stop:
            try:
                n = pol.stat().st_size
            except OSError:
                continue
            samples[0] += 1
            if n < steady - 4096:
                partial.append(n)

    def write():
        i = 0
        while not stop:
            subprocess.run([sys.executable, "-m", "airlock.cli", "allow", "revoke", "0", "-y"],
                           env=env, capture_output=True)
            subprocess.run([sys.executable, "-m", "airlock.cli", "allow", "Read",
                            "--match", f"/tmp/r{i}/*"], env=env, capture_output=True)
            i += 1

    threads = [threading.Thread(target=watch, daemon=True) for _ in range(2)]
    threads += [threading.Thread(target=write, daemon=True) for _ in range(2)]
    for t in threads:
        t.start()
    time.sleep(4)
    stop.append(True)
    time.sleep(0.4)
    s.check("the policy is never observable half-written",
            not partial, f"{len(partial)} truncated states, smallest {min(partial) if partial else 0} bytes")
    s.check("the watcher actually looked", samples[0] > 10_000, samples[0])


def _outcome_loop(s):
    home = pathlib.Path(tempfile.mkdtemp(prefix="bd-h-"))
    (home / ".claude").mkdir(parents=True)
    (home / "proj").mkdir()
    env = dict(os.environ, PYTHONPATH=str(ROOT), HOME=str(home),
               AIRLOCK_HOME=str(home / ".airlock"), AIRLOCK_QUIET="1", AIRLOCK_NOTIFY="0")
    env.pop("AIRLOCK_POLICY", None)

    def hook(payload, *args):
        return subprocess.run([sys.executable, "-m", "airlock.cc_hook", *args],
                              input=json.dumps(payload), text=True,
                              capture_output=True, env=env)

    # Airlock asks; Claude Code puts its own prompt in front of the human.
    a1 = {"file_path": "/srv/data/a.txt", "content": "x"}
    a2 = {"file_path": "/srv/other/b.txt", "content": "y"}
    r = hook({"tool_name": "Write", "tool_input": a1, "session_id": "s1"})
    s.check("a call outside the workspace is handed to the agent's prompt",
            "permissionDecision" in r.stdout, r.stdout[:120])
    # the human said yes, so the tool ran and PostToolUse fires
    r = hook({"tool_name": "Write", "tool_input": a1, "session_id": "s1",
              "hook_event_name": "PostToolUse", "tool_response": {"ok": True}}, "--post")
    s.check("recording an outcome never blocks the call that already ran",
            r.returncode == 0, r.returncode)
    # ...and here the human said no, so nothing fires
    hook({"tool_name": "Write", "tool_input": a2, "session_id": "s1"})

    old = os.environ.get("AIRLOCK_HOME")
    os.environ["AIRLOCK_HOME"] = str(home / ".airlock")
    try:
        h = R.build(days=7).to_dict()["human"]
    finally:
        if old is None:
            os.environ.pop("AIRLOCK_HOME", None)
        else:
            os.environ["AIRLOCK_HOME"] = old
    s.check("the log now says which handed-over call ran",
            h.get("handed_over_and_ran") == 1, h)
    s.check("...and which one did not", h.get("handed_over_and_did_not") == 1, h)

    # both spellings of the hook command must work: init writes the second one
    # whenever the console script is not on PATH
    for form in (["-m", "airlock.cc_hook", "--post"], ["-m", "airlock.cli", "hook", "--post"]):
        r = subprocess.run([sys.executable, *form],
                           input=json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/x"},
                                             "hook_event_name": "PostToolUse"}),
                           text=True, capture_output=True, env=env)
        s.check(f"`{' '.join(form[1:])}` records instead of erroring",
                r.returncode == 0, f"rc={r.returncode} {r.stderr[:100]}")

    r = subprocess.run([sys.executable, "-m", "airlock.cli", "init"], env=env,
                       capture_output=True, text=True)
    wired = json.loads((home / ".claude" / "settings.json").read_text())["hooks"]
    s.check("init wires PreToolUse", "PreToolUse" in wired, list(wired))
    s.check("init wires PostToolUse too", "PostToolUse" in wired, list(wired))
    post = wired["PostToolUse"][0]["hooks"][0]["command"]
    s.check("the PostToolUse entry asks for an outcome, not a decision",
            post.endswith("--post"), post)
    subprocess.run([sys.executable, "-m", "airlock.cli", "uninstall", "-y"],
                   env=env, capture_output=True)
    left = json.loads((home / ".claude" / "settings.json").read_text()).get("hooks")
    s.check("uninstall removes both", not left, left)


def _workspace_boundary(s):
    """`${workspace}` is a policy variable whose value the agent can influence."""
    import importlib
    from airlock import config as _cfg

    home = pathlib.Path(tempfile.mkdtemp(prefix="bd-ws-"))
    (home / "proj").mkdir()
    (home / "proj" / ".git").mkdir()
    (home / "secrets").mkdir()
    (home / "bin").mkdir()

    def ws(cwd, path_prefix=""):
        code = ("import os,sys;sys.path.insert(0,%r);"
                "from airlock import config;print(config.workspace())" % str(ROOT))
        env = dict(os.environ, HOME=str(home))
        env.pop("AIRLOCK_WORKSPACE", None)
        if path_prefix:
            env["PATH"] = f"{path_prefix}:{env['PATH']}"
        r = subprocess.run([sys.executable, "-c", code], cwd=str(cwd),
                           capture_output=True, text=True, env=env)
        return r.stdout.strip()

    s.check("a repo is found by walking up, from inside it",
            ws(home / "proj") == str(home / "proj"), ws(home / "proj"))

    # A `git` on PATH that answers rev-parse with a directory of its choosing
    # used to move ${workspace} — and shelling out at all meant the gate ran a
    # binary the caller may control, on every decision.
    fake = home / "bin" / "git"
    fake.write_text('#!/bin/sh\n'
                    'echo called >> "$AIRLOCK_TEST_GIT_LOG"\n'
                    f'[ "$1" = "rev-parse" ] && {{ echo "{home}"; exit 0; }}\n'
                    'exec /usr/bin/git "$@"\n')
    fake.chmod(0o755)
    log = home / "git.log"
    log.write_text("")
    os.environ["AIRLOCK_TEST_GIT_LOG"] = str(log)
    try:
        got = ws(home / "proj", path_prefix=str(home / "bin"))
    finally:
        os.environ.pop("AIRLOCK_TEST_GIT_LOG", None)
    s.check("a hostile `git` on PATH cannot move the workspace",
            got == str(home / "proj"), got)
    s.check("...because the gate never runs `git` at all",
            log.read_text() == "", log.read_text()[:60])

    # `git init ~` is a command an agent can run. A repo whose root is the home
    # directory is not a project, and treating it as one would turn every
    # ${workspace} rule into a home-wide one.
    (home / ".git").mkdir()
    s.check("a repo at $HOME is not treated as the project",
            ws(home / "proj") == str(home / "proj"), ws(home / "proj"))
    nested = home / "proj" / "vendor" / "dep"
    nested.mkdir(parents=True)
    (nested / ".git").mkdir()
    s.check("the nearest enclosing repo wins", ws(nested) == str(nested), ws(nested))

    # ...and when cwd genuinely is the home directory, say so rather than
    # quietly scoping every allow rule to all of it.
    r = subprocess.run([sys.executable, "-m", "airlock.cli", "doctor"],
                       cwd=str(home), capture_output=True, text=True,
                       env=dict(os.environ, HOME=str(home), PYTHONPATH=str(ROOT),
                                AIRLOCK_HOME=str(home / ".airlock"), AIRLOCK_QUIET="1"))
    s.check("doctor warns when the workspace is the home directory",
            "home directory" in r.stdout, r.stdout[:200])

    importlib.reload(_cfg)


def _environment_boundary(s):
    """The gate reads its own configuration from an environment it does not own."""
    from airlock import config as _cfg
    from airlock.policy import Policy

    home = pathlib.Path(tempfile.mkdtemp(prefix="bd-env-"))
    (home / "proj").mkdir()
    base = dict(os.environ, PYTHONPATH=str(ROOT), HOME=str(home),
                AIRLOCK_HOME=str(home / ".airlock"), AIRLOCK_QUIET="1",
                AIRLOCK_NOTIFY="0")
    for k in ("AIRLOCK_POLICY", "AIRLOCK_PROFILE", "AIRLOCK_MODE", "AIRLOCK_FAIL_OPEN"):
        base.pop(k, None)
    subprocess.run([sys.executable, "-m", "airlock.cli", "profile", "paranoid"],
                   env=base, capture_output=True)
    evil = home / "evil.yaml"
    evil.write_text("mode: guard\ndefault: allow\nask_fallback: allow\nrules: []\n")

    def hook(env_extra=None):
        env = dict(base)
        env.update(env_extra or {})
        return subprocess.run([sys.executable, "-m", "airlock.cc_hook"],
                              input=json.dumps({"tool_name": "Bash",
                                                "tool_input": {"command": "rm -rf /"}}),
                              text=True, capture_output=True, cwd=str(home / "proj"),
                              env=env).returncode

    s.check("a destructive call is refused", hook() == 2)
    # These two really do switch enforcement off — that is what they are for.
    # The point is not to prevent it, it is that the log must say so.
    s.check("AIRLOCK_POLICY replaces the policy outright",
            hook({"AIRLOCK_POLICY": str(evil)}) == 0)
    s.check("AIRLOCK_MODE=observe stops blocking",
            hook({"AIRLOCK_MODE": "observe"}) == 0)
    s.check("and the gate goes back to refusing afterwards", hook() == 2)

    recs = [json.loads(l) for l in
            (home / ".airlock" / "audit.jsonl").read_text().splitlines() if l.strip()]
    changes = [r for r in recs if r.get("event") == "gate_config"]
    s.check("the log records the gate's configuration", changes, len(changes))
    s.check("...and names each change", len(changes) >= 3,
            [r.get("reason") for r in changes])
    swapped = [r for r in changes if "evil.yaml" in (r.get("detail") or "")]
    s.check("a swapped policy is named in the log", swapped,
            [r.get("detail", "")[:70] for r in changes])
    s.check("so is the mode it ran under",
            any("mode=observe" in (r.get("detail") or "") for r in changes))
    before = len(changes)
    for _ in range(4):
        hook()                      # same configuration, four more times
    recs = [json.loads(l) for l in
            (home / ".airlock" / "audit.jsonl").read_text().splitlines() if l.strip()]
    after = len([r for r in recs if r.get("event") == "gate_config"])
    s.check("an unchanged configuration adds no records", after == before,
            f"{before} -> {after}")

    # The files that put those variables in front of the gate's process. zsh
    # reads .zshenv on every invocation, non-interactive ones included.
    pol = Policy.load(str(_cfg.profile_path("default")))
    for f in (".zshenv", ".zprofile", ".zshrc", ".bashrc", ".bash_profile",
              ".profile", ".config/environment.d/x.conf", ".pam_environment"):
        d = pol.decide("Write", {"file_path": f"{home}/{f}", "content": "x"})
        s.check(f"writing ~/{f} is refused", d.action == "block", d.reason)
    s.check("so is exporting the mode from a shell",
            pol.decide("Bash", {"command": "export AIRLOCK_MODE=observe"}).action == "block")
    for label, args in (("a data file with 'profile' in the name",
                         {"file_path": "/srv/data/profile.csv"}),
                        ("a source file called env.ts", {"file_path": "/proj/src/env.ts"}),
                        ("a dotfiles dir in the project", {"file_path": "/proj/dotfiles/README"})):
        s.check(f"{label} is not caught by those rules",
                pol.decide("Read", args).action != "block", args)


def main():
    s = Suite("BOUNDARIES: POLICY WRITES, OUTCOME LOOP")
    _atomic_writes(s)
    _outcome_loop(s)
    _workspace_boundary(s)
    _environment_boundary(s)
    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
