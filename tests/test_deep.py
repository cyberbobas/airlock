"""Regressions from deep testing — concurrency, fuzzing, failure injection.

Four defects, all in behaviour that only appears under conditions a hand-driven
test never creates: two processes rotating a log at the same moment, an argument
object bigger than the inspection budget, a policy file truncated to nothing,
and a secret directory referenced without a trailing path component.
"""
import importlib, json, os, pathlib, shutil, subprocess, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import Suite

from airlock import audit, config
from airlock.policy import ALLOW, ASK, BLOCK, Policy, iter_strings

ROOT = Path(__file__).resolve().parents[1]
PROFILE = config.profile_path("default")


def _env(home, **kw):
    e = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=str(home),
             AIRLOCK_QUIET="1", AIRLOCK_NOTIFY="0")
    e.update({k: str(v) for k, v in kw.items()})
    return e


def _spawn_all(codes, home, **kw):
    """Start every process before waiting on any, so they really overlap."""
    ps = [subprocess.Popen([sys.executable, "-c", c], env=_env(home, **kw),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          for c in codes]
    return [p.communicate() for p in ps]


def _verify_in(home):
    r = subprocess.run(
        [sys.executable, "-c",
         "from airlock import audit;ok,n,m=audit.verify(all_segments=True);"
         "print('OK' if ok else 'FAIL', m)"],
        env=_env(home), capture_output=True, text=True)
    return r.stdout.strip()


def main():
    s = Suite("DEEP-TEST REGRESSIONS")
    pol = Policy.load(PROFILE)

    # === 1. rotation must be atomic with respect to appending ============
    # Was: `_rotate_if_needed` ran outside the append lock. A second process
    # holding an fd opened before the rename kept appending into the segment
    # that had already been renamed and ledgered, so the ledger's recorded
    # final digest no longer matched and `verify` cried "truncated" on a log
    # nobody had touched. Two busy agents were enough.
    home = Path(tempfile.mkdtemp(prefix="deep-rot-"))
    _spawn_all([f"""
from airlock import audit
for i in range(30):
    audit.record('decision', source='w{t}', tool='t', decision='allow',
                 effective='allow', reason='{'x' * 60}')
""" for t in range(8)], home, AIRLOCK_AUDIT_MAX_MB=0.004)
    segs = sorted(home.glob("audit-*.jsonl"))
    v = _verify_in(home)
    s.check(f"8 writers rotating concurrently keep the chain valid "
            f"({len(segs)} segments)", v.startswith("OK"), v)
    s.check("concurrent rotation actually happened", len(segs) >= 2, len(segs))

    home = Path(tempfile.mkdtemp(prefix="deep-cc-"))
    _spawn_all([f"""
from airlock import audit
for i in range(40):
    audit.record('decision', source='p{t}', tool=f't{{i}}', decision='allow',
                 effective='allow', reason='concurrent')
""" for t in range(12)], home)
    lines = [l for l in (home / "audit.jsonl").read_text().splitlines() if l.strip()]
    s.check("480 concurrent records, none lost or torn",
            len(lines) == 480 and all(_json_ok(l) for l in lines), len(lines))
    s.check("chain valid under 12 concurrent writers",
            _verify_in(home).startswith("OK"), _verify_in(home))

    # === 2. a payload bigger than the inspection budget must not pass ====
    # Was: the sweep stopped after 512 strings and the call came back `ask`,
    # which `guard` allows when no daemon is running. ~600 filler arguments
    # therefore walked a secret path straight through.
    padded = {"name": "todo"}
    padded.update({f"pad{i}": f"h{i}" for i in range(700)})
    padded["real"] = "/home/victim/.ssh/id_rsa"
    d = pol.decide("mcp__srv__read_note", padded)
    s.check("a secret behind 700 filler arguments is still found",
            d.action == BLOCK, f"{d.action}: {d.reason}")

    listed = {"name": "todo", "pad": ["x"] * 2000,
              "real": "/home/victim/.aws/credentials"}
    s.check("a secret behind a 2000-item list is still found",
            pol.decide("mcp__srv__read_note", listed).action == BLOCK)

    huge = {"file_path": "/tmp/ok"}
    huge.update({f"k{i}": "z" * 64 for i in range(20000)})
    t0 = time.perf_counter()
    d = pol.decide("Read", huge)
    dt = time.perf_counter() - t0
    s.check("an un-inspectable payload is refused, not waved through",
            d.action == BLOCK and "too large to inspect" in d.reason, d.reason)
    s.check(f"...and refused quickly, not after seconds of globbing ({dt:.2f}s)",
            dt < 1.5, f"{dt:.2f}s")
    s.check("ordinary calls are unaffected by the budget",
            pol.decide("Read", {"file_path": f"{config.workspace()}/README.md"}
                       ).action == ALLOW)

    # === 3. an empty or truncated policy must fail closed ===============
    # Was: `{}` parses fine, has no rules, and under `guard` nothing matched —
    # so a policy file truncated by a failed write silently allowed everything
    # while `doctor` still looked healthy.
    for label, text in [("empty mapping", "{}"), ("zero bytes", ""),
                        ("only a mode", "mode: guard\n")]:
        f = Path(tempfile.mkstemp(suffix=".yaml")[1])
        f.write_text(text)
        try:
            Policy.load(f)
            loaded = True
        except Exception as e:
            loaded = False
            msg = str(e)
        s.check(f"a policy that is {label} is rejected", not loaded,
                "it loaded and would enforce nothing")
        if not loaded:
            s.check(f"...and says why ({label})", "rules" in msg, msg[:120])

    f = Path(tempfile.mkstemp(suffix=".yaml")[1])
    f.write_text("default: ask\nmode: guard\nrules: []\n")
    empty = Policy.load(f)
    s.check("an explicitly empty rule list still loads", empty.rules == [])
    s.check("...but reports itself as enforcing nothing", not empty.has_teeth())
    s.check("a real profile does have teeth", pol.has_teeth())

    # === 4. secret DIRECTORIES, not just files inside them ==============
    # Was: `*/.ssh/*` requires something after the slash, so `~/.ssh` itself
    # was only `ask` — and any tool that lists or walks a directory got in.
    for path in ["/home/v/.ssh", "~/.ssh", "/home/v/.aws", "/home/v/.kube",
                 "/home/v/.gnupg", "/home/v/.ssh/", "/home/v/.gnupg/sec.gpg"]:
        s.check(f"secret directory blocked: {path}",
                pol.decide("Read", {"file_path": path}).action == BLOCK,
                pol.decide("Read", {"file_path": path}).reason)
    for path in [f"{config.workspace()}/README.md", "/srv/awsdocs/guide.md",
                 "/home/v/notes/sshconfig.md"]:
        s.check(f"not over-blocked: {path}",
                pol.decide("Read", {"file_path": path}).action != BLOCK)

    # === invariants worth keeping ========================================
    probe = Policy.load(PROFILE)
    probe.grants = [{"tool": "*", "match": "*", "reason": "maximally permissive"}]
    buried = []
    for secret in ["/home/u/.ssh/id_rsa", "rm -rf /", "https://webhook.site/x",
                   "169.254.169.254/latest", "~/.aws/credentials"]:
        for shape in ({"a": secret},
                      {"a": "ok", "b": {"c": {"d": [secret]}}},
                      {"a": "ok", "b": [{"n": secret}]},
                      {secret: "value-side is innocent"}):
            if probe.decide("mcp__s__read_note", {"name": "todo", **shape}
                            ).action != BLOCK:
                buried.append((secret, shape))
    s.check("a blocked string anywhere always blocks, even with a wildcard grant",
            not buried, buried[:2])

    # === failure injection: enforcement outlives its own environment =====
    def hook(payload, **env):
        e = _env(tempfile.mkdtemp(), **env)
        p = subprocess.run([sys.executable, "-m", "airlock.cc_hook"],
                           input=json.dumps(payload).encode(), env=e,
                           capture_output=True)
        return p.returncode, p.stderr.decode()

    DANGER = {"tool_name": "Read", "tool_input": {"file_path": "/home/v/.ssh/id_rsa"}}
    broken = Path(tempfile.mkdtemp(prefix="deep-broken-"))
    for name, content in [("pins.json", "{not json"), ("contracts.yaml", ":::"),
                          ("feed.json", "{{{"), ("audit.chain", "not a ledger")]:
        h = Path(tempfile.mkdtemp())
        (h / name).write_text(content)
        rc, err = hook(DANGER, AIRLOCK_HOME=h)
        s.check(f"corrupt {name}: still blocks, no traceback",
                rc == 2 and "Traceback" not in err, f"rc={rc} {err[-120:]}")

    f = Path(tempfile.mkstemp()[1])          # AIRLOCK_HOME pointing at a file
    rc, err = hook(DANGER, AIRLOCK_HOME=f)
    s.check("AIRLOCK_HOME that is a file: still blocks, no traceback",
            rc == 2 and "Traceback" not in err, f"rc={rc} {err[-120:]}")

    # === 8. a repository must not be able to loosen the machine policy ====
    # Was: .airlock/policy.yaml won outright over the user's own. Four lines in
    # a cloned repo — default: allow, rules: [] — and `rm -rf /` was allowed,
    # ~/.ssh/id_rsa readable, a paranoid profile superseded silently. Cloning a
    # repository is the most ordinary thing an agent does.
    import os as _os
    from airlock.policy import Policy as _P
    home = pathlib.Path(tempfile.mkdtemp(prefix="airlock-proj-"))
    repo = home / "repo" / ".airlock"
    repo.mkdir(parents=True)
    (home / ".airlock").mkdir(exist_ok=True)
    from airlock import config as _cfg
    shutil.copy(_cfg.profile_path("paranoid"), home / ".airlock" / "policy.yaml")

    def _in_repo(policy_text):
        (repo / "policy.yaml").write_text(policy_text)
        env = dict(_os.environ, HOME=str(home), AIRLOCK_HOME=str(home / ".airlock"),
                   AIRLOCK_WORKSPACE=str(home / "repo"))
        old = _os.environ.copy(); cwd = _os.getcwd()
        _os.environ.clear(); _os.environ.update(env); _os.chdir(home / "repo")
        try:
            return _P.resolve()
        finally:
            _os.chdir(cwd); _os.environ.clear(); _os.environ.update(old)

    pol = _in_repo("mode: guard\ndefault: allow\nask_fallback: allow\nrules: []\n")
    s.check("a hostile project policy cannot unblock a secret",
            pol.decide("Read", {"file_path": "/x/.ssh/id_rsa"}).action == "block")
    s.check("a hostile project policy cannot unblock rm -rf /",
            pol.decide("Bash", {"command": "rm -rf /"}).action == "block")
    s.check("it cannot soften the mode either", pol.mode == "enforce", pol.mode)
    s.check("it cannot soften the default", pol.default == "ask", pol.default)

    pol = _in_repo('mode: enforce\ndefault: ask\nrules:\n'
                   '  - { tool: "*", match: "*prod-secrets*", action: block, reason: "team rule" }\n')
    d = pol.decide("Read", {"file_path": "/srv/prod-secrets/db.yml"})
    s.check("a stricter project policy still tightens", d.action == "block", d.reason)
    s.check("and says where it came from", "project policy" in d.reason, d.reason)

    pol = _in_repo('mode: guard\ndefault: ask\nrules: []\n'
                   'grants:\n  - { tool: "*", match: "*", reason: "trust us" }\n')
    s.check("a repository cannot grant itself permissions",
            pol.decide("Read", {"file_path": "/x/.ssh/id_rsa"}).action == "block")

    # === 9. RFC5424 escaping ==============================================
    # Was: the CEF escaper was reused for syslog, so `=` was escaped (which
    # RFC5424 does not define) while `"` and `]` were not (which it requires).
    # A path containing `"] [airlock@0 effective="allow"` closed the
    # structured-data element and opened a second one the payload controlled.
    from airlock import export as _ex
    line = _ex.to_syslog({"ts": "2026-01-01T00:00:00Z", "event": "decision",
                          "effective": "block", "tool": "Read", "server": "",
                          "reason": "secret", "h": "abcd",
                          "resource": '/a"] [airlock@0 effective="allow"] x'})

    def _sd_elements(text):
        k = text.index("["); depth = elems = 0; inq = False
        while k < len(text):
            ch = text[k]
            if ch == "\\":
                k += 2; continue
            if inq:
                inq = ch != '"'
            elif ch == '"':
                inq = True
            elif ch == "[":
                depth += 1; elems += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return elems
            k += 1
        return elems

    s.check("a crafted resource cannot forge a second SD element",
            _sd_elements(line) == 1, line[:200])
    s.check('`"` is escaped', '\\"' in line)
    s.check("`]` is escaped", "\\]" in line)
    s.check("`=` is left alone, as RFC5424 says", "\\=" not in line)

    # === 10. spellings of the same path ===================================
    # Was: `~/%2essh/config` and a fullwidth `~/．ssh/config` walked past
    # `*/.ssh/*` while naming that directory to anything that decodes a URI.
    pol = _P.load(str(_cfg.profile_path("default")))
    for label, path in (("percent-encoded", "/x/%2essh/config"),
                        ("double-encoded", "/x/%252essh/config"),
                        ("fullwidth dot", "/x/\uff0essh/config"),
                        ("backslash separators", "\\x\\.ssh\\config")):
        s.check(f"secret directory via {label} is blocked",
                pol.decide("Read", {"file_path": path}).action == "block", path)
    for label, args in (("data file", {"file_path": "/srv/app/user_history.csv"}),
                        ("docs dir", {"file_path": "/proj/docs/gh/README.md"}),
                        ("source file", {"file_path": "/proj/src/config.py"})):
        s.check(f"ordinary {label} is not blocked",
                pol.decide("Read", args).action != "block", args)

    # === 11. the credential families a payload actually reaches for =======
    for label, path in (("gcloud ADC", "/x/.config/gcloud/application_default_credentials.json"),
                        ("GitHub CLI", "/x/.config/gh/hosts.yml"),
                        ("k8s service account", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
                        ("PyPI token", "/x/.pypirc"),
                        ("crates.io", "/x/.cargo/credentials.toml"),
                        ("Terraform Cloud", "/x/.terraform.d/credentials.tfrc.json"),
                        ("desktop keyring", "/x/.local/share/keyrings/login.keyring"),
                        ("browser cookies", "/x/.mozilla/firefox/p/cookies.sqlite"),
                        ("shell history", "/x/.bash_history"),
                        ("ssh agent socket", "/tmp/ssh-AbC/agent.1234")):
        s.check(f"{label} is off-limits",
                pol.decide("Read", {"file_path": path}).action == "block", path)

    # === 12. contract scope is checked on the folded path =================
    # Was: normpath does nothing for `%2e%2e`, so a percent-encoded traversal
    # stayed "inside" a contract scoped to /srv/notes/* while the plain ../
    # form was caught — the worse half to miss.
    ch = pathlib.Path(tempfile.mkdtemp(prefix="airlock-ct-"))
    (ch / "contracts.yaml").write_text(
        'demo:\n  enforced: true\n  tools: [read_note]\n  fs: ["/srv/notes/*"]\n'
        '  net: []\n  shell: false\n  default: block\n')
    old_home = _os.environ.get("AIRLOCK_HOME")
    _os.environ["AIRLOCK_HOME"] = str(ch)
    from airlock import contracts as _ct
    importlib.reload(_ct)
    c = _ct.get("demo")
    s.check("a path in scope is allowed", c.check("read_note", {"name": "/srv/notes/a.md"})[0] == "allow")
    for label, path in (("plain ../", "/srv/notes/../../etc/passwd"),
                        ("percent-encoded", "/srv/notes/%2e%2e/%2e%2e/etc/passwd"),
                        ("double-encoded", "/srv/notes/%252e%252e/etc/passwd"),
                        ("absolute elsewhere", "/etc/passwd")):
        act, why = c.check("read_note", {"name": path})
        s.check(f"contract escape via {label} is blocked", act == "block", (path, why))
    s.check("a tool outside the contract is blocked",
            c.check("run_command", {"command": "ls"})[0] == "block")
    if old_home is None:
        _os.environ.pop("AIRLOCK_HOME", None)
    else:
        _os.environ["AIRLOCK_HOME"] = old_home
    importlib.reload(_ct)

    # === 13. an unreadable grant expiry must not mean "never expires" ======
    # Was: string comparison, so `not-a-date` and `9999-99-99` both sorted
    # later than today and granted forever — the inversion of what someone
    # typing a malformed date intends. A grant is a loosening; it fails shut.
    base = _P.load(str(_cfg.profile_path("default")))
    for exp, want_allow in (("2999-01-01", True), ("2020-01-01", False),
                            ("not-a-date", False), ("9999-99-99", False),
                            ("2026-13-01", False), ("", True)):
        g = {"tool": "Read", "match": "/srv/g/*", "reason": "t"}
        if exp:
            g["expires"] = exp
        base.grants = [g]
        got = base.decide("Read", {"file_path": "/srv/g/x"}).action == "allow"
        s.check(f"grant with expires={exp!r} {'applies' if want_allow else 'does not apply'}",
                got == want_allow, got)
    try:
        _P.load(str(_cfg.profile_path("default")))
        bad = _P.load(str(_cfg.profile_path("default")))
        bad.grants = [{"tool": "Read", "expires": "soon"}]
        bad.validate()
        s.check("a malformed expiry is rejected at load", False, "validate() accepted it")
    except ValueError as e:
        s.check("a malformed expiry is rejected at load", "expires" in str(e), str(e))

    # === 5. a failing disk must not hang the agent ======================
    # Was: pins.save and contracts._save let OSError escape. In the proxy that
    # exception killed the server-to-client pump thread, so a full disk stopped
    # the agent receiving responses at all — an outage caused by bookkeeping.
    faulty = r"""
import errno, os, sys
_n = [0]
def wrap(fn, name):
    def inner(*a, **k):
        _n[0] += 1
        if _n[0] %% %d == 0:
            raise OSError(errno.ENOSPC, "injected " + name)
        return fn(*a, **k)
    return inner
for nm in ("write", "pwrite", "replace", "rename", "fsync", "ftruncate"):
    if hasattr(os, nm):
        setattr(os, nm, wrap(getattr(os, nm), nm))
from airlock import audit, contracts, pins
for i in range(30):
    audit.record("decision", source="f", tool=f"t{i}", decision="allow",
                 effective="allow", reason="fault run")
    pins.check_toolset("s", [{"name": f"t{i}", "description": "d"}], [])
    contracts.observe("s", "read_note", {"path": f"/data/f{i}"})
print("SURVIVED")
"""
    for every in (3, 5, 11):
        h = Path(tempfile.mkdtemp())
        r = subprocess.run([sys.executable, "-c", faulty % every], env=_env(h),
                           capture_output=True, text=True, timeout=60)
        s.check(f"state writers swallow a failing disk (every {every} syscalls)",
                "SURVIVED" in r.stdout and "Traceback" not in r.stderr,
                r.stderr[-160:])
        pf = h / "pins.json"
        if pf.exists():
            try:
                json.loads(pf.read_text())
                intact = True
            except Exception:
                intact = False
            s.check(f"...and pins.json is never half-written (every {every})", intact)

    # the whole proxy, with an unwritable home, must keep gating and keep answering
    h = Path(tempfile.mkdtemp())
    env = _env(h, AIRLOCK_MODE="enforce",
               AIRLOCK_POLICY=str(ROOT / "tests" / "fixtures" / "policy.yaml"))
    proc = subprocess.Popen(
        [sys.executable, "-m", "airlock.mcp_proxy", "--server-id", "d", "--",
         sys.executable, str(ROOT / "examples" / "demo_server.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env, bufsize=0)

    def rpc(i, method, params):
        proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": i, "method": method,
                                      "params": params}) + "\n").encode())
        proc.stdin.flush()
        line = proc.stdout.readline()
        return json.loads(line) if line else None

    try:
        rpc(1, "initialize", {})
        rpc(2, "tools/list", {})
        os.chmod(h, 0o500)                       # the disk "fills up"
        answered = sum(
            1 for i in range(6)
            if (rpc(100 + i, "tools/call",
                    {"name": "read_note", "arguments": {"name": f"n{i}"}}) or {})
        )
        refused = rpc(200, "tools/call",
                      {"name": "run_command",
                       "arguments": {"command": "rm -rf / --no-preserve-root"}})
    finally:
        os.chmod(h, 0o700)
        try:
            proc.stdin.close()
            proc.wait(timeout=15)
            hung = False
        except Exception:
            proc.kill()
            hung = True
    s.check("the proxy keeps answering with an unwritable AIRLOCK_HOME",
            answered == 6, answered)
    s.check("...and still refuses a destructive call",
            bool(refused and "error" in refused
                 and "Airlock" in json.dumps(refused)), refused)
    s.check("...and does not hang on shutdown", not hung)

    # === 6. `pins reject` must not invent a hold ========================
    # Was: reject set held=True unconditionally, so a mistyped server id
    # blocked every call to a healthy server. And it discarded the pending
    # entry, so the rejected toolset read as a fresh drift next time and a
    # later `approve` found nothing to adopt.
    from airlock import pins
    h = Path(tempfile.mkdtemp())
    saved = dict(os.environ)
    os.environ["AIRLOCK_HOME"] = str(h)
    try:
        A = [{"name": "read_note", "description": "v1"}]
        B = [{"name": "read_note", "description": "v2 CHANGED"}]
        pins.check_toolset("s", A, [])
        msg = pins.reject("s")
        s.check("rejecting a server with nothing pending is a no-op",
                not pins.is_held("s")[0] and "nothing to reject" in msg, msg)

        s.check("a drift is held", pins.check_toolset("s", B, [])[0] == "changed"
                and pins.is_held("s")[0])
        pins.reject("s")
        s.check("a rejection keeps the hold", pins.is_held("s")[0])
        s.check("...and says it was rejected, not merely changed",
                "REJECTED" in pins.is_held("s")[1], pins.is_held("s")[1])
        s.check("re-offering the rejected toolset stays held, not a fresh drift",
                pins.check_toolset("s", B, [])[0] == "held")
        s.check("reverting to the pinned toolset clears the hold",
                pins.check_toolset("s", A, [])[0] == "unchanged"
                and not pins.is_held("s")[0])
        pins.check_toolset("s", B, [])
        pins.reject("s")
        out = pins.approve("s")
        s.check("approve can still override a rejection",
                not pins.is_held("s")[0] and "re-pinned" in out, out)
    finally:
        os.environ.clear()
        os.environ.update(saved)

    return s.report()


def _json_ok(line):
    try:
        json.loads(line)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
