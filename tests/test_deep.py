"""Regressions from deep testing — concurrency, fuzzing, failure injection.

Four defects, all in behaviour that only appears under conditions a hand-driven
test never creates: two processes rotating a log at the same moment, an argument
object bigger than the inspection budget, a policy file truncated to nothing,
and a secret directory referenced without a trailing path component.
"""
import importlib, json, os, subprocess, sys, tempfile, time
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

    return s.report()


def _json_ok(line):
    try:
        json.loads(line)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
