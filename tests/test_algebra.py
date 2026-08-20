"""Grants as an algebra, pins and contracts as one state machine.

Both subsystems were tested apart and passed. What they promise together —
"a grant permits exactly what was refused and nothing wider", "forget means
start over" — is a different set of statements, and it is where the gaps were.
"""
import copy, importlib, json, os, pathlib, random, re, subprocess, sys, tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite
from airlock import config
from airlock.policy import Policy, RANK, ALLOW, ASK, BLOCK

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = {n: Policy.load(str(config.profile_path(n))) for n in ("default", "paranoid")}

RES = ["/srv/data/a.csv", "/srv/data/sub/b.csv", "/srv/data/.env", "/srv/other/c.csv",
       "/x/.ssh/id_rsa", "/srv/datafile.csv", "rm -rf /",
       "https://api.github.com/x", "https://evil.example/x"]
TOOLS = ["Read", "Write", "Bash", "WebFetch", "Grep"]
GRANTS = [
    {"tool": "Read", "match": "/srv/data/*", "reason": "g1"},
    {"tool": "*", "match": "/srv/data/*", "reason": "g2"},
    {"tool": "Read", "match": "*", "reason": "g3"},
    {"tool": "Read", "match": "/srv/other/*", "reason": "g4"},
    {"tool": "Bash", "match": "*rm*", "reason": "g5"},
    {"tool": "WebFetch", "match": "*evil*", "reason": "g6"},
]


def _pol(name="paranoid", grants=()):
    p = copy.copy(BASE[name])
    p.rules = list(BASE[name].rules)
    p.grants = [dict(g) for g in grants]
    p.escalate = dict(BASE[name].escalate)
    p._tool_index = {}
    return p


def _field(tool):
    return "command" if tool == "Bash" else ("url" if tool == "WebFetch" else "file_path")


def _verdicts(p):
    return {(t, r): p.decide(t, {_field(t): r}).action for t in TOOLS for r in RES}


def _grant_laws(s):
    rng = random.Random(41)

    bad = None
    for _ in range(120):
        name = rng.choice(["default", "paranoid"])
        have = rng.sample(GRANTS, rng.randint(0, 3))
        a = _verdicts(_pol(name, have))
        b = _verdicts(_pol(name, have + [rng.choice(GRANTS)]))
        worse = [k for k in a if RANK[b[k]] > RANK[a[k]]]
        if worse:
            bad = f"{worse[0]}: {a[worse[0]]} -> {b[worse[0]]}"
            break
    s.check("adding a grant never tightens a decision", bad is None, bad)

    bad = None
    for _ in range(120):
        name = rng.choice(["default", "paranoid"])
        g = rng.choice(GRANTS)
        base, with_g = _verdicts(_pol(name)), _verdicts(_pol(name, [g]))
        lifted = [k for k, v in base.items() if v == BLOCK and with_g[k] != BLOCK]
        if lifted:
            bad = f"{lifted[0]} lifted by {g}"
            break
    s.check("no grant lifts an absolute block", bad is None, bad)

    s.check("adding the same grant twice changes nothing",
            all(_verdicts(_pol("paranoid", [g])) == _verdicts(_pol("paranoid", [g, g]))
                for g in GRANTS))

    bad = None
    for _ in range(60):
        gs = rng.sample(GRANTS, rng.randint(2, 4))
        shuffled = gs[:]
        rng.shuffle(shuffled)
        if _verdicts(_pol("paranoid", gs)) != _verdicts(_pol("paranoid", shuffled)):
            bad = [g["reason"] for g in gs]
            break
    s.check("the order of grants changes no verdict", bad is None, bad)

    s.check("an expired grant is indistinguishable from none",
            all(_verdicts(_pol("paranoid", [dict(g, expires="2000-01-01")]))
                == _verdicts(_pol("paranoid")) for g in GRANTS))
    s.check("a future-dated grant behaves like an undated one",
            all(_verdicts(_pol("paranoid", [dict(g, expires="2999-01-01")]))
                == _verdicts(_pol("paranoid", [g])) for g in GRANTS))

    g = {"tool": "Read", "match": "/srv/data/*", "reason": "scoped"}
    base, with_g = _verdicts(_pol("paranoid")), _verdicts(_pol("paranoid", [g]))
    stray = [(t, r) for (t, r), v in with_g.items()
             if v != base[(t, r)] and not (t == "Read" and r.startswith("/srv/data/"))]
    s.check("a scoped grant only changes what it names", not stray, stray[:3])

    bad = None
    for _ in range(60):
        a, b = rng.sample(GRANTS, 2)
        va, vb = _verdicts(_pol("paranoid", [a])), _verdicts(_pol("paranoid", [b]))
        vab = _verdicts(_pol("paranoid", [a, b]))
        off = [k for k in vab if RANK[vab[k]] != min(RANK[va[k]], RANK[vb[k]])]
        if off:
            bad = f"{off[0]}: a={va[off[0]]} b={vb[off[0]]} both={vab[off[0]]}"
            break
    s.check("two grants allow exactly the union of each alone", bad is None, bad)


def _grant_end_to_end(s):
    """The same laws through `airlock allow`, where the grant is written for us."""
    def new():
        h = pathlib.Path(tempfile.mkdtemp(prefix="alg-"))
        (h / "proj").mkdir()
        e = dict(os.environ, HOME=str(h), AIRLOCK_HOME=str(h / ".airlock"),
                 PYTHONPATH=str(ROOT), AIRLOCK_QUIET="1", AIRLOCK_NOTIFY="0", TERM="xterm")
        e.pop("AIRLOCK_POLICY", None)
        e.pop("AIRLOCK_PROFILE", None)
        subprocess.run([sys.executable, "-m", "airlock.cli", "profile", "paranoid"],
                       env=e, capture_output=True)
        return h, e

    def cli(e, *args):
        return subprocess.run([sys.executable, "-m", "airlock.cli", *args],
                              env=e, capture_output=True, text=True)

    def hook(e, tool, args):
        subprocess.run([sys.executable, "-m", "airlock.cc_hook"],
                       input=json.dumps({"tool_name": tool, "tool_input": args}),
                       text=True, capture_output=True, env=e)

    def check(e, path):
        r = cli(e, "check", "Read", json.dumps({"file_path": path}))
        for line in r.stdout.splitlines():
            if "effect" in line:
                return re.sub(r"\x1b\[[0-9;]*m", "", line).split()[1]
        return "?"

    PROBE = ["/srv/data/f1.csv", "/srv/data/f2.csv", "/srv/data/sub/deep.csv",
             "/srv/other/x.csv", "/srv/datafile.csv", "/srv/data/.env"]

    h, e = new()
    before = {p: check(e, p) for p in PROBE}
    for p in ("/srv/data/f1.csv", "/srv/data/f2.csv"):
        hook(e, "Read", {"file_path": p})
    cli(e, "allow", "last")
    after = {p: check(e, p) for p in PROBE}
    import yaml
    written = (yaml.safe_load((h / ".airlock" / "policy.yaml").read_text()) or {}).get("grants") or []
    s.check("repeated refusals fold into one grant", len(written) == 1, written)
    s.check("the refused calls are permitted afterwards",
            after["/srv/data/f1.csv"] == "ALLOW" and after["/srv/data/f2.csv"] == "ALLOW",
            after)
    changed = [p for p in PROBE if after[p] != before[p]]
    s.check("nothing outside the folded directory changed",
            all(p.startswith("/srv/data/") for p in changed), changed)
    s.check("an absolute block inside the granted directory still holds",
            after["/srv/data/.env"] == "BLOCK", after["/srv/data/.env"])
    s.check("a prefix-sharing sibling is untouched",
            after["/srv/datafile.csv"] == before["/srv/datafile.csv"])

    r = cli(e, "allow", "revoke", "0", "-y")
    s.check("revoking restores every verdict", {p: check(e, p) for p in PROBE} == before)
    s.check("revoking a real grant reports success", r.returncode == 0, r.returncode)
    s.check("revoking a grant that is not there reports failure",
            cli(e, "allow", "revoke", "9", "-y").returncode == 1)
    s.check("revoking something that is not a number is a usage error",
            cli(e, "allow", "revoke", "abc", "-y").returncode == 2)

    h, e = new()
    hook(e, "Read", {"file_path": "/x/.ssh/id_rsa"})
    out = cli(e, "allow", "last").stdout
    s.check("allow refuses a grant that would do nothing", "refused" in out, out[-160:])

    h, e = new()
    hook(e, "Read", {"file_path": "/srv/data/f1.csv"})
    cli(e, "allow", "last", "--match", "/srv/data/f1.csv")
    s.check("an explicit --match grants that file only",
            check(e, "/srv/data/f1.csv") == "ALLOW" and check(e, "/srv/data/f2.csv") != "ALLOW",
            (check(e, "/srv/data/f1.csv"), check(e, "/srv/data/f2.csv")))


TOOLSETS = {"A": [{"name": "read_note", "description": "Read a note."}],
            "B": [{"name": "read_note", "description": "Read a note."},
                  {"name": "run_command", "description": "Run a command."}],
            "C": [{"name": "fetch_url", "description": "Fetch."}]}
CALLS = [("read_note", {"name": "/srv/notes/a.md"}),
         ("read_note", {"name": "/etc/passwd"}),
         ("run_command", {"command": "ls"}),
         ("fetch_url", {"url": "https://example.com/x"})]


def _joint_machine(s):
    saved = os.environ.get("AIRLOCK_HOME")
    rng = random.Random(61)
    bad = {}
    try:
        for _ in range(25):
            h = pathlib.Path(tempfile.mkdtemp(prefix="alg-j-"))
            os.environ["AIRLOCK_HOME"] = str(h)
            from airlock import pins, contracts
            importlib.reload(pins)
            importlib.reload(contracts)
            pol = Policy.load(str(config.profile_path("default")))
            pinned = held = pending = None
            held = False

            def verdict(tool, args):
                if pins.is_held("s")[0]:
                    return "block"
                d = pol.decide(f"mcp__s__{tool}", args)
                ct = contracts.get("s")
                if ct and ct.enforced:
                    act, _why = ct.check(tool, args)
                    if RANK[act] > RANK[d.action]:
                        d = type(d)(act, "contract", -1)
                return pol.posture(d).action

            for _ in range(10):
                op = rng.choice(["see", "see", "see", "call", "observe", "promote",
                                 "approve", "reject", "forget"])
                if op == "see":
                    key = rng.choice(list(TOOLSETS))
                    status, _ = pins.check_toolset("s", TOOLSETS[key], [])
                    contracts.ensure_default("s", [t["name"] for t in TOOLSETS[key]])
                    if pinned is None:
                        pinned, held, pending = key, False, None
                        expect = "new"
                    elif key == pinned:
                        held, pending = False, None
                        expect = "unchanged"
                    elif held and key == pending:
                        expect = "held"
                    else:
                        pending, held = key, True
                        expect = "changed"
                    if status != expect:
                        bad.setdefault("pin status", f"{status} vs {expect}")
                elif op == "approve":
                    pins.approve("s")
                    if held:
                        pinned, held, pending = pending, False, None
                elif op == "reject":
                    pins.reject("s")
                elif op == "forget":
                    pins.forget("s")
                    pinned, held, pending = None, False, None
                elif op == "observe":
                    t, a = rng.choice(CALLS)
                    contracts.observe("s", t, a)
                elif op == "promote":
                    contracts.promote("s")
                else:
                    t, a = rng.choice(CALLS)
                    v = verdict(t, a)
                    if held and v != "block":
                        bad.setdefault("held blocks everything", f"{t} -> {v}")
                    ct = contracts.get("s")
                    if ct and ct.enforced and not held:
                        bare = pol.posture(pol.decide(f"mcp__s__{t}", a)).action
                        if RANK[v] < RANK[bare]:
                            bad.setdefault("contract only tightens", f"{bare} -> {v}")
                        if v == "allow" and ct.tools is not None and t not in ct.tools:
                            bad.setdefault("contract never allows an outside tool", t)

            contracts.observe("s", "read_note", {"name": "/srv/notes/a.md"})
            contracts.promote("s")
            ct = contracts.get("s")
            obs = (contracts._load().get("s") or {}).get("_observed") or {}
            if ct and ct.enforced and obs:
                if not set(ct.tools or []) <= set(obs.get("tools") or []):
                    bad.setdefault("promotion keeps only observed tools", ct.tools)
                if ct.shell and not obs.get("shell"):
                    bad.setdefault("promotion does not invent shell", True)
                if not set(ct.net or []) <= set(obs.get("net") or []):
                    bad.setdefault("promotion does not invent hosts", ct.net)

        for key, label in (("pin status", "pin status matches the model at every step"),
                           ("held blocks everything", "while a toolset is held, every call is blocked"),
                           ("contract only tightens", "an enforced contract only tightens"),
                           ("contract never allows an outside tool",
                            "an enforced contract never allows a tool outside it"),
                           ("promotion keeps only observed tools",
                            "promotion keeps only what was observed"),
                           ("promotion does not invent shell", "promotion does not invent shell access"),
                           ("promotion does not invent hosts", "promotion does not invent hosts")):
            s.check(label, key not in bad, bad.get(key))

        # `forget` means start over — and used to reset only half of it: the pin
        # went, the contract stayed enforced, and the next, different toolset was
        # refused tool by tool while `pins list` showed a healthy new pin.
        h = pathlib.Path(tempfile.mkdtemp(prefix="alg-f-"))
        os.environ["AIRLOCK_HOME"] = str(h)
        from airlock import pins, contracts
        importlib.reload(pins)
        importlib.reload(contracts)
        pins.check_toolset("s", TOOLSETS["A"], [])
        contracts.ensure_default("s", ["read_note"])
        contracts.observe("s", "read_note", {"name": "/srv/notes/a.md"})
        contracts.promote("s")
        s.check("a promoted contract is enforced", contracts.get("s").enforced)
        msg = pins.forget("s")
        s.check("forget says the contract stopped applying too",
                "contract" in msg, msg)
        s.check("the contract is no longer enforced", not contracts.get("s").enforced)
        s.check("but it is still on disk for review",
                contracts.get("s").tools == ["read_note"], contracts.get("s").tools)
        status, _ = pins.check_toolset("s", TOOLSETS["C"], [])
        contracts.ensure_default("s", ["fetch_url"])
        s.check("the new toolset is TOFU'd as new", status == "new", status)
        s.check("...and its tools are not refused by the old contract",
                not pins.is_held("s")[0] and not contracts.get("s").enforced)
    finally:
        if saved is None:
            os.environ.pop("AIRLOCK_HOME", None)
        else:
            os.environ["AIRLOCK_HOME"] = saved
        from airlock import pins, contracts
        importlib.reload(pins)
        importlib.reload(contracts)


def main():
    s = Suite("GRANT ALGEBRA AND ADMISSION STATE")
    _grant_laws(s)
    _grant_end_to_end(s)
    _joint_machine(s)
    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
