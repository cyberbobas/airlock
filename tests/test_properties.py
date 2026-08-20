"""Invariants the engine claims, checked over random policies and arguments.

Case-by-case tests ask "is this input handled right". These ask "is the rule
true at all" — and that is what caught an extra argument turning an `ask` into
an `allow`, and a percent-encoded path that survived two rounds of decoding but
not three. Both were shapes nobody would have thought to write down as a case.
"""
import copy, pathlib, random, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite
from airlock import config
from airlock.policy import Policy, RANK, ALLOW, ASK, BLOCK, normalize

FRAG = ["/x/.ssh/id_rsa", "/srv/data/a.csv", "rm -rf /", "webhook.site/x", "ok",
        ".env", "/tmp/x", "a b", "%2e", "..", "", "Z" * 40, "/x/.aws/credentials",
        "http://169.254.169.254/", "npx mcp-server-time", "hello world"]
TOOLS = ["Read", "Write", "Bash", "WebFetch", "Grep", "mcp__s__read_note",
         "mcp__s__run_command", "READ", "bash", "weird_tool"]
PROFILES = ("default", "paranoid", "yolo")


def _args(rng):
    d = {}
    for i in range(rng.randint(0, 4)):
        v = rng.choice(FRAG)
        r = rng.random()
        d[f"k{i}"] = {"nested": v} if r < 0.2 else ([v] if r < 0.4 else v)
    if rng.random() < 0.6:
        d["file_path" if rng.random() < 0.5 else "command"] = rng.choice(FRAG)
    return d


_BASE = {}


def _policy(rng):
    # Loading a profile means parsing YAML off disk; doing that once per case
    # made this suite take two minutes, and a suite that slow stops being run.
    name = rng.choice(PROFILES)
    if name not in _BASE:
        _BASE[name] = Policy.load(str(config.profile_path(name)))
    p = copy.copy(_BASE[name])
    p.rules = list(_BASE[name].rules)
    p.grants = []
    p.escalate = dict(_BASE[name].escalate)
    for _ in range(rng.randint(0, 4)):
        rule = {"tool": rng.choice(["*", "Read", "*sh*", "mcp__*__*"]),
                "action": rng.choice([ALLOW, ASK, BLOCK]), "reason": "fuzz"}
        m = rng.choice(["*", "*ok*", "*x*", None, "*data*"])
        if m is not None:
            rule["match"] = m
        p.rules.insert(rng.randrange(len(p.rules) + 1), rule)
    p._tool_index = {}
    return p


def main():
    s = Suite("ENGINE INVARIANTS")
    rng = random.Random(7)
    N = 1500

    bad = None
    for _ in range(N):
        pol, tool, args = _policy(rng), rng.choice(TOOLS), _args(rng)
        d0 = pol.decide(tool, args)
        more = dict(args)
        more[f"extra{rng.randint(0, 99)}"] = rng.choice(FRAG)
        d1 = pol.decide(tool, more)
        if RANK[d1.action] < RANK[d0.action]:
            bad = f"{tool} {args} -> {d0.action}; with one more argument -> {d1.action}"
            break
    s.check("an extra argument can tighten a decision, never loosen it", bad is None, bad)

    bad = None
    for _ in range(N):
        pol, tool, args = _policy(rng), rng.choice(TOOLS), _args(rng)
        pol.grants = []
        if pol.decide(tool, args).action != BLOCK:
            continue
        pol.grants = [{"tool": "*", "match": "*", "reason": "fuzz"}]
        if pol.decide(tool, args).action != BLOCK:
            bad = f"{tool} {args}"
            break
    s.check("no grant lifts a block", bad is None, bad)

    bad = None
    for _ in range(N):
        base, over = _policy(rng), _policy(rng)
        tool, args = rng.choice(TOOLS), _args(rng)
        d_base = base.decide(tool, args)
        merged = copy.deepcopy(base)
        over.grants = []
        merged.overlay = over
        d_merged = merged.decide(tool, args)
        if RANK[d_merged.action] < RANK[d_base.action]:
            bad = f"{tool} {args}: base={d_base.action} with overlay={d_merged.action}"
            break
    s.check("a project overlay never loosens", bad is None, bad)

    bad = None
    for _ in range(N):
        pol, tool, args = _policy(rng), rng.choice(TOOLS), _args(rng)
        d = pol.decide(tool, args)
        for sev in ("low", "med", "high"):
            if RANK[pol.apply_flags(d, [{"id": "x", "severity": sev}]).action] < RANK[d.action]:
                bad = f"{sev} flag loosened {d.action}"
                break
        if bad:
            break
    s.check("a scan flag never loosens", bad is None, bad)

    bad = None
    for _ in range(N):
        pol, tool, args = _policy(rng), rng.choice(TOOLS), _args(rng)
        d = pol.decide(tool, args)
        got = {}
        for mode in ("observe", "guard", "enforce"):
            pol.mode = mode
            got[mode] = pol.posture(d).action
        if not (RANK[got["observe"]] <= RANK[got["guard"]] <= RANK[got["enforce"]]):
            bad = str(got)
            break
    s.check("observe <= guard <= enforce, always", bad is None, bad)

    bad = None
    for _ in range(N * 4):
        t = "".join(rng.choice("ab/.%2eé．\\ _-0123456789") for _ in range(rng.randint(0, 16)))
        once = normalize(t)
        if normalize(once) != once:
            bad = f"{t!r} -> {once!r} -> {normalize(once)!r}"
            break
    s.check("normalisation reaches a fixpoint in one pass", bad is None, bad)

    pol = Policy.load(str(config.profile_path("paranoid")))
    for depth in range(1, 8):
        enc = "/x/%" + "25" * (depth - 1) + "2essh/config"
        s.check(f"a secret path encoded {depth} deep is still blocked",
                pol.decide("Read", {"file_path": enc}).action == BLOCK, enc)

    bad = None
    for _ in range(N):
        tool, args = rng.choice(TOOLS), _args(rng)
        a = pol.decide(tool, args).action
        b = pol.decide(tool.swapcase(), args).action
        if a != b:
            bad = f"{tool}: {a} vs {tool.swapcase()}: {b}"
            break
    s.check("the case of a tool name does not change the verdict", bad is None, bad)

    # A rule scoped to a resource cannot vouch for a call whose resource was
    # never identified: the "primary" is then the whole argument blob, and any
    # unrelated argument can satisfy the glob.
    loose = Policy.load(str(config.profile_path("paranoid")))
    loose.rules.insert(0, {"tool": "*", "match": "*safe-dir*", "action": ALLOW,
                           "reason": "user rule"})
    loose._tool_index = {}
    s.check("a resource-scoped allow still works on a real resource",
            loose.decide("Read", {"file_path": "/safe-dir/a"}).action == ALLOW)
    s.check("...but not on a resource nobody could name",
            loose.decide("Read", {"note": "/safe-dir/a", "x": "/etc/shadow"}).action != ALLOW)
    s.check("a tool-scoped allow is unaffected",
            Policy.load(str(config.profile_path("default"))).decide("Grep", {}).action == ALLOW)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
