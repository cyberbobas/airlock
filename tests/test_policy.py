"""Policy-engine unit checks: the deny sweep must tighten without loosening,
and a valid policy must not silently half-load."""
import pathlib, sys, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite
from airlock.policy import ALLOW, ASK, BLOCK, Policy, iter_strings

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    s = Suite("POLICY ENGINE")
    p = Policy.load(ROOT / "tests" / "fixtures" / "policy.yaml")

    # the deny sweep must never turn a block/ask into an allow
    ws = str(__import__("airlock.config", fromlist=["config"]).workspace())
    s.check("benign in-workspace read stays ALLOW",
            p.decide("Read", {"file_path": f"{ws}/a.py"}).action == ALLOW)
    s.check("benign note read stays ALLOW",
            p.decide("mcp__d__read_note", {"name": "todo"}).action == ALLOW)
    s.check("allow-listed egress stays ALLOW",
            p.decide("mcp__d__fetch_url", {"url": "https://api.github.com/x"}).action == ALLOW)
    s.check("unknown tool falls to the default (ask)",
            p.decide("mcp__d__whatever", {"x": "y"}).action == ASK)

    # ...and must catch what the primary field hides
    s.check("secret in a secondary arg -> BLOCK",
            p.decide("Read", {"file_path": f"{ws}/a.py",
                              "note": "/home/boba/.ssh/id_rsa"}).action == BLOCK)
    s.check("secret nested three deep -> BLOCK",
            p.decide("Read", {"file_path": "/ok", "a": {"b": [{"c": "~/.aws/credentials"}]}}
                     ).action == BLOCK)

    # bounded traversal: a huge payload must not hang the gate
    deep = {"file_path": f"{ws}/a.py"}
    node = deep
    for i in range(200):
        node["n"] = {"v": f"x{i}"}
        node = node["n"]
    s.check("deeply nested args terminate", isinstance(
        p.decide("Read", deep).action, str))
    s.check("iter_strings is budget-bounded", len(list(iter_strings(deep))) <= 600)

    # escalation only tightens
    d = p.decide("mcp__d__read_note", {"name": "todo"})
    esc = p.apply_flags(d, [{"id": "injection.override", "severity": "high"}])
    s.check("high-severity scan flag escalates allow -> ask", esc.action == ASK)
    blk = p.decide("Read", {"file_path": "/home/boba/.ssh/id_rsa"})
    s.check("escalation never loosens a block",
            p.apply_flags(blk, [{"id": "x", "severity": "low"}]).action == BLOCK)

    # a malformed policy must fail loudly, not half-load
    for bad, why in [("default: maybe\nrules: []\n", "bad default"),
                     ("default: ask\nrules:\n  - {tool: '*', action: nuke}\n", "bad action"),
                     ("- just\n- a\n- list\n", "not a mapping")]:
        f = pathlib.Path(tempfile.mkstemp(suffix=".yaml")[1])
        f.write_text(bad)
        try:
            Policy.load(f)
            ok = False
        except Exception:
            ok = True
        s.check(f"malformed policy rejected ({why})", ok)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
