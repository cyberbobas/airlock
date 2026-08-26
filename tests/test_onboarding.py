"""Onboarding surface: `airlock policy propose` and `airlock monitor`.

propose has to be *safe* to trust — it must derive allows only from calls that
were actually allowed and clean, and never quietly whitelist a blocked or
flagged one. monitor just has to render what happened without choking.
"""
import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import Suite


def _fresh_home():
    h = Path(tempfile.mkdtemp(prefix="airlock-onb-"))
    os.environ["AIRLOCK_HOME"] = str(h)
    os.environ["AIRLOCK_QUIET"] = "1"
    os.environ["AIRLOCK_NOTIFY"] = "0"
    return h


def _seed_audit():
    from airlock import audit
    # four Read calls under one dir → should collapse to one glob
    for i in range(4):
        audit.record("decision", source="hook", tool="Read", decision="allow",
                     effective="allow", reason="ok",
                     resource=f"/home/user/proj/src/f{i}.py")
    # a second dir, a net host, a shell command
    audit.record("decision", source="hook", tool="Read", decision="allow",
                 effective="allow", reason="ok", resource="/home/user/proj/docs/x.md")
    audit.record("decision", source="mcp", server="fetch", tool="mcp__fetch__get",
                 decision="allow", effective="allow", reason="ok",
                 resource="https://api.github.com/repos/o/r")
    # the shape the gate ACTUALLY records for a net call: a bare host, no scheme
    audit.record("decision", source="hook", tool="WebSearch", decision="allow",
                 effective="allow", reason="ok", resource="docs.python.org")
    audit.record("decision", source="hook", tool="Bash", decision="allow",
                 effective="allow", reason="ok", resource="npm test")
    # must NOT be proposed: a hard block, and a high-flagged allow
    audit.record("decision", source="hook", tool="Read", decision="block",
                 effective="block", reason="secret", resource="/home/user/.ssh/id_rsa")
    audit.record("decision", source="hook", tool="WebFetch", decision="allow",
                 effective="allow", reason="ok", resource="https://evil.example",
                 flags=[{"id": "exfil.collector", "severity": "high"}])


def main():
    s = Suite("ONBOARDING")

    # ---- policy propose --------------------------------------------------
    _fresh_home()
    _seed_audit()
    from airlock import propose, config
    prop = propose.build(days=3650)

    grants = {(g["tool"], g.get("match")) for g in prop.grants}
    s.check("collapses many files under a dir into one glob",
            ("Read", "/home/user/proj/src/*") in grants, sorted(grants))
    s.check("keeps a distinct directory as its own grant",
            ("Read", "/home/user/proj/docs/*") in grants, sorted(grants))
    s.check("proposes an egress host grant",
            ("mcp__fetch__get", "*api.github.com*") in grants, sorted(grants))
    s.check("proposes a grant from a bare host (what the gate really records)",
            ("WebSearch", "*docs.python.org*") in grants, sorted(grants))
    s.check("proposes a shell tool (match=None) for review",
            ("Bash", None) in grants, sorted(grants))

    tools_proposed = {g["tool"] for g in prop.grants}
    s.check("never proposes a tool that was only ever blocked",
            "Read" in tools_proposed and prop.gated.get("Read", 0) == 1
            and all(m != "/home/user/.ssh/*" for _, m in grants),
            (prop.gated, sorted(grants)))
    s.check("never whitelists a high-severity-flagged call",
            "WebFetch" not in tools_proposed and prop.risky.get("WebFetch") == 1,
            (tools_proposed, dict(prop.risky)))

    y = propose.to_yaml(prop)
    s.check("renders reviewable YAML with a header",
            y.startswith("#") and "grants:" in y, y[:80])

    # min_count filters one-off tools
    prop2 = propose.build(days=3650, min_count=2)
    s.check("min-count drops tools seen fewer than N times",
            "mcp__fetch__get" not in {g["tool"] for g in prop2.grants}
            and "Read" in {g["tool"] for g in prop2.grants},
            {g["tool"] for g in prop2.grants})

    # apply writes the grants into a real policy file
    polfile = config.home() / "policy.yaml"
    polfile.write_text("mode: guard\ndefault: ask\nrules: []\ngrants: []\n")
    os.environ["AIRLOCK_POLICY"] = str(polfile)
    from airlock.policy import Policy
    shell_grants = sum(1 for g in prop.grants if "match" not in g)
    added, skipped, held = propose.apply(Policy.resolve(), prop)
    written = polfile.read_text()
    s.check("apply writes the scoped grants to the policy",
            added == len(prop.grants) - shell_grants and "api.github.com" in written,
            (added, skipped, held))
    s.check("apply holds back bare shell grants by default",
            held == shell_grants and shell_grants >= 1 and "Bash" not in written,
            (held, shell_grants))
    # --include-shell writes them too
    added_sh, _, held_sh = propose.apply(Policy.resolve(), prop, include_shell=True)
    s.check("--include-shell writes the shell grants",
            held_sh == 0 and "Bash" in polfile.read_text(), (added_sh, held_sh))
    # second apply is idempotent
    added2, _, _ = propose.apply(Policy.resolve(), propose.build(days=3650),
                                 include_shell=True)
    s.check("apply is idempotent (no duplicate grants)", added2 == 0, added2)
    os.environ.pop("AIRLOCK_POLICY", None)

    # empty log → honest empty proposal, no crash
    _fresh_home()
    empty = propose.build(days=3650)
    s.check("an empty audit log proposes nothing, cleanly",
            empty.grants == [] and empty.allowed == 0, empty)

    # ---- monitor ---------------------------------------------------------
    _fresh_home()
    _seed_audit()
    from airlock import monitor
    buf = io.StringIO()
    rc = monitor.run(once=True, out=buf)
    frame = buf.getvalue()
    s.check("monitor renders a single frame and returns 0", rc == 0 and frame, rc)
    s.check("monitor tallies allow/ask/block",
            "AIRLOCK MONITOR" in frame and "allow" in frame and "block" in frame,
            frame[:120])
    s.check("monitor shows the most recent tool and target",
            "Bash" in frame and "api.github.com" in frame, frame[-400:])

    # a monitor over a missing log must not throw
    _fresh_home()
    (config.home() / "audit.jsonl").unlink(missing_ok=True)
    buf2 = io.StringIO()
    s.check("monitor over an empty log renders without error",
            monitor.run(once=True, out=buf2) == 0 and "AIRLOCK MONITOR" in buf2.getvalue(),
            buf2.getvalue()[:80])

    # rotation renames the live file: records appended just before the rename
    # must still reach the counters (a path-offset tail loses them), and the
    # renamed file's already-counted records must not be counted twice
    import json as _json
    from collections import Counter, deque
    from airlock.monitor import _Tail
    _fresh_home()
    live = config.home() / "audit.jsonl"
    def _rec(i):
        return _json.dumps({"event": "decision", "source": "hook", "tool": "Read",
                            "decision": "allow", "effective": "allow", "reason": "ok",
                            "resource": f"/w/f{i}.txt", "h": f"dig{i:04d}"}) + "\n"
    live.write_text(_rec(1))
    t = _Tail(live)
    c, dq = Counter(), deque()
    t.ingest(c, dq)
    with open(live, "a", encoding="utf-8") as f:
        f.write(_rec(2))                       # lands before the rotation
    os.replace(live, live.with_name("audit-rotated.jsonl"))
    live.write_text(_rec(3))                   # the new live segment
    t.ingest(c, dq)
    s.check("monitor survives rotation without losing records",
            c["allow"] == 3, (dict(c), len(dq)))
    # a second rotation inside the same interval: the middle segment must not
    # vanish from the counters either
    with open(live, "a", encoding="utf-8") as f:
        f.write(_rec(4))
    os.replace(live, live.with_name("audit-rotated2.jsonl"))
    live.write_text(_rec(5))
    t.ingest(c, dq)
    s.check("two rotations in one interval lose nothing and count nothing twice",
            c["allow"] == 5, (dict(c), len(dq)))
    # truncation in place: the offset restarts, and a record that reappears is
    # deduplicated rather than counted again
    live.write_text("")
    t.ingest(c, dq)
    live.write_text(_rec(5))                   # the same record comes back
    t.ingest(c, dq)
    s.check("a truncated live file re-reads without double-counting",
            c["allow"] == 5, (dict(c), len(dq)))

    # ---- demo ------------------------------------------------------------
    # The pip-installed first impression: it must run self-contained (bundled
    # skill + server, no repo checkout) and actually block the exfil calls.
    import subprocess
    demo_home = Path(tempfile.mkdtemp(prefix="airlock-demo-t-"))
    r = subprocess.run(
        [sys.executable, "-m", "airlock.cli", "demo", "--no-color"],
        env=dict(os.environ, AIRLOCK_HOME=str(demo_home), AIRLOCK_NOTIFY="0",
                 PYTHONPATH=str(Path(__file__).resolve().parents[1])),
        capture_output=True, text=True)
    s.check("airlock demo runs self-contained and exits 0",
            r.returncode == 0, r.stderr[-300:])
    s.check("airlock demo blocks the exfil calls and verifies the chain",
            "BLOCK" in r.stdout and "CHAIN INTACT" in r.stdout, r.stdout[-300:])

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
