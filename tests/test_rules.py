"""`airlock rules` — user rule CRUD over the policy YAML, and `airlock status`.

The rules module owns a marked block at the top of the rule list; adding/removing
must keep the policy loadable, preserve the profile's comments, and actually
enforce.
"""
import importlib
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _harness import Suite  # noqa: E402


def _home(tmp):
    os.environ["AIRLOCK_HOME"] = str(tmp)
    from airlock import audit, config
    importlib.reload(config)
    importlib.reload(audit)


def main():
    s = Suite("RULES + STATUS")
    with tempfile.TemporaryDirectory() as d:
        _home(Path(d))
        from airlock import config, rules
        importlib.reload(rules)
        from airlock.policy import Policy

        # seed a user policy from the default profile
        prof = config.profile_path("default")
        up = config.user_policy()
        up.write_text(prof.read_text(encoding="utf-8"), encoding="utf-8")
        before = Policy.load(up)

        ok, _ = rules.add("block", "*ngrok*", reason="no tunnels")
        s.check("add block returns ok", ok)
        ok, _ = rules.add("allow", "*/reports/*", tool="Write")
        s.check("add allow returns ok", ok)
        ok, _ = rules.add("ask", "*deploy*")
        s.check("add ask returns ok", ok)

        L = rules.listing()
        s.check("lists the three user rules", len(L["mine"]) == 3, L["mine"])
        s.check("user rules come first (before profile)",
                len(L["profile"]) == len(before.rules), (len(L["profile"]), len(before.rules)))

        after = Policy.load(up)
        s.check("policy still loads after edits", len(after.rules) == len(before.rules) + 3)
        s.check("profile comments preserved",
                "absolute blocks" in up.read_text(encoding="utf-8"))

        # the block rule actually enforces
        d1 = after.decide("Bash", {"command": "ssh -R 80:x ngrok.io tunnel"})
        s.check("user block rule enforces", d1.action == "block", d1.action)
        # the allow rule wins over the profile's ask for out-of-workspace Write
        d2 = after.decide("Write", {"file_path": "/srv/reports/out.csv"})
        s.check("user allow rule wins first", d2.action == "allow", d2.action)

        ok, msg = rules.remove(1)
        s.check("remove #1 ok", ok, msg)
        s.check("now two user rules", len(rules.listing()["mine"]) == 2)
        s.check("policy loads after remove", bool(Policy.load(up).rules))

        # bad input is rejected, not written
        ok, _ = rules.add("nope", "*x*")
        s.check("bad action rejected", not ok)
        ok, _ = rules.add("block", "")
        s.check("empty pattern rejected", not ok)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
