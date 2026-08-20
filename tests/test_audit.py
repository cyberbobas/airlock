"""The integrity story on its own: chain, ledger, tail checkpoint, signing.

Each case is an attempt to produce a history that verifies while not being what
actually happened — which is the only question that matters about an audit log.
"""
import json, os, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import Suite

from airlock import audit as A

ROOT = Path(__file__).resolve().parents[1]


def _env(home, **kw):
    e = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=str(home),
             AIRLOCK_QUIET="1", AIRLOCK_NOTIFY="0")
    e.pop("AIRLOCK_SIGN", None)
    e.update({k: str(v) for k, v in kw.items()})
    return e


def _write(n=12, **kw):
    home = Path(tempfile.mkdtemp(prefix="audit-"))
    env = _env(home, **kw)
    subprocess.run([sys.executable, "-c", f"""
from airlock import audit
for i in range({n}):
    audit.record('decision', source='mcp', server='s', tool=f'mcp__s__t{{i}}',
                 decision='block' if i % 4 == 0 else 'allow',
                 effective='block' if i % 4 == 0 else 'allow',
                 reason='destructive recursive delete' if i % 4 == 0 else 'routine',
                 resource=f'/data/f{{i}}', flags=[{{'id': 'secrets.ssh',
                                                   'severity': 'high'}}],
                 extra='{'x' * 40}')
"""], env=env, capture_output=True)
    return home, env


def _verify(env):
    r = subprocess.run(
        [sys.executable, "-c",
         "from airlock import audit;ok,n,m=audit.verify(all_segments=True);"
         "print('OK' if ok else 'FAIL','|',m)"],
        env=env, capture_output=True, text=True)
    return r.stdout.strip()


def main():
    s = Suite("AUDIT INTEGRITY")

    # --- the digest must cover everything a record asserts ---------------
    home, env = _write(3)
    rec = json.loads((home / "audit.jsonl").read_text().splitlines()[0])
    uncovered = [k for k in rec if k not in A._CHAINED and k not in ("h", "alg", "sig")]
    s.check("every record field is bound by the digest", not uncovered, uncovered)

    for field, new in [("effective", "allow"), ("decision", "allow"),
                       ("reason", "harmless"), ("tool", "mcp__s__other"),
                       ("resource", "/data/innocent"), ("flags", []),
                       ("ts", "2020-01-01T00:00:00.000Z"), ("detail", "")]:
        home, env = _write(6)
        p = home / "audit.jsonl"
        lines = p.read_text().splitlines()
        r = json.loads(lines[2])
        if r.get(field) == new:
            continue
        r[field] = new
        lines[2] = json.dumps(r, ensure_ascii=False)
        p.write_text("\n".join(lines) + "\n")
        s.check(f"editing `{field}` breaks the chain", _verify(env).startswith("FAIL"))

    # --- tail truncation: the chain cannot speak for what was cut off ----
    # Was invisible: the ledger only covered rotated segments, so deleting the
    # last few lines of the live file — exactly where someone covering their
    # tracks would cut — verified as an intact chain.
    for cut in (1, 3, 8):
        home, env = _write(20)
        p = home / "audit.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:-cut]) + "\n")
        v = _verify(env)
        s.check(f"removing the last {cut} record(s) is detected",
                v.startswith("FAIL") and "truncated" in v, v)

    home, env = _write(10)
    (home / "audit.head").unlink()
    v = _verify(env)
    s.check("a missing tail checkpoint is reported, not silently accepted",
            "no tail checkpoint" in v, v)
    r = subprocess.run([sys.executable, "-m", "airlock.cli", "verify"],
                       env=env, capture_output=True, text=True)
    s.check("...and `airlock verify` exits 2 for it, not 0", r.returncode == 2,
            f"rc={r.returncode}")

    home, env = _write(10)
    r = subprocess.run([sys.executable, "-m", "airlock.cli", "verify"],
                       env=env, capture_output=True, text=True)
    s.check("a healthy log exits 0", r.returncode == 0, r.stdout[-200:])

    # --- signing: the difference between evidence and proof --------------
    home, env = _write(8)
    p = home / "audit.jsonl"
    lines = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    lines[4]["effective"] = "allow"      # index 4 is a block; editing it is real
    lines[4]["reason"] = "harmless"
    prev = A.GENESIS
    for r in lines:
        r["prev"] = prev
        r["h"] = A.chain_digest(r)
        prev = r["h"]
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in lines) + "\n")
    head = json.loads((home / "audit.head").read_text())
    head["last"] = prev
    (home / "audit.head").write_text(json.dumps(head) + "\n")
    s.check("UNSIGNED: a fully recomputed history verifies (the stated limit)",
            _verify(env).startswith("OK"), _verify(env))

    home, env = _write(8, AIRLOCK_SIGN="hmac")
    lines = [json.loads(l) for l in (home / "audit.jsonl").read_text().splitlines()
             if l.strip()]
    s.check("signing puts a signature on every record",
            all(r.get("sig") for r in lines))
    lines[4]["effective"] = "allow"
    lines[4]["reason"] = "harmless"
    prev = A.GENESIS
    for r in lines:
        r["prev"] = prev
        r["h"] = A.chain_digest(r)
        prev = r["h"]
    (home / "audit.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in lines) + "\n")
    s.check("SIGNED: recomputing the chain without the key is caught",
            _verify(env).startswith("FAIL"), _verify(env))

    # The full downgrade: remove the checkpoint so it cannot contradict you,
    # strip every signature so none can fail, rewrite history, recompute the
    # chain. Tolerating unsigned records made this free.
    home, env = _write(8, AIRLOCK_SIGN="hmac")
    lines = [json.loads(l) for l in (home / "audit.jsonl").read_text().splitlines()
             if l.strip()]
    lines[4]["effective"] = "allow"
    lines[4]["reason"] = "harmless"
    for r in lines:
        r.pop("sig", None)
        r.pop("alg", None)
    prev = A.GENESIS
    for r in lines:
        r["prev"] = prev
        r["h"] = A.chain_digest(r)
        prev = r["h"]
    (home / "audit.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in lines) + "\n")
    (home / "audit.head").unlink()
    v = _verify(env)
    s.check("SIGNED: deleting the checkpoint and stripping every signature is caught",
            v.startswith("FAIL"), v)
    r = subprocess.run([sys.executable, "-m", "airlock.cli", "verify"],
                       env=env, capture_output=True, text=True)
    s.check("...and `airlock verify` exits 1 for it", r.returncode == 1, r.returncode)

    home, env = _write(6, AIRLOCK_SIGN="hmac")
    s.check("an honest signed log still verifies", _verify(env).startswith("OK"),
            _verify(env))
    home, env = _write(6)
    s.check("an honest unsigned log still verifies", _verify(env).startswith("OK"),
            _verify(env))

    home, env = _write(8, AIRLOCK_SIGN="hmac")
    p = home / "audit.jsonl"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-2]) + "\n")
    head = json.loads((home / "audit.head").read_text())
    head["count"] = len(lines) - 2
    head["last"] = json.loads(lines[-3])["h"]
    (home / "audit.head").write_text(json.dumps(head) + "\n")
    v = _verify(env)
    s.check("SIGNED: rewriting the checkpoint to match a truncation is caught",
            v.startswith("FAIL") and "checkpoint" in v, v)

    # --- rotation: segments, ledger, and dropping either -----------------
    home, env = _write(150, AIRLOCK_AUDIT_MAX_MB=0.004)
    segs = sorted(home.glob("audit-*.jsonl"))
    s.check(f"the log rotated ({len(segs)} segments)", len(segs) >= 2, len(segs))
    s.check("a rotated log verifies end to end", _verify(env).startswith("OK"),
            _verify(env))

    home, env = _write(150, AIRLOCK_AUDIT_MAX_MB=0.004)
    victim = sorted(home.glob("audit-*.jsonl"))[0]
    victim.unlink()
    s.check("deleting a whole segment is caught", _verify(env).startswith("FAIL"))

    home, env = _write(150, AIRLOCK_AUDIT_MAX_MB=0.004)
    victim = sorted(home.glob("audit-*.jsonl"))[0]
    led = home / "audit.chain"
    led.write_text("\n".join(l for l in led.read_text().splitlines()
                             if victim.name not in l) + "\n")
    victim.unlink()
    s.check("deleting a segment AND its ledger line is still caught",
            _verify(env).startswith("FAIL"), _verify(env))

    home, env = _write(150, AIRLOCK_AUDIT_MAX_MB=0.004)
    led = home / "audit.chain"
    entries = [json.loads(l) for l in led.read_text().splitlines() if l.strip()]
    victim = sorted(home.glob("audit-*.jsonl"))[0]
    entries = [e for e in entries if e.get("segment") != victim.name]
    prev = A.GENESIS
    for e in entries:
        e["prev"] = prev
        e.pop("sig", None)
        e.pop("alg", None)
        e["h"] = A.ledger_digest(e)
        prev = e["h"]
    led.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    victim.unlink()
    s.check("rebuilding the ledger to hide a deleted segment is caught",
            _verify(env).startswith("FAIL"), _verify(env))

    # --- concurrency: rotation is atomic with respect to appending -------
    home = Path(tempfile.mkdtemp(prefix="audit-cc-"))
    env = _env(home, AIRLOCK_AUDIT_MAX_MB=0.004)
    code = ("from airlock import audit\n"
            "for i in range(30):\n"
            "    audit.record('decision', source='w', tool='t', decision='allow',\n"
            "                 effective='allow', reason='%s')" % ("x" * 60))
    ps = [subprocess.Popen([sys.executable, "-c", code], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          for _ in range(8)]
    for p in ps:
        p.communicate()
    v = _verify(env)
    s.check("8 writers rotating at once keep the chain and ledger consistent",
            v.startswith("OK"), v)
    n = len([l for l in (home / "audit.jsonl").read_text().splitlines() if l.strip()])
    n += sum(len([l for l in f.read_text().splitlines() if l.strip()])
             for f in home.glob("audit-*.jsonl"))
    head = json.loads((home / "audit.head").read_text())
    s.check("the tail checkpoint agrees with the record count under contention",
            head["count"] == n, f"head={head['count']} records={n}")

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
