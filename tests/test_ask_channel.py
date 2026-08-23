"""The ask channel across modes, and across a daemon's lifetime.

`ask` is the only verdict whose answer comes from outside the process, so it is
the only one where "what was decided" and "what was recorded" can drift apart.
They did: a human who answered after the caller had given up left an approval
in the log for a call that had already been refused.
"""
import json, os, pathlib, signal, socket, subprocess, sys, tempfile, threading, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = str(ROOT / "tests" / "fixtures" / "policy.yaml")

SERVER = r'''
import json, sys
TOOLS=[{"name":"fetch_url","description":"Fetch a URL.","inputSchema":{"type":"object"}}]
def emit(m):
    sys.stdout.write(json.dumps(m)+"\n"); sys.stdout.flush()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    m=json.loads(line); mid=m.get("id")
    if m.get("method")=="initialize":
        emit({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2024-11-05",
              "serverInfo":{"name":"s"},"capabilities":{"tools":{}}}})
    elif m.get("method")=="tools/list":
        emit({"jsonrpc":"2.0","id":mid,"result":{"tools":TOOLS}})
    elif m.get("method")=="tools/call":
        emit({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"EXECUTED"}]}})
'''

SLOW_ZENITY = '#!/bin/sh\nsleep "${FAKE_ZENITY_DELAY:-3}"\nexit "${FAKE_ZENITY_RC:-0}"\n'


def _server():
    p = pathlib.Path(tempfile.mkdtemp()) / "s.py"
    p.write_text(SERVER)
    return p


class LateHuman(threading.Thread):
    """Answers every request, but only after `delay` seconds."""

    def __init__(self, path, delay, answer="allow"):
        super().__init__(daemon=True)
        self.path = pathlib.Path(path)
        self.delay, self.answer, self.stop = delay, answer, False
        if self.path.exists():
            self.path.unlink()
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            self.srv.bind(str(self.path))
        finally:
            os.umask(old)
        self.srv.listen(8)
        self.srv.settimeout(0.4)

    def run(self):
        while not self.stop:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._answer, args=(conn,), daemon=True).start()

    def _answer(self, conn):
        try:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            time.sleep(self.delay)
            conn.sendall((json.dumps({"decision": self.answer, "via": "late"}) + "\n").encode())
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def shutdown(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass
        if self.path.exists():
            try:
                self.path.unlink()
            except OSError:
                pass


def _call(server, home, mode, timeout, url="https://unlisted.example/x"):
    env = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=str(home),
               AIRLOCK_QUIET="1", AIRLOCK_NOTIFY="0", AIRLOCK_MODE=mode,
               AIRLOCK_ASK_TIMEOUT=str(timeout), AIRLOCK_POLICY=FIXTURE,
               # these cases probe the channel/daemon semantics, so turn off the
               # remembered-answer cache — otherwise a prior identical ask's
               # answer would resolve the next one and mask the fallback path.
               AIRLOCK_ASK_REMEMBER="0",
               # pin the chain: a box with zenity and a DISPLAY would pop a real
               # dialog and make the measurement meaningless
               AIRLOCK_ASK_BACKEND="socket,fallback")
    script = "\n".join(json.dumps(m) for m in [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "fetch_url", "arguments": {"url": url}}}]) + "\n"
    t0 = time.time()
    p = subprocess.run([sys.executable, "-m", "airlock.mcp_proxy", "--server-id", "s",
                        "--", sys.executable, str(server)],
                       input=script.encode(), capture_output=True, env=env, timeout=120)
    verdict = "NO-RESPONSE"
    for line in p.stdout.decode().splitlines():
        try:
            m = json.loads(line)
        except Exception:
            continue
        if isinstance(m, dict) and m.get("id") == 3:
            verdict = "BLOCK" if "error" in m else "ALLOW"
    return verdict, time.time() - t0


def _records(home):
    f = pathlib.Path(home) / "audit.jsonl"
    if not f.exists():
        return []
    return [json.loads(l) for l in f.read_text().splitlines() if l.strip()]


def _daemon(home, auto):
    env = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=str(home), AIRLOCK_QUIET="1")
    p = subprocess.Popen([sys.executable, "-m", "airlock.askd", "--auto", auto],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        if (pathlib.Path(home) / "ask.sock").exists():
            break
        time.sleep(0.05)
    return p


def main():
    s = Suite("ASK CHANNEL")
    srv = _server()

    # --- mode x daemon ---------------------------------------------------
    expected = {
        ("observe", "none"): "ALLOW", ("observe", "allow"): "ALLOW", ("observe", "block"): "ALLOW",
        ("guard", "none"): "ALLOW", ("guard", "allow"): "ALLOW", ("guard", "block"): "BLOCK",
        ("enforce", "none"): "BLOCK", ("enforce", "allow"): "ALLOW", ("enforce", "block"): "BLOCK",
    }
    for (mode, daemon), want in expected.items():
        home = pathlib.Path(tempfile.mkdtemp(prefix="ac-"))
        proc = _daemon(home, daemon) if daemon != "none" else None
        try:
            got, _ = _call(srv, home, mode, 5)
        finally:
            if proc:
                proc.terminate()
                proc.wait()
        s.check(f"mode={mode}, daemon={daemon} -> {want}", got == want, got)

    # --- a human who answers after the caller gave up ---------------------
    home = pathlib.Path(tempfile.mkdtemp(prefix="ac-late-"))
    home.mkdir(exist_ok=True)
    late = LateHuman(home / "ask.sock", delay=3, answer="allow")
    late.start()
    try:
        got, dt = _call(srv, home, "enforce", 1)
    finally:
        time.sleep(3.5)
        late.shutdown()
    s.check("a late answer does not let the call through", got == "BLOCK", got)
    s.check("...and the caller does not wait for it", dt < 3, dt)
    approvals = [r for r in _records(home)
                 if r.get("effective") == "allow" and r.get("event") in ("decision", "ask_prompt")]
    s.check("no record claims a refused call was approved", not approvals,
            [r.get("reason", "")[:60] for r in approvals])

    # The real daemon, with a human who takes three seconds over the dialog.
    fake = pathlib.Path(tempfile.mkdtemp())
    (fake / "zenity").write_text(SLOW_ZENITY)
    (fake / "zenity").chmod(0o755)
    home = pathlib.Path(tempfile.mkdtemp(prefix="ac-real-"))
    home.mkdir(exist_ok=True)
    denv = dict(os.environ, PYTHONPATH=str(ROOT), AIRLOCK_HOME=str(home),
                AIRLOCK_QUIET="1", PATH=f"{fake}:{os.environ['PATH']}", DISPLAY=":0",
                FAKE_ZENITY_DELAY="3", FAKE_ZENITY_RC="0", AIRLOCK_ASK_TIMEOUT="30")
    d = subprocess.Popen([sys.executable, "-m", "airlock.askd"], env=denv,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(80):
            if (home / "ask.sock").exists():
                break
            time.sleep(0.05)
        got, _ = _call(srv, home, "enforce", 1)
        time.sleep(3.5)
    finally:
        d.terminate()
        d.wait()
    recs = _records(home)
    s.check("the real daemon's late answer does not let the call through",
            got == "BLOCK", got)
    s.check("no approval is recorded for it",
            not [r for r in recs if r.get("effective") == "allow"],
            [r.get("reason", "")[:60] for r in recs if r.get("effective") == "allow"])
    late_notes = [r for r in recs if "too late" in (r.get("reason") or "")]
    s.check("the answer is recorded, as an answer that decided nothing",
            len(late_notes) == 1, [r.get("reason", "")[:80] for r in recs])

    # --- daemon lifecycle -------------------------------------------------
    home = pathlib.Path(tempfile.mkdtemp(prefix="ac-life-"))
    home.mkdir(exist_ok=True)
    d1 = LateHuman(home / "ask.sock", delay=0, answer="allow")
    d1.start()
    time.sleep(0.3)
    v1, _ = _call(srv, home, "enforce", 5)
    d1.shutdown()
    time.sleep(0.3)
    v2, _ = _call(srv, home, "enforce", 3)
    d2 = LateHuman(home / "ask.sock", delay=0, answer="block")
    d2.start()
    time.sleep(0.3)
    v3, _ = _call(srv, home, "enforce", 5)
    d2.shutdown()
    s.check("a live daemon is honoured", v1 == "ALLOW", v1)
    s.check("a dead daemon falls back to the mode", v2 == "BLOCK", v2)
    s.check("a restarted daemon answers for itself", v3 == "BLOCK", v3)

    home = pathlib.Path(tempfile.mkdtemp(prefix="ac-stale-"))
    home.mkdir(exist_ok=True)
    (home / "ask.sock").write_text("")      # a plain file where a socket should be
    got, dt = _call(srv, home, "enforce", 3)
    s.check("a stale socket file does not hang the gate", dt < 10, dt)
    s.check("...and it fails closed", got == "BLOCK", got)

    # ---- remembered answers: a repeat of the same ask does not re-prompt ---
    rhome = pathlib.Path(tempfile.mkdtemp(prefix="ask-remember-"))
    os.environ["AIRLOCK_HOME"] = str(rhome)
    os.environ.pop("AIRLOCK_ASK_REMEMBER", None)
    os.environ["AIRLOCK_ASK_BACKEND"] = "fallback"
    from airlock import ask
    req = {"server": "repo", "tool": "summarize",
           "resource": "/home/user/proj/a.py", "reason": "review"}
    s.check("a fresh question is not remembered", ask.recall(req) is None, ask.recall(req))
    ask.remember(req, "allow")
    d, via = ask.resolve_ask(req, ask_fallback="block")
    s.check("a remembered allow silences the repeat without a backend",
            (d, via) == ("allow", "remembered"), (d, via))
    # a different target is NOT covered, and a fallback answer is never cached
    other = dict(req, resource="/home/user/proj/b.py")
    d2, via2 = ask.resolve_ask(other, ask_fallback="block")
    s.check("a different target still asks (exact-match only)",
            via2 == "fallback" and ask.recall(other) is None, (via2, ask.recall(other)))
    # AIRLOCK_ASK_REMEMBER=0 turns it off
    os.environ["AIRLOCK_ASK_REMEMBER"] = "0"
    s.check("AIRLOCK_ASK_REMEMBER=0 disables the cache",
            ask.resolve_ask(req, ask_fallback="block") == ("block", "fallback"),
            ask.resolve_ask(req, ask_fallback="block"))
    os.environ.pop("AIRLOCK_ASK_REMEMBER", None)
    os.environ.pop("AIRLOCK_ASK_BACKEND", None)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
