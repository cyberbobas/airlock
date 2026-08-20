"""Proxy robustness: malformed input, oversized payloads, notifications,
a misbehaving server, and the observe/enforce mode boundary. A gate that can be
made to crash, hang or skip a decision is not a gate.
"""
import json, sys, pathlib, tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import HANDSHAKE, Suite, blocked, call, drive, forwarded, rpc

s = Suite("PROXY ROBUSTNESS")
E = {"AIRLOCK_MODE": "enforce"}

# split a secret path across two arguments
r,_,_ = drive(HANDSHAKE + call(3,"read_note",{"name":"todo","a":"/home/boba/.ss","b":"h/id_rsa"}), env_extra=E)
s.check("secret split across two args", blocked(r.get(3)), r.get(3))

# case tricks
r,_,_ = drive(HANDSHAKE + call(3,"read_note",{"name":"/HOME/BOBA/.SSH/ID_RSA"}), env_extra=E)
s.check("uppercase secret path", blocked(r.get(3)), r.get(3))

# resources/read is an fs read by another name
r,_,_ = drive(HANDSHAKE + rpc(3,"resources/read",{"uri":"file:///home/boba/.ssh/id_rsa"}), env_extra=E)
s.check("resources/read of a secret is gated", blocked(r.get(3)), r.get(3))

# tools/call as a NOTIFICATION (no id) -- must not be forwarded
notif = json.dumps({"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_command","arguments":{"command":"rm -rf /"}}})+"\n"
r,err,home = drive(HANDSHAKE + notif + call(9,"read_note",{"name":"todo"}), env_extra=E)
import pathlib as pl
ev=[json.loads(l) for l in (pl.Path(home)/"audit.jsonl").read_text().splitlines() if l.strip()]
s.check("notification tools/call is decided, not ignored",
        any(e.get("tool","").endswith("run_command") and e["effective"]=="block" for e in ev))
s.check("blocked notification gets no bogus response (JSON-RPC)", r.get(None) is None)
s.check("proxy survives the notification (later call still answered)", forwarded(r.get(9)) or blocked(r.get(9)), r.get(9))

# oversized payload must not hang the gate
big = {"name":"todo","junk":["x"*5000 for _ in range(200)]}
r,_,_ = drive(HANDSHAKE + call(3,"read_note",big), env_extra=E, timeout=20)
s.check("1MB payload decided without hanging", r.get(3) is not None)

# a server that spews garbage must not crash the proxy
bad = pathlib.Path(tempfile.mkdtemp())/"bad.py"
bad.write_text('import sys\nsys.stdout.write("not json\\n");sys.stdout.flush()\n'
               'for l in sys.stdin:\n'
               '  import json\n'
               '  m=json.loads(l)\n'
               '  if isinstance(m,dict) and m.get("id") is not None:\n'
               '    sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":{"tools":[]}})+"\\n");sys.stdout.flush()\n')
r,_,_ = drive(HANDSHAKE, server=str(bad), server_id="bad", env_extra=E)
s.check("non-JSON server output does not crash the proxy", r.get(1) is not None or r.get(2) is not None)

# observe mode records but never blocks
r,_,home = drive(HANDSHAKE + call(3,"run_command",{"command":"rm -rf /"}), mode="observe")
s.check("observe mode never blocks", forwarded(r.get(3)), r.get(3))
import yaml
c=yaml.safe_load((pl.Path(home)/"contracts.yaml").read_text())
s.check("observe mode records the footprint", bool((c.get("demo") or {}).get("_observed")), c)

# enforce mode: same call blocks
r,_,_ = drive(HANDSHAKE + call(3,"run_command",{"command":"rm -rf /"}), env_extra=E)
s.check("enforce mode blocks the same call", blocked(r.get(3)))

sys.exit(s.report())
