"""Airlock MCP proxy — a stdio man-in-the-middle for one MCP server.

The agent (client) launches THIS instead of the real server; we launch the real
server as a child and shuttle newline-delimited JSON-RPC between them, enforcing
policy on the way through:

    client(agent) <--stdio--> [airlock] <--stdio--> server(skill/MCP)

  * tools/list  (server -> client) : pin the toolset (plane 4 admission) and
                                      static-scan every tool description.
                                      Paginated lists are accumulated across
                                      pages before pinning, so a server cannot
                                      hide a tool behind `nextCursor`.
  * tools/call  (client -> server) : policy decision (plane 2). On block we do
                                      NOT forward; we synthesize a JSON-RPC error
                                      back to the agent so it sees the refusal.
  * resources/read                 : gated too — a resource URI is an egress /
                                      file read by another name.

JSON-RPC batches (a top-level array) are gated element by element: blocked
elements get an error object, survivors are forwarded as a smaller batch.

Usage:
    airlock-mcp --server-id NAME -- <real server command...>
Example:
    airlock-mcp --server-id fs -- \
        npx -y @modelcontextprotocol/server-filesystem ~/src
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import threading

from . import audit, config, contracts, notify, pins, scan
from .ask import resolve_ask
from .policy import ASK, BLOCK, OBSERVE, Decision, Policy

# JSON-RPC error code we return for an Airlock refusal
E_BLOCKED = -32001
# how long a tools/call waits for an in-flight tools/list to resolve
LIST_WAIT = float(os.environ.get("AIRLOCK_LIST_WAIT", "5"))


class Proxy:
    def __init__(self, server_id: str, server_cmd: list[str], policy: Policy):
        self.server_id = server_id
        self.policy = policy
        self.pending: dict = {}          # jsonrpc id -> method (client requests)
        self.lock = threading.Lock()     # guards self.pending
        self.out_lock = threading.Lock() # guards writes to our stdout
        self._tool_pages: list[dict] = []  # accumulator for paginated tools/list
        # A tools/call must not overtake an in-flight tools/list: admission
        # state (pin / hold) is only known once that response comes back, and a
        # gate that decides on stale state is not a gate.
        self._lists_inflight = 0
        self._list_settled = threading.Event()
        self._list_settled.set()
        self.proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            bufsize=0,
        )

    # ---- framing -------------------------------------------------------
    def _to_client(self, payload) -> None:
        """Serialize one JSON-RPC message/batch to the agent.

        Both pump threads write here (block refusals from one, real responses
        from the other), so the write must be atomic or the two interleave and
        corrupt the stream.
        """
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        with self.out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    def _to_client_raw(self, raw: bytes) -> None:
        with self.out_lock:
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()

    @staticmethod
    def _block_response(req_id, reason: str, flags=None) -> dict:
        return {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": E_BLOCKED,
                      "message": f"Airlock blocked this call: {reason}",
                      "data": {"blocked_by": "airlock", "flags": flags or []}},
        }

    # ---- client -> server ---------------------------------------------
    def pump_client_to_server(self):
        client_in = sys.stdin.buffer
        server_in = self.proc.stdin
        for raw in client_in:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                # not our business to repair; hand it to the server untouched
                self._write_server(server_in, raw)
                continue

            try:
                if isinstance(msg, list):
                    self._forward_batch(server_in, msg)
                elif isinstance(msg, dict):
                    self._forward_one(server_in, msg, raw)
                else:
                    self._write_server(server_in, raw)
            except BrokenPipeError:
                break
            except Exception as e:      # a crashed pump = an open gate: never
                audit.record("proxy_error", source="mcp", server=self.server_id,
                             effective="block", reason=f"gate error: {e}")
                self._to_client(self._block_response(
                    msg.get("id") if isinstance(msg, dict) else None,
                    f"internal gate error, failing closed: {e}"))
        try:
            server_in.close()
        except Exception:
            pass

    @staticmethod
    def _write_server(server_in, raw: bytes) -> None:
        server_in.write(raw if raw.endswith(b"\n") else raw + b"\n")
        server_in.flush()

    def _forward_one(self, server_in, msg: dict, raw: bytes | None = None) -> None:
        verdict = self._gate(msg)
        if verdict is not None:
            # A notification (no id) gets no response under JSON-RPC 2.0 — it is
            # dropped instead. The refusal is still in the audit log.
            if msg.get("id") is not None:
                self._to_client(verdict)
            return
        self._remember(msg)
        self._write_server(server_in, raw if raw is not None
                           else (json.dumps(msg, ensure_ascii=False) + "\n").encode())

    def _forward_batch(self, server_in, batch: list) -> None:
        """Gate every element; forward survivors, answer the rest."""
        survivors, refusals = [], []
        for item in batch:
            if not isinstance(item, dict):
                survivors.append(item)
                continue
            verdict = self._gate(item)
            if verdict is not None:
                if item.get("id") is not None:
                    refusals.append(verdict)
            else:
                self._remember(item)
                survivors.append(item)
        if survivors:
            self._write_server(
                server_in, (json.dumps(survivors, ensure_ascii=False) + "\n").encode())
        if refusals:
            self._to_client(refusals if len(refusals) > 1 else refusals[0])

    def _remember(self, msg: dict) -> None:
        method = msg.get("method")
        if isinstance(msg.get("id"), (str, int)) and method:
            with self.lock:
                self.pending[msg["id"]] = method
                if method == "tools/list":
                    self._lists_inflight += 1
                    self._list_settled.clear()

    def _list_done(self) -> None:
        with self.lock:
            self._lists_inflight = max(0, self._lists_inflight - 1)
            if self._lists_inflight == 0:
                self._list_settled.set()

    # ---- the gate ------------------------------------------------------
    def _gate(self, msg: dict):
        """Return a JSON-RPC error object if the call must NOT be forwarded,
        else None."""
        method = msg.get("method")
        if method == "tools/call":
            params = msg.get("params") or {}
            return self._gate_call(msg, params.get("name", "?"),
                                   params.get("arguments") or {})
        if method == "resources/read":
            params = msg.get("params") or {}
            return self._gate_call(msg, "resources_read",
                                   {"uri": params.get("uri", "")})
        return None

    def _gate_call(self, msg: dict, name: str, args: dict):
        # Wait for any in-flight toolset listing so admission state is current.
        if not self._list_settled.is_set():
            self._list_settled.wait(timeout=LIST_WAIT)

        qualified = f"mcp__{self.server_id}__{name}"
        arg_flags = scan.scan_text(json.dumps(args, ensure_ascii=False))
        _, resource = contracts.classify(qualified, args)

        # (0) plane 4 admission: a server whose toolset drifted is held entirely.
        held, hold_reason = pins.is_held(self.server_id)
        if held and self.policy.mode != OBSERVE:
            audit.record("decision", source="mcp", server=self.server_id,
                         tool=qualified, decision=BLOCK, effective=BLOCK,
                         reason=hold_reason, args=args, flags=arg_flags,
                         resource=resource)
            notify.blocked(tool=qualified, reason="toolset changed since it was pinned",
                           resource=resource,
                           fix=f"airlock pins approve {self.server_id}")
            return self._block_response(msg.get("id"), hold_reason, arg_flags)

        # (1) global policy, (2) scan-flag escalation, (3) per-skill contract:
        #     strictest wins.
        d = self.policy.decide(qualified, args)
        d = self.policy.apply_flags(d, arg_flags)
        contract = contracts.get(self.server_id)
        if contract and contract.enforced:
            c_action, c_reason = contract.check(name, args)
            other = Decision(c_action, f"contract: {c_reason}" if c_reason else d.reason,
                             -1)   # rule=-1: an explicit grant, not the default
            d = d.combine(other)
        d = self.policy.posture(d)

        effective, via = self._resolve(d, name, args, arg_flags, resource)
        audit.record("decision", source="mcp", server=self.server_id,
                     tool=qualified, decision=d.action, effective=effective,
                     reason=d.reason + (f" [{via}]" if via else ""),
                     args=args, flags=arg_flags, resource=resource)

        # observe/learn: record what the skill touched, propose a contract
        if self.policy.mode == OBSERVE:
            contracts.observe(self.server_id, name, args)

        if effective == BLOCK:
            notify.blocked(tool=qualified, reason=d.reason, resource=resource,
                           fix=f"airlock allow {self.server_id} {name}")
            return self._block_response(msg.get("id"), d.reason, arg_flags)
        return None

    def _resolve(self, d: Decision, tool: str, args: dict, flags: list,
                 resource: str) -> tuple[str, str]:
        """Collapse a decision to allow/block. `ask` goes to the ask channel."""
        if d.action != ASK:
            return d.action, ""
        req = {"server": self.server_id, "tool": tool, "reason": d.reason,
               "resource": resource, "flags": flags}
        decision, backend = resolve_ask(
            req, ask_fallback=self.policy.unattended_ask(),
            timeout=float(os.environ.get("AIRLOCK_ASK_TIMEOUT", "60")))
        return decision, f"ask:{backend}"

    # ---- server -> client ---------------------------------------------
    def pump_server_to_client(self):
        for raw in self.proc.stdout:
            line = raw.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self._to_client_raw(raw)
                continue
            kept = []
            for m in (msg if isinstance(msg, list) else [msg]):
                if not isinstance(m, dict):
                    kept.append(m)
                    continue
                rid = m.get("id")
                with self.lock:
                    method = self.pending.pop(rid, None) if rid is not None else None
                if self._unsolicited(m, rid, method):
                    continue
                kept.append(m)
                try:
                    if method == "tools/list":
                        if isinstance(m.get("result"), dict):
                            self._observe_tools_page(m["result"])
                        self._list_done()
                    elif m.get("method") == "notifications/tools/list_changed":
                        # server announces a new toolset: force a re-pin next list
                        self._tool_pages = []
                except Exception as e:
                    # Admission bookkeeping (pinning, scanning, contracts) must
                    # not be able to kill this thread. It did: one OSError from
                    # a full disk stopped the pump, and the agent then waited
                    # forever for responses that were never going to be relayed.
                    self._list_done()
                    audit.record("proxy_error", source="mcp", server=self.server_id,
                                 effective="flag",
                                 reason=f"admission bookkeeping failed: {e}")
            if isinstance(msg, list):
                if kept:
                    self._to_client(kept)
            elif kept:
                self._to_client_raw(raw)
        # server stdout closed: release anyone waiting on a listing
        with self.lock:
            self._lists_inflight = 0
        self._list_settled.set()

    def _unsolicited(self, m: dict, rid, method) -> bool:
        """Drop a response to something the client never asked for.

        A response is a message carrying an `id` and no `method`. If that id is
        not one we forwarded, the server made it up — and a server that can
        make one up can answer a call we just refused, or deliver "tool output"
        for a call that never happened. Either way the client receives
        attacker-chosen content attributed to a tool, with no decision and no
        audit line behind it.

        Server-initiated *requests* (`sampling/createMessage`, `roots/list`)
        also carry ids, but they carry a `method` too, and those are the
        server's own ids to choose. They pass.
        """
        if rid is None or m.get("method") is not None or method is not None:
            return False
        audit.record("decision", source="mcp", server=self.server_id,
                     tool=f"mcp__{self.server_id}__<unsolicited>",
                     decision=BLOCK, effective=BLOCK,
                     reason="server answered an id the client never sent — dropped",
                     resource=str(rid)[:60],
                     extra=json.dumps(m.get("result") or m.get("error") or {},
                                      ensure_ascii=False)[:200])
        return True

    def _observe_tools_page(self, result: dict) -> None:
        """Accumulate paginated tools/list results, pin once the list is whole."""
        self._tool_pages.extend(result.get("tools") or [])
        if result.get("nextCursor"):
            return                       # more pages coming; do not pin a subset
        tools, self._tool_pages = self._tool_pages, []
        self._admit_toolset(tools)

    def _admit_toolset(self, tools: list[dict]):
        flags: list[dict] = []
        for t in tools:
            flags.extend(scan.scan_tool(t))
        # A high-severity finding in a tool *description* is not an argument
        # to weigh at call time — it is a reason not to trust the toolset at
        # all. Held on the same mechanism as a rug pull, and only when the
        # profile says a high flag means something (`yolo` sets no escalate).
        high = [f for f in flags if f.get("severity") == "high"]
        hold = bool(high) and bool(self.policy.escalate.get("high"))
        status, _pin = pins.check_toolset(self.server_id, tools, flags,
                                          hold_on_flag=hold)
        names = ", ".join(sorted(t.get("name", "?") for t in tools)) or "(none)"
        if status == "new" and hold:
            audit.record("toolset_held", source="mcp", server=self.server_id,
                         effective="hold",
                         reason=("tool descriptions carry "
                                 + ", ".join(sorted({f["id"] for f in high}))
                                 + f" — HELD until `airlock pins approve "
                                   f"{self.server_id}`"),
                         flags=flags, extra=names)
            notify.blocked(tool=f"mcp__{self.server_id}__*",
                           reason="a tool description looks poisoned",
                           resource=names[:120],
                           fix=f"airlock pins approve {self.server_id}")
        elif status == "new":
            contracts.ensure_default(
                self.server_id, [t.get("name", "?") for t in tools])
            audit.record("toolset_admitted", source="mcp", server=self.server_id,
                         effective="admit", reason=f"{len(tools)} tools pinned",
                         flags=flags, extra=names)
        if _pin and _pin.get("persisted") is False:
            # Losing the pin means the next session re-TOFUs this server, so
            # rug-pull detection is off until the store is writable again.
            audit.record("pin_unwritable", source="mcp", server=self.server_id,
                         effective="flag",
                         reason="could not write the pin store — rug-pull "
                                "detection is degraded for this server")
        elif status == "changed":
            audit.record("toolset_changed", source="mcp", server=self.server_id,
                         effective="hold",
                         reason="toolset hash changed — calls HELD until "
                                f"`airlock pins approve {self.server_id}`",
                         flags=flags, extra=names)
        elif status == "held":
            audit.record("toolset_held", source="mcp", server=self.server_id,
                         effective="hold",
                         reason=f"still held — `airlock pins approve {self.server_id}`",
                         flags=flags, extra=names)
        for f in flags:
            audit.record("scan_flag", source="mcp", server=self.server_id,
                         tool=f.get("tool", "?"), effective="flag",
                         reason=f"{f['id']} ({f['severity']})", extra=f.get("hit", ""))

    def run(self) -> int:
        t1 = threading.Thread(target=self.pump_client_to_server, daemon=True)
        t2 = threading.Thread(target=self.pump_server_to_client, daemon=True)
        t1.start(); t2.start()
        rc = self.proc.wait()
        # Fully drain server->client (t2 ends at server-stdout EOF) so no buffered
        # response is lost when the child exits; then let the client pump settle.
        t2.join()
        t1.join(timeout=1.0)
        return rc


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    server_id = "server"
    if argv and argv[0] == "--server-id":
        if len(argv) < 2:
            print("airlock-mcp: --server-id needs a value", file=sys.stderr)
            return 2
        server_id = argv[1]; argv = argv[2:]
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("usage: airlock-mcp [--server-id NAME] -- <server cmd...>",
              file=sys.stderr)
        return 2
    try:
        policy = Policy.resolve()
    except Exception as e:
        # No policy means no boundary. Refuse to launch rather than proxy blind.
        path, _why = config.resolve_policy()
        print(f"[airlock] refusing to start: cannot load policy {path}: {e}",
              file=sys.stderr)
        return 78  # EX_CONFIG
    try:
        from .policy import gate_fingerprint
        audit.note_gate(*gate_fingerprint(policy))
        audit.record("proxy_start", source="mcp", server=server_id, effective="admit",
                     reason=f"mode={policy.mode}", extra=" ".join(argv))
    except Exception as e:
        # An unwritable $AIRLOCK_HOME used to escape as a traceback: the server
        # simply never came up and the user saw a stack trace with no idea
        # which part of their setup was at fault. Refusing is right; refusing
        # legibly is the difference between a security control and a crash.
        print(f"[airlock] refusing to start: cannot use {config.home()}: {e}",
              file=sys.stderr)
        return 78  # EX_CONFIG
    try:
        return Proxy(server_id, argv, policy).run()
    except FileNotFoundError as e:
        print(f"[airlock] cannot launch MCP server: {e.filename or argv[0]} "
              f"not found on PATH", file=sys.stderr)
        return 127
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
