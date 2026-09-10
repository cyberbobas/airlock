"""Summary path must fail safe like the judge path.

Regression for a real defect: a judge-only fine-tune ignores SUMMARY_SYSTEM and
answers in its trained shape — a `{"decision": ...}` verdict, or an echo of the
judge prompt scaffolding. The judge path already discards unusable output
(`_parse_verdict` -> None -> rules stand); the summary path used to return the
model's text verbatim, so that leak printed as the "narrative" above the recap.
`_looks_like_summary` closes the asymmetry: an off-task reply is dropped and the
caller degrades to the always-correct structured summary.
"""
import json, pathlib, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite

from airlock.ai.openai_compat import (OpenAICompatBackend, _looks_like_summary,
                                       _has_verdict_json)


class _Stub(BaseHTTPRequestHandler):
    """OpenAI-compatible endpoint that replies with a settable content string."""
    CONTENT = ""
    def log_message(self, *a):
        pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"data":[]}')
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        body = json.dumps({"choices": [{"message": {"content": _Stub.CONTENT}}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.end_headers(); self.wfile.write(body)


def _start():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


NARRATIVE = ("During this session the agent made 12 tool calls. Airlock blocked "
             "three attempts to reach an untrusted host and allowed the rest. "
             "Nothing sensitive was touched. Review the two asked calls first.")
VERDICT_LEAK = json.dumps({"decision": "block", "reason": "reaches untrusted network"})
SCAFFOLD_LEAK = ("tool: Bash\nserver/plane: mcp\nrules said: ask\n"
                 "why escalated: shell execution\narguments: {'command': 'git status'}")
# Shape B — what `airlock summary` actually emits with a judge-only model: an echo
# of JUDGE_SYSTEM's instructions. No JSON verdict, none of the scaffold markers.
# This is the exact 508-char string reproduced end-to-end through the product.
JUDGE_INSTR_LEAK = (
    "The agent tried to shell out to a remote host. It wants to read or write to a "
    "file outside the workspace. Deterministic rules already ran and left this in the "
    "gray zone. Decide exactly one of: allow, block, ask. Prefer 'ask' when unsure. "
    "Block only clearly dangerous actions (destroying data, exfiltrating secrets, "
    "reaching untrusted networks, disabling safety). Reply with a single line of JSON: "
    '{"decision":"allow|block|ask", "reason":"<=12 words"}. The reason is shown to a '
    "human, so be concrete and short.")
# A genuine narrative that names untrusted networks / secrets in prose must stay safe.
TRICKY_NARRATIVE = (
    "This session the agent tried reaching untrusted networks and touching secrets; "
    "Airlock blocked those and allowed the safe git reads. One action was asked for review.")


def main():
    s = Suite("summary fails safe on an off-task (judge-only) model")

    # 1) unit: the classifier keeps real narratives, drops leaks
    s.check("real narrative (says 'blocked'/'allowed') is kept",
            _looks_like_summary(NARRATIVE) is True)
    s.check("a JSON verdict is not a summary",
            _looks_like_summary(VERDICT_LEAK) is False)
    s.check("judge-prompt scaffolding (shape A) is not a summary",
            _looks_like_summary(SCAFFOLD_LEAK) is False)
    s.check("judge-instruction echo (shape B, what the product emits) is not a summary",
            _looks_like_summary(JUDGE_INSTR_LEAK) is False)
    s.check("too-short reply is not a summary",
            _looks_like_summary("ok") is False)
    s.check("narrative that merely mentions the word ask is kept",
            _looks_like_summary("The agent asked to edit a config file; Airlock "
                                "surfaced it for review. A quiet session overall.") is True)
    s.check("narrative naming 'untrusted networks'/'secrets' in prose is kept",
            _looks_like_summary(TRICKY_NARRATIVE) is True)
    s.check("_has_verdict_json ignores prose keywords",
            _has_verdict_json("many calls were blocked and allowed today") is False)
    s.check("_has_verdict_json spots a real verdict object",
            _has_verdict_json("noise " + VERDICT_LEAK) is True)

    # 2) end-to-end through the real backend transport
    srv, port = _start()
    try:
        be = OpenAICompatBackend(base_url=f"http://127.0.0.1:{port}/v1", model="x")
        facts = {"totals": {"decisions": 12, "blocked": 3}}

        _Stub.CONTENT = VERDICT_LEAK
        s.check("backend suppresses a leaked verdict (returns '')",
                be.summarize(facts, timeout_ms=2000) == "")

        _Stub.CONTENT = SCAFFOLD_LEAK
        s.check("backend suppresses leaked scaffolding (returns '')",
                be.summarize(facts, timeout_ms=2000) == "")

        _Stub.CONTENT = JUDGE_INSTR_LEAK
        s.check("backend suppresses a judge-instruction echo (returns '')",
                be.summarize(facts, timeout_ms=2000) == "")

        _Stub.CONTENT = NARRATIVE
        s.check("backend passes a real narrative through unchanged",
                be.summarize(facts, timeout_ms=2000) == NARRATIVE)
    finally:
        srv.shutdown()

    return s.report()


if __name__ == "__main__":
    sys.exit(main())
