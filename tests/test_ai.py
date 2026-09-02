"""AI layer (M0/M1): config tier/ai/cloud keys, the Backend interface, secret
redaction, and the non-LLM session summary. The AI must only ever tighten and
fail closed, so the null/lite path is what most of this pins down."""
import json, os, pathlib, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite


class _Stub(BaseHTTPRequestHandler):
    """A tiny OpenAI-compatible endpoint. Reply verdict is settable per test."""
    VERDICT = "block"
    REASON = "deletes the tree"
    def log_message(self, *a):
        pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{"data":[]}')
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        content = json.dumps({"decision": _Stub.VERDICT, "reason": _Stub.REASON})
        body = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.end_headers(); self.wfile.write(body)


def _start_stub():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]

from airlock.policy import Policy
from airlock import ai
from airlock.ai import base, prompts

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _write(tmp, text):
    p = pathlib.Path(tmp) / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def main():
    s = Suite("AI LAYER (M0/M1)")

    # ---- config: new keys load, default safely, reject garbage -----------
    tmp = tempfile.mkdtemp(prefix="airlock-ai-")
    p = Policy.load(_write(tmp, "rules: []\n"))
    s.check("tier defaults to lite", p.tier == "lite")
    s.check("cloud defaults to off (no egress by default)", p.cloud == "off")
    s.check("ai defaults to empty mapping", p.ai == {})

    p = Policy.load(_write(tmp, "rules: []\ntier: standard\ncloud: locked-off\nai: {judge: {enabled: true}}\n"))
    s.check("valid tier loads", p.tier == "standard")
    s.check("valid cloud loads", p.cloud == "locked-off")
    s.check("ai mapping loads", p.ai.get("judge", {}).get("enabled") is True)

    def _rejects(text):
        try:
            Policy.load(_write(tmp, text))
            return False
        except ValueError:
            return True
    s.check("bogus tier is rejected (no silent half-load)", _rejects("rules: []\ntier: nope\n"))
    s.check("bogus cloud is rejected", _rejects("rules: []\ncloud: maybe\n"))
    s.check("non-mapping ai is rejected", _rejects("rules: []\nai: [1,2]\n"))

    # ---- backend interface / fail-safe ----------------------------------
    b = ai.get_backend()
    s.check("default backend is unavailable (lite falls back)", b.available() is False)
    s.check("null judge gives no opinion", b.judge(base.JudgeContext(tool="Bash"), timeout_ms=50) is None)
    s.check("null summarize is empty", b.summarize({}) == "")

    good = base.Verdict(decision="block", reason="destroys data")
    s.check("valid verdict passes through", good.decision == "block")
    bad = base.Verdict(decision="yeet", reason="")
    s.check("out-of-vocabulary verdict becomes ask (safe middle)", bad.decision == "ask")
    s.check("out-of-vocabulary verdict is marked failsafe", bad.source == "failsafe")

    # ---- redaction ------------------------------------------------------
    red = prompts.redact("run with ghp_ABCDEFGHIJKLMNOPQRSTUVWX and sk-ant-0123456789abcdef")
    s.check("github PAT redacted", "ghp_" not in red)
    s.check("anthropic key redacted", "sk-ant-" not in red)
    kv = prompts.redact('API_TOKEN="s3cr3t-value-here"')
    s.check("secret-looking key=value redacted", "s3cr3t-value-here" not in kv)
    obj = prompts.redact_obj({"cmd": "export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWX", "ok": ["plain"]})
    s.check("deep redaction walks dicts/lists", "ghp_" not in obj["cmd"] and obj["ok"] == ["plain"])

    # ---- summary (M1): non-LLM facts over a synthetic log ---------------
    home = tempfile.mkdtemp(prefix="airlock-sum-")
    os.environ["AIRLOCK_HOME"] = home
    os.environ["AIRLOCK_NOTIFY"] = "0"
    from airlock import audit
    import importlib
    from airlock import summarize as summ
    importlib.reload(audit)   # pick up AIRLOCK_HOME
    importlib.reload(summ)

    empty = summ.build_facts(days=None)
    s.check("empty log reports zero events", empty.totals.get("events", 0) == 0)
    s.check("empty summary says so", "no activity" in summ.render(empty).lower())

    audit.record("decision", source="mcp", server="gh", tool="mcp__gh__create_issue",
                 decision="allow", effective="allow", reason="rule#3", resource="repo:x")
    audit.record("decision", source="hook", tool="Bash", decision="block", effective="block",
                 reason="absolute block", resource="rm -rf /")
    audit.record("decision", source="mcp", server="fs", tool="mcp__fs__read", decision="ask",
                 effective="ask", reason="no grant", resource="/home/u/.ssh/id_rsa")
    audit.record("decision", source="hook", tool="WebFetch", decision="ask", effective="ask",
                 reason="untrusted host", resource="http://evil", flags=[{"id": "X", "severity": "high"}])
    audit.record("outcome", source="hook", tool="Bash", effective="ran", resource="ls")

    f = summ.build_facts(days=None)
    s.check("counts 4 decisions", f.totals["decisions"] == 4)
    s.check("counts 1 blocked", f.totals["blocked"] == 1)
    s.check("counts 2 asked", f.totals["asked"] == 2)
    s.check("counts 1 allowed", f.totals["allowed"] == 1)
    s.check("counts 1 ran (outcome)", f.totals["ran"] == 1)
    s.check("blocked list carries the rm -rf", any("rm -rf" in r["resource"] for r in f.blocked))
    s.check("scan flags counted by severity", f.scan_flags["by_severity"].get("high") == 1)
    out = summ.render(f)
    s.check("render shows a BLOCKED section", "BLOCKED" in out)
    s.check("markdown render is non-empty", summ.render_markdown(f).startswith("## airlock summary"))

    # ---- M2: verdict parsing (fail-safe) --------------------------------
    from airlock.ai.openai_compat import _parse_verdict
    s.check("fenced JSON verdict parses", _parse_verdict('```json\n{"decision":"allow","reason":"ok"}\n```')[0] == "allow")
    s.check("garbage output -> None (fail closed)", _parse_verdict("hmm, maybe, whatever") is None)
    s.check("bare keyword falls back to block", _parse_verdict("I would BLOCK this")[0] == "block")

    # ---- M2: built-in backend via a stubbed local endpoint --------------
    srv, port = _start_stub()
    os.environ["AIRLOCK_AI_URL"] = f"http://127.0.0.1:{port}/v1"
    import importlib
    from airlock import ai as aimod
    importlib.reload(aimod)  # pick up AIRLOCK_AI_URL in a fresh BuiltinBackend

    class _Cfg:  # stand-in for a Policy
        tier = "standard"; cloud = "off"

    class _Lite:
        tier = "lite"; cloud = "off"

    s.check("lite tier -> null backend", type(aimod.get_backend(_Lite())).__name__ == "NullBackend")
    b = aimod.get_backend(_Cfg())
    s.check("standard tier -> built-in backend available", b.available() and type(b).__name__ == "BuiltinBackend")
    v = b.judge(base.JudgeContext(tool="Bash", args={"command": "rm -rf /"}, rule_verdict="ask"), timeout_ms=2000)
    s.check("built-in judge returns a verdict", v is not None and v.decision == "block")
    s.check("built-in judge is tagged 'mini'", v.source == "mini")
    srv.shutdown()
    os.environ.pop("AIRLOCK_AI_URL", None)

    # ---- M2: training dataset from human-answered gray-zone calls --------
    from airlock.ai import dataset
    audit.record("decision", source="mcp", server="fs", tool="mcp__fs__read", decision="ask",
                 effective="block", reason="reading ssh key [ask:socket]", resource="/h/.ssh/id_rsa")
    audit.record("decision", source="hook", tool="WebFetch", decision="ask",
                 effective="allow", reason="fetch docs [ask:zenity]", resource="https://docs.example")
    audit.record("decision", source="hook", tool="Bash", decision="ask",
                 effective="block", reason="unattended [ask:fallback]", resource="x")
    ex = dataset.build_examples(days=None, human_only=True)
    s.check("dataset harvests human-answered examples", len(ex) == 2)
    s.check("fallback resolutions excluded from human-only set",
            all("fallback" not in m["content"] for e in ex for m in e["messages"]))
    asst = json.loads(ex[0]["messages"][-1]["content"])
    s.check("assistant label is a clean verdict", asst["decision"] in ("allow", "block"))
    s.check("provenance tag stripped from label reason", "[ask:" not in asst.get("reason", ""))
    incl = dataset.build_examples(days=None, human_only=False)
    s.check("include-fallback widens the set", len(incl) == 3)

    # ---- M3: inline judge (tighten-only, fail-safe, gray-zone) ----------
    from airlock.policy import ALLOW, ASK, BLOCK, Decision
    from airlock.ai import judge as aijudge
    from airlock.ai.openai_compat import OpenAICompatBackend

    srv2, port2 = _start_stub()
    be = OpenAICompatBackend(base_url=f"http://127.0.0.1:{port2}/v1", model="x", source="mini")

    class Std:  # standard tier, default judge config
        tier = "standard"; cloud = "off"; ai = {}

    class Lite:
        tier = "lite"; cloud = "off"; ai = {}

    _Stub.VERDICT = "block"
    s.check("hard BLOCK is never touched by the judge",
            aijudge.consult(Decision(BLOCK, "rule", 0), tool="Bash", cfg=Std(), backend=be).action == BLOCK)
    s.check("lite tier does not consult the judge",
            aijudge.consult(Decision(ASK, "gray", None), tool="Bash", cfg=Lite(), backend=be).action == ASK)
    tightened = aijudge.consult(Decision(ASK, "gray", None), tool="Bash", cfg=Std(), backend=be)
    s.check("judge tightens ask -> block", tightened.action == BLOCK)
    s.check("tightened reason is attributed to AI", tightened.reason.startswith("AI:"))
    s.check("allow is NOT judged by default (gray-zone only)",
            aijudge.consult(Decision(ALLOW, "ok", 1), tool="Bash", cfg=Std(), backend=be).action == ALLOW)

    class StdCheckAllow:
        tier = "standard"; cloud = "off"; ai = {"judge": {"check_allow": True}}
    s.check("check_allow lets the judge tighten an allow -> block",
            aijudge.consult(Decision(ALLOW, "ok", 1), tool="Bash", cfg=StdCheckAllow(), backend=be).action == BLOCK)

    _Stub.VERDICT = "allow"
    s.check("judge does NOT relax ask -> allow by default (fail-closed)",
            aijudge.consult(Decision(ASK, "gray", None), tool="Bash", cfg=Std(), backend=be).action == ASK)

    class StdRelax:
        tier = "standard"; cloud = "off"; ai = {"judge": {"relax_ask": True}}
    s.check("relax_ask opt-in allows ask -> allow",
            aijudge.consult(Decision(ASK, "gray", None), tool="Bash", cfg=StdRelax(), backend=be).action == ALLOW)
    srv2.shutdown()

    dead = OpenAICompatBackend(base_url="http://127.0.0.1:1/v1", model="x", source="mini")
    s.check("model unreachable -> rules decision stands (fail-safe)",
            aijudge.consult(Decision(ASK, "gray", None), tool="Bash", cfg=Std(), backend=dead).action == ASK)

    # ---- M4: providers, cloud gating, keychain, Anthropic ---------------
    from airlock.ai import providers, keys
    keys._keyring = None   # force the 0600-file fallback so the test is hermetic

    s.check("presets cover the promised set",
            all(p in providers.PRESETS for p in ("claude", "openai", "deepseek", "qwen", "kimi", "glm", "ollama", "custom")))
    s.check("localhost is local", providers.is_local("http://localhost:11434/v1"))
    s.check("a remote host is not local", not providers.is_local("https://api.openai.com/v1"))
    s.check("unknown preset -> None", providers.resolve("nope") is None)
    s.check("custom with a remote url is treated as cloud",
            providers.resolve("custom", base_url="https://x.example/v1", model="m")["local"] is False)

    # keychain fallback: set / has / get / delete
    keys.set_key("openai", "sk-test-123")
    s.check("key stored", keys.has_key("openai") and keys.get_key("openai") == "sk-test-123")
    keys.delete_key("openai")
    s.check("key deleted", not keys.has_key("openai"))

    class Pro:
        def __init__(self, preset, cloud="off"):
            self.tier = "pro"; self.cloud = cloud
            self.ai = {"provider": {"preset": preset}}

    s.check("cloud preset blocked when cloud is off",
            providers.backend_for(Pro("openai", "off")) is None)
    s.check("cloud preset needs a key even when cloud is on",
            providers.backend_for(Pro("openai", "on")) is None)
    keys.set_key("openai", "sk-test-123")
    b_openai = providers.backend_for(Pro("openai", "on"))
    s.check("cloud preset + key + cloud:on -> OpenAI backend",
            type(b_openai).__name__ == "OpenAICompatBackend")
    s.check("local ollama preset allowed even when cloud is off",
            type(providers.backend_for(Pro("ollama", "off"))).__name__ == "OpenAICompatBackend")
    keys.set_key("claude", "sk-ant-test")
    s.check("claude preset -> native Anthropic backend",
            type(providers.backend_for(Pro("claude", "on"))).__name__ == "AnthropicBackend")
    keys.delete_key("openai"); keys.delete_key("claude")

    # Anthropic adapter parses a Messages-API reply
    class _AnthStub(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get("content-length", 0)))
            body = json.dumps({"content": [{"type": "text",
                "text": '{"decision":"block","reason":"reads a secret"}'}]}).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(body)
    asrv = ThreadingHTTPServer(("127.0.0.1", 0), _AnthStub)
    threading.Thread(target=asrv.serve_forever, daemon=True).start()
    from airlock.ai.anthropic import AnthropicBackend
    ab = AnthropicBackend(f"http://127.0.0.1:{asrv.server_address[1]}", "claude-x", api_key="k")
    av = ab.judge(base.JudgeContext(tool="Read", args={"file_path": "/etc/shadow"}, rule_verdict="ask"), timeout_ms=2000)
    s.check("Anthropic adapter returns a parsed verdict", av is not None and av.decision == "block")
    asrv.shutdown()

    class StdDisabled:
        tier = "standard"; cloud = "off"; ai = {"judge": {"enabled": False}}
    _Stub.VERDICT = "block"
    srv3, port3 = _start_stub()
    be3 = OpenAICompatBackend(base_url=f"http://127.0.0.1:{port3}/v1", model="x", source="mini")
    s.check("judge disabled in config is a no-op",
            aijudge.consult(Decision(ASK, "gray", None), tool="Bash", cfg=StdDisabled(), backend=be3).action == ASK)
    srv3.shutdown()

    # ---- M5: tier switch (in-Settings, no reinstall) --------------------
    from types import SimpleNamespace
    import airlock.cli as cli
    from airlock import config as cfgmod
    up = cfgmod.user_policy()
    up.write_text("default: ask\nrules: []\n", encoding="utf-8")
    s.check("ai-tier show returns 0", cli.cmd_ai_tier(SimpleNamespace(tier=None)) == 0)
    cli.cmd_ai_tier(SimpleNamespace(tier="pro"))
    s.check("ai-tier writes the tier into the policy", "tier: pro" in up.read_text())
    cli.cmd_ai_tier(SimpleNamespace(tier="standard"))
    txt = up.read_text()
    s.check("ai-tier replaces rather than duplicates", txt.count("tier:") == 1 and "tier: standard" in txt)
    s.check("ai-tier preserves the rest of the policy", "rules: []" in txt and "default: ask" in txt)
    s.check("bad tier is rejected", cli.cmd_ai_tier(SimpleNamespace(tier="bogus")) == 2)
    s.check("switched policy still loads", Policy.load(up).tier == "standard")

    # ai-provider writes the BYO provider block
    up.write_text("default: ask\nrules: []\n", encoding="utf-8")
    cli.cmd_ai_provider(SimpleNamespace(preset="claude", model=None, base_url=None, cloud="on"))
    pol2 = Policy.load(up)
    s.check("ai-provider sets the provider preset", pol2.ai.get("provider", {}).get("preset") == "claude")
    s.check("ai-provider sets cloud egress", pol2.cloud == "on")
    s.check("ai-provider rejects an unknown preset",
            cli.cmd_ai_provider(SimpleNamespace(preset="nope", model=None, base_url=None, cloud=None)) == 2)

    # ---- judge latency budget scales with local vs cloud ----------------
    class CloudCfg:
        tier = "pro"; cloud = "on"; ai = {}
    s.check("local judge budget is short (hot path)", aijudge._cfg(CloudCfg(), local=True)["budget"] == 800)
    s.check("cloud judge budget is longer so it actually runs",
            aijudge._cfg(CloudCfg(), local=False)["budget"] > 800)

    # ---- menu: informative, grouped, explains the AI ---------------------
    help_text = cli.build_parser().format_help()
    s.check("menu has an explained AI section", "AI in the middle" in help_text)
    s.check("menu groups commands", "first run" in help_text and "every day" in help_text)
    s.check("menu lists the AI commands", all(c in help_text for c in
            ("ai-status", "ai-tier", "ai-model", "ai-key", "ai-dataset", "summary")))
    s.check("menu says the AI only tightens (safety)", "STRICTER" in help_text)

    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
