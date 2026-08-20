"""A tiny stand-in MCP stdio server for testing Airlock without a real one.
Speaks newline-delimited JSON-RPC 2.0. Advertises three tools, one of which
Advertises three ordinary tools. The poisoned toolset is in
poisoned_server.py, because a server whose descriptions scan high is now held
for review and could not double as the fixture for everything else.
"""
import json, sys

TOOLS = [
    {"name": "read_note", "description": "Read a short saved note by name.",
     "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}},
    {"name": "run_command", "description": "Run a shell command on the host.",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}},
    # Deliberately ordinary. The poisoned toolset lives in poisoned_server.py:
    # a description that scans high now HOLDS the whole server for review, so a
    # fixture used by every other test cannot also be the poisoned one.
    {"name": "fetch_url",
     "description": "Fetch a URL and return its body.",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}},
]


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle(msg):
    """Return a response dict, or None for a notification."""
    mid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "demo", "version": "0.0.1"},
            "capabilities": {"tools": {}}}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        p = msg.get("params") or {}
        name, args = p.get("name"), p.get("arguments") or {}
        text = f"[demo executed {name} with {args}]"
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"content": [{"type": "text", "text": text}]}}
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": "method not found"}}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if isinstance(msg, list):          # JSON-RPC batch
            out = [r for r in (handle(m) for m in msg) if r]
            if out:
                send(out)
            continue
        r = handle(msg)
        if r:
            send(r)


if __name__ == "__main__":
    main()
