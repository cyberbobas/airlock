#!/usr/bin/env python3
"""Sign an indicator feed so `airlock update` will accept it.

    AIRLOCK_FEED_KEY=<hex-or-utf8-secret> python3 tools/sign_feed.py feed.json

Writes the HMAC-SHA256 signature into the feed's `signature` block in place. The
same key goes to subscribers as AIRLOCK_FEED_KEY; without it (or --allow-unsigned)
the client refuses the feed — a detection-rule supply chain must be authenticated
just like any other. This is the maintainer side of feed.py's verification.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from airlock import feed  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: AIRLOCK_FEED_KEY=… python3 tools/sign_feed.py <feed.json>",
              file=sys.stderr)
        return 2
    key = feed.signing_key()
    if not key:
        print("set AIRLOCK_FEED_KEY to the signing secret first", file=sys.stderr)
        return 2
    p = Path(sys.argv[1])
    data = json.loads(p.read_text(encoding="utf-8"))
    data.pop("signature", None)
    sig = feed.sign_payload(data, key)
    data["signature"] = {"alg": "hmac-sha256", "value": sig}
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                 encoding="utf-8")
    print(f"signed {p} — {len(data.get('patterns') or [])} patterns, "
          f"{len(data.get('block_hosts') or [])} hosts")
    print(f"subscribers verify with AIRLOCK_FEED_KEY and: airlock update {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
