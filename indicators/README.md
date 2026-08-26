# Airlock indicators — the public feed & advisory list

This directory is the seed of the public **`cyberbobas/indicators`** repository
that `airlock update` fetches from. Two things live here:

1. **`feed.json`** — the signed indicator feed: collector hosts, injection
   phrasings and bad-server fingerprints that rot like antivirus signatures.
   Merged *on top of* the bundled floor in every Airlock install; it can add
   indicators and raise a severity, never delete one or lower a severity.

2. **`advisories/`** — an OSV-style, human-readable record per poisoned skill or
   MCP server (the agent-ecosystem analogue of the OSV database). Each advisory
   can contribute a `block_host` or a `pattern` to `feed.json`, and each is a
   thing we can cite: "Airlock found and disclosed this."

## Publishing a feed (maintainers)

```bash
# 1. edit feed.json (bump `version`, add patterns / block_hosts)
# 2. sign it with the private feed key
AIRLOCK_FEED_KEY=<secret> python3 ../tools/sign_feed.py feed.json
# 3. commit + push to cyberbobas/indicators; the raw URL is HOSTED_FEED_URL
```

## Consuming it (users)

```bash
export AIRLOCK_FEED_KEY=<the published public verification secret>
airlock update            # fetches + verifies the signed feed
airlock update --status   # what is active, over the bundled floor
```

**Unsigned feeds are refused by default.** The detection rules of a supply-chain
tool are themselves a supply chain; fetching them unauthenticated would be the
exact failure this project exists to prevent.

> Status: not yet hosted. Until `cyberbobas/indicators` is published, point
> `airlock update` at a local signed `feed.json` (or your own mirror) — the
> mechanism is complete and tested; only the hosting is pending.
