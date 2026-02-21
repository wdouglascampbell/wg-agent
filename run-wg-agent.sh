#!/usr/bin/env bash
# Wrapper to run wg-agent with uvicorn. Sources /etc/wg-agent/wg-agent.env
# for PORT and optional BIND_ADDRESS. Idempotent; safe to run manually or via systemd.

set -e
cd "$(dirname "$0")"

if [[ -f /etc/wg-agent/wg-agent.env ]]; then
  set -a
  # shellcheck source=/dev/null
  source /etc/wg-agent/wg-agent.env
  set +a
fi

PORT="${PORT:-50085}"
BIND_ADDRESS="${BIND_ADDRESS:-0.0.0.0}"

exec .venv/bin/uvicorn wg_agent:app --host "$BIND_ADDRESS" --port "$PORT"
