#!/usr/bin/env bash
# Watchdog: check wg-agent health and restart the service if the check fails.
# Called by wg-agent-watchdog.timer. Uses /health-local (localhost-only, no auth).

set -e

CONFIG_DIR="/etc/wg-agent"
ENV_FILE="${CONFIG_DIR}/wg-agent.env"
PORT="${PORT:-50085}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

PORT="${PORT:-50085}"
URL="http://127.0.0.1:${PORT}/health-local"

if curl -sf --connect-timeout 5 --max-time 10 "$URL" >/dev/null; then
  exit 0
fi

echo "wg-agent health check failed, restarting service"
systemctl restart wg-agent
