#!/usr/bin/env bash
# Add a static (unmanaged) peer to a managed WireGuard interface config.

set -e

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with sudo (root privileges)." >&2
  exit 1
fi

MANAGED_MARKER="# BEGIN MANAGED PEERS"
CONFIG_DIR="/etc/wg-agent"
ENV_FILE="${CONFIG_DIR}/wg-agent.env"
WG_DIR="/etc/wireguard"

# Load managed interface names from wg-agent.env
declare -a INTERFACES
if [[ -f "$ENV_FILE" ]]; then
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^INTERFACES=(.*)$ ]]; then
      for name in ${BASH_REMATCH[1]//,/ }; do
        name=$(echo "$name" | xargs)
        [[ -n "$name" ]] && INTERFACES+=("$name")
      done
      break
    fi
  done < "$ENV_FILE"
fi

# Choose interface: menu if we have a list, otherwise prompt
iface=""
if [[ ${#INTERFACES[@]} -gt 0 ]]; then
  echo "Managed WireGuard interfaces:"
  for i in "${!INTERFACES[@]}"; do
    echo "  $((i+1))) ${INTERFACES[$i]}"
  done
  echo "  $(( ${#INTERFACES[@]} + 1 ))) Enter interface name manually"
  echo ""
  read -r -p "Select interface (1-$(( ${#INTERFACES[@]} + 1 ))): " choice
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    idx=$((choice - 1))
    if (( idx >= 0 && idx < ${#INTERFACES[@]} )); then
      iface="${INTERFACES[$idx]}"
    elif (( idx == ${#INTERFACES[@]} )); then
      read -r -p "Interface name: " iface
    fi
  fi
else
  read -r -p "WireGuard interface name: " iface
fi

if [[ -z "$iface" ]]; then
  echo "No interface selected." >&2
  exit 1
fi

CONFIG_PATH="${WG_DIR}/${iface}.conf"
if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Config not found: $CONFIG_PATH" >&2
  exit 1
fi

if ! grep -q "$MANAGED_MARKER" "$CONFIG_PATH"; then
  echo "Config does not contain $MANAGED_MARKER; cannot safely insert peer." >&2
  exit 1
fi

echo ""
read -r -p "Peer public key: " public_key
if [[ -z "$public_key" ]]; then
  echo "Public key is required." >&2
  exit 1
fi

read -r -p "Peer endpoint (hostname or IP:port, e.g. test.xtoany.net:51820): " endpoint
if [[ -z "$endpoint" ]]; then
  echo "Endpoint is required." >&2
  exit 1
fi

read -r -p "AllowedIPs (e.g. 192.168.71.1/32 or comma-separated): " allowed_ips
if [[ -z "$allowed_ips" ]]; then
  echo "AllowedIPs is required." >&2
  exit 1
fi
# Normalize: trim spaces around commas
allowed_ips=$(echo "$allowed_ips" | tr ',' ' ' | xargs | tr ' ' ',')

# Insert new [Peer] block before the first occurrence of MANAGED_MARKER
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
inserted=0
while IFS= read -r line; do
  if [[ "$line" == "$MANAGED_MARKER" ]] && [[ $inserted -eq 0 ]]; then
    echo "[Peer]"
    echo "PublicKey = ${public_key}"
    echo "Endpoint = ${endpoint}"
    echo "AllowedIPs = ${allowed_ips}"
    echo "PersistentKeepalive = 25"
    echo ""
    inserted=1
  fi
  echo "$line"
done < "$CONFIG_PATH" > "$tmp"

# Validate with wg-quick
if ! wg-quick strip "$tmp" --dry-run &>/dev/null; then
  echo "Generated config failed validation (wg-quick strip --dry-run)." >&2
  exit 1
fi

cp "$tmp" "$CONFIG_PATH"
echo "Peer added to $CONFIG_PATH. Applying with wg syncconf..."
wg syncconf "$iface" "$CONFIG_PATH"
echo "Done."
