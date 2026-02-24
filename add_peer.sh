#!/usr/bin/env bash
# Add a static (unmanaged) peer to a managed WireGuard interface config.

set -e

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with sudo (root privileges)." >&2
  exit 1
fi

clear

MANAGED_MARKER="# BEGIN MANAGED PEERS"
CONFIG_DIR="/etc/wg-agent"
ENV_FILE="${CONFIG_DIR}/wg-agent.env"
WG_DIR="/etc/wireguard"

# Load managed interface names from wg-agent.env
declare -a INTERFACES
if [[ -f "$ENV_FILE" ]]; then
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
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
public_key=$(echo "$public_key" | xargs)
if [[ -z "$public_key" ]]; then
  echo "Public key is required." >&2
  exit 1
fi

# Check for duplicate: find existing peer with this public key and get current Endpoint/AllowedIPs
current_endpoint=""
current_allowed_ips=""
in_peer=0
peer_key=""
while IFS= read -r line; do
  if [[ "$line" =~ ^\[Peer\] ]]; then
    in_peer=1
    current_endpoint=""
    current_allowed_ips=""
    peer_key=""
  fi
  if [[ $in_peer -eq 1 ]]; then
    if [[ "$line" =~ ^PublicKey[[:space:]]*=[[:space:]]*(.*) ]]; then
      peer_key=$(echo "${BASH_REMATCH[1]}" | xargs)
    fi
    if [[ "$line" =~ ^Endpoint[[:space:]]*=[[:space:]]*(.*) ]]; then
      current_endpoint=$(echo "${BASH_REMATCH[1]}" | xargs)
    fi
    if [[ "$line" =~ ^AllowedIPs[[:space:]]*=[[:space:]]*(.*) ]]; then
      current_allowed_ips=$(echo "${BASH_REMATCH[1]}" | xargs)
    fi
    if [[ "$line" =~ ^\[ ]] && ! [[ "$line" =~ ^\[Peer\] ]]; then
      in_peer=0
    fi
  fi
done < "$CONFIG_PATH"

# If we found a peer with this key (use -F so + and = in key are literal)
if grep -qF "PublicKey = ${public_key}" "$CONFIG_PATH" || grep -qF "PublicKey=${public_key}" "$CONFIG_PATH"; then
  echo ""
  echo "Warning: A peer with this public key already exists." >&2
  read -r -p "Edit existing peer? [y/N]: " edit_choice
  if [[ ! "${edit_choice,,}" =~ ^y(es)?$ ]]; then
    echo "Aborted." >&2
    exit 0
  fi
  # Re-read to get current Endpoint/AllowedIPs for this peer
  current_endpoint=""
  current_allowed_ips=""
  in_peer=0
  peer_key=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^\[Peer\] ]]; then
      in_peer=1
      current_endpoint=""
      current_allowed_ips=""
      peer_key=""
    fi
    if [[ $in_peer -eq 1 ]]; then
      if [[ "$line" =~ ^PublicKey[[:space:]]*=[[:space:]]*(.*) ]]; then
        peer_key=$(echo "${BASH_REMATCH[1]}" | xargs)
      fi
      if [[ "$peer_key" == "$public_key" ]]; then
        if [[ "$line" =~ ^Endpoint[[:space:]]*=[[:space:]]*(.*) ]]; then
          current_endpoint=$(echo "${BASH_REMATCH[1]}" | xargs)
        fi
        if [[ "$line" =~ ^AllowedIPs[[:space:]]*=[[:space:]]*(.*) ]]; then
          current_allowed_ips=$(echo "${BASH_REMATCH[1]}" | xargs)
        fi
      fi
      if [[ "$line" =~ ^\[ ]] && ! [[ "$line" =~ ^\[Peer\] ]]; then
        in_peer=0
      fi
    fi
  done < "$CONFIG_PATH"
  echo ""
  read -r -p "Endpoint [${current_endpoint:-}]: " endpoint_input
  endpoint=$(echo "$endpoint_input" | xargs)
  endpoint="${endpoint:-$current_endpoint}"
  read -r -p "AllowedIPs [${current_allowed_ips:-}]: " allowed_input
  allowed_ips=$(echo "$allowed_input" | xargs)
  allowed_ips="${allowed_ips:-$current_allowed_ips}"
  if [[ -z "$endpoint" ]] || [[ -z "$allowed_ips" ]]; then
    echo "Endpoint and AllowedIPs are required." >&2
    exit 1
  fi
  allowed_ips=$(echo "$allowed_ips" | tr ',' ' ' | xargs | tr ' ' ',')
  update_existing=1
else
  read -r -p "Peer endpoint (hostname or IP:port, e.g. yourdomain.com:51820): " endpoint
  if [[ -z "$endpoint" ]]; then
    echo "Endpoint is required." >&2
    exit 1
  fi

  read -r -p "AllowedIPs (e.g. 192.168.71.1/32 or comma-separated): " allowed_ips
  if [[ -z "$allowed_ips" ]]; then
    echo "AllowedIPs is required." >&2
    exit 1
  fi
  allowed_ips=$(echo "$allowed_ips" | tr ',' ' ' | xargs | tr ' ' ',')
  update_existing=0
fi

# Build new config: either insert new peer or update existing peer block
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
tmp="${tmpdir}/${iface}.conf"

if [[ "${update_existing:-0}" -eq 1 ]]; then
  # Update: copy config, replacing Endpoint and AllowedIPs in the matching [Peer] block
  in_peer=0
  peer_matched=0
  while IFS= read -r line; do
    if [[ "$line" =~ ^\[Peer\] ]]; then
      in_peer=1
      peer_matched=0
      echo "$line"
      continue
    fi
    if [[ $in_peer -eq 1 ]]; then
      if [[ "$line" =~ ^PublicKey[[:space:]]*=[[:space:]]*(.*) ]]; then
        pk=$(echo "${BASH_REMATCH[1]}" | xargs)
        [[ "$pk" == "$public_key" ]] && peer_matched=1
      fi
      if [[ $peer_matched -eq 1 ]]; then
        if [[ "$line" =~ ^Endpoint[[:space:]]*= ]]; then
          echo "Endpoint = ${endpoint}"
          continue
        fi
        if [[ "$line" =~ ^AllowedIPs[[:space:]]*= ]]; then
          echo "AllowedIPs = ${allowed_ips}"
          continue
        fi
      fi
    fi
    if [[ "$line" =~ ^\[ ]] && ! [[ "$line" =~ ^\[Peer\] ]]; then
      in_peer=0
    fi
    echo "$line"
  done < "$CONFIG_PATH" > "$tmp"
else
  # Insert new [Peer] block before the first occurrence of MANAGED_MARKER
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
fi

# Validate with wg-quick strip
if ! wg-quick strip "$tmp" &>/dev/null; then
  echo "Generated config failed validation (wg-quick strip)." >&2
  exit 1
fi

cp "$tmp" "$CONFIG_PATH"
echo "Peer added to $CONFIG_PATH. Applying with wg syncconf..."
wg syncconf "$iface" <(wg-quick strip "$CONFIG_PATH")
echo "Done."
