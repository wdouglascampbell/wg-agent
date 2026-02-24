#!/usr/bin/env bash
set -e

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with sudo (root privileges)." >&2
  exit 1
fi

CONFIG_DIR="/etc/wg-agent"
ENV_FILE="${CONFIG_DIR}/wg-agent.env"

# -----------------------------
# Input validation helpers
# -----------------------------
# Linux IFNAMSIZ is 16 (incl. null) => max 15 chars; allowed: alphanumeric, hyphen, underscore
MAX_IFACE_LEN=15
IFACE_PATTERN='^[a-zA-Z0-9_-]+$'

is_valid_port() {
  local port="$1"
  [[ -z "$port" ]] && return 1
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  (( port >= 1 && port <= 65535 )) || return 1
  return 0
}

# True if something is already listening on this port (TCP or UDP)
is_port_in_use() {
  local port="$1"
  if command -v ss &>/dev/null; then
    ss -tuln 2>/dev/null | grep -qE ":${port}[[:space:]]"
  else
    netstat -tuln 2>/dev/null | grep -qE ":${port}[[:space:]]"
  fi
}

is_valid_ipv4() {
  local ip="$1"
  [[ -z "$ip" ]] && return 1
  if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local o1 o2 o3 o4
    o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]}
    (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )) || return 1
    return 0
  fi
  return 1
}

is_valid_ipv6() {
  local ip="$1"
  [[ -z "$ip" ]] && return 1
  # Only hex digits and colons; must contain colon; max length for full IPv6
  [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
  [[ "$ip" == *:* ]] || return 1
  [[ ${#ip} -le 45 ]] || return 1
  return 0
}

is_valid_ip() {
  is_valid_ipv4 "$1" || is_valid_ipv6 "$1"
}

# Reserved/bad addresses for use as WireGuard tunnel (interface) address
is_reserved_tunnel_ip() {
  local ip="$1"
  if is_valid_ipv4 "$ip"; then
    # Reject 0.x.x.x, 127.x.x.x (loopback), 224+.x.x.x (multicast/reserved), 255.255.255.255
    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
      local o1=${BASH_REMATCH[1]}
      (( o1 == 0 )) && return 0   # 0.0.0.0/8
      (( o1 == 127 )) && return 0  # loopback
      (( o1 >= 224 )) && return 0  # multicast, reserved
      return 1
    fi
    return 1
  fi
  if is_valid_ipv6 "$ip"; then
    # Reject ::, ::1 (loopback), ff00::/8 (multicast)
    [[ "$ip" == "::" ]] && return 0
    [[ "$ip" == "::1" ]] && return 0
    [[ "$ip" =~ ^[fF][fF] ]] && return 0
    return 1
  fi
  return 1
}

is_valid_interface_name() {
  local name="$1"
  [[ -z "$name" ]] && return 1
  [[ ${#name} -le $MAX_IFACE_LEN ]] || return 1
  [[ "$name" =~ $IFACE_PATTERN ]] || return 1
  return 0
}

# Optional: reject duplicate interface name in current list (pass array as remaining args)
is_duplicate_interface() {
  local name="$1"
  shift
  local n
  for n in "$@"; do
    [[ "$n" == "$name" ]] && return 0
  done
  return 1
}

mkdir -p "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"
chown root:root "$CONFIG_DIR"

clear

declare -a INTERFACE_NAMES
HAD_INTERFACES_FROM_START=0
PORT=""
ALLOWED_CLIENT_IPS=""

if [[ -f "$ENV_FILE" ]]; then
  echo "Existing configuration found at $ENV_FILE"
  while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^PORT=(.*)$ ]]; then
      PORT="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^ALLOWED_CLIENT_IPS=(.*)$ ]]; then
      ALLOWED_CLIENT_IPS="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^INTERFACES=(.*)$ ]]; then
      for name in ${BASH_REMATCH[1]//,/ }; do
        name=$(echo "$name" | xargs)
        [[ -n "$name" ]] && INTERFACE_NAMES+=("$name")
      done
    fi
  done < "$ENV_FILE"

  # Offer to update ALLOWED_CLIENT_IPS when we have an existing list
  if [[ -n "$ALLOWED_CLIENT_IPS" ]]; then
    echo ""
    echo "Current ALLOWED_CLIENT_IPS: $ALLOWED_CLIENT_IPS"
    echo "  (1) Keep as-is"
    echo "  (2) Add one IP to the list"
    echo "  (3) Replace with new list (full edit)"
    read -r -p "Choice [1]: " aip_choice
    aip_choice="${aip_choice:-1}"
    case "$aip_choice" in
      2)
        read -r -p "IP to add (IPv4 or IPv6): " new_ip
        new_ip=$(echo "$new_ip" | xargs)
        if [[ -n "$new_ip" ]] && is_valid_ip "$new_ip"; then
          ALLOWED_CLIENT_IPS=$(echo "$ALLOWED_CLIENT_IPS" | tr ',' ' ' | xargs)
          ALLOWED_CLIENT_IPS=$(echo "$ALLOWED_CLIENT_IPS $new_ip" | xargs | tr ' ' ',')
        else
          [[ -n "$new_ip" ]] && echo "Invalid IP; keeping existing list." >&2
        fi
        ;;
      3)
        echo "Enter new comma- or space-separated list (replaces current)."
        while true; do
          read -r -p "Allowed client IPs: " input_ips
          ALLOWED_CLIENT_IPS=$(echo "$input_ips" | tr ',' ' ' | xargs)
          if [[ -z "$ALLOWED_CLIENT_IPS" ]]; then
            echo "At least one allowed client IP is required." >&2
            continue
          fi
          bad=""
          for ip in $ALLOWED_CLIENT_IPS; do
            if ! is_valid_ip "$ip"; then
              bad="$bad $ip"
            fi
          done
          if [[ -n "$bad" ]]; then
            echo "Invalid IP address(es):$bad (use valid IPv4 or IPv6)." >&2
            continue
          fi
          break
        done
        ALLOWED_CLIENT_IPS=$(echo "$ALLOWED_CLIENT_IPS" | tr ' ' ',')
        ;;
      *) ;; # 1 or default: keep as-is
    esac
  fi
  HAD_INTERFACES_FROM_START=${#INTERFACE_NAMES[@]}
fi

# -----------------------------
# Prompt for PORT and ALLOWED_CLIENT_IPS if no env yet
# -----------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  echo ""
  echo "No wg-agent.env found. Please provide the following."
  echo ""

  default_port="50085"
  while true; do
    read -r -p "Listening port [$default_port]: " input_port
    PORT="${input_port:-$default_port}"
    if ! is_valid_port "$PORT"; then
      echo "Invalid port. Enter a number between 1 and 65535." >&2
      continue
    fi
    if is_port_in_use "$PORT"; then
      read -r -p "Port $PORT is already in use. Proceed anyway? [y/N]: " proceed
      if [[ "${proceed,,}" =~ ^y(es)?$ ]]; then
        break
      fi
      continue
    fi
    break
  done

  echo "Enter client IPs allowed to access the agent (comma- or space-separated)."
  while true; do
    read -r -p "Allowed client IPs: " input_ips
    ALLOWED_CLIENT_IPS=$(echo "$input_ips" | tr ',' ' ' | xargs)
    if [[ -z "$ALLOWED_CLIENT_IPS" ]]; then
      echo "At least one allowed client IP is required." >&2
      continue
    fi
    bad=""
    for ip in $ALLOWED_CLIENT_IPS; do
      if ! is_valid_ip "$ip"; then
        bad="$bad $ip"
      fi
    done
    if [[ -n "$bad" ]]; then
      echo "Invalid IP address(es):$bad (use valid IPv4 or IPv6)." >&2
      continue
    fi
    break
  done
  # Store as comma-separated in env
  ALLOWED_CLIENT_IPS=$(echo "$ALLOWED_CLIENT_IPS" | tr ' ' ',')
fi

# -----------------------------
# If no interface configured, prompt for at least one (and optionally more)
# -----------------------------
WG_DIR="/etc/wireguard"

create_or_overwrite_wg_interface() {
  local iface_name="$1"
  local iface_addr="$2"
  local already_managed="${3:-}"
  local wg_conf="${WG_DIR}/${iface_name}.conf"

  # If not overwriting an already-managed interface, check for existing (unmanaged) config
  if [[ "$already_managed" != "already_managed" ]]; then
    if [[ -f "$wg_conf" ]]; then
      read -r -p "A WireGuard config already exists for $iface_name. Overwrite the current (unmanaged) configuration? [y/N]: " overwrite
      if [[ ! "${overwrite,,}" =~ ^y(es)?$ ]]; then
        echo "Skipping WireGuard config creation for $iface_name (existing config left unchanged)."
        return 0
      fi
    fi
  fi

  # External interface for NAT (used in PostUp/PostDown)
  ext_if=$(ip route | awk '/default/ {print $5; exit}')
  if [[ -z "$ext_if" ]]; then
    echo "Could not detect default route interface." >&2
    return 1
  fi

  mkdir -p "$WG_DIR"

  # Generate key pair only if we don't already have one (e.g. when overwriting managed, keep existing keys)
  if [[ ! -f "${WG_DIR}/${iface_name}-privatekey" ]]; then
    wg genkey | tee "${WG_DIR}/${iface_name}-privatekey" | wg pubkey > "${WG_DIR}/${iface_name}-publickey"
    chmod 600 "${WG_DIR}/${iface_name}-privatekey" "${WG_DIR}/${iface_name}-publickey"
    # Set SELinux context (script-created files can get unconfined_u; force system_u:object_r:etc_t:s0)
    chcon system_u:object_r:etc_t:s0 "${WG_DIR}/${iface_name}-privatekey" "${WG_DIR}/${iface_name}-publickey" 2>/dev/null || true
  fi

  privatekey=$(cat "${WG_DIR}/${iface_name}-privatekey")

  # Write WireGuard config
  cat > "$wg_conf" << EOF
[Interface]
Address = ${iface_addr}/32
PrivateKey = ${privatekey}
PostUp = iptables -A FORWARD -i ${iface_name} -o ${ext_if} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${ext_if} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${iface_name} -o ${ext_if} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${ext_if} -j MASQUERADE

# BEGIN MANAGED PEERS
# END MANAGED PEERS
EOF

  systemctl enable "wg-quick@${iface_name}"
  systemctl start "wg-quick@${iface_name}"
  echo "Created $wg_conf and started wg-quick@${iface_name}."
}

if [[ ${#INTERFACE_NAMES[@]} -eq 0 ]]; then
  echo ""
  echo "No WireGuard interface is configured yet. Please add at least one."
  echo ""

  while true; do
    read -r -p "Interface name (e.g. wg-tunnel): " iface_name
    if ! is_valid_interface_name "$iface_name"; then
      if [[ -z "$iface_name" ]]; then
        echo "Interface name cannot be empty."
      elif [[ ${#iface_name} -gt $MAX_IFACE_LEN ]]; then
        echo "Interface name must be at most $MAX_IFACE_LEN characters (Linux limit)."
      else
        echo "Interface name may only contain letters, numbers, hyphens, and underscores."
      fi
      continue
    fi
    # Already managed (in .env or added this run): warn early and ask to overwrite
    if is_duplicate_interface "$iface_name" "${INTERFACE_NAMES[@]}"; then
      read -r -p "Interface '$iface_name' is already managed. Overwrite its configuration? [y/N]: " overwrite_managed
      if [[ ! "${overwrite_managed,,}" =~ ^y(es)?$ ]]; then
        continue
      fi
      # Default: current Address from existing .conf if present
      current_addr=""
      if [[ -f "${WG_DIR}/${iface_name}.conf" ]]; then
        current_addr=$(grep -m1 "^Address" "${WG_DIR}/${iface_name}.conf" 2>/dev/null | sed "s/.*=[ \t]*//;s/\/.*//")
      fi
      echo "Host tunnel IP: the IP address this host will have on this WireGuard interface (the tunnel-side address for this server)."
      read -r -p "Host tunnel IP for $iface_name [${current_addr:-}]: " iface_addr
      iface_addr="${iface_addr:-$current_addr}"
      if ! is_valid_ip "$iface_addr"; then
        echo "Invalid IP address. Enter a valid IPv4 or IPv6 address."
        continue
      fi
      if is_reserved_tunnel_ip "$iface_addr"; then
        echo "That address is reserved (e.g. loopback, multicast, 0.0.0.0). Use a unicast tunnel address."
        continue
      fi
      create_or_overwrite_wg_interface "$iface_name" "$iface_addr" "already_managed" || continue
    else
      echo "Host tunnel IP: the IP address this host will have on this WireGuard interface (the tunnel-side address for this server)."
      read -r -p "Host tunnel IP for $iface_name: " iface_addr
      if ! is_valid_ip "$iface_addr"; then
        echo "Invalid IP address. Enter a valid IPv4 or IPv6 address."
        continue
      fi
      if is_reserved_tunnel_ip "$iface_addr"; then
        echo "That address is reserved (e.g. loopback, multicast, 0.0.0.0). Use a unicast tunnel address."
        continue
      fi

      create_or_overwrite_wg_interface "$iface_name" "$iface_addr" || continue

      INTERFACE_NAMES+=("$iface_name")
    fi

    read -r -p "Add another interface? [y/N]: " add_more
    if [[ ! "${add_more,,}" =~ ^y(es)?$ ]]; then
      break
    fi
    echo ""
  done
fi

# -----------------------------
# When we already had interfaces at start (e.g. from .env), offer to add more
# -----------------------------
if [[ $HAD_INTERFACES_FROM_START -gt 0 ]]; then
  while true; do
    read -r -p "Add another WireGuard interface? [y/N]: " add_more
    if [[ ! "${add_more,,}" =~ ^y(es)?$ ]]; then
      break
    fi
    echo ""
    read -r -p "Interface name (e.g. wg-tunnel): " iface_name
    if ! is_valid_interface_name "$iface_name"; then
      if [[ -z "$iface_name" ]]; then
        echo "Interface name cannot be empty."
      elif [[ ${#iface_name} -gt $MAX_IFACE_LEN ]]; then
        echo "Interface name must be at most $MAX_IFACE_LEN characters (Linux limit)."
      else
        echo "Interface name may only contain letters, numbers, hyphens, and underscores."
      fi
      continue
    fi
    if is_duplicate_interface "$iface_name" "${INTERFACE_NAMES[@]}"; then
      read -r -p "Interface '$iface_name' is already managed. Overwrite its configuration? [y/N]: " overwrite_managed
      if [[ ! "${overwrite_managed,,}" =~ ^y(es)?$ ]]; then
        continue
      fi
      current_addr=""
      if [[ -f "${WG_DIR}/${iface_name}.conf" ]]; then
        current_addr=$(grep -m1 "^Address" "${WG_DIR}/${iface_name}.conf" 2>/dev/null | sed "s/.*=[ \t]*//;s/\/.*//")
      fi
      echo "Host tunnel IP: the IP address this host will have on this WireGuard interface (the tunnel-side address for this server)."
      read -r -p "Host tunnel IP for $iface_name [${current_addr:-}]: " iface_addr
      iface_addr="${iface_addr:-$current_addr}"
      if ! is_valid_ip "$iface_addr"; then
        echo "Invalid IP address. Enter a valid IPv4 or IPv6 address."
        continue
      fi
      if is_reserved_tunnel_ip "$iface_addr"; then
        echo "That address is reserved (e.g. loopback, multicast, 0.0.0.0). Use a unicast tunnel address."
        continue
      fi
      create_or_overwrite_wg_interface "$iface_name" "$iface_addr" "already_managed" || continue
    else
      echo "Host tunnel IP: the IP address this host will have on this WireGuard interface (the tunnel-side address for this server)."
      read -r -p "Host tunnel IP for $iface_name: " iface_addr
      if ! is_valid_ip "$iface_addr"; then
        echo "Invalid IP address. Enter a valid IPv4 or IPv6 address."
        continue
      fi
      if is_reserved_tunnel_ip "$iface_addr"; then
        echo "That address is reserved (e.g. loopback, multicast, 0.0.0.0). Use a unicast tunnel address."
        continue
      fi
      create_or_overwrite_wg_interface "$iface_name" "$iface_addr" || continue
      INTERFACE_NAMES+=("$iface_name")
    fi
    echo ""
  done
fi

# -----------------------------
# Ensure we have PORT and ALLOWED_CLIENT_IPS when we had existing env (only interfaces)
# -----------------------------
if [[ -f "$ENV_FILE" ]] && [[ -z "$PORT" ]]; then
  default_port="50085"
  while true; do
    read -r -p "Listening port [$default_port]: " input_port
    PORT="${input_port:-$default_port}"
    if ! is_valid_port "$PORT"; then
      echo "Invalid port. Enter a number between 1 and 65535." >&2
      continue
    fi
    if is_port_in_use "$PORT"; then
      read -r -p "Port $PORT is already in use. Proceed anyway? [y/N]: " proceed
      if [[ "${proceed,,}" =~ ^y(es)?$ ]]; then
        break
      fi
      continue
    fi
    break
  done
fi
if [[ -f "$ENV_FILE" ]] && [[ -z "$ALLOWED_CLIENT_IPS" ]]; then
  while true; do
    read -r -p "Allowed client IPs (comma- or space-separated): " input_ips
    ALLOWED_CLIENT_IPS=$(echo "$input_ips" | tr ',' ' ' | xargs)
    if [[ -z "$ALLOWED_CLIENT_IPS" ]]; then
      echo "At least one allowed client IP is required." >&2
      continue
    fi
    bad=""
    for ip in $ALLOWED_CLIENT_IPS; do
      if ! is_valid_ip "$ip"; then
        bad="$bad $ip"
      fi
    done
    if [[ -n "$bad" ]]; then
      echo "Invalid IP address(es):$bad (use valid IPv4 or IPv6)." >&2
      continue
    fi
    break
  done
  ALLOWED_CLIENT_IPS=$(echo "$ALLOWED_CLIENT_IPS" | tr ' ' ',')
fi

# -----------------------------
# Write wg-agent.env
# -----------------------------
{
  echo "# wg-agent configuration (generated by setup.sh)"
  echo "PORT=${PORT}"
  echo "ALLOWED_CLIENT_IPS=${ALLOWED_CLIENT_IPS}"
  # Comma-separated list of interface names
  printf -v interfaces_comma "%s," "${INTERFACE_NAMES[@]}"
  echo "INTERFACES=${interfaces_comma%,}"
} > "$ENV_FILE"

chmod 644 "$ENV_FILE"
chown root:root "$ENV_FILE"

# -----------------------------
# nftables firewall rules for wg-agent port (idempotent)
# -----------------------------
NFT_SNIPPET="${CONFIG_DIR}/nftables-wg_agent_filter.nft"
# Build accept rules from ALLOWED_CLIENT_IPS (ip saddr for IPv4, ip6 saddr for IPv6)
accept_rules=""
for ip in ${ALLOWED_CLIENT_IPS//,/ }; do
  ip=$(echo "$ip" | xargs)
  [[ -z "$ip" ]] && continue
  if [[ "$ip" == *:* ]]; then
    accept_rules="${accept_rules}        tcp dport $PORT ip6 saddr $ip accept
"
  else
    accept_rules="${accept_rules}        tcp dport $PORT ip saddr $ip accept
"
  fi
done
cat > "$NFT_SNIPPET" << EOF
# wg-agent: restrict agent port to allowed client IPs (generated by setup.sh)
table inet wg_agent_filter {
    chain input {
        type filter hook input priority -10;
        policy accept;

${accept_rules}        # Drop all other attempts to that port
        tcp dport $PORT drop
    }
}
EOF
chmod 644 "$NFT_SNIPPET"
chown root:root "$NFT_SNIPPET"

if [[ ! -f /etc/nftables.conf ]]; then
  echo "Creating /etc/nftables.conf with wg-agent wg_agent_filter rules ..."
  cat > /etc/nftables.conf << EOF
# Minimal nftables config (created by wg-agent setup)
flush ruleset
include "$NFT_SNIPPET"
EOF
else
  # Add our include for persistence if not already present (idempotent).
  if ! grep -q "nftables-wg_agent_filter.nft" /etc/nftables.conf 2>/dev/null; then
    echo "Adding wg-agent include to /etc/nftables.conf for persistence."
    printf "\n# wg-agent (setup.sh)\ninclude \"%s\"\n" "$NFT_SNIPPET" >> /etc/nftables.conf
  else
    echo "wg-agent include already present in /etc/nftables.conf."
  fi
fi
# Load rules and enable nftables (idempotent: safe to run every time)
if command -v nft &>/dev/null; then
  nft delete table inet wg_agent_filter 2>/dev/null || true
  nft -f /etc/nftables.conf
fi
if command -v systemctl &>/dev/null; then
  systemctl enable --quiet nftables 2>/dev/null || true
fi

# -----------------------------
# Python virtual environment for wg_agent.py (idempotent)
# -----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
  echo "Creating Python virtual environment at $VENV_DIR ..."
  python3 -m venv "$VENV_DIR"
fi
if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
  echo "Ensuring Python requirements are installed (idempotent) ..."
  "${VENV_DIR}/bin/pip" install -q --upgrade pip
  "${VENV_DIR}/bin/pip" install -q -r "${SCRIPT_DIR}/requirements.txt"
else
  echo "No requirements.txt found; skipping pip install."
fi

# -----------------------------
# systemd wg-agent service (idempotent)
# -----------------------------
if [[ -f "${SCRIPT_DIR}/wg-agent.service" ]]; then
  sed "s|INSTALL_DIR|${SCRIPT_DIR}|g" "${SCRIPT_DIR}/wg-agent.service" > /etc/systemd/system/wg-agent.service
  chmod 644 /etc/systemd/system/wg-agent.service
  if [[ -f "${SCRIPT_DIR}/run-wg-agent.sh" ]]; then
    chmod 755 "${SCRIPT_DIR}/run-wg-agent.sh"
    chown root:root "${SCRIPT_DIR}/run-wg-agent.sh"
  fi
  systemctl daemon-reload
  systemctl enable --quiet wg-agent 2>/dev/null || true
  echo "wg-agent systemd unit installed and enabled (start with: systemctl start wg-agent)."
fi

# -----------------------------
# systemd wg-agent watchdog (idempotent)
# -----------------------------
if [[ -f "${SCRIPT_DIR}/wg-agent-watchdog.service" ]] && [[ -f "${SCRIPT_DIR}/wg-agent-watchdog.timer" ]]; then
  sed "s|INSTALL_DIR|${SCRIPT_DIR}|g" "${SCRIPT_DIR}/wg-agent-watchdog.service" > /etc/systemd/system/wg-agent-watchdog.service
  cp "${SCRIPT_DIR}/wg-agent-watchdog.timer" /etc/systemd/system/wg-agent-watchdog.timer
  chmod 644 /etc/systemd/system/wg-agent-watchdog.service /etc/systemd/system/wg-agent-watchdog.timer
  if [[ -f "${SCRIPT_DIR}/check-wg-agent-health.sh" ]]; then
    chmod 755 "${SCRIPT_DIR}/check-wg-agent-health.sh"
    chown root:root "${SCRIPT_DIR}/check-wg-agent-health.sh"
  fi
  systemctl daemon-reload
  systemctl enable --quiet wg-agent-watchdog.timer 2>/dev/null || true
  systemctl start --quiet wg-agent-watchdog.timer 2>/dev/null || true
  echo "wg-agent watchdog timer installed and enabled (checks /health-local every 2 min, restarts service on failure)."
fi

echo ""
echo "Configuration written to $ENV_FILE"
echo "PORT=$PORT"
echo "ALLOWED_CLIENT_IPS=$ALLOWED_CLIENT_IPS"
echo "Interfaces: ${INTERFACE_NAMES[*]}"
echo ""

if [[ ${#INTERFACE_NAMES[@]} -gt 0 ]]; then
  echo "--- Tunnel public keys and tunnel IPs (this host) ---"
  echo "Use these to configure the other end of each tunnel (e.g. on the control plane)."
  echo ""
  for iface in "${INTERFACE_NAMES[@]}"; do
    pubkey_file="${WG_DIR}/${iface}-publickey"
    wg_conf="${WG_DIR}/${iface}.conf"
    if [[ -f "$pubkey_file" ]]; then
      pubkey=$(cat "$pubkey_file")
      tunnel_addr=""
      if [[ -f "$wg_conf" ]]; then
        tunnel_addr=$(grep -m1 "^Address" "$wg_conf" 2>/dev/null | sed "s/.*=[ \t]*//")
      fi
      echo "  $iface:"
      echo "    PublicKey: $pubkey"
      if [[ -n "$tunnel_addr" ]]; then
        echo "    Tunnel IP (this host): $tunnel_addr"
      fi
      echo ""
    fi
  done
  echo "On the control plane (other end), add this host as a peer with the public key above. In AllowedIPs include at least the tunnel IP for this host on that interface (you may add other ranges as needed)."
  echo ""
fi

echo "Done."
