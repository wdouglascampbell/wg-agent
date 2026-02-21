# wg-agent

A small HTTP API that manages the **managed peers** section of WireGuard interface configs. Authorized clients can list interfaces, get the current managed peers, or replace the managed peers block for any configured interface. The agent applies changes live with `wg syncconf` and does not touch static (unmanaged) peers above the managed block.

Useful when a control plane (e.g. Xray or another service) needs to update WireGuard peers on this host without direct file or shell access.

---

## Overview

- **API:** FastAPI app; reads config from environment (`/etc/wg-agent/wg-agent.env`).
- **Config:** Port, allowed client IPs, and a list of managed interface names. Access is restricted by IP and by nftables.
- **WireGuard:** Each managed interface has a config under `/etc/wireguard/<name>.conf` with a `# BEGIN MANAGED PEERS` / `# END MANAGED PEERS` block. The agent only rewrites that block and runs `wg syncconf` for that interface.
- **Static peers:** Add fixed peers (e.g. a control-plane peer) with `add_peer.sh`; they live above the managed block and are not modified by the API.

---

## Prerequisites

- Linux host with WireGuard (`wg`, `wg-quick`), `nftables` (optional but recommended), and `systemd`.
- Python 3 with `venv` (for the agent).
- Root/sudo for setup and for running the agent (it reads/writes WireGuard configs and runs `wg syncconf`).

---

## Deployment

### 1. Clone or copy the repo to the server

```bash
# Example: clone into /opt/wg-agent (or any path you prefer)
git clone <your-repo-url> /opt/wg-agent
cd /opt/wg-agent
```

### 2. Run setup (interactive)

```bash
sudo ./setup.sh
```

Setup will:

- Create `/etc/wg-agent` and prompt for **listening port** (default `50085`) and **allowed client IPs** (comma- or space-separated). Only these IPs can call the API; the script also configures nftables to restrict the port to those IPs.
- If no interfaces are configured yet, prompt for at least one **WireGuard interface**: name (e.g. `wg-xray`) and **host tunnel IP** (the server’s address on that WireGuard interface). For each new interface it will:
  - Generate a key pair under `/etc/wireguard/`.
  - Create `/etc/wireguard/<name>.conf` with `[Interface]`, PostUp/PostDown (NAT via default-route interface), and a managed peers block.
  - Enable and start `wg-quick@<name>`.
- Write `/etc/wg-agent/wg-agent.env` (PORT, ALLOWED_CLIENT_IPS, INTERFACES).
- Install an nftables snippet (`wg_agent_filter` table) and, if `/etc/nftables.conf` exists, add an include for it; otherwise create a minimal `nftables.conf`. Then load rules and enable nftables.
- Create a Python venv (`.venv`), install dependencies from `requirements.txt`.
- Install the systemd unit `wg-agent.service` (enabled; not started by default).

Re-running setup is idempotent: it won’t overwrite existing config unless you choose to (e.g. overwrite an existing unmanaged or managed interface).

### 3. (Optional) Add a static peer

If you need a fixed peer (e.g. the control plane) that should not be managed by the API:

```bash
sudo ./add_peer.sh
```

You’ll choose the WireGuard interface (from a menu if `wg-agent.env` has INTERFACES), then enter the peer’s **public key**, **endpoint** (hostname or IP:port), and **AllowedIPs** (one or more CIDRs). The script inserts a `[Peer]` block immediately before `# BEGIN MANAGED PEERS` and runs `wg syncconf`. Run once per static peer (or as needed).

### 4. Start the agent

```bash
sudo systemctl start wg-agent
# Optional: already enabled by setup
sudo systemctl enable wg-agent
```

Check status:

```bash
sudo systemctl status wg-agent
```

**Watchdog:** Setup also installs a timer that checks the agent every 2 minutes. If `GET /health-local` (localhost-only, no auth) fails, it restarts `wg-agent`. The timer is enabled and started automatically. To inspect: `systemctl status wg-agent-watchdog.timer`.

The agent listens on the port configured in `wg-agent.env` (default `50085`), on all interfaces (`BIND_ADDRESS` defaults to `0.0.0.0`). To bind a specific address, set `BIND_ADDRESS` in `/etc/wg-agent/wg-agent.env` and restart the service.

---

## Configuration

- **File:** `/etc/wg-agent/wg-agent.env`
- **Variables:**
  - `PORT` – TCP port for the API (default in script: `50085`).
  - `ALLOWED_CLIENT_IPS` – Comma-separated list of client IPs allowed to call the API (and allowed through nftables to that port).
  - `INTERFACES` – Comma-separated list of WireGuard interface names the agent is allowed to manage.
  - `BIND_ADDRESS` – (Optional) Address to bind the API server. Default `0.0.0.0`. Set to a specific IP to listen only on that address.

After editing the env file, restart the service:

```bash
sudo systemctl restart wg-agent
```

---

## API usage

- **Base URL:** `http://<host>:<PORT>` (e.g. `http://192.168.250.1:50085`).
- **Authentication:** None (HTTP only). Access is restricted by **client IP**: only IPs in `ALLOWED_CLIENT_IPS` are allowed (enforced by the app and by nftables). Use TLS and/or a reverse proxy in front if you need encryption or additional auth.

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check. Returns `{"status":"ok"}`. Requires client IP in `ALLOWED_CLIENT_IPS`. |
| GET | `/health-local` | Health check for **localhost only** (127.0.0.1 / ::1). No auth. Used by the watchdog; returns 403 from other IPs. |
| GET | `/interfaces` | List configured interface names. Returns `{"interfaces":["wg-xray",...]}`. |
| GET | `/interfaces/{interface_name}/peers` | Get the current managed peers block (raw text) for that interface. |
| POST | `/interfaces/{interface_name}/peers` | Replace the managed peers block for that interface. Body: JSON array of peer objects. |

### Peer object (for POST)

Each element in the JSON array must have:

- `public_key` (string)
- `allowed_ips` (array of strings, e.g. `["192.168.74.1/32"]`)
- `endpoint` (string, e.g. `"hostname:51820"` or `"10.0.0.2:51820"`)

Example:

```bash
curl -X POST "http://192.168.250.1:50085/interfaces/wg-xray/peers" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "public_key": "1XcnvAe7qB7Hy1Qcj7DJjEzs/Lf+sHFrnB1m+c6bNR8=",
      "allowed_ips": ["192.168.74.1/32"],
      "endpoint": "test.xtoany.net:51820"
    }
  ]'
```

Response: `{"status":"success","interface":"wg-xray","num_peers":1}`.

If the client IP is not in `ALLOWED_CLIENT_IPS`, the API returns `403 Forbidden`. If the interface name is not in `INTERFACES`, it returns `404`.

---

## Scripts and files

| Item | Purpose |
|------|--------|
| `setup.sh` | Interactive setup: `/etc/wg-agent`, env, WireGuard interfaces (keys + config + wg-quick), nftables, venv, systemd unit. Run once (or re-run to add interfaces / change port or allowed IPs). Requires sudo. |
| `add_peer.sh` | Add one static (unmanaged) peer to a WireGuard config before the managed block. Run with sudo when you have the peer’s public key, endpoint, and AllowedIPs. |
| `run-wg-agent.sh` | Wrapper that sources `wg-agent.env` and runs `uvicorn wg_agent:app`. Used by the systemd unit. |
| `wg_agent.py` | FastAPI application and WireGuard managed-block logic. |
| `wg-agent.service` | Systemd unit template; setup installs it into `/etc/systemd/system/` with the correct paths. |
| `check-wg-agent-health.sh` | Watchdog script: curls `/health-local`, restarts `wg-agent` on failure. Run by the timer. |
| `wg-agent-watchdog.service` | One-shot unit that runs the health-check script. |
| `wg-agent-watchdog.timer` | Fires every 2 minutes to run the watchdog service. |
| `requirements.txt` | Python dependencies (fastapi, uvicorn). |

---

## Firewall (nftables)

Setup installs a table `inet wg_agent_filter` that:

- Accepts traffic to the agent port only from `ALLOWED_CLIENT_IPS`.
- Drops all other traffic to that port.

The snippet is written to `/etc/wg-agent/nftables-wg_agent_filter.nft`. If `/etc/nftables.conf` already exists, setup appends an `include` for that snippet and reloads; otherwise it creates a minimal `nftables.conf` and enables nftables. This keeps the agent port restricted even if the API is bound to `0.0.0.0`.

---

## License

Use and modify as needed for your environment.
