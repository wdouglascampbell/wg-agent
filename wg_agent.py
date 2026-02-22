from fastapi import FastAPI, Request, HTTPException, Body
import os
import re
import subprocess
from typing import List

# -----------------------------
# Configuration (from environment, set by run-wg-agent.sh via wg-agent.env)
# -----------------------------
MANAGED_START = "# BEGIN MANAGED PEERS"
MANAGED_END = "# END MANAGED PEERS"

def _load_config() -> dict:
    """Load configuration from environment. Called at request time so env is available."""
    raw_ips = os.environ.get("ALLOWED_CLIENT_IPS", "")
    allowed_client_ips = [s.strip() for s in raw_ips.split(",") if s.strip()]

    raw_interfaces = os.environ.get("INTERFACES", "")
    interface_names = [s.strip() for s in raw_interfaces.split(",") if s.strip()]

    return {
        "allowed_client_ips": allowed_client_ips,
        "interface_names": interface_names,
    }

def get_config() -> dict:
    return _load_config()

def get_config_path(interface_name: str) -> str:
    return f"/etc/wireguard/{interface_name}.conf"

app = FastAPI(title="wg-agent")

# -----------------------------
# Utility Functions
# -----------------------------
def validate_client_ip(request: Request) -> None:
    config = get_config()
    client_ip = request.client.host
    if client_ip not in config["allowed_client_ips"]:
        raise HTTPException(status_code=403, detail="Forbidden")

def validate_interface(interface_name: str) -> None:
    """Raise 404 if interface is not configured."""
    config = get_config()
    if interface_name not in config["interface_names"]:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown interface: {interface_name}. Configured: {config['interface_names']}",
        )

def parse_managed_block(interface_name: str) -> List[dict]:
    """Parse the managed peers section into a list of peer dicts (public_key, allowed_ips, endpoint)."""
    config_path = get_config_path(interface_name)
    with open(config_path, "r") as f:
        content = f.read()
    try:
        start_idx = content.index(MANAGED_START)
        end_idx = content.index(MANAGED_END) + len(MANAGED_END)
    except ValueError:
        raise RuntimeError("Managed peers markers not found in config")
    managed_section = content[start_idx:end_idx]

    peers = []
    # Split on [Peer] blocks; strip markers from content
    block_text = managed_section
    for marker in (MANAGED_START, MANAGED_END):
        block_text = block_text.replace(marker, "").strip()
    if not block_text.strip():
        return peers

    raw_blocks = re.split(r"\n\[Peer\]\s*\n", block_text, flags=re.IGNORECASE)
    for raw in raw_blocks:
        raw = raw.strip()
        if not raw:
            continue
        peer = {}
        for line in raw.split("\n"):
            line = line.strip()
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()
                if key == "publickey":
                    peer["public_key"] = value
                elif key == "endpoint":
                    peer["endpoint"] = value
                elif key == "allowedips":
                    peer["allowed_ips"] = [s.strip() for s in value.split(",") if s.strip()]
        if peer.get("public_key") and peer.get("allowed_ips") is not None and peer.get("endpoint"):
            peers.append(peer)
    return peers


def rewrite_managed_block(interface_name: str, peers: List[dict]) -> None:
    """
    Rewrite the managed peers section for the given interface.
    peers: list of dicts with public_key, allowed_ips, endpoint (optional persistent_keepalive).
    """
    config_path = get_config_path(interface_name)

    for p in peers:
        if "public_key" not in p or not p["public_key"]:
            raise ValueError("Each peer must have a 'public_key'")
        if "allowed_ips" not in p or not p["allowed_ips"]:
            raise ValueError("Each peer must have 'allowed_ips'")
        if "endpoint" not in p or not p["endpoint"]:
            raise ValueError("Each peer must have 'endpoint'")

    with open(config_path, "r") as f:
        content = f.read()

    try:
        start_idx = content.index(MANAGED_START)
        end_idx = content.index(MANAGED_END) + len(MANAGED_END)
    except ValueError:
        raise RuntimeError("Managed peers markers not found in config")

    static_part = content[:start_idx]
    footer = content[end_idx:]

    managed_section = MANAGED_START + "\n"
    for p in peers:
        managed_section += f"[Peer]\nPublicKey = {p['public_key']}\n"
        managed_section += f"Endpoint = {p['endpoint']}\n"
        managed_section += f"AllowedIPs = {','.join(p['allowed_ips'])}\n"
        managed_section += f"PersistentKeepalive = 25\n"
    managed_section += MANAGED_END + "\n"

    new_config = static_part + managed_section + footer

    tmp_path = config_path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(new_config)

    try:
        strip_result = subprocess.run(
            ["wg-quick", "strip", tmp_path],
            capture_output=True,
            check=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError("Generated WireGuard config is invalid")

    os.replace(tmp_path, config_path)
    os.chmod(config_path, 0o600)

    # Reuse stripped output from validation; syncconf expects stripped config
    subprocess.run(
        ["wg", "syncconf", interface_name, "-"],
        input=strip_result.stdout,
        check=True,
        text=True,
    )

# -----------------------------
# API Endpoints
# -----------------------------
@app.get("/interfaces")
async def list_interfaces(request: Request):
    validate_client_ip(request)
    config = get_config()
    return {"interfaces": config["interface_names"]}

@app.post("/interfaces/{interface_name}/peers")
async def set_peers(request: Request, interface_name: str, peers: List[dict]):
    validate_client_ip(request)
    validate_interface(interface_name)
    try:
        rewrite_managed_block(interface_name, peers)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "success", "interface": interface_name, "num_peers": len(peers)}

@app.get("/interfaces/{interface_name}/peers/list")
async def list_peers(request: Request, interface_name: str):
    validate_client_ip(request)
    validate_interface(interface_name)
    try:
        peers = parse_managed_block(interface_name)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"interface": interface_name, "peers": peers}


@app.post("/interfaces/{interface_name}/peers/add")
async def add_peer(request: Request, interface_name: str, peer: dict):
    validate_client_ip(request)
    validate_interface(interface_name)
    try:
        peers = parse_managed_block(interface_name)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    keys = {p["public_key"] for p in peers}
    if peer.get("public_key") in keys:
        raise HTTPException(status_code=409, detail="Peer with this public_key already exists")
    for key in ("public_key", "allowed_ips", "endpoint"):
        if not peer.get(key):
            raise HTTPException(status_code=400, detail=f"Peer must have '{key}'")
    peers.append(peer)
    try:
        rewrite_managed_block(interface_name, peers)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "success", "interface": interface_name, "added_peer": peer.get("public_key")}


@app.delete("/interfaces/{interface_name}/peers")
async def remove_peer(request: Request, interface_name: str, body: dict = Body(...)):
    validate_client_ip(request)
    validate_interface(interface_name)
    public_key = body.get("public_key")
    if not public_key:
        raise HTTPException(status_code=400, detail="Body must include 'public_key'")
    try:
        peers = parse_managed_block(interface_name)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    new_peers = [p for p in peers if p.get("public_key") != public_key]
    if len(new_peers) == len(peers):
        raise HTTPException(status_code=404, detail="Peer not found")
    try:
        rewrite_managed_block(interface_name, new_peers)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "success", "interface": interface_name, "removed_peer": public_key}

@app.get("/health")
async def health(request: Request):
    validate_client_ip(request)
    return {"status": "ok"}


@app.get("/health-local")
async def health_local(request: Request):
    """Unauthenticated health check for localhost only (e.g. watchdog)."""
    client = request.client.host if request.client else ""
    if client not in ("127.0.0.1", "::1"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"status": "ok"}
