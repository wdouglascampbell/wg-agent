import asyncio
import base64
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import List

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, field_validator

# -----------------------------
# Configuration (from environment, set by run-wg-agent.sh via wg-agent.env)
# -----------------------------
MANAGED_START = "# BEGIN MANAGED PEERS"
MANAGED_END = "# END MANAGED PEERS"

# Size limits (tunable)
MAX_PEERS_PER_INTERFACE = 500
MAX_PUBLIC_KEY_LEN = 64
MAX_ENDPOINT_LEN = 256
MAX_ALLOWED_IPS_PER_PEER = 100

SUBPROCESS_TIMEOUT = 10

_config_cache: dict | None = None
_interface_locks: dict[str, asyncio.Lock] = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)


def _load_config() -> dict:
    """Load configuration from environment."""
    raw_ips = os.environ.get("ALLOWED_CLIENT_IPS", "")
    allowed_client_ips = [s.strip() for s in raw_ips.split(",") if s.strip()]

    raw_interfaces = os.environ.get("INTERFACES", "")
    interface_names = [s.strip() for s in raw_interfaces.split(",") if s.strip()]

    return {
        "allowed_client_ips": allowed_client_ips,
        "interface_names": interface_names,
    }


def get_config() -> dict:
    """Return config; load from env once per process and cache."""
    global _config_cache
    if _config_cache is None:
        _config_cache = _load_config()
    return _config_cache

def get_config_path(interface_name: str) -> str:
    return f"/etc/wireguard/{interface_name}.conf"


def get_interface_lock(interface_name: str) -> asyncio.Lock:
    if interface_name not in _interface_locks:
        _interface_locks[interface_name] = asyncio.Lock()
    return _interface_locks[interface_name]


app = FastAPI(title="wg-agent")

# -----------------------------
# Utility Functions
# -----------------------------
def validate_client_ip(request: Request) -> None:
    client = getattr(request, "client", None)
    if not client:
        raise HTTPException(status_code=403, detail="Forbidden")
    config = get_config()
    if client.host not in config["allowed_client_ips"]:
        raise HTTPException(status_code=403, detail="Forbidden")


def validate_interface(interface_name: str) -> None:
    """Raise 404 if interface is not configured; reject path traversal."""
    if "/" in interface_name or ".." in interface_name:
        raise HTTPException(status_code=400, detail="Invalid interface name")
    config = get_config()
    if interface_name not in config["interface_names"]:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown interface: {interface_name}. Configured: {config['interface_names']}",
        )


# -----------------------------
# Request/response models and validators
# -----------------------------
_CIDR4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_CIDR6 = re.compile(r"^[0-9a-fA-F:]+/\d{1,3}$")
_ENDPOINT = re.compile(r"^[^:]+:\d{1,5}$")


def _validate_cidr(v: str) -> str:
    if not v or len(v) > 128:
        raise ValueError("Invalid CIDR")
    if ":" in v:
        if not _CIDR6.match(v):
            raise ValueError("IPv6 AllowedIPs must be in CIDR form (e.g. fd00::/64)")
        parts = v.split("/")
        if len(parts) == 2:
            prefix = int(parts[1])
            if prefix < 0 or prefix > 128:
                raise ValueError("IPv6 prefix must be 0-128")
    else:
        if not _CIDR4.match(v):
            raise ValueError("IPv4 AllowedIPs must be in CIDR form (e.g. 192.168.1.0/24)")
        parts = v.split("/")
        if len(parts) == 2:
            prefix = int(parts[1])
            if prefix < 0 or prefix > 32:
                raise ValueError("IPv4 prefix must be 0-32")
    return v


class Peer(BaseModel):
    public_key: str
    allowed_ips: List[str]
    endpoint: str = ""

    @field_validator("public_key")
    @classmethod
    def check_public_key(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("public_key must be a string")
        v = v.strip()
        if len(v) > MAX_PUBLIC_KEY_LEN:
            raise ValueError(f"public_key length must be at most {MAX_PUBLIC_KEY_LEN}")
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("public_key must be base64")
        if len(raw) != 32:
            raise ValueError("public_key must decode to 32 bytes")
        return v

    @field_validator("allowed_ips")
    @classmethod
    def check_allowed_ips(cls, v: object) -> List[str]:
        if isinstance(v, str):
            v = [s.strip() for s in v.split(",") if s.strip()]
        if not isinstance(v, list):
            raise ValueError("allowed_ips must be a list")
        if len(v) > MAX_ALLOWED_IPS_PER_PEER:
            raise ValueError(f"allowed_ips count must be at most {MAX_ALLOWED_IPS_PER_PEER}")
        return [_validate_cidr(str(x).strip()) for x in v]

    @field_validator("endpoint", mode="before")
    @classmethod
    def check_endpoint(cls, v: object) -> str:
        s = (v or "").strip() if isinstance(v, str) else ""
        if len(s) > MAX_ENDPOINT_LEN:
            raise ValueError(f"endpoint length must be at most {MAX_ENDPOINT_LEN}")
        if s and not _ENDPOINT.match(s):
            raise ValueError("endpoint must be host:port")
        return s


class DeletePeerBody(BaseModel):
    public_key: str

    @field_validator("public_key")
    @classmethod
    def check_public_key(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("public_key must be a string")
        v = v.strip()
        if len(v) > MAX_PUBLIC_KEY_LEN:
            raise ValueError(f"public_key length must be at most {MAX_PUBLIC_KEY_LEN}")
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("public_key must be base64")
        if len(raw) != 32:
            raise ValueError("public_key must decode to 32 bytes")
        return v


def parse_managed_block(interface_name: str) -> List[dict]:
    """Parse the managed peers section into a list of peer dicts (public_key, allowed_ips, endpoint)."""
    config_path = get_config_path(interface_name)
    with open(config_path, "r") as f:
        content = f.read()
    content = content.replace("\r\n", "\n").replace("\r", "\n")
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
        if peer.get("public_key") and peer.get("allowed_ips") is not None:
            peer.setdefault("endpoint", "")
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
        ips = p.get("allowed_ips")
        if ips is None:
            raise ValueError("Each peer must have 'allowed_ips'")
        if not isinstance(ips, list):
            p["allowed_ips"] = [str(x).strip() for x in (ips if isinstance(ips, (list, tuple)) else [ips]) if str(x).strip()]
        if not p["allowed_ips"]:
            raise ValueError("Each peer must have at least one allowed_ip")
        p.setdefault("endpoint", "")

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
        managed_section += f"Endpoint = {p.get('endpoint', '')}\n"
        managed_section += f"AllowedIPs = {','.join(p['allowed_ips'])}\n"
        managed_section += f"PersistentKeepalive = 25\n"
    managed_section += MANAGED_END + "\n"

    new_config = static_part + managed_section + footer

    # wg-quick strip requires the file to be named INTERFACE.conf
    tmpdir = tempfile.mkdtemp()
    try:
        tmp_path = os.path.join(tmpdir, f"{interface_name}.conf")
        with open(tmp_path, "w") as f:
            f.write(new_config)

        try:
            subprocess.run(
                ["wg-quick", "strip", tmp_path],
                capture_output=True,
                check=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError("Generated WireGuard config is invalid")
        except subprocess.TimeoutExpired:
            raise RuntimeError("wg-quick strip timed out")

        shutil.copy2(tmp_path, config_path)
        os.chmod(config_path, 0o600)

        # Apply config and routes via service restart (syncconf does not update routes)
        try:
            subprocess.run(
                ["systemctl", "restart", f"wg-quick@{interface_name}"],
                check=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to restart wg-quick@{interface_name}: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("systemctl restart timed out")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

# -----------------------------
# API Endpoints
# -----------------------------
@app.get("/interfaces")
async def list_interfaces(request: Request):
    validate_client_ip(request)
    config = get_config()
    return {"interfaces": config["interface_names"]}

@app.post("/interfaces/{interface_name}/peers")
async def set_peers(request: Request, interface_name: str, peers: List[Peer]):
    validate_client_ip(request)
    validate_interface(interface_name)
    if len(peers) > MAX_PEERS_PER_INTERFACE:
        raise HTTPException(
            status_code=400,
            detail=f"At most {MAX_PEERS_PER_INTERFACE} peers per interface",
        )
    seen = set()
    for p in peers:
        if p.public_key in seen:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate public_key in request: {p.public_key[:16]}...",
            )
        seen.add(p.public_key)
    peer_dicts = [p.model_dump() for p in peers]
    lock = get_interface_lock(interface_name)
    async with lock:
        try:
            rewrite_managed_block(interface_name, peer_dicts)
        except (ValueError, RuntimeError) as e:
            logger.warning("set_peers failed interface=%s: %s", interface_name, e)
            raise HTTPException(status_code=400, detail=str(e))
    logger.info("set_peers interface=%s num_peers=%s", interface_name, len(peers))
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
async def add_peer(request: Request, interface_name: str, peer: Peer):
    validate_client_ip(request)
    validate_interface(interface_name)
    lock = get_interface_lock(interface_name)
    async with lock:
        try:
            peers = parse_managed_block(interface_name)
        except RuntimeError as e:
            logger.warning("add_peer parse failed interface=%s: %s", interface_name, e)
            raise HTTPException(status_code=500, detail=str(e))
        keys = {p["public_key"] for p in peers}
        if peer.public_key in keys:
            raise HTTPException(status_code=409, detail="Peer with this public_key already exists")
        if len(peers) >= MAX_PEERS_PER_INTERFACE:
            raise HTTPException(
                status_code=400,
                detail=f"At most {MAX_PEERS_PER_INTERFACE} peers per interface",
            )
        peer_dict = peer.model_dump()
        peers.append(peer_dict)
        try:
            rewrite_managed_block(interface_name, peers)
        except (ValueError, RuntimeError) as e:
            logger.warning("add_peer rewrite failed interface=%s: %s", interface_name, e)
            raise HTTPException(status_code=400, detail=str(e))
    logger.info("add_peer interface=%s public_key=%s...", interface_name, peer.public_key[:16])
    return {"status": "success", "interface": interface_name, "added_peer": peer.public_key}


@app.delete("/interfaces/{interface_name}/peers")
async def remove_peer(request: Request, interface_name: str, body: DeletePeerBody):
    validate_client_ip(request)
    validate_interface(interface_name)
    public_key = body.public_key
    lock = get_interface_lock(interface_name)
    async with lock:
        try:
            peers = parse_managed_block(interface_name)
        except RuntimeError as e:
            logger.warning("remove_peer parse failed interface=%s: %s", interface_name, e)
            raise HTTPException(status_code=500, detail=str(e))
        new_peers = [p for p in peers if p.get("public_key") != public_key]
        if len(new_peers) == len(peers):
            raise HTTPException(status_code=404, detail="Peer not found")
        try:
            rewrite_managed_block(interface_name, new_peers)
        except (ValueError, RuntimeError) as e:
            logger.warning("remove_peer rewrite failed interface=%s: %s", interface_name, e)
            raise HTTPException(status_code=400, detail=str(e))
    logger.info("remove_peer interface=%s public_key=%s...", interface_name, public_key[:16])
    return {"status": "success", "interface": interface_name, "removed_peer": public_key}

@app.get("/health")
async def health(request: Request):
    validate_client_ip(request)
    return {"status": "ok"}


@app.get("/health-local")
async def health_local(request: Request):
    """Unauthenticated health check for localhost only (e.g. watchdog)."""
    client = getattr(request, "client", None)
    if not client or client.host not in ("127.0.0.1", "::1"):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"status": "ok"}
