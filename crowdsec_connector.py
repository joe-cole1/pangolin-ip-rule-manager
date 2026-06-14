import json
import os
import re
import shlex
import subprocess
import threading
import time
import ipaddress
from datetime import datetime, timezone

# Local configuration (read from env, mirrors app.py defaults)
CROWDSEC_ENABLED = os.getenv("CROWDSEC_ENABLED", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
CROWDSEC_CSCLI_BIN = os.getenv("CROWDSEC_CSCLI_BIN", "cscli").strip()
CROWDSEC_CMD_PREFIX = os.getenv("CROWDSEC_CMD_PREFIX", "").strip()
CROWDSEC_ALLOWLIST_NAME = os.getenv(
    "CROWDSEC_ALLOWLIST_NAME", "pangolin-ip-rule-manager"
).strip()
CROWDSEC_CACHE_TTL_SECONDS = int(os.getenv("CROWDSEC_CACHE_TTL_SECONDS", "3600"))

# Runtime flags/caches (local to this module)
_cache_lock = threading.Lock()
_crowdsec_allowlist_ready = False
_crowdsec_cache = {"ts": 0.0, "ip_set": set()}

# Allowlist names must be alphanumeric + hyphens/underscores, 1–63 chars.
_ALLOWLIST_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _validate_ip(ip: str) -> None:
    """Raise ValueError if ip is not a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"invalid IP address passed to CrowdSec connector: {ip!r}")


def _validate_allowlist_name(name: str) -> None:
    """Raise ValueError if name contains characters that are not safe for cscli arguments."""
    if not name or not _ALLOWLIST_NAME_RE.match(name):
        raise ValueError(
            f"invalid CrowdSec allowlist name {name!r} — "
            "use alphanumeric characters, hyphens, or underscores only (max 63 chars)"
        )


def _crowdsec_check_connectivity() -> None:
    """Run 'cscli version' to verify the full exec chain is reachable at startup."""
    rc, out, err = run_cscli(["version"])
    if rc == 0:
        version_line = out.splitlines()[0] if out else "unknown"
        print(f"[crowdsec] connectivity OK — {version_line}")
    else:
        print(
            f"[crowdsec] WARNING: connectivity check failed (rc={rc}): "
            f"{err or 'no output'} — check DOCKER_HOST and CROWDSEC_CMD_PREFIX"
        )


def _build_cscli_cmd(args: list[str]) -> list[str]:
    parts: list[str] = []
    if CROWDSEC_CMD_PREFIX:
        try:
            parts.extend(shlex.split(CROWDSEC_CMD_PREFIX))
        except Exception as e:
            print(
                f"[crowdsec] WARNING: could not parse CROWDSEC_CMD_PREFIX with shlex ({e}); "
                "treating as single token"
            )
            parts.append(CROWDSEC_CMD_PREFIX)
    parts.append(CROWDSEC_CSCLI_BIN)
    parts.extend(args)
    return parts


def run_cscli(args: list[str]) -> tuple[int, str, str]:
    """Run cscli command. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            _build_cscli_cmd(args),
            capture_output=True,
            text=True,
            timeout=15,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "cscli not found"
    except Exception as e:
        return 1, "", str(e)


def crowdsec_allowlist_exists(name: str) -> bool:
    # Prefer JSON output if available
    rc, out, err = run_cscli(["allowlist", "list", "-o", "json"])  # newest cscli
    if rc == 0 and out:
        try:
            data = json.loads(out)
            # expect list of allowlists with name fields
            if isinstance(data, list):
                return any(
                    (isinstance(x, dict) and x.get("name") == name) for x in data
                )
        except Exception:
            pass
    else:
        # try legacy plural command
        rc2, out2, _ = run_cscli(["allowlists", "list", "-o", "json"])  # legacy
        if rc2 == 0 and out2:
            try:
                data = json.loads(out2)
                if isinstance(data, list):
                    return any(
                        (isinstance(x, dict) and x.get("name") == name) for x in data
                    )
            except Exception:
                pass
    # Fallback: plain text search
    for args in (["allowlist", "list"], ["allowlists", "list"]):
        rc3, out3, _ = run_cscli(args)
        if rc3 == 0 and out3:
            if name in out3:
                return True
    return False


def crowdsec_create_allowlist(name: str) -> bool:
    # Try modern command
    args = [
        "allowlist",
        "create",
        name,
        "-d",
        "allowlist created by pangolin-ip-rule-manager",
    ]
    rc, out, err = run_cscli(args)
    if rc == 0:
        print(f"[crowdsec] created allowlist '{name}' via: {' '.join(args)}")
        return True
    print(f"[crowdsec] failed to create allowlist '{name}'", rc, out, err)
    return False


def crowdsec_ensure_allowlist() -> None:
    global _crowdsec_allowlist_ready
    if not CROWDSEC_ENABLED:
        return
    if _crowdsec_allowlist_ready:
        return
    if not CROWDSEC_CMD_PREFIX:
        print(
            "[crowdsec] WARNING: CROWDSEC_ENABLED=true but CROWDSEC_CMD_PREFIX is not set. "
            "The container image does not ship cscli locally; all cscli calls will fail. "
            "Set CROWDSEC_CMD_PREFIX='docker exec <crowdsec-container>' "
            "or point DOCKER_HOST at a socket proxy."
        )
    _validate_allowlist_name(CROWDSEC_ALLOWLIST_NAME)
    _crowdsec_check_connectivity()
    exists = crowdsec_allowlist_exists(CROWDSEC_ALLOWLIST_NAME)
    if not exists:
        ok = crowdsec_create_allowlist(CROWDSEC_ALLOWLIST_NAME)
        if not ok:
            print(
                f"[crowdsec] WARNING: could not create allowlist '{CROWDSEC_ALLOWLIST_NAME}'. Commands may fail."
            )
    _crowdsec_allowlist_ready = True


def _parse_crowdsec_entries_from_json(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except Exception:
        return set()
    ips: set[str] = set()
    # Possible structures: list[str], list[dict], dict with 'entries'/'ips'/'items'
    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("entries", "ips", "items", "members"):
            if key in data and isinstance(data[key], (list, tuple)):
                items = data[key]
                break
    if items is None:
        return set()
    for it in items:
        if isinstance(it, str):
            tok = it.strip()
            try:
                # accept single IP or CIDR; normalize to compressed ip (network -> network address as string)
                if "/" in tok:
                    net = ipaddress.ip_network(tok, strict=False)
                    ips.add(str(net.network_address))
                else:
                    ips.add(str(ipaddress.ip_address(tok)))
            except Exception:
                continue
        elif isinstance(it, dict):
            for key in ("ip", "value", "cidr", "address"):
                val = it.get(key)
                if isinstance(val, str):
                    try:
                        if "/" in val:
                            net = ipaddress.ip_network(val, strict=False)
                            ips.add(str(net.network_address))
                        else:
                            ips.add(str(ipaddress.ip_address(val)))
                    except Exception:
                        pass
    return ips


def _crowdsec_refresh_allowlist_ip_set() -> set[str]:
    """Force refresh the cache by running 'cscli allowlist <name> list' or variants."""
    if not CROWDSEC_ENABLED:
        return set()
    ip_set: set[str] = set()

    args = ["allowlist", "inspect", CROWDSEC_ALLOWLIST_NAME, "-o", "json"]

    rc, out, err = run_cscli(args)
    if rc == 0 and out:
        parsed = _parse_crowdsec_entries_from_json(out)
        if parsed:
            ip_set = parsed

    with _cache_lock:
        _crowdsec_cache["ts"] = time.time()
        _crowdsec_cache["ip_set"] = ip_set
    return ip_set


def _get_crowdsec_ip_set_cached() -> set[str]:
    if not CROWDSEC_ENABLED:
        return set()
    with _cache_lock:
        ts = _crowdsec_cache.get("ts", 0.0)
        ip_set = set(_crowdsec_cache.get("ip_set", set()))
    if ip_set and (time.time() - ts) < CROWDSEC_CACHE_TTL_SECONDS:
        return ip_set
    return _crowdsec_refresh_allowlist_ip_set()


def _crowdsec_ip_known_or_refresh(ip: str) -> bool:
    # Quick check against current cache
    ip_set = _get_crowdsec_ip_set_cached()
    if ip in ip_set:
        return True
    # Not known -> force refresh from cscli once
    ip_set = _crowdsec_refresh_allowlist_ip_set()
    return ip in ip_set


def crowdsec_add_ip(ip: str) -> None:
    if not CROWDSEC_ENABLED:
        return
    _validate_ip(ip)
    crowdsec_ensure_allowlist()
    # If we already know this IP is present, skip calling cscli add
    if _crowdsec_ip_known_or_refresh(ip):
        print(
            f"[crowdsec] already present {ip} in allowlist '{CROWDSEC_ALLOWLIST_NAME}' (cache)"
        )
        return
    args = [
        "allowlist",
        "add",
        CROWDSEC_ALLOWLIST_NAME,
        ip,
        "-d",
        "added on " + _now_utc_iso() + " by pangolin-ip-rule-manager",
    ]
    backoff = 1.0
    rc, out, err = 1, "", ""
    for attempt in range(3):
        rc, out, err = run_cscli(args)
        if rc == 0:
            print(f"[crowdsec] added {ip} to allowlist '{CROWDSEC_ALLOWLIST_NAME}'")
            with _cache_lock:
                _crowdsec_cache.setdefault("ip_set", set()).add(ip)
                if not _crowdsec_cache.get("ts"):
                    _crowdsec_cache["ts"] = time.time()
            return
        if attempt < 2:
            print(
                f"[crowdsec] add attempt {attempt + 1}/3 failed (rc={rc}) — retrying in {backoff:.1f}s"
            )
            time.sleep(backoff)
            backoff *= 2
    # All attempts failed: maybe it already existed; re-list once to confirm
    refreshed = _crowdsec_refresh_allowlist_ip_set()
    if ip in refreshed:
        print(
            f"[crowdsec] add reported failure but IP already present {ip} in '{CROWDSEC_ALLOWLIST_NAME}'"
        )
        return
    print(
        f"[crowdsec] WARNING: failed to add {ip} to allowlist '{CROWDSEC_ALLOWLIST_NAME}'",
        rc,
        out,
        err,
    )
    raise RuntimeError(
        f"CrowdSec: failed to add {ip} to allowlist '{CROWDSEC_ALLOWLIST_NAME}' after 3 attempts (rc={rc}): {err}"
    )


def crowdsec_remove_ip(ip: str) -> None:
    if not CROWDSEC_ENABLED:
        return
    _validate_ip(ip)
    # Only attempt removal if we know it's present; otherwise refresh once and re-check
    present = ip in _get_crowdsec_ip_set_cached()
    if not present:
        present = ip in _crowdsec_refresh_allowlist_ip_set()
    if not present:
        # nothing to do
        return
    args = ["allowlist", "remove", CROWDSEC_ALLOWLIST_NAME, ip]
    backoff = 1.0
    for attempt in range(3):
        rc, out, err = run_cscli(args)
        if rc == 0:
            print(f"[crowdsec] removed {ip} from allowlist '{CROWDSEC_ALLOWLIST_NAME}'")
            with _cache_lock:
                _crowdsec_cache.setdefault("ip_set", set()).discard(ip)
            return
        if attempt < 2:
            print(
                f"[crowdsec] remove attempt {attempt + 1}/3 failed (rc={rc}) — retrying in {backoff:.1f}s"
            )
            time.sleep(backoff)
            backoff *= 2
    print(
        f"[crowdsec] WARNING: failed to remove {ip} from allowlist '{CROWDSEC_ALLOWLIST_NAME}'"
    )
