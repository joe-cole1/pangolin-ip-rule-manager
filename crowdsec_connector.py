import json
import os
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

# LAPI mode — cscli runs inside this container and authenticates to the
# CrowdSec LAPI over the network. Takes precedence over CMD_PREFIX mode.
CROWDSEC_LAPI_URL = os.getenv("CROWDSEC_LAPI_URL", "").strip()
CROWDSEC_LAPI_LOGIN = os.getenv("CROWDSEC_LAPI_LOGIN", "").strip()
CROWDSEC_LAPI_PASSWORD = os.getenv("CROWDSEC_LAPI_PASSWORD", "").strip()

_LAPI_MODE = bool(CROWDSEC_LAPI_URL and CROWDSEC_LAPI_LOGIN)

if _LAPI_MODE and CROWDSEC_CMD_PREFIX:
    print(
        "[crowdsec] WARNING: both CROWDSEC_LAPI_URL and CROWDSEC_CMD_PREFIX are set. "
        "LAPI mode takes precedence; CROWDSEC_CMD_PREFIX will be ignored."
    )

# Paths for the cscli config files written at startup in LAPI mode.
# These are module-level constants so tests can patch them to a tmp directory.
_LAPI_CONFIG_PATH = "/tmp/pangolin-cs-config.yaml"
_LAPI_CREDENTIALS_PATH = "/tmp/pangolin-cs-credentials.yaml"
_LAPI_CS_DIR = "/tmp/pangolin-cs"  # cscli requires config_paths dirs to exist

# Runtime flags/caches (local to this module)
_cache_lock = threading.Lock()
_crowdsec_allowlist_ready = False
_crowdsec_cache = {"ts": 0.0, "ip_set": set()}


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_lapi_config() -> None:
    """Write cscli config and credentials files for LAPI mode.

    Called once at startup from crowdsec_ensure_allowlist(). The files live in
    /tmp/ (inside the container) and are referenced by every cscli invocation
    via the -c flag. The password is written only to the credentials file, never
    to the config file.
    """
    os.makedirs(os.path.join(_LAPI_CS_DIR, "data"), exist_ok=True)
    os.makedirs(os.path.join(_LAPI_CS_DIR, "hub"), exist_ok=True)
    credentials_fd = os.open(
        _LAPI_CREDENTIALS_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    with os.fdopen(credentials_fd, "w", encoding="utf-8") as f:
        f.write(
            f"url: {CROWDSEC_LAPI_URL}\n"
            f"login: {CROWDSEC_LAPI_LOGIN}\n"
            f"password: {CROWDSEC_LAPI_PASSWORD}\n"
        )
    config_fd = os.open(_LAPI_CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(config_fd, "w", encoding="utf-8") as f:
        f.write(
            "common:\n"
            "  log_level: warning\n"
            "  log_media: stdout\n"
            "config_paths:\n"
            f"  config_dir: {_LAPI_CS_DIR}\n"
            f"  data_dir: {_LAPI_CS_DIR}/data\n"
            f"  hub_dir: {_LAPI_CS_DIR}/hub\n"
            "api:\n"
            "  server:\n"
            "    enable: true\n"
            "  client:\n"
            "    insecure_skip_verify: false\n"
            f"    credentials_path: {_LAPI_CREDENTIALS_PATH}\n"
        )
    print(
        f"[crowdsec] LAPI mode: wrote cscli config to {_LAPI_CONFIG_PATH} "
        f"(url={CROWDSEC_LAPI_URL} login={CROWDSEC_LAPI_LOGIN})"
    )


def _build_cscli_cmd(args: list[str]) -> list[str]:
    if _LAPI_MODE:
        return ["cscli", "-c", _LAPI_CONFIG_PATH] + args
    parts: list[str] = []
    if CROWDSEC_CMD_PREFIX:
        try:
            parts.extend(shlex.split(CROWDSEC_CMD_PREFIX))
        except Exception:
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
    if _LAPI_MODE:
        _write_lapi_config()
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
