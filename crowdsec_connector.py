import ipaddress
import json
import os
import re
import shlex
import subprocess
import threading
import time
from datetime import UTC, datetime

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
# Lock acquisition order (never inverted):
#   _ensure_lock -> _cache_lock (leaf)
_ensure_lock = threading.Lock()
_cache_lock = threading.Lock()
_crowdsec_allowlist_ready = False
_crowdsec_allowlist_last_failed_ts = 0.0
_crowdsec_cache = {"ts": 0.0, "failed_ts": 0.0, "ip_set": set()}

_ALLOWLIST_RETRY_COOLDOWN_SECONDS = 60.0
_REFRESH_GUARD_SECONDS = 5.0

# Allowlist names must be alphanumeric + hyphens/underscores, 1–63 chars.
_ALLOWLIST_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")
_HTTP_403_RE = re.compile(r"\b403\b")


def _now_utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _validate_ip(ip: str) -> str:
    """Validate ip as an IPv4 or IPv6 address and return its canonical form."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(
            f"invalid IP address passed to CrowdSec connector: {ip!r}"
        ) from None


def _entry_matches_ip(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
    entry: str,
    *,
    include_broader_cidrs: bool,
) -> bool:
    """Return True if an allowlist entry matches ip_obj under the requested CIDR policy."""
    try:
        if "/" in entry:
            net = ipaddress.ip_network(entry, strict=False)
            if include_broader_cidrs:
                return ip_obj in net
            return net.prefixlen == net.max_prefixlen and ip_obj == net.network_address
        return ip_obj == ipaddress.ip_address(entry)
    except ValueError:
        return False


def _ip_matches_entries(
    ip: str,
    ip_set: set[str],
    *,
    include_broader_cidrs: bool,
) -> bool:
    """Return True if ip matches any entry in ip_set."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(
        _entry_matches_ip(ip_obj, entry, include_broader_cidrs=include_broader_cidrs)
        for entry in ip_set
    )


def _validate_allowlist_name(name: str) -> None:
    """Raise ValueError if name contains characters that are not safe for cscli arguments."""
    if not name or not _ALLOWLIST_NAME_RE.match(name):
        raise ValueError(
            f"invalid CrowdSec allowlist name {name!r} — "
            "use alphanumeric characters, hyphens, or underscores only (max 63 chars)"
        )


def _run_docker_cmd(args: list[str]) -> tuple[int, str, str]:
    """Run a docker command directly, respecting DOCKER_HOST from the environment."""
    try:
        proc = subprocess.run(
            ["docker"] + args,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "docker not found"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _crowdsec_check_connectivity() -> None:
    """Staged startup check to isolate socket-proxy, container, and cscli failures.

    Stage 1 (docker exec prefix only): docker version — proves Docker API / socket proxy.
    Stage 2 (docker exec prefix only): docker inspect <container> — proves container exists
      and is running.
    Stage 3 (always): cscli version via run_cscli — proves the full exec chain works.
    Stages 1 and 2 are skipped when CROWDSEC_CMD_PREFIX is not a docker exec command.
    All failures are warnings; the function never raises.
    """
    prefix_parts: list[str] = []
    if CROWDSEC_CMD_PREFIX:
        try:
            prefix_parts = shlex.split(CROWDSEC_CMD_PREFIX)
        except ValueError:
            prefix_parts = [CROWDSEC_CMD_PREFIX]

    is_docker_exec = (
        len(prefix_parts) >= 2
        and prefix_parts[0] == "docker"
        and "exec" in prefix_parts
    )

    if is_docker_exec:
        # Stage 1: Docker API / socket proxy reachability
        rc, out, err = _run_docker_cmd(["version", "--format", "{{.Server.Version}}"])
        if rc != 0:
            combined = f"{err}\n{out}"
            if "forbidden" in combined.lower() or _HTTP_403_RE.search(combined):
                print(
                    "[crowdsec] Docker /version returned 403 Forbidden "
                    "(expected with least-privilege socket-proxy); "
                    "proceeding to container check"
                )
            else:
                docker_host = os.environ.get("DOCKER_HOST", "(not set)")
                print(
                    f"[crowdsec] WARNING: Docker API unreachable (rc={rc}): "
                    f"{err or 'no output'} — DOCKER_HOST={docker_host}"
                )
                return
        else:
            print(f"[crowdsec] Docker API OK — server v{out}")

        # Stage 2: CrowdSec container existence and running state
        container = prefix_parts[-1]
        rc2, out2, _ = _run_docker_cmd(
            ["inspect", "--format", "{{.State.Running}}", "--", container]
        )
        if rc2 != 0:
            print(
                f"[crowdsec] WARNING: container '{container}' not found — "
                "check CROWDSEC_CMD_PREFIX"
            )
            return
        if out2 != "true":
            print(
                f"[crowdsec] WARNING: container '{container}' exists but is not running"
            )
            return
        print(f"[crowdsec] container '{container}' is running")

    # Stage 3: cscli reachability via the full exec chain
    rc3, out3, err3 = run_cscli(["version"])
    if rc3 == 0:
        version_line = out3.splitlines()[0] if out3 else "unknown"
        print(f"[crowdsec] cscli OK — {version_line}")
    else:
        print(
            f"[crowdsec] WARNING: cscli check failed (rc={rc3}): "
            f"{err3 or 'no output'} — check DOCKER_HOST and CROWDSEC_CMD_PREFIX"
        )


def _build_cscli_cmd(args: list[str]) -> list[str]:
    parts: list[str] = []
    if CROWDSEC_CMD_PREFIX:
        try:
            parts.extend(shlex.split(CROWDSEC_CMD_PREFIX))
        except Exception as e:  # noqa: BLE001
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
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "cscli not found"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def crowdsec_allowlist_exists(name: str) -> bool:
    # Prefer JSON output if available
    rc, out, _err = run_cscli(["allowlist", "list", "-o", "json"])  # newest cscli
    if rc == 0 and out:
        try:
            data = json.loads(out)
            # expect list of allowlists with name fields
            if isinstance(data, list):
                return any(
                    (isinstance(x, dict) and x.get("name") == name) for x in data
                )
        except (json.JSONDecodeError, TypeError, KeyError, AttributeError):
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
            except (json.JSONDecodeError, TypeError, KeyError, AttributeError):
                pass
    # Fallback: plain text search. Match a whole whitespace-delimited token rather
    # than a substring so a shorter name cannot false-match a longer allowlist name.
    for args in (["allowlist", "list"], ["allowlists", "list"]):
        rc3, out3, _ = run_cscli(args)
        if rc3 == 0 and out3 and name in out3.split():
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
    global _crowdsec_allowlist_ready, _crowdsec_allowlist_last_failed_ts
    if not CROWDSEC_ENABLED:
        return
    now = time.monotonic()
    with _cache_lock:
        if _crowdsec_allowlist_ready:
            return
        if (
            _crowdsec_allowlist_last_failed_ts > 0.0
            and (now - _crowdsec_allowlist_last_failed_ts)
            < _ALLOWLIST_RETRY_COOLDOWN_SECONDS
        ):
            return
    with _ensure_lock:
        now = time.monotonic()
        with _cache_lock:
            if _crowdsec_allowlist_ready:
                return
            if (
                _crowdsec_allowlist_last_failed_ts > 0.0
                and (now - _crowdsec_allowlist_last_failed_ts)
                < _ALLOWLIST_RETRY_COOLDOWN_SECONDS
            ):
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
        if exists:
            with _cache_lock:
                _crowdsec_allowlist_ready = True
                _crowdsec_allowlist_last_failed_ts = 0.0
            return
        ok = crowdsec_create_allowlist(CROWDSEC_ALLOWLIST_NAME)
        if ok:
            with _cache_lock:
                _crowdsec_allowlist_ready = True
                _crowdsec_allowlist_last_failed_ts = 0.0
            return
        print(
            f"[crowdsec] WARNING: could not create allowlist '{CROWDSEC_ALLOWLIST_NAME}'. "
            f"Will retry after {int(_ALLOWLIST_RETRY_COOLDOWN_SECONDS)}s cooldown; commands may fail."
        )
        with _cache_lock:
            _crowdsec_allowlist_last_failed_ts = time.monotonic()


def _parse_crowdsec_entries_from_json(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
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
                # accept single IP or CIDR; preserve CIDR block string if present
                if "/" in tok:
                    net = ipaddress.ip_network(tok, strict=False)
                    ips.add(str(net))
                else:
                    ips.add(str(ipaddress.ip_address(tok)))
            except (ValueError, TypeError):
                continue
        elif isinstance(it, dict):
            for key in ("ip", "value", "cidr", "address"):
                val = it.get(key)
                if isinstance(val, str):
                    val = val.strip()
                    try:
                        if "/" in val:
                            net = ipaddress.ip_network(val, strict=False)
                            ips.add(str(net))
                        else:
                            ips.add(str(ipaddress.ip_address(val)))
                    except (ValueError, TypeError):
                        pass
    return ips


def _crowdsec_refresh_allowlist_ip_set() -> set[str]:
    """Force refresh the cache by running 'cscli allowlist inspect <name> -o json'."""
    if not CROWDSEC_ENABLED:
        return set()

    args = ["allowlist", "inspect", CROWDSEC_ALLOWLIST_NAME, "-o", "json"]

    rc, out, _err = run_cscli(args)
    now = time.monotonic()
    if rc == 0:
        ip_set = _parse_crowdsec_entries_from_json(out) if out else set()
        with _cache_lock:
            _crowdsec_cache["ts"] = now
            _crowdsec_cache["failed_ts"] = 0.0
            _crowdsec_cache["ip_set"] = ip_set
        return set(ip_set)

    with _cache_lock:
        _crowdsec_cache["failed_ts"] = now
        return set(_crowdsec_cache.get("ip_set", set()))


def _get_crowdsec_ip_set_cached() -> set[str]:
    if not CROWDSEC_ENABLED:
        return set()
    now = time.monotonic()
    with _cache_lock:
        ts = _crowdsec_cache.get("ts", 0.0)
        failed_ts = _crowdsec_cache.get("failed_ts", 0.0)
        ip_set = set(_crowdsec_cache.get("ip_set", set()))
    if ts > 0.0 and (now - ts) < CROWDSEC_CACHE_TTL_SECONDS:
        return ip_set
    if failed_ts > 0.0 and (now - failed_ts) < _REFRESH_GUARD_SECONDS:
        return ip_set
    return _crowdsec_refresh_allowlist_ip_set()


def _crowdsec_ip_known_or_refresh(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False

    # Quick check against current cache
    ip_set = _get_crowdsec_ip_set_cached()
    if _ip_matches_entries(ip, ip_set, include_broader_cidrs=True):
        return True
    # Not known -> force refresh from cscli once unless we just refreshed or failed
    with _cache_lock:
        last_attempt = max(
            _crowdsec_cache.get("ts", 0.0),
            _crowdsec_cache.get("failed_ts", 0.0),
        )
    if (
        last_attempt > 0.0
        and (time.monotonic() - last_attempt) < _REFRESH_GUARD_SECONDS
    ):
        return False
    ip_set = _crowdsec_refresh_allowlist_ip_set()
    return _ip_matches_entries(ip, ip_set, include_broader_cidrs=True)


def crowdsec_add_ip(ip: str) -> None:
    if not CROWDSEC_ENABLED:
        return
    canonical_ip = _validate_ip(ip)
    crowdsec_ensure_allowlist()
    _validate_allowlist_name(CROWDSEC_ALLOWLIST_NAME)
    # If we already know this IP is present, skip calling cscli add
    if _crowdsec_ip_known_or_refresh(canonical_ip):
        print(
            f"[crowdsec] already present {canonical_ip} in allowlist '{CROWDSEC_ALLOWLIST_NAME}' (cache)"
        )
        return
    args = [
        "allowlist",
        "add",
        CROWDSEC_ALLOWLIST_NAME,
        canonical_ip,
        "-d",
        "added on " + _now_utc_iso() + " by pangolin-ip-rule-manager",
    ]
    backoff = 1.0
    rc, out, err = 1, "", ""
    for attempt in range(3):
        rc, out, err = run_cscli(args)
        if rc == 0:
            print(
                f"[crowdsec] added {canonical_ip} to allowlist '{CROWDSEC_ALLOWLIST_NAME}'"
            )
            with _cache_lock:
                _crowdsec_cache.setdefault("ip_set", set()).add(canonical_ip)
            return
        if attempt < 2:
            print(
                f"[crowdsec] add attempt {attempt + 1}/3 failed (rc={rc}) — retrying in {backoff:.1f}s"
            )
            time.sleep(backoff)
            backoff *= 2
    # All attempts failed: maybe it already existed; re-list once to confirm
    refreshed = _crowdsec_refresh_allowlist_ip_set()
    if _ip_matches_entries(canonical_ip, refreshed, include_broader_cidrs=True):
        print(
            f"[crowdsec] add reported failure but IP already present {canonical_ip} in '{CROWDSEC_ALLOWLIST_NAME}'"
        )
        return
    print(
        f"[crowdsec] WARNING: failed to add {canonical_ip} to allowlist '{CROWDSEC_ALLOWLIST_NAME}'",
        rc,
        out,
        err,
    )
    raise RuntimeError(
        f"CrowdSec: failed to add {canonical_ip} to allowlist '{CROWDSEC_ALLOWLIST_NAME}' after 3 attempts (rc={rc}): {err}"
    )


def crowdsec_remove_ip(ip: str) -> None:
    if not CROWDSEC_ENABLED:
        return
    canonical_ip = _validate_ip(ip)
    _validate_allowlist_name(CROWDSEC_ALLOWLIST_NAME)
    # Only attempt removal if an exact host entry is present; otherwise refresh once and re-check
    present = _ip_matches_entries(
        canonical_ip,
        _get_crowdsec_ip_set_cached(),
        include_broader_cidrs=False,
    )
    if not present:
        with _cache_lock:
            last_attempt = max(
                _crowdsec_cache.get("ts", 0.0),
                _crowdsec_cache.get("failed_ts", 0.0),
            )
        if not (
            last_attempt > 0.0
            and (time.monotonic() - last_attempt) < _REFRESH_GUARD_SECONDS
        ):
            present = _ip_matches_entries(
                canonical_ip,
                _crowdsec_refresh_allowlist_ip_set(),
                include_broader_cidrs=False,
            )
    if not present:
        # nothing to do
        return
    args = ["allowlist", "remove", CROWDSEC_ALLOWLIST_NAME, canonical_ip]
    backoff = 1.0
    for attempt in range(3):
        rc, _out, _err = run_cscli(args)
        if rc == 0:
            print(
                f"[crowdsec] removed {canonical_ip} from allowlist '{CROWDSEC_ALLOWLIST_NAME}'"
            )
            ip_obj = ipaddress.ip_address(canonical_ip)
            with _cache_lock:
                ip_set = _crowdsec_cache.setdefault("ip_set", set())
                to_discard = {
                    entry
                    for entry in ip_set
                    if _entry_matches_ip(ip_obj, entry, include_broader_cidrs=False)
                }
                ip_set.difference_update(to_discard)
            return
        if attempt < 2:
            print(
                f"[crowdsec] remove attempt {attempt + 1}/3 failed (rc={rc}) — retrying in {backoff:.1f}s"
            )
            time.sleep(backoff)
            backoff *= 2
    print(
        f"[crowdsec] WARNING: failed to remove {canonical_ip} from allowlist '{CROWDSEC_ALLOWLIST_NAME}'"
    )
