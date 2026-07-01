import base64
import contextlib
import json
import os
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from crowdsec_connector import (
    crowdsec_add_ip,
    crowdsec_remove_ip,
    crowdsec_ensure_allowlist,
)
from pangolin_connector import (
    PangolinContext,
    get_ip_set_for_resource_cached as pg_get_ip_set_for_resource_cached,
    ensure_ip_rule as pg_ensure_ip_rule,
    delete_ip_rule_if_created_by_us as pg_delete_ip_rule_if_created_by_us,
    list_org_resources as pg_list_org_resources,
    filter_resources_for_user as pg_filter_resources_for_user,
)

# Config via environment
PANGOLIN_URL = os.getenv("PANGOLIN_URL", "").rstrip("/")
PANGOLIN_TOKEN = os.getenv("PANGOLIN_TOKEN", "")
ORG_ID = os.getenv("ORG_ID", "")
RESOURCE_IDS = [int(x) for x in os.getenv("RESOURCE_IDS", "").split(",") if x.strip()]
RETENTION_MINUTES = int(
    os.getenv("RETENTION_MINUTES", "1440")
)  # default 1 day in minutes
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
STATE_FILE = os.getenv("STATE_FILE", "/data/state.json")
CLEANUP_INTERVAL_MINUTES = int(
    os.getenv("CLEANUP_INTERVAL_MINUTES", "60")
)  # default 1 hour in minutes
RULE_PRIORITY = int(os.getenv("RULE_PRIORITY", "0"))
RATE_LIMIT_SECONDS = int(os.getenv("RATE_LIMIT_SECONDS", "300"))
RULES_CACHE_TTL_SECONDS = int(
    os.getenv("RULES_CACHE_TTL_SECONDS", "3600")
)  # cache for existence checks (~1h)
# CrowdSec optional integration via cscli
CROWDSEC_ENABLED = os.getenv("CROWDSEC_ENABLED", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
CROWDSEC_CSCLI_BIN = os.getenv("CROWDSEC_CSCLI_BIN", "cscli").strip()
# Optional: a command prefix to run cscli in a container, e.g. "docker exec crowdsec"
CROWDSEC_CMD_PREFIX = os.getenv("CROWDSEC_CMD_PREFIX", "").strip()
CROWDSEC_ALLOWLIST_NAME = os.getenv(
    "CROWDSEC_ALLOWLIST_NAME", "pangolin-ip-rule-manager"
).strip()
CROWDSEC_CACHE_TTL_SECONDS = int(
    os.getenv("CROWDSEC_CACHE_TTL_SECONDS", "3600")
)  # cache TTL for CrowdSec allowlist entries (~1h)
# Optional: site name shown in the HTML check-in and error pages
SITE_NAME = os.getenv("SITE_NAME", "").strip()
# Optional: allow overriding the caller IP via /update?ip=...
UPDATE_ENDPOINT_ENABLED = os.getenv(
    "UPDATE_ENDPOINT_ENABLED", "false"
).strip().lower() in ("1", "true", "yes", "on")
# Optional: defense-in-depth shared secret that the upstream proxy (Pangolin/Traefik)
# must inject as the X-Proxy-Secret header. When set, requests missing or mismatching
# the secret are rejected before any state write or API call. Leave empty to disable
# (the service then relies solely on network topology to keep it behind the proxy).
PROXY_SHARED_SECRET = os.getenv("PROXY_SHARED_SECRET", "")

# Minimal 1x1 PNG (transparent) as bytes
BANNER_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
)
# Minimal 1x1 GIF (transparent) as bytes
BANNER_GIF = base64.b64decode(
    "R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw=="
)

state_lock = threading.Lock()
# Serializes save_state() so concurrent writers (request threads + cleanup thread)
# cannot race on the temporary file or clobber each other's os.replace.
_save_lock = threading.Lock()
state = {
    # ip: {
    #   "last_seen": "2025-01-01T00:00:00Z",
    #   "resources": {"2": {"created_by_us": true}, ...}
    # }
}

# In-memory cache: per resourceId set of IPs known to have a rule, with TTL
rules_cache = {
    # rid: {"ts": epoch_seconds, "ip_set": set([...])}
}

# CrowdSec allowlist readiness/caches live in crowdsec_connector; app.py does not
# duplicate them.

# Per-IP rate limit cache: {ip: (monotonic_timestamp, last_result)}
_api_rate_limit: dict[str, tuple[float, dict]] = {}
_api_rate_limit_lock = threading.Lock()


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def redact_headers_for_log(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers suitable for logging.
    - Redacts Authorization/Proxy-Authorization values.
    Header names are matched case-insensitively.
    """
    redacted: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl in ("authorization", "proxy-authorization"):
            redacted[k] = "<redacted>"
        else:
            redacted[k] = v
    return redacted


def load_state():
    global state
    if not os.path.exists(STATE_FILE):
        return
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            state = data
    except Exception as e:
        print(f"[state] failed to load state: {e}")


def save_state():
    with _save_lock:
        with state_lock:
            snapshot = json.dumps(state, indent=2, sort_keys=True)
        state_dir = os.path.dirname(os.path.abspath(STATE_FILE))
        tmp_file = None
        try:
            fd, tmp_file = tempfile.mkstemp(dir=state_dir, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(snapshot)
            os.replace(tmp_file, STATE_FILE)
            tmp_file = None
            os.chmod(STATE_FILE, 0o600)
        except Exception as e:
            print(f"[state] failed to save state: {e}")
            if tmp_file is not None:
                with contextlib.suppress(OSError):
                    os.remove(tmp_file)


def http_json(method: str, url: str, body: dict | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {PANGOLIN_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=20) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            text = resp.read().decode(charset, errors="replace")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
    except HTTPError as e:
        try:
            err = e.read().decode("utf-8", errors="replace")
        except (UnicodeDecodeError, IOError):
            err = str(e)
        raise RuntimeError(f"HTTP {e.code} {e.reason}: {err}")
    except URLError as e:
        raise RuntimeError(f"Network error: {e}")


# Targets common interface. All targets share one add_ip signature so the caller can
# dispatch uniformly without type checks; targets ignore resource_ids they don't use.
class Target:
    name = "target"

    def ensure_ready(self) -> None:
        pass

    def add_ip(self, ip: str, resource_ids: list[int] | None = None) -> None:
        raise NotImplementedError

    def expire_ip(self, ip: str) -> None:
        pass


class PangolinTarget(Target):
    name = "pangolin"

    def __init__(self, ctx_factory):
        self._ctx_factory = ctx_factory

    def add_ip(self, ip: str, resource_ids: list[int] | None = None) -> None:
        from dataclasses import replace as _dc_replace

        ctx = self._ctx_factory()
        if resource_ids is not None:
            ctx = _dc_replace(ctx, resource_ids=resource_ids)
        pg_ensure_ip_rule(ctx, ip)

    # Pangolin cleanup is handled separately based on created_by_us; no expire here.
    def expire_ip(self, ip: str) -> None:
        return


class CrowdSecTarget(Target):
    name = "crowdsec"

    def ensure_ready(self) -> None:
        crowdsec_ensure_allowlist()

    def add_ip(self, ip: str, resource_ids: list[int] | None = None) -> None:
        crowdsec_add_ip(ip)

    def expire_ip(self, ip: str) -> None:
        crowdsec_remove_ip(ip)


def make_pangolin_context() -> PangolinContext:
    return PangolinContext(
        url=PANGOLIN_URL,
        token=PANGOLIN_TOKEN,
        resource_ids=RESOURCE_IDS,
        rule_priority=RULE_PRIORITY,
        rules_cache_ttl_seconds=RULES_CACHE_TTL_SECONDS,
        rules_cache=rules_cache,
        state=state,
        state_lock=state_lock,
        save_state=save_state,
        now_utc_iso=now_utc_iso,
        http_json=http_json,
    )


# Register targets
TARGETS: list[Target] = [PangolinTarget(make_pangolin_context)]
if CROWDSEC_ENABLED:
    TARGETS.append(CrowdSecTarget())


def _get_ip_set_for_resource_cached(rid: int):
    """Return a set of IPs that currently have a rule for the resource.
    Uses a 1h TTL cache to avoid frequent GET calls."""
    ctx = make_pangolin_context()
    return pg_get_ip_set_for_resource_cached(ctx, rid)


# --------------------------
# Target aggregation (extensibility point)
# --------------------------


def add_ip_to_targets(ip: str, remote_user: str = "") -> dict:
    """Add/allow this IP across configured targets (Pangolin, CrowdSec, etc.).
    Requires remote_user (value of the Remote-User header forwarded by Pangolin).
    Fails closed: returns ok=False without touching any target if the user cannot
    be identified or is not authorised for any configured resource.
    Returns a dict of per-target results for display purposes.
    """

    def _fail(detail: str) -> dict:
        print(f"[targets] fail-closed: {detail}")
        return {
            "pangolin": {"ok": False, "detail": detail, "enabled": True},
            "crowdsec": {
                "ok": False,
                "detail": "not reached",
                "enabled": CROWDSEC_ENABLED,
            },
        }

    if not remote_user:
        return _fail(
            "Remote-User header not present — cannot identify user. "
            "Ensure this resource uses SSO authentication in Pangolin."
        )

    # Skip API fan-out if this IP was successfully processed recently
    if RATE_LIMIT_SECONDS > 0:
        with _api_rate_limit_lock:
            entry = _api_rate_limit.get(ip)
            if entry and (time.monotonic() - entry[0]) < RATE_LIMIT_SECONDS:
                print(f"[targets] rate limited {ip} — returning cached result")
                return entry[1]

    ctx = make_pangolin_context()
    try:
        effective_resources = pg_filter_resources_for_user(ctx, ORG_ID, remote_user)
    except Exception as e:
        return _fail(f"User authorization failed for {remote_user!r}: {e}")

    if not effective_resources:
        return _fail(
            f"User {remote_user!r} is not authorised for any configured resource."
        )

    effective_ids = [r["resourceId"] for r in effective_resources]
    results = {
        "pangolin": {"ok": False, "detail": "not attempted", "enabled": True},
        "crowdsec": {"ok": False, "detail": "disabled", "enabled": CROWDSEC_ENABLED},
        "resources": effective_resources,
    }
    for t in TARGETS:
        key = t.name
        try:
            t.add_ip(ip, resource_ids=effective_ids)
            results[key]["ok"] = True
            results[key]["detail"] = "ok"
        except Exception as e:
            results[key]["ok"] = False
            results[key]["detail"] = str(e)
            print(f"[targets] add failed for {ip} on {t.__class__.__name__}: {e}")

    if RATE_LIMIT_SECONDS > 0:
        with _api_rate_limit_lock:
            now_mono = time.monotonic()
            _api_rate_limit[ip] = (now_mono, results)
            # Prune entries that have aged out so the dict doesn't grow without bound
            cutoff = now_mono - RATE_LIMIT_SECONDS
            stale = [k for k, (ts, _) in _api_rate_limit.items() if ts < cutoff]
            for k in stale:
                del _api_rate_limit[k]

    return results


def expire_ip_from_targets(ip: str) -> None:
    """Expire/remove this IP across optional targets when our retention hit."""
    for t in TARGETS:
        try:
            t.expire_ip(ip)
        except Exception as e:
            print(f"[targets] expire failed for {ip} on {t.__class__.__name__}: {e}")


def delete_ip_rule_if_created_by_us(ip: str, rid: int) -> bool:
    ctx = make_pangolin_context()
    return pg_delete_ip_rule_if_created_by_us(ctx, ip, rid)


def cleanup_old_ips():
    print("[cleanup] starting")

    now_sec = datetime.now(timezone.utc).replace(microsecond=0)
    cutoff = now_sec - timedelta(minutes=RETENTION_MINUTES)
    with state_lock:
        ips = list(state.keys())
    for ip in ips:
        with state_lock:
            rec = state.get(ip) or {}
            last_seen_str = rec.get("last_seen")
            resources = rec.get("resources", {})
        try:
            last_seen = datetime.fromisoformat(last_seen_str) if last_seen_str else None
        except ValueError:
            print(f"[cleanup] Invalid datetime format in last_seen: {last_seen_str}")
            last_seen = None
        # Skip if record is missing timestamp or not yet expired
        if not last_seen or last_seen >= cutoff:
            continue
        # Time to clean up per resource if created_by_us
        changed = False
        for rid_str, meta in list(resources.items()):
            rid = int(rid_str)
            if not meta.get("created_by_us"):
                continue
            if delete_ip_rule_if_created_by_us(ip, rid):
                # Remove our reference
                with state_lock:
                    rec2 = state.get(ip)
                    if rec2 and rid_str in rec2.get("resources", {}):
                        rec2["resources"].pop(rid_str, None)
                        changed = True
                print(
                    f"[cleanup] deleted rule for {ip} on resource {rid} (last_seen={last_seen_str})"
                )
            else:
                print(
                    f"[cleanup] delete failed for {ip} on resource {rid} — will retry next cycle"
                )
        # If no resources remain, drop the IP record
        with state_lock:
            rec3 = state.get(ip)
            if rec3 and not rec3.get("resources"):
                state.pop(ip, None)
                changed = True
        # Drop expired created_by_us=False resource entries from state.
        # We never created these rules so we don't delete them from Pangolin,
        # but we also don't need to track them forever.
        with state_lock:
            rec4 = state.get(ip)
            if rec4:
                expired_unowned = [
                    rid_str
                    for rid_str, meta in rec4.get("resources", {}).items()
                    if not meta.get("created_by_us")
                ]
                for rid_str in expired_unowned:
                    rec4["resources"].pop(rid_str, None)
                    changed = True
                    print(
                        f"[cleanup] dropped unowned state entry for {ip} on resource {rid_str} (last_seen={last_seen_str})"
                    )
                # If that emptied the record entirely, drop the IP
                if not rec4.get("resources"):
                    state.pop(ip, None)
                    changed = True

        # Always attempt CrowdSec expiration for expired IPs (idempotent)
        try:
            expire_ip_from_targets(ip)
        except Exception as e:
            print(f"[cleanup] crowdsec expire failed for {ip}: {e}")
        if changed:
            save_state()
            print(f"[cleanup] finished expiring {ip} (last_seen={last_seen_str})")
    print("[cleanup] done")


def cleanup_loop():
    while True:
        try:
            cleanup_old_ips()
        except Exception as e:
            print(f"[cleanup] unexpected error: {e}")
        time.sleep(CLEANUP_INTERVAL_MINUTES * 60)


from request_handler import create_image_request_handler  # noqa: E402


def _make_image_handler_context() -> dict:
    return {
        "update_enabled": UPDATE_ENDPOINT_ENABLED,
        "retention_minutes": RETENTION_MINUTES,
        "crowdsec_enabled": CROWDSEC_ENABLED,
        "site_name": SITE_NAME,
        "proxy_shared_secret": PROXY_SHARED_SECRET,
        "state": state,
        "state_lock": state_lock,
        "now_utc_iso": now_utc_iso,
        "save_state": save_state,
        "add_ip_to_targets": add_ip_to_targets,
        "banner_png": BANNER_PNG,
        "banner_gif": BANNER_GIF,
        "redact_headers_for_log": redact_headers_for_log,
    }


# Expose the HTTP handler class
ImageRequestHandler = create_image_request_handler(_make_image_handler_context())


def self_check():
    # Double-check mandatory environment settings and print useful warnings/summary.
    missing = []
    if not PANGOLIN_URL:
        missing.append("PANGOLIN_URL")
    if not RESOURCE_IDS:
        missing.append("RESOURCE_IDS")
    if missing:
        print(
            "[self-check] WARNING: Missing required environment variables: "
            + ", ".join(missing)
        )
        raise RuntimeError(
            "Missing required environment variables: " + ", ".join(missing)
        )

    if PANGOLIN_URL:
        parsed_url = urlparse(PANGOLIN_URL)
        if parsed_url.scheme != "https":
            raise RuntimeError(
                f"PANGOLIN_URL must use https:// scheme; got {parsed_url.scheme!r}"
            )

    for _name, _val, _min in [
        ("CLEANUP_INTERVAL_MINUTES", CLEANUP_INTERVAL_MINUTES, 1),
        ("RETENTION_MINUTES", RETENTION_MINUTES, 1),
        ("RATE_LIMIT_SECONDS", RATE_LIMIT_SECONDS, 0),
        ("RULES_CACHE_TTL_SECONDS", RULES_CACHE_TTL_SECONDS, 1),
        ("CROWDSEC_CACHE_TTL_SECONDS", CROWDSEC_CACHE_TTL_SECONDS, 1),
    ]:
        if _val < _min:
            raise RuntimeError(f"{_name}={_val} is below minimum allowed value {_min}")

    if not PANGOLIN_TOKEN:
        print("")
        print("=" * 60)
        print("[WARN] PANGOLIN_TOKEN is not set or empty.")
        print("       All Pangolin API calls will be skipped.")
        print("       IP rules will NOT be created or deleted.")
        print("       If this is unintentional, check your environment.")
        print("=" * 60)
        print("")
    if not ORG_ID:
        print("[warn] ORG_ID is not set; startup resource listing will be skipped.")
    if not PROXY_SHARED_SECRET:
        print(
            "[warn] PROXY_SHARED_SECRET is not set; the service relies solely on network "
            "topology to stay behind the proxy. Set it and have Pangolin/Traefik inject "
            "the X-Proxy-Secret header for defense-in-depth."
        )

    # Verify state file directory is writable before we need it
    state_dir = os.path.dirname(os.path.abspath(STATE_FILE))
    if not os.path.isdir(state_dir):
        print("")
        print("=" * 60)
        print(f"[WARN] State file directory does not exist: {state_dir}")
        print("       State will be lost on restart.")
        print(f"       Check your volume mount for STATE_FILE={STATE_FILE}")
        print("=" * 60)
        print("")
    else:
        test_file = os.path.join(state_dir, ".write_test")
        try:
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except OSError as e:
            print("")
            print("=" * 60)
            print(f"[WARN] State file directory is not writable: {state_dir}")
            print("       State will be lost on restart.")
            print(f"       Error: {e}")
            print("=" * 60)
            print("")

    cs_status = (
        f"enabled name='{CROWDSEC_ALLOWLIST_NAME}' bin='{CROWDSEC_CSCLI_BIN}' prefix='{CROWDSEC_CMD_PREFIX}'"
        if CROWDSEC_ENABLED
        else "disabled"
    )

    print(
        f"[self-check] OK. listen_port={LISTEN_PORT} state_file={STATE_FILE} "
        f"resources={RESOURCE_IDS} retention_minutes={RETENTION_MINUTES} "
        f"cleanup_interval_minutes={CLEANUP_INTERVAL_MINUTES} rule_priority={RULE_PRIORITY} "
        f"crowdsec={cs_status} update_endpoint_enabled={UPDATE_ENDPOINT_ENABLED} "
        f"site_name={SITE_NAME!r}"
    )


def print_org_resources():
    ctx = make_pangolin_context()
    pg_list_org_resources(ctx, ORG_ID)


def main():
    self_check()
    load_state()

    # Fetch and print resources for the configured org (helper for selecting resource IDs).
    # Also serves as a startup connectivity/auth check against the Pangolin API.
    try:
        print_org_resources()
    except Exception as e:
        err_str = str(e)
        print("")
        print("=" * 60)
        if "401" in err_str or "403" in err_str:
            print("[WARN] Pangolin API auth failed at startup.")
            print(
                "       Check that PANGOLIN_TOKEN is correct and has the required permissions."
            )
        else:
            print(f"[WARN] Pangolin API unreachable at startup: {e}")
            print("       Check PANGOLIN_URL and network connectivity.")
        print(
            "       The service will still start, but Pangolin rules will fail until resolved."
        )
        print("=" * 60)
        print("")

    # Ensure targets are ready (e.g., create CrowdSec allowlist if enabled)
    for t in TARGETS:
        try:
            t.ensure_ready()
        except Exception as e:
            print(f"[targets] ensure_ready failed for {t.__class__.__name__}: {e}")

    # Start cleanup thread
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()

    addr = ("0.0.0.0", LISTEN_PORT)
    httpd = ThreadingHTTPServer(addr, ImageRequestHandler)
    print(
        f"[start] Listening on {addr[0]}:{addr[1]} | resources={RESOURCE_IDS} | retention_minutes={RETENTION_MINUTES} | cleanup_interval_minutes={CLEANUP_INTERVAL_MINUTES}"
    )

    httpd.serve_forever()


if __name__ == "__main__":
    main()
