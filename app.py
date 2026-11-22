import base64
import contextlib
import copy
import ipaddress
import json
import os
import signal
import tempfile
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from crowdsec_connector import (
    CROWDSEC_ALLOWLIST_NAME,
    CROWDSEC_CACHE_TTL_SECONDS,
    CROWDSEC_CMD_PREFIX,
    CROWDSEC_CSCLI_BIN,
    CROWDSEC_ENABLED,
    crowdsec_add_ip,
    crowdsec_ensure_allowlist,
    crowdsec_remove_ip,
)
from pangolin_connector import (
    PangolinContext,
)
from pangolin_connector import (
    delete_ip_rule_if_created_by_us as pg_delete_ip_rule_if_created_by_us,
)
from pangolin_connector import (
    ensure_ip_rule as pg_ensure_ip_rule,
)
from pangolin_connector import (
    filter_resources_for_user as pg_filter_resources_for_user,
)
from pangolin_connector import (
    list_org_resources as pg_list_org_resources,
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
# Optional: site name shown in the HTML check-in and error pages
SITE_NAME = os.getenv("SITE_NAME", "").strip()
# Optional: allow overriding the caller IP via /update?ip=...
UPDATE_ENDPOINT_ENABLED = os.getenv(
    "UPDATE_ENDPOINT_ENABLED", "false"
).strip().lower() in ("1", "true", "yes", "on")
# Required shared secret that Pangolin sends in the X-Proxy-Secret request header.
# Requests missing or mismatching the secret are rejected before any state write
# or API call.
PROXY_SHARED_SECRET = os.getenv("PROXY_SHARED_SECRET", "")
# Optional: log request headers with credentials, tokens, cookies, and the proxy secret redacted.
DEBUG_LOG_HEADERS = os.getenv("DEBUG_LOG_HEADERS", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
# Optional: redirect browser check-ins directly to Pangolin Resource Launcher (dashboard)
REDIRECT_TO_LAUNCHER = os.getenv("REDIRECT_TO_LAUNCHER", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
# Optional: delay redirect by X seconds. Set to 0 for immediate redirect. Default is 3.
try:
    REDIRECT_DELAY_SECONDS = int(os.getenv("REDIRECT_DELAY_SECONDS", "3"))
except ValueError:
    REDIRECT_DELAY_SECONDS = 3
# Optional: explicitly override the Pangolin Resource Launcher dashboard URL.
# If empty, it is automatically derived from PANGOLIN_URL and ORG_ID.
PANGOLIN_DASHBOARD_URL = os.getenv("PANGOLIN_DASHBOARD_URL", "").strip().rstrip("/")
if not PANGOLIN_DASHBOARD_URL and PANGOLIN_URL:
    # Derive from PANGOLIN_URL (strip api/version suffixes and append ORG_ID if present)
    _base = PANGOLIN_URL
    for _suffix in ("/v1", "/v2", "/api"):
        _base = _base.removesuffix(_suffix)
    _base = _base.rstrip("/")
    if ORG_ID:
        PANGOLIN_DASHBOARD_URL = f"{_base}/{ORG_ID}"
    else:
        PANGOLIN_DASHBOARD_URL = _base


# Minimal 1x1 PNG (transparent) as bytes
BANNER_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII="
)
# Minimal 1x1 GIF (transparent) as bytes
BANNER_GIF = base64.b64decode(
    "R0lGODlhAQABAPAAAP///wAAACH5BAAAAAAALAAAAAABAAEAAAICRAEAOw=="
)

state_lock = threading.Lock()
# Serializes save_state() / load_state() so concurrent writers and loaders cannot
# race on the temporary file, clobber os.replace, or invert lock ordering.
_save_lock = threading.Lock()
# Global lock acquisition order (never inverted):
#   _ip_locks[stripe] -> _api_rate_limit_lock (leaf)
#   _ip_locks[stripe] -> _save_lock -> state_lock (leaf)
_IP_LOCK_STRIPES = 64
_ip_locks: tuple[threading.Lock, ...] = tuple(
    threading.Lock() for _ in range(_IP_LOCK_STRIPES)
)


def _canonicalize_ip_key(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def _get_ip_lock(ip: str) -> threading.Lock:
    return _ip_locks[hash(_canonicalize_ip_key(ip)) % _IP_LOCK_STRIPES]


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

# Per-(IP, stable Pangolin user ID, username) rate limit cache.
_API_RATE_LIMIT_MAX_ENTRIES = 4096
_api_rate_limit: dict[tuple[str, str, str], tuple[float, dict]] = {}
_api_rate_limit_lock = threading.Lock()


def _evict_rate_limit_for_ip(ip: str) -> None:
    canonical_ip = _canonicalize_ip_key(ip)
    with _api_rate_limit_lock:
        to_remove = [
            k
            for k in _api_rate_limit
            if k[0] == ip or _canonicalize_ip_key(k[0]) == canonical_ip
        ]
        for k in to_remove:
            del _api_rate_limit[k]


shutdown_event = threading.Event()
_SHUTDOWN_TIMEOUT_SECONDS = 4.0


def now_utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


_REDACTED_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-proxy-secret",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)
_REDACTED_HEADER_SUBSTRINGS = (
    "cookie",
    "secret",
    "token",
    "auth",
    "api-key",
    "apikey",
    "password",
)


def _is_sensitive_header(name: str) -> bool:
    kl = name.lower()
    return kl in _REDACTED_HEADER_NAMES or any(
        sub in kl for sub in _REDACTED_HEADER_SUBSTRINGS
    )


def redact_headers_for_log(headers):
    """Return a copy of headers suitable for logging.

    Accepts either a Mapping (returning a dict) or a sequence/iterable of
    (name, value) pairs such as HTTPMessage.items() (returning a list of pairs
    to preserve duplicate headers). Redacts explicit sensitive headers and any
    header name containing sensitive substrings (case-insensitively), and
    sanitizes logged header names and non-redacted values against control chars.
    """
    if isinstance(headers, Mapping):
        redacted: dict[str, str] = {}
        for k, v in headers.items():
            name = str(k)
            safe_name = sanitize_for_log(name)
            if _is_sensitive_header(name):
                redacted[safe_name] = "<redacted>"
            else:
                redacted[safe_name] = sanitize_for_log(v)
        return redacted

    items = headers.items() if hasattr(headers, "items") else headers
    redacted_pairs: list[tuple[str, str]] = []
    for k, v in items:
        name = str(k)
        safe_name = sanitize_for_log(name)
        if _is_sensitive_header(name):
            redacted_pairs.append((safe_name, "<redacted>"))
        else:
            redacted_pairs.append((safe_name, sanitize_for_log(v)))
    return redacted_pairs


def load_state():
    with _save_lock:
        if not os.path.exists(STATE_FILE):
            return
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                # The HTTP handler already holds this mapping; preserve its identity.
                with state_lock:
                    state.clear()
                    state.update(data)
        except Exception as e:  # noqa: BLE001
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
                if hasattr(os, "fchmod"):
                    os.fchmod(f.fileno(), 0o600)
                f.write(snapshot)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, STATE_FILE)
            tmp_file = None
        except Exception as e:  # noqa: BLE001
            print(f"[state] failed to save state: {e}")
            if tmp_file is not None:
                with contextlib.suppress(OSError):
                    os.remove(tmp_file)


_MAX_HTTP_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_HTTP_ERROR_BYTES = 4096
# Internal test/compatibility-harness opt-in only; never configurable via env vars.
_ALLOW_INSECURE_HTTP = False


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_HTTP_OPENER = build_opener(ProxyHandler({}), _NoRedirects())


def _sanitize_http_error_body(raw: bytes) -> str:
    """Decode and strip control/newline characters from an upstream error excerpt."""
    text = raw.decode("utf-8", errors="replace")
    return "".join(
        " " if (ord(ch) < 32 or ord(ch) == 127 or ch in ("\u2028", "\u2029")) else ch
        for ch in text
    ).strip()


def http_json(method: str, url: str, body: dict | None = None) -> dict:
    """Perform an outbound JSON request to the configured Pangolin origin."""
    parsed = urlparse(url)
    allowed_schemes = ("https", "http") if _ALLOW_INSECURE_HTTP else ("https",)
    if parsed.scheme.lower() not in allowed_schemes or not parsed.netloc:
        raise RuntimeError(
            f"Blocked outbound request with disallowed URL scheme or missing host: {parsed.scheme!r}"
        )
    if parsed.username is not None or parsed.password is not None:
        raise RuntimeError("Blocked outbound request containing URL credentials")

    base = urlparse(PANGOLIN_URL)
    if not base.scheme or not base.netloc:
        raise RuntimeError("PANGOLIN_URL is not configured with a valid origin")
    if (
        parsed.scheme.lower() != base.scheme.lower()
        or parsed.netloc.lower() != base.netloc.lower()
    ):
        raise RuntimeError("Blocked outbound request to unexpected Pangolin origin")

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
        with _HTTP_OPENER.open(req, timeout=20) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            raw = resp.read(_MAX_HTTP_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_HTTP_RESPONSE_BYTES:
                raise RuntimeError(
                    f"Upstream response exceeded {_MAX_HTTP_RESPONSE_BYTES} byte limit"
                )
            try:
                text = raw.decode(charset, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
    except HTTPError as e:
        try:
            raw_err = e.read(_MAX_HTTP_ERROR_BYTES)
            err_snippet = _sanitize_http_error_body(raw_err)
        except (OSError, AttributeError, ValueError):
            err_snippet = ""
        finally:
            with contextlib.suppress(Exception):
                e.close()
        safe_reason = sanitize_for_log(e.reason)
        if err_snippet:
            print(f"[http_json] HTTP {e.code} {safe_reason}: {err_snippet}")
        else:
            print(f"[http_json] HTTP {e.code} {safe_reason}")
        raise RuntimeError(f"HTTP {e.code} {e.reason}") from None
    except URLError as e:
        raise RuntimeError(f"Network error: {e.reason}") from None


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


# --------------------------
# Target aggregation (extensibility point)
# --------------------------


def _is_identity_denial_error(exc: Exception, org_id: str, user_id: str) -> bool:
    """Return True when pg_filter_resources_for_user failed due to identity denial
    (mismatch or user absent in org) rather than an upstream API or config error.
    """
    msg = str(exc)
    if msg.startswith("Pangolin identity mismatch:"):
        return True
    if msg in ("Remote-User-Id header is empty", "Remote-User header is empty"):
        return True
    return msg == f"User {user_id!r} not found in org {org_id!r}"


def add_ip_to_targets(ip: str, remote_user_id: str = "", remote_user: str = "") -> dict:
    """Add/allow this IP across configured targets (Pangolin, CrowdSec, etc.).
    Requires the Remote-User-Id and Remote-User values forwarded by Pangolin.
    Fails closed: returns ok=False without touching any target if the user cannot
    be identified or is not authorised for any configured resource.
    Returns a dict of per-target results for display purposes.
    """

    def _fail(detail: str, error_kind: str = "auth") -> dict:
        print(f"[targets] fail-closed: {sanitize_for_log(detail)}")
        return {
            "error_kind": error_kind,
            "pangolin": {"ok": False, "detail": detail, "enabled": True},
            "crowdsec": {
                "ok": False,
                "detail": "not reached",
                "enabled": CROWDSEC_ENABLED,
            },
        }

    if not remote_user_id:
        return _fail(
            "Remote-User-Id header not present — cannot identify user. "
            "Require Badger v1.4.1 or newer and Pangolin user authentication.",
            error_kind="auth",
        )

    if not remote_user:
        return _fail(
            "Remote-User header not present — cannot identify user. "
            "Ensure this resource uses Pangolin user authentication.",
            error_kind="auth",
        )

    cache_key = (ip, remote_user_id, remote_user)
    with _get_ip_lock(ip):
        # Skip API fan-out if this IP was successfully processed recently for this user
        if RATE_LIMIT_SECONDS > 0:
            with _api_rate_limit_lock:
                entry = _api_rate_limit.get(cache_key)
                if entry and (time.monotonic() - entry[0]) < RATE_LIMIT_SECONDS:
                    print(
                        f"[targets] rate limited {sanitize_for_log(ip)} "
                        f"for user_id {sanitize_for_log(remote_user_id)!r} "
                        "— returning cached result"
                    )
                    return copy.deepcopy(entry[1])

        ctx = make_pangolin_context()
        try:
            effective_resources = pg_filter_resources_for_user(
                ctx, ORG_ID, remote_user_id, remote_user
            )
        except Exception as e:  # noqa: BLE001
            error_kind = (
                "auth"
                if _is_identity_denial_error(e, ORG_ID, remote_user_id)
                else "upstream"
            )
            return _fail(
                f"User authorization failed for user_id {sanitize_for_log(remote_user_id)!r}, "
                f"username {sanitize_for_log(remote_user)!r}: {sanitize_for_log(e)}",
                error_kind=error_kind,
            )

        if not effective_resources:
            return _fail(
                f"User {sanitize_for_log(remote_user)!r} ({sanitize_for_log(remote_user_id)}) "
                "is not authorised for any configured resource.",
                error_kind="auth",
            )

        effective_ids = [r["resourceId"] for r in effective_resources]
        results = {
            "pangolin": {"ok": False, "detail": "not attempted", "enabled": True},
            "crowdsec": {
                "ok": False,
                "detail": "disabled",
                "enabled": CROWDSEC_ENABLED,
            },
            "resources": effective_resources,
        }
        for t in TARGETS:
            key = t.name
            try:
                t.add_ip(ip, resource_ids=effective_ids)
                results[key]["ok"] = True
                results[key]["detail"] = "ok"
            except Exception as e:  # noqa: BLE001
                results[key]["ok"] = False
                results[key]["detail"] = str(e)
                print(
                    f"[targets] add failed for {sanitize_for_log(ip)} "
                    f"on {t.__class__.__name__}: {sanitize_for_log(e)}"
                )

        if not results["pangolin"]["ok"]:
            results["error_kind"] = "upstream"

        # Only cache full target success (including CrowdSec when enabled)
        pangolin_ok = bool(results.get("pangolin", {}).get("ok", False))
        crowdsec_ok = bool(results.get("crowdsec", {}).get("ok", False))
        is_success = pangolin_ok and (not CROWDSEC_ENABLED or crowdsec_ok)
        if RATE_LIMIT_SECONDS > 0 and is_success and _API_RATE_LIMIT_MAX_ENTRIES > 0:
            with _api_rate_limit_lock:
                now_mono = time.monotonic()
                # Prune entries that have aged out before enforcing the size cap
                cutoff = now_mono - RATE_LIMIT_SECONDS
                stale = [k for k, (ts, _) in _api_rate_limit.items() if ts < cutoff]
                for k in stale:
                    del _api_rate_limit[k]
                _api_rate_limit.pop(cache_key, None)
                while len(_api_rate_limit) >= _API_RATE_LIMIT_MAX_ENTRIES:
                    oldest_key = min(
                        _api_rate_limit, key=lambda k: _api_rate_limit[k][0]
                    )
                    del _api_rate_limit[oldest_key]
                _api_rate_limit[cache_key] = (now_mono, copy.deepcopy(results))

        return results


def expire_ip_from_targets(ip: str) -> None:
    """Expire/remove this IP across optional targets when our retention hit."""
    for t in TARGETS:
        try:
            t.expire_ip(ip)
        except Exception as e:  # noqa: BLE001
            print(
                f"[targets] expire failed for {sanitize_for_log(ip)} "
                f"on {t.__class__.__name__}: {sanitize_for_log(e)}"
            )


def delete_ip_rule_if_created_by_us(ip: str, rid: int) -> bool:
    ctx = make_pangolin_context()
    return pg_delete_ip_rule_if_created_by_us(ctx, ip, rid)


def _parse_last_seen(
    last_seen_str: object, ip: str, *, warn: bool = True
) -> datetime | None:
    if not last_seen_str:
        return None
    try:
        dt = datetime.fromisoformat(last_seen_str)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        if warn:
            print(
                "[cleanup] Invalid datetime format in last_seen for "
                f"{sanitize_for_log(ip)}: {sanitize_for_log(last_seen_str)}"
            )
        return None
    if dt.tzinfo is None or dt.utcoffset() is None:
        if warn:
            print(
                "[cleanup] Naive datetime in last_seen for "
                f"{sanitize_for_log(ip)}: {sanitize_for_log(last_seen_str)} — assuming UTC"
            )
        dt = dt.replace(tzinfo=UTC)
    return dt


def cleanup_old_ips():
    print("[cleanup] starting")

    now_sec = datetime.now(UTC).replace(microsecond=0)
    cutoff = now_sec - timedelta(minutes=RETENTION_MINUTES)
    with state_lock:
        ips = list(state.keys())

    def _is_still_expired_locked(ip_key: str, snapshot_last_seen: object) -> bool:
        cur = state.get(ip_key)
        if not isinstance(cur, dict):
            return False
        cur_last_seen_str = cur.get("last_seen")
        if cur_last_seen_str != snapshot_last_seen:
            return False
        cur_dt = _parse_last_seen(cur_last_seen_str, ip_key, warn=False)
        return cur_dt is not None and cur_dt < cutoff

    for ip in ips:
        with _get_ip_lock(ip):
            with state_lock:
                rec = state.get(ip)
                if rec is None:
                    continue
                if not isinstance(rec, dict):
                    print(
                        "[cleanup] Invalid state record for "
                        f"{sanitize_for_log(ip)} — skipping"
                    )
                    continue
                last_seen_str = rec.get("last_seen")
                raw_resources = rec.get("resources", {})
                if raw_resources is None:
                    raw_resources = {}
                if not isinstance(raw_resources, dict):
                    print(
                        "[cleanup] Invalid resources mapping for "
                        f"{sanitize_for_log(ip)} — skipping"
                    )
                    continue
                resources = dict(raw_resources)

            last_seen = _parse_last_seen(last_seen_str, ip, warn=True)
            # Skip if record is missing timestamp, invalid, or not yet expired
            if not last_seen or last_seen >= cutoff:
                continue

            changed = False
            renewed = False
            deleted_any = False
            for rid_str, meta in list(resources.items()):
                try:
                    rid = int(rid_str)
                except (ValueError, TypeError):
                    print(
                        "[cleanup] Invalid resource ID key "
                        f"{sanitize_for_log(rid_str)!r} for {sanitize_for_log(ip)} — skipping"
                    )
                    continue
                if not isinstance(meta, dict) or not meta.get("created_by_us"):
                    continue
                with state_lock:
                    if not _is_still_expired_locked(ip, last_seen_str):
                        renewed = True
                        break
                if delete_ip_rule_if_created_by_us(ip, rid):
                    deleted_any = True
                    with state_lock:
                        if not _is_still_expired_locked(ip, last_seen_str):
                            renewed = True
                            break
                        rec2 = state.get(ip)
                        if isinstance(rec2, dict):
                            rec2_resources = rec2.get("resources")
                            if (
                                isinstance(rec2_resources, dict)
                                and rid_str in rec2_resources
                            ):
                                rec2_resources.pop(rid_str, None)
                                changed = True
                    print(
                        f"[cleanup] deleted rule for {sanitize_for_log(ip)} on resource {rid} "
                        f"(last_seen={sanitize_for_log(last_seen_str)})"
                    )
                else:
                    print(
                        f"[cleanup] delete failed for {sanitize_for_log(ip)} on resource {rid} — will retry next cycle"
                    )

            if not renewed:
                with state_lock:
                    if not _is_still_expired_locked(ip, last_seen_str):
                        renewed = True
            if renewed:
                if deleted_any:
                    _evict_rate_limit_for_ip(ip)
                if changed:
                    save_state()
                print(
                    f"[cleanup] {sanitize_for_log(ip)} was renewed during cleanup — skipping remaining expiration"
                )
                continue

            # Evict any rate-limit cache entries for this expired IP before target cleanup
            _evict_rate_limit_for_ip(ip)

            # Always attempt CrowdSec expiration for expired IPs (idempotent)
            try:
                expire_ip_from_targets(ip)
            except Exception as e:  # noqa: BLE001
                print(
                    f"[cleanup] crowdsec expire failed for {sanitize_for_log(ip)}: {sanitize_for_log(e)}"
                )

            with state_lock:
                if not _is_still_expired_locked(ip, last_seen_str):
                    renewed = True
                else:
                    rec_cur = state.get(ip)
                    if isinstance(rec_cur, dict):
                        cur_resources = rec_cur.get("resources")
                        if isinstance(cur_resources, dict):
                            expired_unowned = [
                                rid_str
                                for rid_str, meta in cur_resources.items()
                                if not (
                                    isinstance(meta, dict) and meta.get("created_by_us")
                                )
                            ]
                            for rid_str in expired_unowned:
                                cur_resources.pop(rid_str, None)
                                changed = True
                                print(
                                    "[cleanup] dropped unowned state entry for "
                                    f"{sanitize_for_log(ip)} on resource {sanitize_for_log(rid_str)} "
                                    f"(last_seen={sanitize_for_log(last_seen_str)})"
                                )
                        if not rec_cur.get("resources"):
                            state.pop(ip, None)
                            changed = True

            if renewed:
                if changed:
                    save_state()
                print(
                    f"[cleanup] {sanitize_for_log(ip)} was renewed during cleanup — skipping remaining expiration"
                )
            elif changed:
                save_state()
                print(
                    f"[cleanup] finished expiring {sanitize_for_log(ip)} "
                    f"(last_seen={sanitize_for_log(last_seen_str)})"
                )
    print("[cleanup] done")


def cleanup_loop(stop_event: threading.Event | None = None):
    event = shutdown_event if stop_event is None else stop_event
    while not event.is_set():
        try:
            cleanup_old_ips()
        except Exception as e:  # noqa: BLE001
            print(f"[cleanup] unexpected error: {e}")
        if event.wait(CLEANUP_INTERVAL_MINUTES * 60):
            break


from request_handler import (
    build_plain_http_response,
    create_image_request_handler,
    is_valid_dashboard_url,
    sanitize_for_log,
)


def _make_image_handler_context() -> dict:
    return {
        "update_enabled": UPDATE_ENDPOINT_ENABLED,
        "retention_minutes": RETENTION_MINUTES,
        "crowdsec_enabled": CROWDSEC_ENABLED,
        "site_name": SITE_NAME,
        "proxy_shared_secret": PROXY_SHARED_SECRET,
        "debug_log_headers": DEBUG_LOG_HEADERS,
        "state": state,
        "state_lock": state_lock,
        "now_utc_iso": now_utc_iso,
        "save_state": save_state,
        "add_ip_to_targets": add_ip_to_targets,
        "banner_png": BANNER_PNG,
        "banner_gif": BANNER_GIF,
        "redact_headers_for_log": redact_headers_for_log,
        "redirect_to_launcher": REDIRECT_TO_LAUNCHER,
        "redirect_delay_seconds": REDIRECT_DELAY_SECONDS,
        "pangolin_dashboard_url": PANGOLIN_DASHBOARD_URL,
    }


# Expose the HTTP handler class
ImageRequestHandler = create_image_request_handler(_make_image_handler_context())


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with bounded worker threads and fast-fail 503."""

    max_workers = 32
    request_queue_size = 32
    daemon_threads = True
    block_on_close = False

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        bind_and_activate: bool = True,
        *,
        max_workers: int | None = None,
    ):
        if max_workers is not None:
            if max_workers < 1:
                raise ValueError("max_workers must be >= 1")
            self.max_workers = max_workers
        self._worker_semaphore = threading.BoundedSemaphore(self.max_workers)
        self._workers_lock = threading.Lock()
        self._active_workers: set[threading.Thread] = set()
        super().__init__(
            server_address, RequestHandlerClass, bind_and_activate=bind_and_activate
        )

    def _send_503_and_close(self, request) -> None:
        response = build_plain_http_response(
            503,
            "Service Unavailable",
            "Service Unavailable",
            extra_headers=(("Retry-After", "5"), ("Connection", "close")),
        )
        try:
            with contextlib.suppress(OSError):
                request.settimeout(0.0)
                request.recv(4096)
            try:
                request.settimeout(1.0)
                request.sendall(response)
            except OSError:
                pass
            with contextlib.suppress(OSError):
                request.settimeout(0.0)
                request.recv(4096)
        finally:
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._workers_lock:
                self._active_workers.discard(threading.current_thread())
            self._worker_semaphore.release()

    def process_request(self, request, client_address) -> None:
        if not self._worker_semaphore.acquire(blocking=False):
            print("[http] worker pool saturated; returning 503")
            self._send_503_and_close(request)
            return
        t = threading.Thread(
            target=self.process_request_thread,
            args=(request, client_address),
            daemon=self.daemon_threads,
        )
        with self._workers_lock:
            self._active_workers.add(t)
        try:
            t.start()
        except BaseException:
            with self._workers_lock:
                self._active_workers.discard(t)
            self._worker_semaphore.release()
            self.shutdown_request(request)
            raise

    def join_workers(self, timeout: float) -> None:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            with self._workers_lock:
                workers = list(self._active_workers)
            if not workers:
                return
            for worker in workers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                worker.join(timeout=remaining)


def self_check():
    # Double-check mandatory environment settings and print useful warnings/summary.
    missing = []
    if not PANGOLIN_URL:
        missing.append("PANGOLIN_URL")
    if not RESOURCE_IDS:
        missing.append("RESOURCE_IDS")
    if not PROXY_SHARED_SECRET:
        missing.append("PROXY_SHARED_SECRET")
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

    if PANGOLIN_DASHBOARD_URL and not is_valid_dashboard_url(PANGOLIN_DASHBOARD_URL):
        raise RuntimeError(
            "PANGOLIN_DASHBOARD_URL must be a valid https:// URL without userinfo, "
            f"whitespace, or control characters; got {PANGOLIN_DASHBOARD_URL!r}"
        )

    for _name, _val, _min in [
        ("CLEANUP_INTERVAL_MINUTES", CLEANUP_INTERVAL_MINUTES, 1),
        ("RETENTION_MINUTES", RETENTION_MINUTES, 1),
        ("RATE_LIMIT_SECONDS", RATE_LIMIT_SECONDS, 0),
        ("REDIRECT_DELAY_SECONDS", REDIRECT_DELAY_SECONDS, 0),
        ("RULES_CACHE_TTL_SECONDS", RULES_CACHE_TTL_SECONDS, 1),
        ("CROWDSEC_CACHE_TTL_SECONDS", CROWDSEC_CACHE_TTL_SECONDS, 1),
    ]:
        if _val < _min:
            raise RuntimeError(f"{_name}={_val} is below minimum allowed value {_min}")

    if not PANGOLIN_TOKEN:
        print()
        print("=" * 60)
        print("[WARN] PANGOLIN_TOKEN is not set or empty.")
        print("       All Pangolin API calls will be skipped.")
        print("       IP rules will NOT be created or deleted.")
        print("       If this is unintentional, check your environment.")
        print("=" * 60)
        print()
    if not ORG_ID:
        print("[warn] ORG_ID is not set; startup resource listing will be skipped.")
    # Verify state file directory is writable before we need it
    state_dir = os.path.dirname(os.path.abspath(STATE_FILE))
    if not os.path.isdir(state_dir):
        print()
        print("=" * 60)
        print(f"[WARN] State file directory does not exist: {state_dir}")
        print("       State will be lost on restart.")
        print(f"       Check your volume mount for STATE_FILE={STATE_FILE}")
        print("=" * 60)
        print()
    else:
        test_file = os.path.join(state_dir, ".write_test")
        try:
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
        except OSError as e:
            print()
            print("=" * 60)
            print(f"[WARN] State file directory is not writable: {state_dir}")
            print("       State will be lost on restart.")
            print(f"       Error: {e}")
            print("=" * 60)
            print()

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
        f"site_name={SITE_NAME!r} redirect_to_launcher={REDIRECT_TO_LAUNCHER} "
        f"redirect_delay_seconds={REDIRECT_DELAY_SECONDS} "
        f"pangolin_dashboard_url={PANGOLIN_DASHBOARD_URL!r}"
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
    except Exception as e:  # noqa: BLE001
        err_str = str(e)
        print()
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
        print()

    # Ensure targets are ready (e.g., create CrowdSec allowlist if enabled)
    for t in TARGETS:
        try:
            t.ensure_ready()
        except Exception as e:  # noqa: BLE001
            print(f"[targets] ensure_ready failed for {t.__class__.__name__}: {e}")

    shutdown_event.clear()

    # Start cleanup thread
    cleanup_thread = threading.Thread(
        target=cleanup_loop,
        args=(shutdown_event,),
        name="cleanup-loop",
        daemon=True,
    )
    cleanup_thread.start()

    addr = ("0.0.0.0", LISTEN_PORT)
    httpd = BoundedThreadingHTTPServer(addr, ImageRequestHandler)

    shutdown_triggered = False
    shutdown_started_at: float | None = None

    def _trigger_shutdown(signum, _frame):
        nonlocal shutdown_triggered, shutdown_started_at
        if shutdown_triggered:
            return
        shutdown_triggered = True
        shutdown_started_at = time.monotonic()
        sig_name = signal.Signals(signum).name

        def _shutdown_worker():
            print(f"[shutdown] Received {sig_name}; shutting down gracefully")
            shutdown_event.set()
            httpd.shutdown()

        threading.Thread(
            target=_shutdown_worker, name="shutdown-worker", daemon=True
        ).start()

    prev_sigterm = signal.signal(signal.SIGTERM, _trigger_shutdown)
    prev_sigint = signal.signal(signal.SIGINT, _trigger_shutdown)

    try:
        print(
            f"[start] Listening on {httpd.server_address[0]}:{httpd.server_address[1]} "
            f"| resources={RESOURCE_IDS} | retention_minutes={RETENTION_MINUTES} "
            f"| cleanup_interval_minutes={CLEANUP_INTERVAL_MINUTES}"
        )
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[shutdown] Interrupted; shutting down gracefully")
    finally:
        signal.signal(signal.SIGTERM, prev_sigterm)
        signal.signal(signal.SIGINT, prev_sigint)
        shutdown_event.set()
        start = (
            shutdown_started_at if shutdown_started_at is not None else time.monotonic()
        )
        deadline = start + _SHUTDOWN_TIMEOUT_SECONDS
        httpd.server_close()
        httpd.join_workers(max(0.0, deadline - time.monotonic()))
        cleanup_thread.join(timeout=max(0.0, deadline - time.monotonic()))
        print("[shutdown] Shutdown complete")


if __name__ == "__main__":
    main()
