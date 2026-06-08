from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Set, Any, List
from urllib.parse import quote


def _retry(fn, *, attempts: int = 3, backoff: float = 1.0, label: str = ""):
    """Call fn() up to `attempts` times, sleeping backoff * 2^n between retries.
    Aborts immediately (no retry) on HTTP 401 or 403 — auth failures will not
    resolve with retries and should surface immediately.
    Propagates the final exception if all attempts fail.
    """
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            err_str = str(e)
            if "HTTP 401" in err_str or "HTTP 403" in err_str:
                print(f"[retry] {label} aborted — auth error (will not retry): {e}")
                raise
            if attempt < attempts - 1:
                wait = backoff * (2 ** attempt)
                print(f"[retry] {label} attempt {attempt + 1}/{attempts} failed: {e} — retrying in {wait:.1f}s")
                time.sleep(wait)
    raise last_exc


@dataclass
class PangolinContext:
    url: str
    token: str
    resource_ids: List[int]
    rule_priority: int
    rules_cache_ttl_seconds: int

    # Shared mutable state/caches and helpers injected from app
    rules_cache: Dict[int, Dict[str, Any]]
    state: Dict[str, Any]
    state_lock: threading.Lock
    save_state: Callable[[], None]
    now_utc_iso: Callable[[], str]
    http_json: Callable[[str, str, Dict[str, Any] | None], Dict[str, Any]]


def get_ip_set_for_resource_cached(ctx: PangolinContext, rid: int) -> Set[str]:
    """Return a set of IPs that currently have a rule for the resource.
    Uses a TTL cache to avoid frequent GET calls.
    """
    now = time.time()
    with ctx.state_lock:
        entry = ctx.rules_cache.get(rid)
        if entry and (now - entry.get("ts", 0) < ctx.rules_cache_ttl_seconds):
            return entry.get("ip_set", set())

    # Refresh from Pangolin
    print(f"[pangolin] refreshing rules for resource {rid}")
    rules_resp = _retry(
        lambda: ctx.http_json("GET", f"{ctx.url}/v1/resource/{rid}/rules?limit=10000"),
        label=f"GET rules resource={rid}",
    )
    rules = rules_resp.get("data", {}).get("rules", [])
    ip_set: Set[str] = set()
    for r in rules:
        if r.get("match") == "IP":
            v = r.get("value")
            if isinstance(v, str):
                ip_set.add(v)
    with ctx.state_lock:
        ctx.rules_cache[rid] = {"ts": now, "ip_set": ip_set}
    return ip_set


def ensure_ip_rule(ctx: PangolinContext, ip: str) -> None:
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — Pangolin API calls are disabled. Check your environment configuration.")
    failures: list[str] = []
    for rid in ctx.resource_ids:
        try:
            # 1) check cached existence
            ip_set = get_ip_set_for_resource_cached(ctx, rid)
            if ip in ip_set:
                print(f"[pangolin] rule already exists for IP {ip} on resource {rid}")
                # Track presence but not created_by_us
                with ctx.state_lock:
                    rec = ctx.state.setdefault(ip, {"last_seen": ctx.now_utc_iso(), "resources": {}})
                    rec["last_seen"] = ctx.now_utc_iso()
                    rec["resources"].setdefault(str(rid), {"created_by_us": False})
                continue
            # 2) create rule
            payload = {
                "action": "ACCEPT",
                "match": "IP",
                "value": ip,
                "priority": ctx.rule_priority,
                "enabled": True,
            }
            _ = _retry(
                lambda: ctx.http_json("PUT", f"{ctx.url}/v1/resource/{rid}/rule", payload),
                label=f"PUT rule ip={ip} resource={rid}",
            )
            print(f"[pangolin] created rule for IP {ip} on resource {rid}")
            # Update cache to include newly created rule
            with ctx.state_lock:
                entry = ctx.rules_cache.get(rid)
                if entry:
                    entry.setdefault("ip_set", set()).add(ip)  # type: ignore[arg-type]
                else:
                    ctx.rules_cache[rid] = {"ts": time.time(), "ip_set": {ip}}
            # Update persistent state
            with ctx.state_lock:
                rec = ctx.state.setdefault(ip, {"last_seen": ctx.now_utc_iso(), "resources": {}})
                rec["last_seen"] = ctx.now_utc_iso()
                rec["resources"][str(rid)] = {"created_by_us": True}
            ctx.save_state()
        except Exception as e:
            print(f"[pangolin] ensure rule failed for resource {rid}, ip {ip}: {e}")
            failures.append(f"resource {rid}: {e}")
    if failures:
        raise RuntimeError(f"Pangolin: rule creation failed for {len(failures)}/{len(ctx.resource_ids)} resource(s): {'; '.join(failures)}")


def delete_ip_rule_if_created_by_us(ctx: PangolinContext, ip: str, rid: int) -> bool:
    """Return True if the rule is definitively gone — either we deleted it, or it was
    already absent (manually removed or expired externally). Return False only when a
    failure occurred and we cannot confirm the rule has been removed; the caller should
    retain the IP in state and retry on the next cleanup cycle."""
    try:
        rules_resp = _retry(
            lambda: ctx.http_json("GET", f"{ctx.url}/v1/resource/{rid}/rules?limit=10000"),
            label=f"GET rules (delete phase) resource={rid}",
        )
        rules = rules_resp.get("data", {}).get("rules", [])
        to_delete = [r for r in rules if r.get("match") == "IP" and r.get("value") == ip]
        if not to_delete:
            # Rule is already absent — safe to clear this entry from state
            print(f"[pangolin] no rule found for IP {ip} on resource {rid} (already absent — clearing state)")
            return True
        deleted_any = False
        for r in to_delete:
            rule_id = r.get("ruleId")
            if rule_id is None:
                continue
            try:
                _ = _retry(
                    lambda: ctx.http_json("DELETE", f"{ctx.url}/v1/resource/{rid}/rule/{rule_id}"),
                    label=f"DELETE rule={rule_id} ip={ip} resource={rid}",
                )
                print(f"[pangolin] deleted rule {rule_id} for IP {ip} on resource {rid}")
                deleted_any = True
            except Exception as e:
                print(f"[pangolin] delete failed for rule {rule_id} on {rid}: {e}")
        return deleted_any
    except Exception as e:
        print(f"[pangolin] fetch rules (delete phase) failed for {rid}, ip {ip}: {e}")
        return False


def list_org_resources(ctx: PangolinContext, org_id: str) -> None:
    try:
        url = f"{ctx.url}/v1/org/{org_id}/resources?limit=1000&offset=0"
        resp = ctx.http_json("GET", url)
        resources = (
            resp.get("data", {}).get("resources")
            if isinstance(resp, dict)
            else []
        ) or resp.get("resources", []) or []
        print(f"[pangolin] These are the resources for org '{org_id}'. Use the resourceId numbers for your configuration:")
        if not resources:
            print("  (no resources found or empty response)")
            return
        for r in resources:
            name = r.get("name") or r.get("resourceName") or "(no-name)"
            rid = r.get("resourceId") or r.get("id")
            print(f"  - {name} (resourceId={rid})")
    except Exception as e:
        print(f"[pangolin] failed to list resources for org {org_id}: {e}")
        raise e


def get_user_info(ctx: PangolinContext, org_id: str, username: str) -> tuple[str, list[int]]:
    """Return (userId, roleIds) for the given username in the org.
    Raises RuntimeError on any failure (caller is responsible for fail-closed behaviour).

    Replaces the former get_user_role_ids(); userId is now also returned so that direct
    resource-user assignments can be checked in filter_resources_for_user without an
    additional API call.
    """
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — cannot look up user")
    url = f"{ctx.url}/v1/org/{org_id}/user-by-username?username={quote(username, safe='')}"
    resp = _retry(
        lambda: ctx.http_json("GET", url),
        label=f"GET user-by-username username={username}",
    )
    data = resp.get("data", {})
    role_ids = data.get("roleIds")
    user_id = data.get("userId")
    if role_ids is None or user_id is None:
        raise RuntimeError(f"User {username!r} not found in org {org_id!r} (or unexpected response shape)")
    return user_id, role_ids


def get_resource_allowed_role_ids(ctx: PangolinContext, rid: int) -> set[int]:
    """Return the set of roleIds authorised for the given resource.
    Raises RuntimeError on any failure.
    """
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — cannot look up resource roles")
    url = f"{ctx.url}/v1/resource/{rid}/roles"
    resp = _retry(
        lambda: ctx.http_json("GET", url),
        label=f"GET resource/{rid}/roles",
    )
    roles = resp.get("data", {}).get("roles", [])
    return {r["roleId"] for r in roles if "roleId" in r}


def get_resource_allowed_user_ids(ctx: PangolinContext, rid: int) -> set[str]:
    """Return the set of userIds directly assigned to the given resource.
    This covers the 'Users' section in Pangolin Access Controls, which is separate from
    role-based access. Both paths grant access in Pangolin's SSO check; we mirror that here.
    Raises RuntimeError on any failure.
    """
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — cannot look up resource users")
    url = f"{ctx.url}/v1/resource/{rid}/users"
    resp = _retry(
        lambda: ctx.http_json("GET", url),
        label=f"GET resource/{rid}/users",
    )
    users = resp.get("data", {}).get("users", [])
    return {u["userId"] for u in users if "userId" in u}


def get_resource(ctx: PangolinContext, rid: int) -> dict:
    """Return display metadata for a resource: resourceId, name, fullDomain, ssl.
    Raises RuntimeError on any failure.
    """
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — cannot look up resource")
    url = f"{ctx.url}/v1/resource/{rid}"
    resp = _retry(
        lambda: ctx.http_json("GET", url),
        label=f"GET resource/{rid}",
    )
    data = resp.get("data", {})
    if not data:
        raise RuntimeError(f"Resource {rid} not found or unexpected response shape")
    return {
        "resourceId": rid,
        "name": data.get("name") or str(rid),
        "fullDomain": data.get("fullDomain", ""),
        "ssl": data.get("ssl", True),
    }


def filter_resources_for_user(ctx: PangolinContext, org_id: str, username: str) -> list[dict]:
    """Return the subset of ctx.resource_ids the user is authorised for, with metadata.
    Each entry is {"resourceId": int, "name": str, "fullDomain": str, "ssl": bool}.

    Mirrors Pangolin's own SSO access check: a user is authorised for a resource if
    *either* one of their roles is allowed on that resource (role-based) *or* they are
    directly assigned to the resource via the Users section (direct-user). Either path
    is sufficient — matching Pangolin's OR logic in isUserAllowedToAccessResource().

    Raises on any API error (fail-closed). Returns an empty list if no resource matches
    but no error occurred.
    """
    user_id, user_role_ids_list = get_user_info(ctx, org_id, username)
    user_role_ids = set(user_role_ids_list)
    effective: list[dict] = []
    for rid in ctx.resource_ids:
        resource_role_ids = get_resource_allowed_role_ids(ctx, rid)
        resource_user_ids = get_resource_allowed_user_ids(ctx, rid)
        role_match = bool(user_role_ids & resource_role_ids)
        user_match = user_id in resource_user_ids
        if role_match or user_match:
            reason = "role" if role_match else "direct-user"
            meta = get_resource(ctx, rid)
            print(f"[pangolin] user {username!r} authorised for resource {rid} ({meta.get('name')}) via {reason}")
            effective.append(meta)
        else:
            print(f"[pangolin] user {username!r} not authorised for resource {rid} — skipping")
    return effective
