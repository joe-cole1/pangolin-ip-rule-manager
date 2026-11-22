from __future__ import annotations

import ipaddress
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
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
                wait = backoff * (2**attempt)
                print(
                    f"[retry] {label} attempt {attempt + 1}/{attempts} failed: {e} — retrying in {wait:.1f}s"
                )
                time.sleep(wait)
    raise last_exc


@dataclass
class PangolinContext:
    url: str
    token: str
    resource_ids: list[int]
    rule_priority: int
    rules_cache_ttl_seconds: int

    # Shared mutable state/caches and helpers injected from app
    rules_cache: dict[int, dict[str, Any]]
    state: dict[str, Any]
    state_lock: threading.Lock
    save_state: Callable[[], None]
    now_utc_iso: Callable[[], str]
    http_json: Callable[[str, str, dict[str, Any] | None], dict[str, Any]]


def _canonicalize_ip(value: object) -> str | None:
    """Return canonical IPv4/IPv6 string for a valid IP literal, or None."""
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _require_api_success(resp: object, label: str) -> dict[str, Any]:
    """Validate that a Pangolin API response is a dict with success=True."""
    if not isinstance(resp, dict) or resp.get("success") is not True:
        raise RuntimeError(
            f"{label}: Pangolin API reported failure or unexpected response shape"
        )
    return resp


def _unexpected_api_error(label: str, detail: str) -> RuntimeError:
    return RuntimeError(f"{label}: {detail}")


def _extract_api_data(resp: object, label: str) -> dict[str, Any]:
    """Validate success=True and return the dict payload under resp['data']."""
    ok_resp = _require_api_success(resp, label)
    data = ok_resp.get("data")
    if not isinstance(data, dict):
        raise _unexpected_api_error(label, "Pangolin API response missing dict data")
    return data


def _extract_dict_list(
    data: dict[str, Any], key: str, label: str
) -> list[dict[str, Any]]:
    """Extract and validate a list of dicts from `data[key]`."""
    items = data.get(key)
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise _unexpected_api_error(
            label, f"unexpected {key} list in Pangolin API response"
        )
    return items


def _extract_created_rule_id(resp: dict[str, Any]) -> int | None:
    """Extract an optional integer ruleId from a PUT /rule response."""
    data = resp.get("data")
    if not isinstance(data, dict):
        return None
    candidate = data.get("ruleId")
    if candidate is None and isinstance(data.get("rule"), dict):
        candidate = data["rule"].get("ruleId")
    if isinstance(candidate, int) and not isinstance(candidate, bool):
        return candidate
    return None


def _extract_rules_list(resp: object, label: str) -> list[dict[str, Any]]:
    """Validate a GET /rules response and return its list of rule dicts."""
    data = _extract_api_data(resp, label)
    return _extract_dict_list(data, "rules", label)


def _evict_ip_from_rules_cache(ctx: PangolinContext, rid: int, *ips: str) -> None:
    """Remove IP entries from the in-memory resource existence cache."""
    with ctx.state_lock:
        entry = ctx.rules_cache.get(rid)
        if entry:
            cached_ips = entry.get("ip_set", set())
            for addr in ips:
                cached_ips.discard(addr)


def _lookup_target_rule_id(
    ctx: PangolinContext,
    ip: str,
    canonical_ip: str,
    rid: int,
    explicit_rule_id: int | None,
) -> int | None:
    """Resolve explicit or persisted rule_id for (ip, rid), if valid."""
    if isinstance(explicit_rule_id, int) and not isinstance(explicit_rule_id, bool):
        return explicit_rule_id
    with ctx.state_lock:
        rec = ctx.state.get(ip)
        if not isinstance(rec, dict) and canonical_ip != ip:
            rec = ctx.state.get(canonical_ip)
        if not isinstance(rec, dict):
            return None
        res_meta = rec.get("resources", {}).get(str(rid), {})
        if not isinstance(res_meta, dict):
            return None
        stored_rule_id = res_meta.get("rule_id")
        if isinstance(stored_rule_id, int) and not isinstance(stored_rule_id, bool):
            return stored_rule_id
        return None


def get_ip_set_for_resource_cached(ctx: PangolinContext, rid: int) -> set[str]:
    """Return a set of canonical IPs that currently have an active ACCEPT rule
    for the resource. Uses a monotonic TTL cache to avoid frequent GET calls.
    """
    now = time.monotonic()
    with ctx.state_lock:
        entry = ctx.rules_cache.get(rid)
        if entry:
            ts = entry.get("ts")
            if (
                isinstance(ts, (int, float))
                and not isinstance(ts, bool)
                and ts > 0
                and (now - ts < ctx.rules_cache_ttl_seconds)
            ):
                return set(entry.get("ip_set", set()))

    # Refresh from Pangolin
    print(f"[pangolin] refreshing rules for resource {rid}")
    rules_resp = _retry(
        lambda: ctx.http_json("GET", f"{ctx.url}/v1/resource/{rid}/rules?limit=10000"),
        label=f"GET rules resource={rid}",
    )
    rules = _extract_rules_list(rules_resp, f"GET rules resource={rid}")
    ip_set: set[str] = set()
    for r in rules:
        if (
            r.get("match") == "IP"
            and r.get("action") == "ACCEPT"
            and r.get("enabled") is True
        ):
            v = r.get("value")
            canonical = _canonicalize_ip(v)
            if canonical is not None:
                ip_set.add(canonical)
            elif isinstance(v, str):
                print(f"[pangolin] ignoring invalid IP value in rules response: {v!r}")
    refreshed_at = time.monotonic()
    with ctx.state_lock:
        ctx.rules_cache[rid] = {"ts": refreshed_at, "ip_set": ip_set}
    return ip_set


def ensure_ip_rule(ctx: PangolinContext, ip: str) -> None:
    if not ctx.token:
        raise RuntimeError(
            "PANGOLIN_TOKEN is not set — Pangolin API calls are disabled. Check your environment configuration."
        )
    canonical_ip = _canonicalize_ip(ip) or ip
    failures: list[str] = []
    for rid in ctx.resource_ids:
        try:
            # 1) check cached existence
            ip_set = get_ip_set_for_resource_cached(ctx, rid)
            if canonical_ip in ip_set:
                print(
                    f"[pangolin] rule already exists for IP {canonical_ip} on resource {rid}"
                )
                # Track presence but not created_by_us
                with ctx.state_lock:
                    rec = ctx.state.setdefault(
                        ip, {"last_seen": ctx.now_utc_iso(), "resources": {}}
                    )
                    rec["last_seen"] = ctx.now_utc_iso()
                    rec["resources"].setdefault(str(rid), {"created_by_us": False})
                ctx.save_state()
                continue
            # 2) create rule
            payload = {
                "action": "ACCEPT",
                "match": "IP",
                "value": canonical_ip,
                "priority": ctx.rule_priority,
                "enabled": True,
            }
            put_resp = _retry(
                lambda r=rid, p=payload: ctx.http_json(
                    "PUT", f"{ctx.url}/v1/resource/{r}/rule", p
                ),
                label=f"PUT rule ip={canonical_ip} resource={rid}",
            )
            _require_api_success(put_resp, f"PUT rule ip={canonical_ip} resource={rid}")
            created_rule_id = _extract_created_rule_id(put_resp)
            print(f"[pangolin] created rule for IP {canonical_ip} on resource {rid}")
            # Update cache to include newly created rule
            with ctx.state_lock:
                entry = ctx.rules_cache.get(rid)
                if entry:
                    entry.setdefault("ip_set", set()).add(canonical_ip)  # type: ignore[arg-type]
                else:
                    ctx.rules_cache[rid] = {
                        "ts": time.monotonic(),
                        "ip_set": {canonical_ip},
                    }
            # Update persistent state
            resource_entry: dict[str, Any] = {"created_by_us": True}
            if created_rule_id is not None:
                resource_entry["rule_id"] = created_rule_id
            with ctx.state_lock:
                rec = ctx.state.setdefault(
                    ip, {"last_seen": ctx.now_utc_iso(), "resources": {}}
                )
                rec["last_seen"] = ctx.now_utc_iso()
                rec["resources"][str(rid)] = resource_entry
            ctx.save_state()
        except Exception as e:  # noqa: BLE001
            print(
                f"[pangolin] ensure rule failed for resource {rid}, ip {canonical_ip}: {e}"
            )
            failures.append(f"resource {rid}: {e}")
    if failures:
        raise RuntimeError(
            f"Pangolin: rule creation failed for {len(failures)}/{len(ctx.resource_ids)} resource(s): {'; '.join(failures)}"
        )


def delete_ip_rule_if_created_by_us(
    ctx: PangolinContext, ip: str, rid: int, *, rule_id: int | None = None
) -> bool:
    """Return True if the rule is definitively gone — either we deleted all matching
    owned rules, or none remain (manually removed or expired externally). Return False
    when a failure occurred or a matched rule could not be confirmed deleted; the caller
    should retain the IP in state and retry on the next cleanup cycle."""
    canonical_ip = _canonicalize_ip(ip) or ip
    target_rule_id = _lookup_target_rule_id(ctx, ip, canonical_ip, rid, rule_id)

    try:
        rules_resp = _retry(
            lambda r=rid: ctx.http_json(
                "GET", f"{ctx.url}/v1/resource/{r}/rules?limit=10000"
            ),
            label=f"GET rules (delete phase) resource={rid}",
        )
        rules = _extract_rules_list(
            rules_resp, f"GET rules (delete phase) resource={rid}"
        )
        if target_rule_id is not None:
            to_delete = [
                r
                for r in rules
                if r.get("ruleId") == target_rule_id
                and r.get("match") == "IP"
                and r.get("action") == "ACCEPT"
                and _canonicalize_ip(r.get("value")) == canonical_ip
            ]
        else:
            to_delete = [
                r
                for r in rules
                if r.get("match") == "IP"
                and r.get("action") == "ACCEPT"
                and r.get("enabled") is True
                and _canonicalize_ip(r.get("value")) == canonical_ip
            ]
        if not to_delete:
            # Rule is already absent — safe to clear this entry from state
            print(
                f"[pangolin] no rule found for IP {canonical_ip} on resource {rid} (already absent — clearing state)"
            )
            _evict_ip_from_rules_cache(ctx, rid, canonical_ip, ip)
            return True
        deleted_any = False
        all_deleted = True
        for r in to_delete:
            matched_rule_id = r.get("ruleId")
            if not isinstance(matched_rule_id, int) or isinstance(
                matched_rule_id, bool
            ):
                print(
                    f"[pangolin] matching rule on resource {rid} for IP {canonical_ip} "
                    f"has invalid/missing ruleId: {matched_rule_id!r}"
                )
                all_deleted = False
                continue
            try:
                del_resp = _retry(
                    lambda r=rid, r_id=matched_rule_id: ctx.http_json(
                        "DELETE", f"{ctx.url}/v1/resource/{r}/rule/{r_id}"
                    ),
                    label=f"DELETE rule={matched_rule_id} ip={canonical_ip} resource={rid}",
                )
                _require_api_success(
                    del_resp,
                    f"DELETE rule={matched_rule_id} ip={canonical_ip} resource={rid}",
                )
                print(
                    f"[pangolin] deleted rule {matched_rule_id} for IP {canonical_ip} on resource {rid}"
                )
                deleted_any = True
            except Exception as e:  # noqa: BLE001
                print(
                    f"[pangolin] delete failed for rule {matched_rule_id} on {rid}: {e}"
                )
                all_deleted = False
        if deleted_any:
            # Evict the IP from the existence cache so a re-check-in re-creates the
            # rule instead of trusting a stale "already exists" entry until TTL expiry.
            _evict_ip_from_rules_cache(ctx, rid, canonical_ip, ip)
        return all_deleted
    except Exception as e:  # noqa: BLE001
        print(
            f"[pangolin] fetch rules (delete phase) failed for {rid}, ip {canonical_ip}: {e}"
        )
        return False


def list_org_resources(ctx: PangolinContext, org_id: str) -> None:
    try:
        encoded_org_id = quote(org_id, safe="")
        url = f"{ctx.url}/v1/org/{encoded_org_id}/resources"
        resp = ctx.http_json("GET", url)
        _require_api_success(resp, f"GET org/{org_id}/resources")
        data = resp.get("data")
        if isinstance(data, dict) and "resources" in data:
            resources = data["resources"]
        elif "resources" in resp:
            resources = resp["resources"]
        else:
            resources = []
        if not isinstance(resources, list) or any(
            not isinstance(r, dict) for r in resources
        ):
            raise RuntimeError(
                f"GET org/{org_id}/resources: unexpected resources list in Pangolin API response"
            )
        print(
            f"[pangolin] These are the resources for org '{org_id}'. Use the resourceId numbers for your configuration:"
        )
        if not resources:
            print("  (no resources found or empty response)")
            return
        for r in resources:
            name = r.get("name") or r.get("resourceName") or "(no-name)"
            rid = r.get("resourceId") or r.get("id")
            print(f"  - {name} (resourceId={rid})")
    except Exception as e:
        print(f"[pangolin] failed to list resources for org {org_id}: {e}")
        raise


def get_user_info(
    ctx: PangolinContext, org_id: str, user_id: str, username: str
) -> tuple[str, list[int]]:
    """Return (userId, roleIds) for a verified Pangolin identity in the org.
    Raises RuntimeError on any failure (caller is responsible for fail-closed behaviour).

    Pangolin's List Users route is searched with Remote-User. A result is trusted
    only when its exact username and stable ID match Remote-User and
    Remote-User-Id, respectively.
    """
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — cannot look up user")
    if not user_id:
        raise RuntimeError("Remote-User-Id header is empty")
    if not username:
        raise RuntimeError("Remote-User header is empty")

    encoded_org_id = quote(org_id, safe="")
    encoded_username = quote(username, safe="")
    page = 1
    page_size = 100
    username_was_found = False
    user_id_was_found = False

    def unexpected_response_error() -> RuntimeError:
        return RuntimeError(
            f"User {user_id!r} not found in org {org_id!r} "
            "(or unexpected response shape)"
        )

    while True:
        url = (
            f"{ctx.url}/v1/org/{encoded_org_id}/users"
            f"?query={encoded_username}&pageSize={page_size}&page={page}"
        )
        resp = _retry(
            lambda request_url=url: ctx.http_json("GET", request_url),
            label=f"GET org users query for user_id={user_id} page={page}",
        )
        if resp.get("success") is not True:
            raise RuntimeError(
                f"User {user_id!r} not found in org {org_id!r} "
                "(Pangolin API reported failure)"
            )

        data = resp.get("data")
        if not isinstance(data, dict):
            raise unexpected_response_error()

        users = data.get("users")
        pagination = data.get("pagination")
        if not isinstance(users, list) or not isinstance(pagination, dict):
            raise unexpected_response_error()

        total = pagination.get("total")
        response_page = pagination.get("page")
        response_page_size = pagination.get("pageSize")
        pagination_values = (total, response_page, response_page_size)
        if (
            any(
                not isinstance(value, int) or isinstance(value, bool)
                for value in pagination_values
            )
            or total < 0
            or response_page != page
            or response_page_size <= 0
        ):
            raise unexpected_response_error()

        for api_user in users:
            if not isinstance(api_user, dict):
                raise unexpected_response_error()

            api_user_id = api_user.get("id")
            api_username = api_user.get("username")
            if not isinstance(api_user_id, str) or not isinstance(api_username, str):
                raise unexpected_response_error()

            username_was_found = username_was_found or api_username == username
            user_id_was_found = user_id_was_found or api_user_id == user_id
            if api_user_id != user_id or api_username != username:
                continue

            roles = api_user.get("roles")
            if not isinstance(roles, list):
                raise unexpected_response_error()

            role_ids: list[int] = []
            for role in roles:
                if not isinstance(role, dict):
                    raise unexpected_response_error()
                role_id = role.get("roleId")
                if not isinstance(role_id, int) or isinstance(role_id, bool):
                    raise unexpected_response_error()
                role_ids.append(role_id)
            return api_user_id, role_ids

        if page * response_page_size >= total:
            break
        if not users:
            raise unexpected_response_error()
        page += 1

    if username_was_found:
        raise RuntimeError(
            "Pangolin identity mismatch: API user id does not match Remote-User-Id"
        )
    if user_id_was_found:
        raise RuntimeError(
            "Pangolin identity mismatch: API username does not match Remote-User"
        )
    raise RuntimeError(f"User {user_id!r} not found in org {org_id!r}")


def get_resource_allowed_role_ids(ctx: PangolinContext, rid: int) -> set[int]:
    """Return the set of roleIds authorised for the given resource.
    Raises RuntimeError on any failure.
    """
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — cannot look up resource roles")
    label = f"GET resource/{rid}/roles"
    url = f"{ctx.url}/v1/resource/{rid}/roles"
    resp = _retry(lambda: ctx.http_json("GET", url), label=label)
    data = _extract_api_data(resp, label)
    roles = _extract_dict_list(data, "roles", label)
    role_ids: set[int] = set()
    for r in roles:
        role_id = r.get("roleId")
        if not isinstance(role_id, int) or isinstance(role_id, bool):
            raise _unexpected_api_error(
                label, "unexpected roleId in Pangolin API response"
            )
        role_ids.add(role_id)
    return role_ids


def get_resource_allowed_user_ids(ctx: PangolinContext, rid: int) -> set[str]:
    """Return the set of userIds directly assigned to the given resource.
    This covers the 'Users' section in Pangolin Access Controls, which is separate from
    role-based access. Both paths grant access in Pangolin's SSO check; we mirror that here.
    Raises RuntimeError on any failure.
    """
    if not ctx.token:
        raise RuntimeError("PANGOLIN_TOKEN is not set — cannot look up resource users")
    label = f"GET resource/{rid}/users"
    url = f"{ctx.url}/v1/resource/{rid}/users"
    resp = _retry(lambda: ctx.http_json("GET", url), label=label)
    data = _extract_api_data(resp, label)
    users = _extract_dict_list(data, "users", label)
    user_ids: set[str] = set()
    for u in users:
        uid = u.get("userId")
        if not isinstance(uid, str) or not uid:
            raise _unexpected_api_error(
                label, "unexpected userId in Pangolin API response"
            )
        user_ids.add(uid)
    return user_ids


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
    data = _extract_api_data(resp, f"GET resource/{rid}")
    if not data:
        raise RuntimeError(f"Resource {rid} not found or unexpected response shape")
    return {
        "resourceId": rid,
        "name": data.get("name") or str(rid),
        "fullDomain": data.get("fullDomain", ""),
        "ssl": data.get("ssl", True),
    }


def filter_resources_for_user(
    ctx: PangolinContext, org_id: str, user_id: str, username: str
) -> list[dict]:
    """Return the subset of ctx.resource_ids the user is authorised for, with metadata.
    Each entry is {"resourceId": int, "name": str, "fullDomain": str, "ssl": bool}.

    Mirrors Pangolin's own SSO access check: a user is authorised for a resource if
    *either* one of their roles is allowed on that resource (role-based) *or* they are
    directly assigned to the resource via the Users section (direct-user). Either path
    is sufficient — matching Pangolin's OR logic in isUserAllowedToAccessResource().

    Raises on any API error (fail-closed). Returns an empty list if no resource matches
    but no error occurred.
    """
    user_id, user_role_ids_list = get_user_info(ctx, org_id, user_id, username)
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
            print(
                f"[pangolin] user {username!r} authorised for resource {rid} ({meta.get('name')}) via {reason}"
            )
            effective.append(meta)
        else:
            print(
                f"[pangolin] user {username!r} not authorised for resource {rid} — skipping"
            )
    return effective
