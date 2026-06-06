from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Set, Any, List


def _retry(fn, *, attempts: int = 3, backoff: float = 1.0, label: str = ""):
    """Call fn() up to `attempts` times, sleeping backoff * 2^n between retries.
    Only retries on Exception; propagates the final exception if all attempts fail.
    """
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as e:
            last_exc = e
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
    """Returns True if a deletion was performed, False otherwise."""
    try:
        rules_resp = _retry(
            lambda: ctx.http_json("GET", f"{ctx.url}/v1/resource/{rid}/rules?limit=10000"),
            label=f"GET rules (delete phase) resource={rid}",
        )
        rules = rules_resp.get("data", {}).get("rules", [])
        to_delete = [r for r in rules if r.get("match") == "IP" and r.get("value") == ip]
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