"""Unit tests for pangolin_connector.py.

All tests use monkeypatch / injected mock http_json callables; no live
Pangolin instance or network access is required.
"""

import contextlib
import threading
import time as _time_mod

import pytest
from helpers import org_user, org_users_response

import pangolin_connector


def test_rules_cache_uses_cache(monkeypatch, app_module):
    app = app_module

    calls = {"count": 0}

    def fake_http_json(method, url, body=None):
        calls["count"] += 1
        assert method == "GET"
        assert "/rules" in url
        return {
            "data": {
                "rules": [
                    {
                        "match": "IP",
                        "action": "ACCEPT",
                        "enabled": True,
                        "value": "9.8.7.6",
                    },
                    {
                        "match": "IP",
                        "action": "ACCEPT",
                        "enabled": True,
                        "value": "1.2.3.4",
                    },
                ]
            },
            "success": True,
        }

    monkeypatch.setattr(app, "http_json", fake_http_json)

    from pangolin_connector import get_ip_set_for_resource_cached

    ctx = app.make_pangolin_context()

    # First call should hit http_json
    s1 = get_ip_set_for_resource_cached(ctx, 5)
    assert "9.8.7.6" in s1
    assert calls["count"] == 1

    # Second call within TTL should use cache
    s2 = get_ip_set_for_resource_cached(ctx, 5)
    assert "1.2.3.4" in s2
    assert calls["count"] == 1


def test_retry_aborts_immediately_on_401():
    """_retry() must not sleep or retry on HTTP 401 — raise on first attempt."""
    sleep_calls = []
    attempts = {"count": 0}

    def fn():
        attempts["count"] += 1
        raise RuntimeError("HTTP 401 Unauthorized: invalid token")

    # Patch time.sleep inside pangolin_connector to detect any retry sleep
    original = pangolin_connector.time.sleep
    pangolin_connector.time.sleep = lambda s: sleep_calls.append(s)
    try:
        try:
            pangolin_connector._retry(fn, attempts=3, backoff=1.0, label="test-401")
        except RuntimeError as e:
            assert "401" in str(e)
        else:
            raise AssertionError("_retry should have raised")
    finally:
        pangolin_connector.time.sleep = original

    assert attempts["count"] == 1, (
        f"_retry must not retry on 401 — expected 1 attempt, got {attempts['count']}"
    )
    assert sleep_calls == [], (
        f"_retry must not sleep on 401 — got sleep calls: {sleep_calls}"
    )


def test_retry_aborts_immediately_on_403():
    """_retry() must not sleep or retry on HTTP 403 — raise on first attempt."""
    sleep_calls = []
    attempts = {"count": 0}

    def fn():
        attempts["count"] += 1
        raise RuntimeError("HTTP 403 Forbidden: key lacks permission")

    original = pangolin_connector.time.sleep
    pangolin_connector.time.sleep = lambda s: sleep_calls.append(s)
    try:
        try:
            pangolin_connector._retry(fn, attempts=3, backoff=1.0, label="test-403")
        except RuntimeError as e:
            assert "403" in str(e)
        else:
            raise AssertionError("_retry should have raised")
    finally:
        pangolin_connector.time.sleep = original

    assert attempts["count"] == 1, (
        f"_retry must not retry on 403 — expected 1 attempt, got {attempts['count']}"
    )
    assert sleep_calls == [], (
        f"_retry must not sleep on 403 — got sleep calls: {sleep_calls}"
    )


def test_retry_retries_on_non_auth_error():
    """_retry must attempt the function the full number of times on non-auth errors."""
    attempts = {"count": 0}
    sleep_calls = []

    def fn():
        attempts["count"] += 1
        raise RuntimeError("HTTP 500 Internal Server Error")

    original = pangolin_connector.time.sleep
    pangolin_connector.time.sleep = lambda s: sleep_calls.append(s)
    try:
        with contextlib.suppress(RuntimeError):
            pangolin_connector._retry(fn, attempts=3, backoff=1.0, label="test-500")
    finally:
        pangolin_connector.time.sleep = original

    assert attempts["count"] == 3, (
        f"Expected 3 attempts on non-auth error, got {attempts['count']}"
    )
    assert len(sleep_calls) == 2, (
        f"Expected 2 sleep calls between 3 attempts, got {sleep_calls}"
    )


def test_retry_propagates_last_exception():
    """_retry must raise the exception from the final attempt, not the first."""
    call_num = {"n": 0}

    def fn():
        call_num["n"] += 1
        raise RuntimeError(f"error on attempt {call_num['n']}")

    original = pangolin_connector.time.sleep
    pangolin_connector.time.sleep = lambda s: None
    try:
        try:
            pangolin_connector._retry(
                fn, attempts=3, backoff=0.0, label="test-last-exc"
            )
            raise AssertionError("_retry should have raised")
        except RuntimeError as e:
            assert "attempt 3" in str(e), (
                f"Expected exception from final attempt, got: {e}"
            )
    finally:
        pangolin_connector.time.sleep = original


def _make_pg_ctx(
    http_json=None,
    token="test-token",
    resource_ids=None,
    rules_cache=None,
    state=None,
    save_calls=None,
):
    """Construct a PangolinContext with all injected dependencies faked."""
    _state = state if state is not None else {}
    _cache = rules_cache if rules_cache is not None else {}
    _saves = save_calls if save_calls is not None else []
    return pangolin_connector.PangolinContext(
        url="https://pg.test",
        token=token,
        resource_ids=resource_ids or [5],
        rule_priority=0,
        rules_cache_ttl_seconds=3600,
        rules_cache=_cache,
        state=_state,
        state_lock=threading.Lock(),
        save_state=lambda: _saves.append(1),
        now_utc_iso=lambda: "2025-01-01T00:00:00+00:00",
        http_json=http_json or (lambda m, u, b=None: {}),
    )


def test_delete_rule_absent_returns_true():
    """GET returns no matching IP rules — rule already gone, returns True."""
    ctx = _make_pg_ctx(
        http_json=lambda m, u, b=None: {"data": {"rules": []}, "success": True}
    )
    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True


def test_delete_rule_success_returns_true():
    """Rule with ruleId=42 found; DELETE issued and succeeds; returns True."""
    calls = []

    def fake_http(method, url, body=None):
        calls.append((method, url))
        if method == "GET":
            return {
                "data": {
                    "rules": [
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                            "ruleId": 42,
                        }
                    ]
                },
                "success": True,
            }
        return {"success": True}

    ctx = _make_pg_ctx(http_json=fake_http)
    result = pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5)
    assert result is True
    assert any(m == "DELETE" and "rule/42" in u for m, u in calls), (
        "DELETE must be called with the correct rule URL"
    )


def test_delete_rule_evicts_ip_from_rules_cache():
    """A successful delete must remove the IP from rules_cache so a later check-in
    re-creates the rule instead of trusting a stale 'already exists' entry."""

    def fake_http(method, url, body=None):
        if method == "GET":
            return {
                "data": {
                    "rules": [
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                            "ruleId": 42,
                        }
                    ]
                },
                "success": True,
            }
        return {"success": True}

    cache = {5: {"ts": 9e18, "ip_set": {"1.2.3.4", "9.9.9.9"}}}
    ctx = _make_pg_ctx(http_json=fake_http, rules_cache=cache)

    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True
    assert "1.2.3.4" not in cache[5]["ip_set"], "deleted IP must be evicted from cache"
    assert "9.9.9.9" in cache[5]["ip_set"], "other cached IPs must be preserved"


def test_delete_rule_no_rule_id_returns_false():
    """Matching rule has no ruleId field — skipped, returns False."""

    def fake_http(method, url, body=None):
        if method == "GET":
            return {
                "data": {
                    "rules": [
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                        }
                    ]
                },
                "success": True,
            }
        return {"success": True}

    ctx = _make_pg_ctx(http_json=fake_http)
    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is False
    )


def test_delete_multiple_matching_rules_all_deleted():
    """Two rules for same IP — both DELETEs called, returns True."""
    deleted_ids = []

    def fake_http(method, url, body=None):
        if method == "GET":
            return {
                "data": {
                    "rules": [
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                            "ruleId": 10,
                        },
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                            "ruleId": 11,
                        },
                    ]
                },
                "success": True,
            }
        if method == "DELETE":
            deleted_ids.append(url.split("/")[-1])
        return {"success": True}

    ctx = _make_pg_ctx(http_json=fake_http)
    result = pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5)
    assert result is True
    assert set(deleted_ids) == {"10", "11"}


def test_delete_get_fails_returns_false(monkeypatch):
    """GET raises RuntimeError — outer except catches it, returns False without propagating."""
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    def fake_http(method, url, body=None):
        raise RuntimeError("HTTP 500 Internal Server Error")

    ctx = _make_pg_ctx(http_json=fake_http)
    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is False
    )


def test_ensure_ip_rule_no_token_raises():
    """Empty token raises RuntimeError immediately — http_json never called."""
    calls = []
    ctx = _make_pg_ctx(
        http_json=lambda m, u, b=None: calls.append((m, u)) or {},
        token="",
    )
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.ensure_ip_rule(ctx, "1.2.3.4")
    assert calls == [], "http_json must not be called when token is empty"


def test_ensure_ip_rule_existing_rule_not_created_by_us():
    """IP already in cached ip_set — state written with created_by_us=False, no PUT."""
    put_calls = []

    def fake_http(method, url, body=None):
        if method == "PUT":
            put_calls.append(url)
        return {}

    save_calls = []
    state = {}
    rules_cache = {5: {"ts": _time_mod.monotonic(), "ip_set": {"1.2.3.4"}}}
    ctx = _make_pg_ctx(
        http_json=fake_http,
        rules_cache=rules_cache,
        state=state,
        save_calls=save_calls,
    )
    pangolin_connector.ensure_ip_rule(ctx, "1.2.3.4")

    assert put_calls == [], "No PUT should be issued when rule already exists in cache"
    assert state["1.2.3.4"]["resources"]["5"]["created_by_us"] is False
    assert save_calls, (
        "save_state must be called to persist the not-created-by-us record"
    )


def test_ensure_ip_rule_partial_failure_raises(monkeypatch):
    """Resource 5 PUT succeeds, resource 6 PUT fails → RuntimeError 1/2; resource 5 in state."""
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    state = {}
    save_calls = []

    def fake_http(method, url, body=None):
        if method == "GET":
            return {"data": {"rules": []}, "success": True}
        if method == "PUT" and "/resource/5/rule" in url:
            return {"success": True}
        if method == "PUT" and "/resource/6/rule" in url:
            raise RuntimeError("HTTP 500 rule creation failed")
        return {}

    ctx = _make_pg_ctx(
        http_json=fake_http,
        resource_ids=[5, 6],
        state=state,
        save_calls=save_calls,
    )
    with pytest.raises(RuntimeError, match="1/2"):
        pangolin_connector.ensure_ip_rule(ctx, "1.2.3.4")

    resources = state.get("1.2.3.4", {}).get("resources", {})
    assert resources.get("5", {}).get("created_by_us") is True, (
        "Resource 5 succeeded — must be recorded in state"
    )
    assert "6" not in resources, "Resource 6 failed — must not appear in state"


def test_cache_expired_triggers_refresh():
    """Cache entry with ts=0 (epoch) is expired — http_json called, fresh ip_set returned."""
    call_count = {"n": 0}

    def fake_http(method, url, body=None):
        call_count["n"] += 1
        return {
            "data": {
                "rules": [
                    {
                        "match": "IP",
                        "action": "ACCEPT",
                        "enabled": True,
                        "value": "10.0.0.1",
                    }
                ]
            },
            "success": True,
        }

    rules_cache = {5: {"ts": 0, "ip_set": {"10.0.0.2"}}}
    ctx = _make_pg_ctx(http_json=fake_http, rules_cache=rules_cache)

    result = pangolin_connector.get_ip_set_for_resource_cached(ctx, 5)
    assert "10.0.0.1" in result
    assert "10.0.0.2" not in result
    assert call_count["n"] == 1, "http_json must be called exactly once for the refresh"


@pytest.mark.parametrize(
    "bad_resp",
    [
        {"raw": "<html>gateway error</html>"},
        {
            "success": False,
            "data": {"rules": [], "roles": [], "users": [], "name": "TV"},
        },
        {"success": True, "data": "not-a-dict"},
        {"success": True, "data": {}},
    ],
)
def test_pangolin_connectors_reject_malformed_or_failed_envelopes(
    monkeypatch, bad_resp
):
    """Malformed 200 / raw HTML / success=False fail closed across all endpoints."""
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    cache = {5: {"ts": 0, "ip_set": {"9.9.9.9"}}}
    ctx = _make_pg_ctx(http_json=lambda m, u, b=None: bad_resp, rules_cache=cache)

    with pytest.raises(RuntimeError):
        pangolin_connector.get_ip_set_for_resource_cached(ctx, 5)
    assert cache[5] == {"ts": 0, "ip_set": {"9.9.9.9"}}, (
        "Failed rules fetch must not overwrite or stamp rules_cache"
    )

    with pytest.raises(RuntimeError):
        pangolin_connector.get_resource_allowed_role_ids(ctx, 5)

    with pytest.raises(RuntimeError):
        pangolin_connector.get_resource_allowed_user_ids(ctx, 5)

    with pytest.raises(RuntimeError):
        pangolin_connector.get_resource(ctx, 5)

    # delete_ip_rule_if_created_by_us must fail closed (False) on malformed GET /rules
    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is False
    )


def test_pangolin_connectors_reject_malformed_list_elements(monkeypatch):
    """Non-list or malformed role/user/rule list entries fail closed."""
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    ctx_non_lists = _make_pg_ctx(
        http_json=lambda m, u, b=None: {
            "success": True,
            "data": {"rules": "bad", "roles": "bad", "users": "bad"},
        }
    )
    with pytest.raises(RuntimeError):
        pangolin_connector.get_ip_set_for_resource_cached(ctx_non_lists, 5)
    with pytest.raises(RuntimeError):
        pangolin_connector.get_resource_allowed_role_ids(ctx_non_lists, 5)
    with pytest.raises(RuntimeError):
        pangolin_connector.get_resource_allowed_user_ids(ctx_non_lists, 5)
    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx_non_lists, "1.2.3.4", 5)
        is False
    )

    ctx_roles = _make_pg_ctx(
        http_json=lambda m, u, b=None: {
            "success": True,
            "data": {"roles": [{"roleId": True}]},
        }
    )
    with pytest.raises(RuntimeError):
        pangolin_connector.get_resource_allowed_role_ids(ctx_roles, 5)

    ctx_users = _make_pg_ctx(
        http_json=lambda m, u, b=None: {
            "success": True,
            "data": {"users": [{"userId": ""}]},
        }
    )
    with pytest.raises(RuntimeError):
        pangolin_connector.get_resource_allowed_user_ids(ctx_users, 5)

    ctx_rules = _make_pg_ctx(
        http_json=lambda m, u, b=None: {
            "success": True,
            "data": {"rules": ["not-a-dict"]},
        }
    )
    with pytest.raises(RuntimeError):
        pangolin_connector.get_ip_set_for_resource_cached(ctx_rules, 5)


@pytest.mark.parametrize(
    "bad_put_resp",
    [
        {"raw": "<html>bad gateway</html>"},
        {"success": False, "message": "denied"},
        {},
    ],
)
def test_ensure_ip_rule_rejects_unsuccessful_put_response(monkeypatch, bad_put_resp):
    """PUT /rule returning raw/success=False fails closed and writes no state/cache."""
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)
    state = {}
    cache = {}
    save_calls = []

    def fake_http(method, url, body=None):
        if method == "GET":
            return {"success": True, "data": {"rules": []}}
        return bad_put_resp

    ctx = _make_pg_ctx(
        http_json=fake_http, state=state, rules_cache=cache, save_calls=save_calls
    )
    with pytest.raises(RuntimeError, match="1/1"):
        pangolin_connector.ensure_ip_rule(ctx, "1.2.3.4")

    assert state == {}
    assert "1.2.3.4" not in cache[5]["ip_set"]
    assert save_calls == []


@pytest.mark.parametrize(
    "bad_delete_resp",
    [
        {"raw": "<html>bad gateway</html>"},
        {"success": False, "message": "denied"},
        {},
    ],
)
def test_delete_rule_rejects_unsuccessful_delete_response(monkeypatch, bad_delete_resp):
    """DELETE /rule/{id} returning raw/success=False returns False and keeps cache."""
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)
    cache = {5: {"ts": 9e18, "ip_set": {"1.2.3.4"}}}

    def fake_http(method, url, body=None):
        if method == "GET":
            return {
                "success": True,
                "data": {
                    "rules": [
                        {
                            "ruleId": 42,
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                        }
                    ]
                },
            }
        return bad_delete_resp

    ctx = _make_pg_ctx(http_json=fake_http, rules_cache=cache)
    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is False
    )
    assert "1.2.3.4" in cache[5]["ip_set"]


def test_get_ip_set_ignores_non_accept_and_disabled_rules():
    """Only enabled IP ACCEPT rules satisfy existence check; DROP/PASS/disabled trigger PUT."""
    put_bodies = []

    def fake_http(method, url, body=None):
        if method == "GET":
            return {
                "success": True,
                "data": {
                    "rules": [
                        {
                            "match": "IP",
                            "action": "DROP",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                        {
                            "match": "IP",
                            "action": "PASS",
                            "enabled": True,
                            "value": "1.2.3.5",
                        },
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": False,
                            "value": "1.2.3.6",
                        },
                        {
                            "match": "METHOD",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.7",
                        },
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "9.9.9.9",
                        },
                    ]
                },
            }
        if method == "PUT":
            put_bodies.append(body)
            return {"success": True, "data": {"ruleId": 55}}
        raise AssertionError(f"Unexpected call: {method} {url}")

    state = {}
    ctx = _make_pg_ctx(http_json=fake_http, state=state)
    ip_set = pangolin_connector.get_ip_set_for_resource_cached(ctx, 5)
    assert ip_set == {"9.9.9.9"}

    pangolin_connector.ensure_ip_rule(ctx, "1.2.3.6")
    assert len(put_bodies) == 1
    assert put_bodies[0]["value"] == "1.2.3.6"
    assert state["1.2.3.6"]["resources"]["5"] == {"created_by_us": True, "rule_id": 55}


@pytest.mark.parametrize(
    ("put_resp", "expected_entry"),
    [
        (
            {"success": True, "data": {"ruleId": 77}},
            {"created_by_us": True, "rule_id": 77},
        ),
        (
            {"success": True, "data": {"rule": {"ruleId": 88}}},
            {"created_by_us": True, "rule_id": 88},
        ),
        ({"success": True}, {"created_by_us": True}),
        ({"success": True, "data": {"ruleId": True}}, {"created_by_us": True}),
    ],
)
def test_ensure_ip_rule_persists_rule_id_shapes(put_resp, expected_entry):
    """ensure_ip_rule persists integer ruleId from either response nesting and omits non-ints."""

    def fake_http(method, url, body=None):
        if method == "GET":
            return {"success": True, "data": {"rules": []}}
        return put_resp

    state = {}
    ctx = _make_pg_ctx(http_json=fake_http, state=state)
    pangolin_connector.ensure_ip_rule(ctx, "1.2.3.4")
    assert state["1.2.3.4"]["resources"]["5"] == expected_entry


def test_delete_targets_stored_rule_id_preserving_sibling_rules():
    """When rule_id is in state, only that exact IP/ACCEPT rule is deleted."""
    deleted_ids = []
    rules_payload = [
        {
            "ruleId": 200,
            "match": "IP",
            "action": "ACCEPT",
            "enabled": False,
            "value": "1.2.3.4",
        },
        {
            "ruleId": 201,
            "match": "IP",
            "action": "ACCEPT",
            "enabled": True,
            "value": "1.2.3.4",
        },
        {
            "ruleId": 202,
            "match": "IP",
            "action": "DROP",
            "enabled": True,
            "value": "1.2.3.4",
        },
        {
            "ruleId": 203,
            "match": "IP",
            "action": "PASS",
            "enabled": True,
            "value": "1.2.3.4",
        },
    ]

    def fake_http(method, url, body=None):
        if method == "GET":
            return {"success": True, "data": {"rules": rules_payload}}
        if method == "DELETE":
            deleted_ids.append(int(url.rsplit("/", 1)[-1]))
            return {"success": True}
        raise AssertionError(f"Unexpected call: {method} {url}")

    state = {
        "1.2.3.4": {
            "last_seen": "2025-01-01T00:00:00+00:00",
            "resources": {"5": {"created_by_us": True, "rule_id": 200}},
        }
    }
    ctx = _make_pg_ctx(http_json=fake_http, state=state)
    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True
    assert deleted_ids == [200]

    # When stored rule_id 200 is already absent, admin sibling rule 201 is untouched.
    rules_payload.pop(0)
    deleted_ids.clear()
    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True
    assert deleted_ids == []


def test_delete_legacy_state_without_rule_id_only_deletes_active_accept():
    """Legacy state entries without rule_id delete only enabled IP/ACCEPT rules."""
    deleted_ids = []

    def fake_http(method, url, body=None):
        if method == "GET":
            return {
                "success": True,
                "data": {
                    "rules": [
                        {
                            "ruleId": 1,
                            "match": "IP",
                            "action": "DROP",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                        {
                            "ruleId": 2,
                            "match": "IP",
                            "action": "PASS",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                        {
                            "ruleId": 3,
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": False,
                            "value": "1.2.3.4",
                        },
                        {
                            "ruleId": 4,
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                    ]
                },
            }
        if method == "DELETE":
            deleted_ids.append(int(url.rsplit("/", 1)[-1]))
            return {"success": True}
        raise AssertionError(f"Unexpected call: {method} {url}")

    state = {
        "1.2.3.4": {
            "last_seen": "2025-01-01T00:00:00+00:00",
            "resources": {"5": {"created_by_us": True}},
        }
    }
    ctx = _make_pg_ctx(http_json=fake_http, state=state)
    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True
    assert deleted_ids == [4]


def test_delete_ignores_drop_and_pass_rules():
    """DROP and PASS rules for the target IP are never matched or deleted."""
    delete_calls = []

    def fake_http(method, url, body=None):
        if method == "GET":
            return {
                "success": True,
                "data": {
                    "rules": [
                        {
                            "ruleId": 10,
                            "match": "IP",
                            "action": "DROP",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                        {
                            "ruleId": 11,
                            "match": "IP",
                            "action": "PASS",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                    ]
                },
            }
        delete_calls.append(url)
        return {"success": True}

    ctx = _make_pg_ctx(http_json=fake_http)
    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True
    assert delete_calls == []


def test_delete_multi_rule_partial_failure_retains_state(monkeypatch, app_module):
    """If 1 of 2 matching rules fails deletion (or lacks ruleId), return False and keep state."""
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    rules = [
        {
            "ruleId": 10,
            "match": "IP",
            "action": "ACCEPT",
            "enabled": True,
            "value": "1.2.3.4",
        },
        {
            "ruleId": 11,
            "match": "IP",
            "action": "ACCEPT",
            "enabled": True,
            "value": "1.2.3.4",
        },
    ]

    def fake_http(method, url, body=None):
        if method == "GET":
            return {"success": True, "data": {"rules": list(rules)}}
        if method == "DELETE" and url.endswith("/rule/10"):
            rules[:] = [r for r in rules if r["ruleId"] != 10]
            return {"success": True}
        if method == "DELETE" and url.endswith("/rule/11"):
            raise RuntimeError("HTTP 500 delete failed")
        raise AssertionError(f"Unexpected call: {method} {url}")

    monkeypatch.setattr(app, "http_json", fake_http)
    with app.state_lock:
        app.state["1.2.3.4"] = {
            "last_seen": "2000-01-01T00:00:00+00:00",
            "resources": {"5": {"created_by_us": True}},
        }
        app.rules_cache[5] = {"ts": _time_mod.monotonic(), "ip_set": {"1.2.3.4"}}

    app.cleanup_old_ips()
    with app.state_lock:
        assert "5" in app.state.get("1.2.3.4", {}).get("resources", {}), (
            "Partial multi-rule deletion failure must retain ownership state for retry"
        )
        assert "1.2.3.4" not in app.rules_cache[5]["ip_set"]

    # Also verify a mixed valid ruleId + missing ruleId returns False
    ctx_missing_id = _make_pg_ctx(
        http_json=lambda m, u, b=None: (
            {
                "success": True,
                "data": {
                    "rules": [
                        {
                            "ruleId": 10,
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                        {
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": "1.2.3.4",
                        },
                    ]
                },
            }
            if m == "GET"
            else {"success": True}
        )
    )
    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx_missing_id, "1.2.3.4", 5)
        is False
    )


def test_ipv6_canonicalization_matches_cache_and_delete():
    """Expanded/uppercase IPv6 returned by Pangolin matches canonical IPv6 in cache & delete."""
    non_canonical_v6 = "2001:0DB8:0000:0000:0000:0000:0000:0001"
    canonical_v6 = "2001:db8::1"
    calls = []

    def fake_http(method, url, body=None):
        calls.append((method, url))
        if method == "GET":
            return {
                "success": True,
                "data": {
                    "rules": [
                        {
                            "ruleId": 71,
                            "match": "IP",
                            "action": "ACCEPT",
                            "enabled": True,
                            "value": non_canonical_v6,
                        }
                    ]
                },
            }
        if method == "DELETE":
            return {"success": True}
        raise AssertionError(f"Unexpected call: {method} {url}")

    state = {}
    ctx = _make_pg_ctx(http_json=fake_http, state=state)
    ip_set = pangolin_connector.get_ip_set_for_resource_cached(ctx, 5)
    assert ip_set == {canonical_v6}

    pangolin_connector.ensure_ip_rule(ctx, canonical_v6)
    assert all(m == "GET" for m, _ in calls), (
        "Canonical IPv6 must match cached non-canonical IPv6 without PUT"
    )
    assert state[canonical_v6]["resources"]["5"]["created_by_us"] is False

    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx, canonical_v6, 5) is True
    )
    assert ("DELETE", "https://pg.test/v1/resource/5/rule/71") in calls


def test_list_org_resources_url_encodes_org_id():
    """list_org_resources URL-encodes org_id and checks success=True."""
    urls = []

    def fake_http(method, url, body=None):
        urls.append(url)
        return {
            "success": True,
            "data": {"resources": [{"name": "App", "resourceId": 1}]},
        }

    ctx = _make_pg_ctx(http_json=fake_http)
    pangolin_connector.list_org_resources(ctx, "my org/1")
    assert urls == ["https://pg.test/v1/org/my%20org%2F1/resources"]

    ctx_fail = _make_pg_ctx(
        http_json=lambda m, u, b=None: {"success": False, "data": {"resources": []}}
    )
    with pytest.raises(RuntimeError):
        pangolin_connector.list_org_resources(ctx_fail, "my org/1")


def test_rules_cache_uses_monotonic_and_treats_ts_zero_expired(monkeypatch):
    """rules_cache TTL uses time.monotonic(), ignores time.time() jumps, and expires ts=0."""
    mono_now = [10.0]
    wall_now = [1_700_000_000.0]
    get_count = [0]

    monkeypatch.setattr(pangolin_connector.time, "monotonic", lambda: mono_now[0])
    monkeypatch.setattr(pangolin_connector.time, "time", lambda: wall_now[0])

    def fake_http(method, url, body=None):
        get_count[0] += 1
        return {
            "success": True,
            "data": {
                "rules": [
                    {
                        "match": "IP",
                        "action": "ACCEPT",
                        "enabled": True,
                        "value": "10.0.0.1",
                    }
                ]
            },
        }

    # Even when monotonic clock (10.0) < ttl (3600), ts=0 must still trigger refresh.
    cache = {5: {"ts": 0, "ip_set": {"10.0.0.2"}}}
    ctx = _make_pg_ctx(http_json=fake_http, rules_cache=cache)
    assert pangolin_connector.get_ip_set_for_resource_cached(ctx, 5) == {"10.0.0.1"}
    assert get_count[0] == 1

    # Huge wall-clock jump must NOT expire the monotonic cache.
    wall_now[0] += 999999.0
    mono_now[0] += 100.0
    assert pangolin_connector.get_ip_set_for_resource_cached(ctx, 5) == {"10.0.0.1"}
    assert get_count[0] == 1

    # Advancing monotonic clock past TTL must refresh.
    mono_now[0] += 3600.0
    assert pangolin_connector.get_ip_set_for_resource_cached(ctx, 5) == {"10.0.0.1"}
    assert get_count[0] == 2


def test_get_user_info_external_oidc_uses_org_user_search():
    """Issue #108 OIDC identity resolves through the current List Users route."""
    calls = []
    remote_user_id = "uelzf8m52bz4uq3"
    remote_user = "3ad3020246532f5a7224496b08e385e20ff79a239766cc3ad8aac5a55ff74c3a"

    def fake_http(method, url, body=None):
        calls.append((method, url))
        user = org_user(remote_user_id, remote_user, [1, 5])
        user.update({"orgId": "primary", "type": "oidc", "idpId": 2})
        return org_users_response(user)

    ctx = _make_pg_ctx(http_json=fake_http)
    result = pangolin_connector.get_user_info(
        ctx, "primary", remote_user_id, remote_user
    )

    assert result == (remote_user_id, [1, 5])
    assert calls == [
        (
            "GET",
            (
                f"https://pg.test/v1/org/primary/users?query={remote_user}"
                "&pageSize=100&page=1"
            ),
        )
    ]


def test_get_user_info_internal_user_uses_same_search_and_exact_match():
    """Internal Pangolin users use the same flow as external OIDC users."""

    def fake_http(method, url, body=None):
        user = org_user("internal-123", "alice", [7])
        user.update({"orgId": "primary", "type": "internal", "idpId": None})
        return org_users_response(user)

    ctx = _make_pg_ctx(http_json=fake_http)
    assert pangolin_connector.get_user_info(
        ctx, "primary", "internal-123", "alice"
    ) == ("internal-123", [7])


@pytest.mark.parametrize(
    ("api_user_id", "api_username", "match"),
    [
        ("victim-id", "attacker", "Remote-User-Id"),
        ("attacker-id", "victim", "Remote-User"),
    ],
)
def test_get_user_info_rejects_spoofed_identity_pair(api_user_id, api_username, match):
    ctx = _make_pg_ctx(
        http_json=lambda method, url, body=None: org_users_response(
            org_user(api_user_id, api_username, [1])
        )
    )
    with pytest.raises(RuntimeError, match=match):
        pangolin_connector.get_user_info(ctx, "primary", "attacker-id", "attacker")


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"users": []},
        {
            "users": [{"id": "user-1", "username": "alice"}],
            "pagination": {"total": 1, "page": 1, "pageSize": 100},
        },
        {
            "users": [{"id": "user-1", "username": "alice", "roles": "not-a-list"}],
            "pagination": {"total": 1, "page": 1, "pageSize": 100},
        },
        {
            "users": [
                {
                    "id": "user-1",
                    "username": "alice",
                    "roles": [{"roleId": True}],
                }
            ],
            "pagination": {"total": 1, "page": 1, "pageSize": 100},
        },
    ],
)
def test_get_user_info_rejects_malformed_response(data):
    ctx = _make_pg_ctx(
        http_json=lambda method, url, body=None: {
            "data": data,
            "success": True,
        }
    )
    with pytest.raises(RuntimeError, match="unexpected response shape"):
        pangolin_connector.get_user_info(ctx, "primary", "user-1", "alice")


def test_get_user_info_rejects_api_failure_even_with_data():
    ctx = _make_pg_ctx(
        http_json=lambda method, url, body=None: {
            "data": org_users_response(org_user("user-1", "alice", [1]))["data"],
            "success": False,
        }
    )
    with pytest.raises(RuntimeError, match="API reported failure"):
        pangolin_connector.get_user_info(ctx, "primary", "user-1", "alice")


def test_get_user_info_paginates_until_exact_identity_match():
    calls = []

    def fake_http(method, url, body=None):
        calls.append(url)
        if url.endswith("page=1"):
            return org_users_response(
                org_user("other-id", "alice.smith", [99]),
                total=2,
                page=1,
                page_size=1,
            )
        return org_users_response(
            org_user("user-1", "alice", [7]),
            total=2,
            page=2,
            page_size=1,
        )

    ctx = _make_pg_ctx(http_json=fake_http)
    assert pangolin_connector.get_user_info(ctx, "primary", "user-1", "alice") == (
        "user-1",
        [7],
    )
    assert calls[-1].endswith("page=2")


def test_get_user_info_list_users_permission_error_fails_closed(monkeypatch):
    calls = []
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    def fake_http(method, url, body=None):
        calls.append(url)
        raise RuntimeError("HTTP 403 Forbidden: key lacks the List Users permission")

    ctx = _make_pg_ctx(http_json=fake_http)
    with pytest.raises(RuntimeError, match="List Users"):
        pangolin_connector.get_user_info(ctx, "primary", "user-1", "alice")
    assert len(calls) == 1, "authorization errors must not be retried"


def test_get_user_info_no_token_raises():
    """get_user_info raises RuntimeError immediately when token is empty."""
    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_user_info(ctx, "org1", "user-123", "user@test.com")


def test_get_resource_allowed_role_ids_no_token_raises():
    """get_resource_allowed_role_ids raises RuntimeError immediately when token is empty."""
    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_resource_allowed_role_ids(ctx, 5)


def test_get_resource_allowed_user_ids_no_token_raises():
    """get_resource_allowed_user_ids raises RuntimeError immediately when token is empty."""
    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_resource_allowed_user_ids(ctx, 5)


def test_get_resource_no_token_raises():
    """get_resource raises RuntimeError immediately when token is empty."""
    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_resource(ctx, 5)
