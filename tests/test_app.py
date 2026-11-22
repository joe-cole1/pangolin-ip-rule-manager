"""Application-level unit and integration tests for app.py."""

import http.client
import json
import threading
import time as _time_mod

import pytest
from helpers import (
    TEST_PROXY_SECRET,
    make_fake_http_json,
    org_user,
    org_users_response,
    proxy_request,
    reload_app,
    reload_app_and_dependencies,
    standard_fake_http_json,
    start_bounded_server,
    start_server,
)


def test_cleanup_once_removes_expired_ips(monkeypatch, app_module):
    app = app_module

    # Make everything immediately expired
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    # Insert an old record created by us
    old_ip = "5.5.5.5"
    with app.state_lock:
        app.state[old_ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"3": {"created_by_us": True}},
        }

    # Do not perform real HTTP calls for deletion; pretend success
    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", lambda ip, rid: True)

    app.cleanup_old_ips()

    with app.state_lock:
        assert old_ip not in app.state


def test_cleanup_longer_scenario_mixed_outcomes(monkeypatch, app_module):
    app = app_module

    # Expire old IPs, keep one fresh
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    ip_removed = "1.1.1.1"  # created_by_us=True, delete succeeds -> fully removed
    ip_delete_failed = "2.2.2.2"  # created_by_us=True, delete fails -> remains in state
    ip_not_created = "3.3.3.3"  # created_by_us=False -> never attempted, remains
    ip_fresh = "4.4.4.4"  # not expired -> remains

    with app.state_lock:
        app.state[ip_removed] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"5": {"created_by_us": True}},
        }
        app.state[ip_delete_failed] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"5": {"created_by_us": True}},
        }
        app.state[ip_not_created] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"5": {"created_by_us": False}},
        }
        app.state[ip_fresh] = {
            "last_seen": app.now_utc_iso(),
            "resources": {"5": {"created_by_us": True}},
        }

    calls = []

    def fake_delete(ip, rid):
        calls.append((ip, rid))
        # Only succeed for ip_removed; fail for ip_delete_failed
        return ip == ip_removed

    # Avoid any external effects
    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", fake_delete)
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    app.cleanup_old_ips()

    with app.state_lock:
        # Removed because deletion returned True and no resources remain
        assert ip_removed not in app.state

        # Deletion failed -> resource still present -> IP remains
        assert ip_delete_failed in app.state
        assert "5" in app.state[ip_delete_failed]["resources"]

        # Not created by us -> state entry removed after expiry (Finding 6E)
        assert ip_not_created not in app.state

        # Fresh (not expired) -> remains untouched
        assert ip_fresh in app.state

    # Verify delete was attempted only for created_by_us expired IPs
    ips_called = {ip for (ip, _rid) in calls}
    assert ip_removed in ips_called
    assert ip_delete_failed in ips_called
    assert ip_not_created not in ips_called
    assert ip_fresh not in ips_called


def test_cleanup_does_not_remove_non_created_rules(monkeypatch, app_module):
    """Ensure that Pangolin rules not created by us are not removed during cleanup."""
    import pytest

    app = app_module

    # Force expiration
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    ip = "7.7.7.7"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"5": {"created_by_us": False}},
        }

    called = []

    def delete_should_not_be_called(ip_arg, rid):
        called.append((ip_arg, rid))
        pytest.fail(
            "delete_ip_rule_if_created_by_us must not be called for non-created rules"
        )

    monkeypatch.setattr(
        app, "delete_ip_rule_if_created_by_us", delete_should_not_be_called
    )
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    app.cleanup_old_ips()

    with app.state_lock:
        # Entry should be removed from state — we clean up our bookkeeping
        # for expired unowned entries even though we don't touch the Pangolin rule
        assert ip not in app.state

    # Ensure no delete attempt was made
    assert called == []


def test_add_ip_to_targets_fails_closed_without_remote_user(app_module):
    """No targets should be touched when Remote-User is absent."""
    app = app_module
    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-alice", remote_user=""
    )
    assert results["pangolin"]["ok"] is False
    assert "Remote-User" in results["pangolin"]["detail"]
    assert results["crowdsec"]["detail"] == "not reached"


def test_add_ip_to_targets_fails_closed_without_remote_user_id(app_module):
    """No targets should be touched when Remote-User-Id is absent."""
    app = app_module
    results = app.add_ip_to_targets("1.2.3.4", remote_user_id="", remote_user="alice")
    assert results["pangolin"]["ok"] is False
    assert "Remote-User-Id" in results["pangolin"]["detail"]
    assert results["crowdsec"]["detail"] == "not reached"


def test_add_ip_to_targets_intersection_filters_by_role(monkeypatch, app_module):
    """Only resources where the user's role matches should be whitelisted."""
    app = app_module

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5, 6])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-denise",
            username="denise@example.com",
            extra_resource_roles={6: [{"roleId": 1, "name": "Admin"}]},
        ),
    )

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4",
        remote_user_id="user-denise",
        remote_user="denise@example.com",
    )

    assert results["pangolin"]["ok"] is True
    assert "resources" in results, "results should include resource metadata"
    assert len(results["resources"]) == 1, "only resource 5 should be authorised"
    assert results["resources"][0]["name"] == "Jellyfin"
    assert results["resources"][0]["fullDomain"] == "jellyfin.example.com"

    with app.state_lock:
        rec = app.state.get("1.2.3.4", {})
        state_resources = rec.get("resources", {})
        assert "5" in state_resources, "resource 5 should be whitelisted (role matches)"
        assert "6" not in state_resources, (
            "resource 6 should be skipped (role mismatch)"
        )


def test_add_ip_to_targets_fails_closed_empty_intersection(monkeypatch, app_module):
    """User exists but none of their roles match any configured resource — fail-closed."""
    app = app_module

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-nobody",
            username="nobody@example.com",
            role_ids=(99,),
        ),
    )

    results = app.add_ip_to_targets(
        "1.2.3.4",
        remote_user_id="user-nobody",
        remote_user="nobody@example.com",
    )

    assert results["pangolin"]["ok"] is False
    assert "not authorised" in results["pangolin"]["detail"]
    assert results["crowdsec"]["detail"] == "not reached"


def test_add_ip_to_targets_fails_closed_user_not_found(monkeypatch, app_module):
    """Organization user lookup returns no user data — fail-closed."""
    app = app_module

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=ghost%40example.com" in url:
            return org_users_response()
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    results = app.add_ip_to_targets(
        "1.2.3.4",
        remote_user_id="user-ghost",
        remote_user="ghost@example.com",
    )

    assert results["pangolin"]["ok"] is False
    assert "authorization failed" in results["pangolin"]["detail"].lower()
    assert results["crowdsec"]["detail"] == "not reached"


def test_add_ip_to_targets_fails_closed_on_roles_api_error(monkeypatch, app_module):
    """get_resource_allowed_role_ids raises (e.g. 403) — fail-closed, no rule created."""
    app = app_module
    # Suppress retry sleep so the test does not take 3+ seconds
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-joe",
            username="joe@example.com",
            roles_error=RuntimeError(
                "HTTP 403 Forbidden: key lacks List Allowed Resource Roles permission"
            ),
        ),
    )

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-joe", remote_user="joe@example.com"
    )

    assert results["pangolin"]["ok"] is False
    assert "authorization failed" in results["pangolin"]["detail"].lower()
    assert results["crowdsec"]["detail"] == "not reached"
    # No state entry should have been written
    with app.state_lock:
        assert "1.2.3.4" not in app.state


def test_add_ip_to_targets_fails_closed_on_resource_metadata_error(
    monkeypatch, app_module
):
    """get_resource raises after successful role intersection — fail-closed, no rule created."""
    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-joe",
            username="joe@example.com",
            resource_error=RuntimeError(
                "HTTP 403 Forbidden: key lacks Get Resource permission"
            ),
        ),
    )

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-joe", remote_user="joe@example.com"
    )

    assert results["pangolin"]["ok"] is False
    assert "authorization failed" in results["pangolin"]["detail"].lower()
    assert results["crowdsec"]["detail"] == "not reached"
    with app.state_lock:
        assert "1.2.3.4" not in app.state


def test_add_ip_to_targets_pangolin_rule_creation_failure(monkeypatch, app_module):
    """Intersection succeeds but rule creation (PUT) fails — pangolin ok=False."""
    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-joe",
            username="joe@example.com",
            put_error=RuntimeError(
                "HTTP 500 Internal Server Error: rule creation failed"
            ),
        ),
    )

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-joe", remote_user="joe@example.com"
    )

    assert results["pangolin"]["ok"] is False
    assert "500" in results["pangolin"]["detail"]


def test_add_ip_to_targets_crowdsec_called_when_enabled(monkeypatch, temp_state_file):
    """CrowdSec add is called alongside Pangolin when CROWDSEC_ENABLED=true."""
    app = reload_app(monkeypatch, temp_state_file, crowdsec_enabled=True)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "http_json", standard_fake_http_json)

    crowdsec_calls = []
    monkeypatch.setattr(app, "crowdsec_add_ip", lambda ip: crowdsec_calls.append(ip))

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )

    assert results["pangolin"]["ok"] is True
    assert results["crowdsec"]["ok"] is True
    assert results["crowdsec"]["enabled"] is True
    assert "1.2.3.4" in crowdsec_calls, "crowdsec_add_ip should have been called"


def test_add_ip_to_targets_crowdsec_failure_isolated(monkeypatch, temp_state_file):
    """CrowdSec failure does not affect Pangolin result — failures reported independently."""
    app = reload_app(monkeypatch, temp_state_file, crowdsec_enabled=True)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "http_json", standard_fake_http_json)

    def fake_crowdsec_fail(ip):
        raise RuntimeError("cscli: command not found")

    monkeypatch.setattr(app, "crowdsec_add_ip", fake_crowdsec_fail)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )

    assert results["pangolin"]["ok"] is True, (
        "Pangolin should succeed regardless of CrowdSec"
    )
    assert results["crowdsec"]["ok"] is False
    assert "cscli" in results["crowdsec"]["detail"]


def test_add_ip_to_targets_authorised_via_direct_user_assignment(
    monkeypatch, app_module
):
    """User has no matching role but IS directly assigned to the resource — must be authorised."""
    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-direct",
            username="direct@example.com",
            role_ids=(99,),
            direct_users=({"userId": "user-direct", "username": "direct@example.com"},),
        ),
    )

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4",
        remote_user_id="user-direct",
        remote_user="direct@example.com",
    )

    assert results["pangolin"]["ok"] is True, (
        "User directly assigned to resource must be authorised even with no role match"
    )
    assert len(results["resources"]) == 1
    assert results["resources"][0]["name"] == "Jellyfin"
    with app.state_lock:
        assert "5" in app.state.get("1.2.3.4", {}).get("resources", {})


def test_add_ip_to_targets_fails_closed_on_users_api_error(monkeypatch, app_module):
    """GET /resource/:id/users raises — fail-closed, no rule created."""
    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-joe",
            username="joe@example.com",
            users_error=RuntimeError(
                "HTTP 403 Forbidden: key lacks List Resource Users permission"
            ),
        ),
    )

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-joe", remote_user="joe@example.com"
    )

    assert results["pangolin"]["ok"] is False
    assert "authorization failed" in results["pangolin"]["detail"].lower()
    assert results["crowdsec"]["detail"] == "not reached"
    with app.state_lock:
        assert "1.2.3.4" not in app.state


def test_rate_limit_skips_api_on_repeat_call(monkeypatch, app_module):
    """Second call within RATE_LIMIT_SECONDS must return the cached result without hitting the API."""
    app = app_module
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 300)

    api_calls = {"count": 0}

    def fake_http_json(method, url, body=None):
        api_calls["count"] += 1
        return standard_fake_http_json(method, url, body)

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    first = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert first["pangolin"]["ok"] is True
    calls_after_first = api_calls["count"]
    assert calls_after_first > 0

    second = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert second["pangolin"]["ok"] is True
    assert api_calls["count"] == calls_after_first, (
        "API should not be called again within the rate limit window"
    )


def test_rate_limit_expires_after_window(monkeypatch, app_module):
    """A call made after the window has elapsed must hit the API again."""
    app = app_module
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 300)

    monkeypatch.setattr(app, "http_json", standard_fake_http_json)

    with app.state_lock:
        app.state.clear()

    first = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert first["pangolin"]["ok"] is True

    # Back-date the cache entry so it looks expired
    with app._api_rate_limit_lock:
        ts, result = app._api_rate_limit[("1.2.3.4", "user-abc", "joe@example.com")]
        app._api_rate_limit[("1.2.3.4", "user-abc", "joe@example.com")] = (
            ts - 400,
            result,
        )

    api_calls = {"count": 0}

    def counting_http_json(method, url, body=None):
        api_calls["count"] += 1
        return standard_fake_http_json(method, url, body)

    monkeypatch.setattr(app, "http_json", counting_http_json)

    second = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert second["pangolin"]["ok"] is True
    assert api_calls["count"] > 0, "API must be called again after the window expires"


def test_rate_limit_zero_disables_limiting(monkeypatch, app_module):
    """Setting RATE_LIMIT_SECONDS=0 must disable rate limiting entirely."""
    app = app_module
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 0)

    api_calls = {"count": 0}

    def counting_http_json(method, url, body=None):
        api_calls["count"] += 1
        return standard_fake_http_json(method, url, body)

    monkeypatch.setattr(app, "http_json", counting_http_json)

    with app.state_lock:
        app.state.clear()

    app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )
    calls_after_first = api_calls["count"]
    assert calls_after_first > 0

    app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert api_calls["count"] > calls_after_first, (
        "With RATE_LIMIT_SECONDS=0, both calls must hit the API"
    )


def test_app_loads_without_custom_header_env(monkeypatch, temp_state_file):
    """App must load successfully without EXPECTED_PANGOLIN_CUSTOM_HEADER_* env vars.
    Previously these were mandatory and the module raised RuntimeError on import without them.
    """
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    # Explicitly ensure neither custom header var is set
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", raising=False)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", raising=False)

    # Should not raise — if it does the test fails
    app = reload_app_and_dependencies()
    assert app is not None


def test_redact_headers_authorization(app_module):
    """Authorization header value must be replaced with <redacted>."""
    app = app_module
    result = app.redact_headers_for_log({"Authorization": "Bearer secret-token"})
    assert result["Authorization"] == "<redacted>"


def test_redact_headers_proxy_authorization(app_module):
    """Proxy-Authorization header value must be replaced with <redacted>."""
    app = app_module
    result = app.redact_headers_for_log({"Proxy-Authorization": "Basic abc123"})
    assert result["Proxy-Authorization"] == "<redacted>"


def test_redact_headers_proxy_shared_secret(app_module):
    """The trusted-ingress secret must never be emitted by debug logging."""
    app = app_module
    result = app.redact_headers_for_log({"X-Proxy-Secret": "do-not-log-me"})
    assert result["X-Proxy-Secret"] == "<redacted>"


def test_redact_headers_case_insensitive(app_module):
    """Redaction must match header names case-insensitively."""
    app = app_module
    result = app.redact_headers_for_log(
        {
            "authorization": "Bearer lower",
            "AUTHORIZATION": "Bearer upper",
            "Authorization": "Bearer mixed",
            "x-PrOxY-SeCrEt": "secret",
        }
    )
    for k in result:
        assert result[k] == "<redacted>", (
            f"Expected <redacted> for {k!r}, got {result[k]!r}"
        )


def test_redact_headers_passthrough(app_module):
    """Non-sensitive headers must be returned unchanged."""
    app = app_module
    headers = {
        "X-Real-IP": "1.2.3.4",
        "Remote-User": "joe@example.com",
        "Content-Type": "application/json",
    }
    result = app.redact_headers_for_log(headers)
    assert result == headers


def test_redact_headers_empty(app_module):
    """Empty dict input must return empty dict."""
    app = app_module
    assert app.redact_headers_for_log({}) == {}


def test_redact_headers_returns_copy(app_module):
    """redact_headers_for_log must not mutate the original dict."""
    app = app_module
    original = {"Authorization": "Bearer secret", "X-Real-IP": "1.2.3.4"}
    _ = app.redact_headers_for_log(original)
    assert original["Authorization"] == "Bearer secret", (
        "Original dict must not be mutated"
    )


@pytest.mark.parametrize(
    "header_name",
    [
        "Cookie",
        "Set-Cookie",
        "X-Api-Key",
        "X-Auth-Token",
        "X-Csrf-Token",
        "X-Xsrf-Token",
        "x-csRf-tOkEn",
        "X-Session-Cookie",
        "X-My-Secret",
        "X-Session-Token",
        "X-Custom-Auth",
        "X-Service-Api-Key",
        "X-ApiKey",
        "X-User-Password",
    ],
)
def test_redact_headers_expanded_names_and_substrings(app_module, header_name):
    """Explicit sensitive headers and sensitive name substrings are redacted."""
    app = app_module
    result = app.redact_headers_for_log({header_name: "sensitive-value"})
    assert result == {header_name: "<redacted>"}


def test_redact_headers_preserves_duplicate_pairs_and_sanitizes(app_module):
    """Sequence-of-pairs input preserves duplicate headers and sanitizes controls."""
    app = app_module
    pairs = [
        ("Remote-User-Id", "user-1"),
        ("Remote-User-Id", "user-2\r\nFAKE"),
        ("Cookie", "sid=secret1"),
        ("Cookie", "sid=secret2"),
        ("X-Custom\x1bName", "ok\x00val\x7f\u2028\u2029"),
    ]
    result = app.redact_headers_for_log(pairs)
    assert result == [
        ("Remote-User-Id", "user-1"),
        ("Remote-User-Id", "user-2\\r\\nFAKE"),
        ("Cookie", "<redacted>"),
        ("Cookie", "<redacted>"),
        ("X-Custom\\x1bName", "ok\\x00val\\x7f\\u2028\\u2029"),
    ]


def test_redact_headers_dict_sanitizes_control_chars(app_module):
    """Mapping input sanitizes control chars in non-redacted header names and values."""
    app = app_module
    result = app.redact_headers_for_log(
        {
            "X-Real-IP": "1.2.3.4\r\nX-Injected: 1",
            "X-Bad\nName": "val\u2028\u2029\x1b",
            "X-Secret-Header": "must-stay-hidden\r\n",
        }
    )
    assert result == {
        "X-Real-IP": "1.2.3.4\\r\\nX-Injected: 1",
        "X-Bad\\nName": "val\\u2028\\u2029\\x1b",
        "X-Secret-Header": "<redacted>",
    }


def test_save_and_load_state_round_trip(monkeypatch, app_module, temp_state_file):
    """State written by save_state must be recovered exactly by load_state."""
    app = app_module
    monkeypatch.setattr(app, "STATE_FILE", temp_state_file)

    test_state = {
        "1.2.3.4": {
            "last_seen": "2025-01-01T00:00:00+00:00",
            "resources": {"5": {"created_by_us": True}},
        },
        "5.6.7.8": {
            "last_seen": "2025-06-01T12:00:00+00:00",
            "resources": {"5": {"created_by_us": False}},
        },
    }
    with app.state_lock:
        app.state.clear()
        app.state.update(test_state)

    app.save_state()

    # Clear in-memory state to prove load_state actually reads from disk
    with app.state_lock:
        app.state.clear()

    app.load_state()

    with app.state_lock:
        assert app.state == test_state


def test_checkin_after_load_preserves_and_saves_state(app_module, temp_state_file):
    """Startup-loaded state and later HTTP writes must share the same mapping."""
    app = app_module
    existing_ip = "1.1.1.1"
    new_ip = "8.8.8.8"
    persisted = {existing_ip: {"last_seen": app.now_utc_iso(), "resources": {}}}
    with open(temp_state_file, "w") as state_file:
        json.dump(persisted, state_file)

    app.load_state()
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        # Missing identity fails closed while recording the audit timestamp.
        proxy_request(conn, "GET", "/checkin.png", headers={"X-Real-IP": new_ip})
        response = conn.getresponse()
        assert response.status == 200
        assert response.read() == app.BANNER_PNG
        conn.close()

    with open(temp_state_file) as state_file:
        saved = json.load(state_file)
    assert saved[existing_ip] == persisted[existing_ip]
    assert saved[new_ip]["resources"] == {}
    assert saved[new_ip]["last_seen"]
    assert app.state == saved


def test_load_state_ignores_missing_file(monkeypatch, app_module, tmp_path):
    """load_state must not raise when the state file does not exist."""
    app = app_module
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "nonexistent.json"))
    with app.state_lock:
        app.state.clear()
    app.load_state()  # must not raise
    with app.state_lock:
        assert app.state == {}


def test_load_state_ignores_non_dict_content(monkeypatch, app_module, tmp_path):
    """load_state must leave state unchanged if the file contains a non-dict."""
    import json as _json

    app = app_module
    state_file = str(tmp_path / "state.json")
    with open(state_file, "w") as f:
        _json.dump([1, 2, 3], f)
    monkeypatch.setattr(app, "STATE_FILE", state_file)
    with app.state_lock:
        app.state.clear()
        app.state["sentinel"] = {"last_seen": "x", "resources": {}}
    app.load_state()
    with app.state_lock:
        # State must be unchanged — list JSON is not a valid state dict
        assert "sentinel" in app.state


def test_cleanup_skips_ip_with_invalid_last_seen_format(monkeypatch, app_module):
    """An IP with an unparseable last_seen value must be skipped, not removed."""
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    ip = "8.8.8.8"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "not-a-valid-datetime",
            "resources": {"5": {"created_by_us": True}},
        }

    delete_calls = []
    monkeypatch.setattr(
        app,
        "delete_ip_rule_if_created_by_us",
        lambda i, r: delete_calls.append((i, r)) or True,
    )
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    app.cleanup_old_ips()

    # IP must remain in state — invalid timestamp means skip, not delete
    with app.state_lock:
        assert ip in app.state, "IP with invalid last_seen must not be removed"
    assert delete_calls == [], (
        "No delete must be attempted for IP with invalid last_seen"
    )


@pytest.fixture
def pangolin_124_api(monkeypatch, app_module):
    """Mock the 1.24 response fields and mixed rules; never call live targets."""
    import secrets
    from urllib.parse import urlsplit

    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", secrets.token_hex(32))
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5, 6])
    monkeypatch.setattr(app, "RULE_PRIORITY", 0)
    monkeypatch.setattr(app, "RULES_CACHE_TTL_SECONDS", 3600)
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 0)
    monkeypatch.setattr(app, "RETENTION_MINUTES", 60)
    monkeypatch.setattr(app, "CROWDSEC_ENABLED", False)
    monkeypatch.setattr(app, "REDIRECT_TO_LAUNCHER", False)
    monkeypatch.setattr(app, "TARGETS", [app.PangolinTarget(app.make_pangolin_context)])

    api = {
        "calls": [],
        "user_roles": [5],
        "direct_users": [],
        "next_rule_id": 100,
        "rules": {
            5: [
                {
                    "ruleId": 10,
                    "match": "METHOD",
                    "value": "POST,PUT",
                    "action": "PASS",
                    "priority": 10,
                    "enabled": True,
                },
                {
                    "ruleId": 11,
                    "match": "METHOD",
                    "value": "GET",
                    "action": "ACCEPT",
                    "priority": 20,
                    "enabled": True,
                },
                {
                    "ruleId": 12,
                    "match": "IP",
                    "value": "9.9.9.9",
                    "action": "ACCEPT",
                    "priority": 30,
                    "enabled": True,
                },
            ],
            6: [],
        },
    }
    api["original_rules"] = {
        rid: [dict(rule) for rule in rules] for rid, rules in api["rules"].items()
    }

    def fake_http(method, url, body=None):
        api["calls"].append((method, url, body))
        path = urlsplit(url).path
        if method == "GET" and path == "/v1/org/test-org/users":
            return org_users_response(
                org_user("user-abc", "joe@example.com", api["user_roles"])
            )
        parts = path.strip("/").split("/")
        assert parts[:2] == ["v1", "resource"], f"Unexpected mock request: {path}"
        rid = int(parts[2])
        if method == "GET" and parts[3:] == ["roles"]:
            return {"data": {"roles": [{"roleId": rid}]}, "success": True}
        if method == "GET" and parts[3:] == ["users"]:
            users = api["direct_users"] if rid == 5 else []
            return {"data": {"users": users}, "success": True}
        if method == "GET" and len(parts) == 3:
            return {
                "data": {
                    "resourceId": rid,
                    "name": "Jellyfin",
                    "fullDomain": "jellyfin.example.com",
                    "ssl": True,
                    "requestHeaders": [
                        {"name": "X-Proxy-Secret", "value": TEST_PROXY_SECRET}
                    ],
                    "responseHeaders": [
                        {"name": "X-Content-Type-Options", "value": "nosniff"}
                    ],
                },
                "success": True,
            }
        if method == "GET" and parts[3:] == ["rules"]:
            return {
                "data": {"rules": [dict(rule) for rule in api["rules"][rid]]},
                "success": True,
            }
        if method == "PUT" and parts[3:] == ["rule"]:
            rule = {**body, "ruleId": api["next_rule_id"]}
            api["next_rule_id"] += 1
            api["rules"][rid].append(rule)
            return {"data": {"rule": dict(rule)}, "success": True}
        if method == "DELETE" and parts[3] == "rule":
            rule_id = int(parts[4])
            api["rules"][rid] = [
                rule for rule in api["rules"][rid] if rule["ruleId"] != rule_id
            ]
            return {"success": True}
        raise AssertionError(f"Unexpected mock request: {method} {path}")

    monkeypatch.setattr(app, "http_json", fake_http)
    return api


@pytest.mark.parametrize("access", ["role", "direct_user"])
def test_pangolin_124_checkin_expiry_and_recheckin_preserve_other_rules(
    app_module, pangolin_124_api, access
):
    """Both access paths survive new header fields and leave other rules untouched."""
    app = app_module
    api = pangolin_124_api
    if access == "direct_user":
        api["user_roles"] = [99]
        api["direct_users"] = [{"userId": "user-abc"}]
    ip = "1.2.3.4"

    results = app.add_ip_to_targets(
        ip, remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert results["pangolin"]["ok"] is True
    assert results["resources"] == [
        {
            "resourceId": 5,
            "name": "Jellyfin",
            "fullDomain": "jellyfin.example.com",
            "ssl": True,
        }
    ], "Display metadata must exclude the request/response headers"
    assert app.state[ip]["resources"] == {"5": {"created_by_us": True, "rule_id": 100}}
    assert app.rules_cache[5]["ip_set"] == {ip, "9.9.9.9"}
    assert api["rules"][5][:-1] == api["original_rules"][5]
    assert api["rules"][5][-1] == {
        "ruleId": 100,
        "match": "IP",
        "value": ip,
        "action": "ACCEPT",
        "priority": 0,
        "enabled": True,
    }
    assert api["rules"][6] == api["original_rules"][6]
    with open(app.STATE_FILE) as state_file:
        assert json.load(state_file)[ip]["resources"] == app.state[ip]["resources"]

    app.state[ip]["last_seen"] = "2000-01-01T00:00:00+00:00"
    app.cleanup_old_ips()
    assert ip not in app.state
    assert app.rules_cache[5]["ip_set"] == {"9.9.9.9"}
    assert api["rules"] == api["original_rules"]

    results = app.add_ip_to_targets(
        ip, remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert results["pangolin"]["ok"] is True
    assert api["rules"][5][:-1] == api["original_rules"][5]
    assert api["rules"][5][-1]["value"] == ip
    mutations = [(method, url) for method, url, _ in api["calls"] if method != "GET"]
    assert mutations == [
        ("PUT", "https://pg.test/v1/resource/5/rule"),
        ("DELETE", "https://pg.test/v1/resource/5/rule/100"),
        ("PUT", "https://pg.test/v1/resource/5/rule"),
    ]


def test_pangolin_124_existing_ip_rule_is_not_claimed_or_deleted(
    app_module, pangolin_124_api
):
    """A pre-existing IP in a mixed rules response remains externally owned."""
    app = app_module
    api = pangolin_124_api
    ip = "9.9.9.9"
    results = app.add_ip_to_targets(
        ip, remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert results["pangolin"]["ok"] is True
    assert app.state[ip]["resources"] == {"5": {"created_by_us": False}}

    app.state[ip]["last_seen"] = "2000-01-01T00:00:00+00:00"
    app.cleanup_old_ips()
    assert ip not in app.state
    assert api["rules"] == api["original_rules"]
    assert all(method == "GET" for method, _, _ in api["calls"])


def test_pangolin_124_checkin_without_identity_cannot_grant_access(
    app_module, pangolin_124_api
):
    """A proxy-forwarded GET without user identity must fail closed, even with 200."""
    app = app_module
    api = pangolin_124_api
    handler = app.create_image_request_handler(app._make_image_handler_context())
    ip = "1.2.3.4"
    with start_server(handler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(
            conn,
            "GET",
            "/checkin.png",
            headers={"X-Real-IP": ip, "Accept": "text/html"},
        )
        response = conn.getresponse()
        body = response.read().decode()
        assert response.status == 200
        assert "Remote-User-Id header not present" in body
        assert "no-store" in response.getheader("Cache-Control")
        assert response.getheader("Content-Security-Policy")
        assert TEST_PROXY_SECRET not in body
        conn.close()

    assert app.state[ip]["resources"] == {}
    assert api["calls"] == [], "Missing identity must stop before any Pangolin API call"
    assert api["rules"] == api["original_rules"]


def test_cleanup_multi_resource_partial_delete(monkeypatch, app_module):
    """One resource deletes successfully, one fails — IP record stays with failing resource."""
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    ip = "1.2.3.4"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {
                "5": {"created_by_us": True},
                "6": {"created_by_us": True},
            },
        }

    def fake_delete(ip_arg, rid):
        return rid == 5  # resource 5 succeeds, resource 6 fails

    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", fake_delete)
    app.cleanup_old_ips()

    with app.state_lock:
        assert ip in app.state, "IP must remain when one resource delete failed"
        resources = app.state[ip]["resources"]
        assert "5" not in resources, "Resource 5 delete succeeded — must be removed"
        assert "6" in resources, "Resource 6 delete failed — must remain for retry"


def test_cleanup_multi_resource_full_delete(monkeypatch, app_module):
    """Both resources deleted successfully — IP record fully removed."""
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    ip = "2.3.4.5"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {
                "5": {"created_by_us": True},
                "6": {"created_by_us": True},
            },
        }

    monkeypatch.setattr(
        app, "delete_ip_rule_if_created_by_us", lambda ip_arg, rid: True
    )
    app.cleanup_old_ips()

    with app.state_lock:
        assert ip not in app.state, "IP must be fully removed when all deletes succeed"


def test_http_json_http_error_raises(monkeypatch, app_module, capsys):
    """HTTPError from _HTTP_OPENER -> RuntimeError with status only; sanitized body logged."""
    from io import BytesIO
    from urllib.error import HTTPError as _HTTPError

    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")

    def fake_open(req, timeout=None):
        raise _HTTPError(
            url="https://pg.test/foo",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(b"something went wrong"),
        )

    monkeypatch.setattr(app._HTTP_OPENER, "open", fake_open)
    with pytest.raises(RuntimeError) as exc_info:
        app.http_json("GET", "https://pg.test/foo")
    assert "HTTP 500" in str(exc_info.value)
    assert "something went wrong" not in str(exc_info.value)
    captured = capsys.readouterr()
    assert "something went wrong" in captured.out


def test_http_json_url_error_raises(monkeypatch, app_module):
    """URLError from _HTTP_OPENER -> RuntimeError with 'Network error' in message."""
    from urllib.error import URLError as _URLError

    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")

    monkeypatch.setattr(
        app._HTTP_OPENER,
        "open",
        lambda req, timeout=None: (_ for _ in ()).throw(
            _URLError("connection refused")
        ),
    )
    with pytest.raises(RuntimeError, match="Network error"):
        app.http_json("GET", "https://pg.test/foo")


def test_http_json_non_json_response_returns_raw(monkeypatch, app_module):
    """Non-JSON response body -> returns {'raw': text} without raising."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")

    class _FakeResp:
        class headers:
            @staticmethod
            def get_content_charset():
                return "utf-8"

        def read(self, amt=-1):
            data = b"not json at all"
            return data if amt < 0 else data[:amt]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(app._HTTP_OPENER, "open", lambda req, timeout=None: _FakeResp())
    result = app.http_json("GET", "https://pg.test/foo")
    assert result == {"raw": "not json at all"}


def test_http_json_rejects_non_https_schemes(monkeypatch, app_module):
    """http_json rejects http://, file://, ftp://, and relative URLs by default."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(
        app._HTTP_OPENER,
        "open",
        lambda *_a, **_kw: pytest.fail("_HTTP_OPENER.open must not be called"),
    )

    for bad_url in (
        "http://pg.test/v1/test",
        "file:///etc/passwd",
        "ftp://pg.test/v1/test",
        "/v1/test",
    ):
        with pytest.raises(RuntimeError, match="disallowed URL scheme"):
            app.http_json("GET", bad_url)


def test_http_json_rejects_cross_origin(monkeypatch, app_module):
    """http_json rejects URLs whose origin differs from PANGOLIN_URL or carries userinfo."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(
        app._HTTP_OPENER,
        "open",
        lambda *_a, **_kw: pytest.fail("_HTTP_OPENER.open must not be called"),
    )

    with pytest.raises(RuntimeError, match="unexpected Pangolin origin"):
        app.http_json("GET", "https://other.example/v1/resource/1")

    with pytest.raises(RuntimeError, match="unexpected Pangolin origin"):
        app.http_json("GET", "https://pg.test:8443/v1/resource/1")

    with pytest.raises(RuntimeError, match="URL credentials"):
        app.http_json("GET", "https://user:pass@pg.test/v1/resource/1")


def test_http_json_allows_same_origin_http_only_with_internal_flag(
    monkeypatch, app_module
):
    """_ALLOW_INSECURE_HTTP=True allows same-origin http:// while blocking others."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "http://pangolin:3003")
    monkeypatch.setattr(app, "_ALLOW_INSECURE_HTTP", True)

    class _FakeResp:
        class headers:
            @staticmethod
            def get_content_charset():
                return "utf-8"

        def read(self, amt=-1):
            data = b'{"ok": true}'
            return data if amt < 0 else data[:amt]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(app._HTTP_OPENER, "open", lambda req, timeout=None: _FakeResp())
    assert app.http_json("GET", "http://pangolin:3003/v1/test") == {"ok": True}

    with pytest.raises(RuntimeError, match="disallowed URL scheme"):
        app.http_json("GET", "file:///etc/passwd")

    with pytest.raises(RuntimeError, match="unexpected Pangolin origin"):
        app.http_json("GET", "http://evil.example/v1/test")


def test_http_json_does_not_follow_redirects(monkeypatch, app_module):
    """302 redirects must not be followed or leak Authorization to redirect targets."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    app = app_module
    secondary_requests = []

    class _SecondaryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            secondary_requests.append((self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args):
            pass

    secondary = HTTPServer(("127.0.0.1", 0), _SecondaryHandler)
    sec_port = secondary.server_port

    class _PrimaryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sec_port}/steal")
            self.end_headers()
            self.wfile.write(b"redirecting")

        def log_message(self, *_args):
            pass

    primary = HTTPServer(("127.0.0.1", 0), _PrimaryHandler)
    pri_port = primary.server_port

    t_sec = threading.Thread(
        target=secondary.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    t_pri = threading.Thread(
        target=primary.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    t_sec.start()
    t_pri.start()
    try:
        monkeypatch.setattr(app, "PANGOLIN_URL", f"http://127.0.0.1:{pri_port}")
        monkeypatch.setattr(app, "PANGOLIN_TOKEN", "super-secret-token")
        monkeypatch.setattr(app, "_ALLOW_INSECURE_HTTP", True)

        with pytest.raises(RuntimeError, match="HTTP 302"):
            app.http_json("GET", f"http://127.0.0.1:{pri_port}/v1/test")
        assert secondary_requests == []
    finally:
        primary.shutdown()
        primary.server_close()
        secondary.shutdown()
        secondary.server_close()
        t_pri.join(timeout=5)
        t_sec.join(timeout=5)


def test_http_json_ignores_proxy_env_vars(monkeypatch, app_module):
    """_HTTP_OPENER bypasses ambient HTTP_PROXY/HTTPS_PROXY environment variables."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    app = app_module

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"direct": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    t.start()
    try:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
        monkeypatch.setenv("https_proxy", "http://127.0.0.1:1")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.setattr(
            app, "PANGOLIN_URL", f"http://127.0.0.1:{server.server_port}"
        )
        monkeypatch.setattr(app, "_ALLOW_INSECURE_HTTP", True)

        assert app.http_json(
            "GET", f"http://127.0.0.1:{server.server_port}/v1/test"
        ) == {"direct": True}
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=5)


def test_http_json_enforces_response_size_cap(monkeypatch, app_module):
    """Responses exceeding _MAX_HTTP_RESPONSE_BYTES raise RuntimeError."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "_MAX_HTTP_RESPONSE_BYTES", 64)

    class _SizedResp:
        def __init__(self, payload: bytes):
            self._payload = payload

        class headers:
            @staticmethod
            def get_content_charset():
                return "utf-8"

        def read(self, amt=-1):
            return self._payload if amt < 0 else self._payload[:amt]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    exact_payload = b'{"k":"' + (b"a" * 56) + b'"}'
    assert len(exact_payload) == 64
    monkeypatch.setattr(
        app._HTTP_OPENER, "open", lambda req, timeout=None: _SizedResp(exact_payload)
    )
    assert app.http_json("GET", "https://pg.test/ok") == {"k": "a" * 56}

    oversized_payload = b'{"k":"' + (b"a" * 60) + b'"}'
    monkeypatch.setattr(
        app._HTTP_OPENER,
        "open",
        lambda req, timeout=None: _SizedResp(oversized_payload),
    )
    with pytest.raises(RuntimeError, match="byte limit"):
        app.http_json("GET", "https://pg.test/too-big")


def test_http_json_caps_and_sanitizes_error_body(monkeypatch, app_module, capsys):
    """Error bodies are capped, CRLF-sanitized in stdout, and omitted from RuntimeError."""
    from io import BytesIO
    from urllib.error import HTTPError as _HTTPError

    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "_MAX_HTTP_ERROR_BYTES", 64)

    body = b"upstream\r\nFAKE LOG LINE " + (b"x" * 200) + b"SECRET_TAIL"

    def fake_open(req, timeout=None):
        raise _HTTPError(
            url="https://pg.test/foo",
            code=502,
            msg="Bad Gateway",
            hdrs={},
            fp=BytesIO(body),
        )

    monkeypatch.setattr(app._HTTP_OPENER, "open", fake_open)
    with pytest.raises(RuntimeError) as exc_info:
        app.http_json("GET", "https://pg.test/foo")

    err_msg = str(exc_info.value)
    assert err_msg == "HTTP 502 Bad Gateway"
    assert "FAKE LOG LINE" not in err_msg
    assert "SECRET_TAIL" not in err_msg

    out = capsys.readouterr().out
    assert "\r" not in out
    assert out.count("\n") == 1
    assert "upstream  FAKE LOG LINE" in out
    assert "SECRET_TAIL" not in out


def test_checkin_html_omits_raw_upstream_error_body(monkeypatch, app_module):
    """Raw upstream HTTPError body never reaches {{PANGOLIN_DETAIL}} on check-in HTML."""
    from io import BytesIO
    from urllib.error import HTTPError as _HTTPError

    from request_handler import _build_checkin_html

    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])

    def fake_open(req, timeout=None):
        raise _HTTPError(
            url="https://pg.test/v1/org/test-org/users",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(b'{"secret":"db-password-leak"}'),
        )

    monkeypatch.setattr(app._HTTP_OPENER, "open", fake_open)
    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-1", remote_user="alice"
    )
    assert results["pangolin"]["ok"] is False

    rendered = _build_checkin_html(
        ip="1.2.3.4",
        results=results,
        retention_minutes=60,
        last_seen="2026-01-01T00:00:00+00:00",
        crowdsec_enabled=False,
    )
    assert "HTTP 500" in rendered
    assert "db-password-leak" not in rendered
    assert '"secret"' not in rendered


def test_self_check_missing_pangolin_url_raises(monkeypatch, app_module):
    """Missing PANGOLIN_URL → RuntimeError at startup."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    with pytest.raises(RuntimeError, match="PANGOLIN_URL"):
        app.self_check()


def test_self_check_missing_resource_ids_raises(monkeypatch, app_module):
    """Empty RESOURCE_IDS → RuntimeError at startup."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [])
    with pytest.raises(RuntimeError, match="RESOURCE_IDS"):
        app.self_check()


def test_self_check_missing_proxy_shared_secret_raises(monkeypatch, app_module):
    """PROXY_SHARED_SECRET is required to enforce the trusted ingress path."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PROXY_SHARED_SECRET", "")
    with pytest.raises(RuntimeError, match="PROXY_SHARED_SECRET"):
        app.self_check()


def test_self_check_empty_token_warns_not_raises(
    monkeypatch, app_module, capsys, tmp_path
):
    """Empty PANGOLIN_TOKEN → warning printed, no exception raised."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    app.self_check()  # must not raise
    out = capsys.readouterr().out
    assert "PANGOLIN_TOKEN" in out


def test_self_check_empty_org_id_warns_not_raises(
    monkeypatch, app_module, capsys, tmp_path
):
    """Empty ORG_ID → warning printed, no exception raised."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "some-token")
    monkeypatch.setattr(app, "ORG_ID", "")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    app.self_check()  # must not raise
    out = capsys.readouterr().out
    assert "ORG_ID" in out


def test_self_check_http_url_raises(monkeypatch, app_module):
    """PANGOLIN_URL with http:// scheme → RuntimeError at startup."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "http://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    with pytest.raises(RuntimeError, match="https://"):
        app.self_check()


def test_self_check_invalid_interval_raises(monkeypatch, app_module):
    """CLEANUP_INTERVAL_MINUTES=0 → RuntimeError at startup."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "CLEANUP_INTERVAL_MINUTES", 0)
    with pytest.raises(RuntimeError, match="CLEANUP_INTERVAL_MINUTES"):
        app.self_check()


def test_self_check_invalid_retention_raises(monkeypatch, app_module):
    """RETENTION_MINUTES=0 → RuntimeError at startup."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)
    with pytest.raises(RuntimeError, match="RETENTION_MINUTES"):
        app.self_check()


def test_self_check_invalid_rules_cache_ttl_raises(monkeypatch, app_module):
    """RULES_CACHE_TTL_SECONDS=0 → RuntimeError at startup."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "RULES_CACHE_TTL_SECONDS", 0)
    with pytest.raises(RuntimeError, match="RULES_CACHE_TTL_SECONDS"):
        app.self_check()


def test_self_check_rate_limit_zero_allowed(monkeypatch, app_module, tmp_path):
    """RATE_LIMIT_SECONDS=0 is allowed (disables rate limiting)."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 0)
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    app.self_check()  # must not raise


@pytest.mark.parametrize("bad_name", ["", "bad name!", "--flag"])
def test_self_check_invalid_crowdsec_allowlist_name_raises(
    monkeypatch, app_module, tmp_path, bad_name
):
    """Invalid CROWDSEC_ALLOWLIST_NAME with CROWDSEC_ENABLED=True raises RuntimeError."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(app, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(app, "CROWDSEC_ALLOWLIST_NAME", bad_name)
    with pytest.raises(RuntimeError, match="invalid CrowdSec allowlist name"):
        app.self_check()


def test_self_check_invalid_crowdsec_allowlist_name_ignored_when_disabled(
    monkeypatch, app_module, tmp_path
):
    """Invalid CROWDSEC_ALLOWLIST_NAME does not raise when CROWDSEC_ENABLED=False."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(app, "CROWDSEC_ENABLED", False)
    monkeypatch.setattr(app, "CROWDSEC_ALLOWLIST_NAME", "bad name!")
    app.self_check()  # must not raise


def test_rate_limit_caching_success_only(app_module, monkeypatch):
    app = app_module
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 10)

    # 1) First call fails (Pangolin API error)
    calls = []

    def fake_fail(ctx, org_id, user_id, username):
        calls.append((user_id, username))
        raise RuntimeError("api down")

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_fail)

    res1 = app.add_ip_to_targets("1.1.1.1", remote_user_id="id-1", remote_user="user-1")
    assert res1["pangolin"]["ok"] is False
    assert len(calls) == 1

    # 2) Second call should NOT be rate limited and should call filter_resources_for_user again
    res2 = app.add_ip_to_targets("1.1.1.1", remote_user_id="id-1", remote_user="user-1")
    assert res2["pangolin"]["ok"] is False
    assert len(calls) == 2


def test_rate_limit_cache_keyed_by_ip_and_stable_user_id(app_module, monkeypatch):
    app = app_module
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 10)
    monkeypatch.setenv("PANGOLIN_TOKEN", "fake")

    calls = []

    def fake_success(ctx, org_id, user_id, username):
        calls.append((user_id, username))
        return [{"resourceId": 5, "name": "Res", "fullDomain": "d.com", "ssl": True}]

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_success)

    # Ensure add_ip call succeeds
    for t in app.TARGETS:
        monkeypatch.setattr(t, "add_ip", lambda ip, resource_ids=None: None)

    # 1) Check in first user
    res1 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="same-username"
    )
    assert res1["pangolin"]["ok"] is True
    assert len(calls) == 1

    # A different stable ID with the same username must not share the cache.
    res2 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-2", remote_user="same-username"
    )
    assert res2["pangolin"]["ok"] is True
    assert len(calls) == 2

    # 3) Check in first user again - should be rate limited and return cached result
    res3 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="same-username"
    )
    assert res3["pangolin"]["ok"] is True
    assert len(calls) == 2  # No new call


def test_dashboard_url_derivation(monkeypatch):
    import importlib

    import app as _app

    # Test 1: Both PANGOLIN_URL and ORG_ID set, no trailing slash/v1
    monkeypatch.setenv("PANGOLIN_URL", "https://pangolin.example.com")
    monkeypatch.setenv("ORG_ID", "example-org")
    monkeypatch.setenv("PANGOLIN_DASHBOARD_URL", "")
    app = importlib.reload(_app)
    assert app.PANGOLIN_DASHBOARD_URL == "https://pangolin.example.com/example-org"

    # Test 2: PANGOLIN_URL has /v1, ORG_ID set
    monkeypatch.setenv("PANGOLIN_URL", "https://pangolin.example.com/v1")
    monkeypatch.setenv("ORG_ID", "example-org")
    monkeypatch.setenv("PANGOLIN_DASHBOARD_URL", "")
    app = importlib.reload(_app)
    assert app.PANGOLIN_DASHBOARD_URL == "https://pangolin.example.com/example-org"

    # Test 3: PANGOLIN_URL has trailing slash and /api
    monkeypatch.setenv("PANGOLIN_URL", "https://api.yourdomain.com/api/")
    monkeypatch.setenv("ORG_ID", "myorg")
    monkeypatch.setenv("PANGOLIN_DASHBOARD_URL", "")
    app = importlib.reload(_app)
    assert app.PANGOLIN_DASHBOARD_URL == "https://api.yourdomain.com/myorg"

    # Test 4: Explicit PANGOLIN_DASHBOARD_URL override
    monkeypatch.setenv("PANGOLIN_URL", "https://pangolin.example.com/v1")
    monkeypatch.setenv("ORG_ID", "example-org")
    monkeypatch.setenv("PANGOLIN_DASHBOARD_URL", "https://custom-dashboard.com/subpath")
    app = importlib.reload(_app)
    assert app.PANGOLIN_DASHBOARD_URL == "https://custom-dashboard.com/subpath"


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://dash.example.com/org",
        "HTTPS://dash.example.com/org",
        "javascript:alert(1)",
        "https://dash.example.com/org\r\nX-Injected: 1",
        "https://dash.example.com/org\n",
        "https://dash.example.com/org with space",
        "https://user@dash.example.com/org",
        "https://user:pass@dash.example.com/org",
        "https:///org",
        "https://",
        "https://:8443/org",
        "https://dash.example.com:99999/org",
    ],
)
def test_self_check_invalid_dashboard_url_raises(
    monkeypatch, app_module, tmp_path, bad_url
):
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(app, "PANGOLIN_DASHBOARD_URL", bad_url)
    with pytest.raises(RuntimeError, match="PANGOLIN_DASHBOARD_URL"):
        app.self_check()


@pytest.mark.parametrize(
    "good_url",
    [
        "",
        "https://dash.example.com:8443/org/launcher?tab=apps&view=grid",
        "https://192.0.2.1:8443/org?a=1&b=2",
        "https://[2001:db8::1]:8443/org?a=1",
    ],
)
def test_self_check_valid_dashboard_url_allowed(
    monkeypatch, app_module, tmp_path, good_url
):
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(app, "PANGOLIN_DASHBOARD_URL", good_url)
    app.self_check()


def test_self_check_negative_redirect_delay_raises(monkeypatch, app_module, tmp_path):
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(app, "REDIRECT_DELAY_SECONDS", -1)
    with pytest.raises(RuntimeError, match="REDIRECT_DELAY_SECONDS"):
        app.self_check()


def test_self_check_zero_redirect_delay_allowed(monkeypatch, app_module, tmp_path):
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setattr(app, "REDIRECT_DELAY_SECONDS", 0)
    app.self_check()


def test_add_ip_to_targets_sanitizes_logs(monkeypatch, app_module, capsys):
    """add_ip_to_targets sanitizes fail-closed, rate-limit, and target error logs."""
    app = app_module
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 60)

    app.add_ip_to_targets(
        "1.2.3.4",
        remote_user_id="uid\r\nFAKE",
        remote_user="",
    )

    def boom_filter(_ctx, _org, _uid, _user):
        raise RuntimeError("boom\r\nFAKE\x1b\u2028")

    monkeypatch.setattr(app, "pg_filter_resources_for_user", boom_filter)
    app.add_ip_to_targets(
        "1.2.3.4",
        remote_user_id="uid\r\n1",
        remote_user="user\n2@example.com",
    )

    monkeypatch.setattr(
        app,
        "pg_filter_resources_for_user",
        lambda _ctx, _org, _uid, _user: [
            {
                "resourceId": 5,
                "name": "App",
                "fullDomain": "app.example.com",
                "ssl": True,
            }
        ],
    )
    monkeypatch.setattr(
        app,
        "pg_ensure_ip_rule",
        lambda _ctx, _ip: (_ for _ in ()).throw(
            RuntimeError("upstream\r\nINJECT\u2029")
        ),
    )
    app.add_ip_to_targets(
        "1.2.3.4\r\nIP",
        remote_user_id="uid-1",
        remote_user="alice@example.com",
    )

    with app._api_rate_limit_lock:
        app._api_rate_limit[("9.9.9.9\r\n", "uid\r\nRATE", "alice@example.com")] = (
            _time_mod.monotonic(),
            {"pangolin": {"ok": True}, "crowdsec": {"ok": False, "enabled": False}},
        )
    app.add_ip_to_targets(
        "9.9.9.9\r\n",
        remote_user_id="uid\r\nRATE",
        remote_user="alice@example.com",
    )

    out = capsys.readouterr().out
    assert "\r" not in out
    assert "\x1b" not in out
    assert "\u2028" not in out
    assert "\u2029" not in out
    assert "boom\\r\\nFAKE\\x1b\\u2028" in out
    assert "upstream\\r\\nINJECT\\u2029" in out
    assert "'uid\\\\r\\\\nRATE'" in out


def test_bounded_server_defaults(app_module):
    """BoundedThreadingHTTPServer enforces the 32-worker / 32-queue cap."""
    srv = app_module.BoundedThreadingHTTPServer
    assert srv.max_workers == 32
    assert srv.request_queue_size == 32
    assert srv.daemon_threads is True
    assert srv.block_on_close is False
    with pytest.raises(ValueError, match="max_workers"):
        srv(
            ("127.0.0.1", 0),
            app_module.ImageRequestHandler,
            bind_and_activate=False,
            max_workers=0,
        )


def test_bounded_server_returns_503_on_saturation_and_recovers(app_module):
    """Saturating max_workers immediately returns 503 without spawning a worker."""
    from http.server import BaseHTTPRequestHandler

    lock = threading.Lock()
    entered = 0
    both_entered = threading.Event()
    release = threading.Event()
    worker_calls = 0

    class _BlockingHandler(BaseHTTPRequestHandler):
        server_version = "BannerServer"
        sys_version = ""

        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            nonlocal entered, worker_calls
            with lock:
                worker_calls += 1
            if self.path == "/block":
                with lock:
                    entered += 1
                    if entered == 2:
                        both_entered.set()
                release.wait(timeout=5)
                body = b"done"
            else:
                body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with start_bounded_server(app_module, _BlockingHandler, max_workers=2) as (
        _httpd,
        port,
    ):
        results = []

        def _worker_req():
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/block")
            r = c.getresponse()
            results.append((r.status, r.read()))
            c.close()

        t1 = threading.Thread(target=_worker_req, daemon=True)
        t2 = threading.Thread(target=_worker_req, daemon=True)
        t1.start()
        t2.start()
        try:
            assert both_entered.wait(timeout=3), "Workers did not block as expected"

            sat_conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            sat_conn.request("GET", "/probe")
            sat_resp = sat_conn.getresponse()
            sat_body = sat_resp.read()
            sat_conn.close()

            assert sat_resp.status == 503
            assert sat_resp.reason == "Service Unavailable"
            assert sat_body == b"Service Unavailable"
            assert sat_resp.getheader("Retry-After") == "5"
            assert sat_resp.getheader("Content-Type") == "text/plain; charset=utf-8"
            assert sat_resp.getheader("Content-Length") == str(
                len(b"Service Unavailable")
            )
            assert "no-store" in sat_resp.getheader("Cache-Control", "")
            assert sat_resp.getheader("Pragma") == "no-cache"
            assert sat_resp.getheader("Expires") == "0"
            assert sat_resp.getheader("Connection") == "close"
            assert sat_resp.getheader("Server") == "BannerServer"
            assert sat_resp.getheader("X-Content-Type-Options") == "nosniff"
            assert sat_resp.getheader("X-Frame-Options") == "DENY"
            assert sat_resp.getheader("Referrer-Policy") == "no-referrer"
            assert sat_resp.getheader("Content-Security-Policy")
            assert worker_calls == 2
        finally:
            release.set()
            t1.join(timeout=3)
            t2.join(timeout=3)

        assert results == [(200, b"done"), (200, b"done")]

        rec_conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        rec_conn.request("GET", "/ok")
        rec_resp = rec_conn.getresponse()
        assert rec_resp.status == 200
        assert rec_resp.read() == b"ok"
        rec_conn.close()


def test_bounded_server_releases_semaphore_on_handler_exception(app_module):
    """Semaphore slot is always released even if a request handler raises."""
    from http.server import BaseHTTPRequestHandler

    calls = {"count": 0}

    class _FlakyHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("boom")
            body = b"recovered"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with start_bounded_server(app_module, _FlakyHandler, max_workers=1) as (
        httpd,
        port,
    ):
        httpd.handle_error = lambda *_args: None
        conn1 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        with pytest.raises(http.client.HTTPException):
            conn1.request("GET", "/first")
            conn1.getresponse()
        conn1.close()

        conn2 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn2.request("GET", "/second")
        resp2 = conn2.getresponse()
        assert resp2.status == 200
        assert resp2.read() == b"recovered"
        conn2.close()


def test_bounded_server_join_workers_respects_timeout_budget(app_module):
    """join_workers stops waiting when timeout expires and clears after exit."""
    from http.server import BaseHTTPRequestHandler

    entered = threading.Event()
    release = threading.Event()

    class _HoldHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            entered.set()
            release.wait(timeout=5)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    with start_bounded_server(app_module, _HoldHandler, max_workers=1) as (
        httpd,
        port,
    ):

        def _run_req():
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/hold")
            r = c.getresponse()
            r.read()
            c.close()

        client = threading.Thread(target=_run_req, daemon=True)
        client.start()
        try:
            assert entered.wait(timeout=2)
            start = _time_mod.monotonic()
            httpd.join_workers(0.15)
            elapsed = _time_mod.monotonic() - start
            assert 0.1 <= elapsed < 1.0
        finally:
            release.set()
            client.join(timeout=3)

        start2 = _time_mod.monotonic()
        httpd.join_workers(2.0)
        assert _time_mod.monotonic() - start2 < 0.5
        with httpd._workers_lock:
            assert not httpd._active_workers


def test_cleanup_loop_exits_promptly_on_stop_event(monkeypatch, app_module):
    """cleanup_loop exits promptly when stop_event is set despite 60m interval."""
    monkeypatch.setattr(app_module, "CLEANUP_INTERVAL_MINUTES", 60)
    ran_once = threading.Event()
    monkeypatch.setattr(app_module, "cleanup_old_ips", lambda: ran_once.set())

    stop_event = threading.Event()
    t = threading.Thread(
        target=app_module.cleanup_loop, args=(stop_event,), daemon=True
    )
    t.start()
    try:
        assert ran_once.wait(timeout=2.0)
        stop_event.set()
        t.join(timeout=2.0)
        assert not t.is_alive()
    finally:
        stop_event.set()


@pytest.mark.parametrize(
    "sig", [pytest.param(15, id="SIGTERM"), pytest.param(2, id="SIGINT")]
)
def test_main_graceful_shutdown_on_signal(tmp_path, sig):
    """Running app.py shuts down cleanly and exits 0 on SIGTERM or SIGINT."""
    import os
    import signal
    import subprocess
    import sys

    import app as app_mod

    env = os.environ.copy()
    env.update(
        {
            "PANGOLIN_URL": "https://example.invalid",
            "PANGOLIN_TOKEN": "",
            "ORG_ID": "",
            "RESOURCE_IDS": "1",
            "PROXY_SHARED_SECRET": TEST_PROXY_SECRET,
            "LISTEN_PORT": "0",
            "STATE_FILE": str(tmp_path / "state.json"),
            "CROWDSEC_ENABLED": "false",
            "PYTHONUNBUFFERED": "1",
        }
    )

    proc = subprocess.Popen(
        [sys.executable, app_mod.__file__],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    watchdog = threading.Timer(10.0, proc.kill)
    watchdog.start()
    lines: list[str] = []
    try:
        assert proc.stdout is not None
        started = False
        for line in proc.stdout:
            lines.append(line)
            if "[start] Listening on" in line:
                started = True
                break
        assert started, f"Server failed to start: {''.join(lines)}"

        sig_obj = signal.Signals(sig)
        start = _time_mod.monotonic()
        proc.send_signal(sig_obj)
        rc = proc.wait(timeout=4.0)
        elapsed = _time_mod.monotonic() - start
        lines.extend(proc.stdout.readlines())
    finally:
        watchdog.cancel()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()

    output = "".join(lines)
    assert rc == 0, f"Expected exit 0, got {rc}; output:\n{output}"
    assert elapsed < 4.0
    assert f"[shutdown] Received {sig_obj.name}; shutting down gracefully" in output
    assert "[shutdown] Shutdown complete" in output


def test_main_restores_signal_handlers_and_joins_within_budget(monkeypatch, app_module):
    """main() restores previous signal handlers and joins server + cleanup."""
    import signal

    prev_sigterm = signal.getsignal(signal.SIGTERM)
    prev_sigint = signal.getsignal(signal.SIGINT)
    events: list[str] = []
    join_timeouts: list[float] = []

    class _FakeThread:
        def __init__(self, target=None, args=(), name=None, daemon=None):
            self.target = target
            self.args = args
            self.name = name
            self.daemon = daemon

        def start(self):
            events.append(f"start:{self.name}")

        def join(self, timeout=None):
            events.append(f"join:{self.name}")
            if timeout is not None:
                join_timeouts.append(timeout)

    class _FakeServer:
        server_address = ("0.0.0.0", 8080)

        def __init__(self, addr, handler_cls):
            self.addr = addr
            self.handler_cls = handler_cls

        def serve_forever(self):
            events.append("serve_forever")
            assert signal.getsignal(signal.SIGTERM) is not prev_sigterm
            assert signal.getsignal(signal.SIGINT) is not prev_sigint

        def shutdown(self):
            events.append("httpd.shutdown")

        def server_close(self):
            events.append("httpd.server_close")

        def join_workers(self, timeout):
            events.append("httpd.join_workers")
            join_timeouts.append(timeout)

    monkeypatch.setattr(app_module, "self_check", lambda: None)
    monkeypatch.setattr(app_module, "load_state", lambda: None)
    monkeypatch.setattr(app_module, "print_org_resources", lambda: None)
    monkeypatch.setattr(app_module, "TARGETS", [])
    monkeypatch.setattr(app_module, "BoundedThreadingHTTPServer", _FakeServer)
    monkeypatch.setattr(app_module.threading, "Thread", _FakeThread)

    app_module.main()

    assert signal.getsignal(signal.SIGTERM) is prev_sigterm
    assert signal.getsignal(signal.SIGINT) is prev_sigint
    assert app_module.shutdown_event.is_set()
    assert events == [
        "start:cleanup-loop",
        "serve_forever",
        "httpd.server_close",
        "httpd.join_workers",
        "join:cleanup-loop",
    ]
    assert len(join_timeouts) == 2
    assert all(0.0 <= t <= app_module._SHUTDOWN_TIMEOUT_SECONDS for t in join_timeouts)


def test_cleanup_toctou_aborts_when_renewed_during_delete(monkeypatch, app_module):
    """Concurrent renewal during delete_ip_rule_if_created_by_us preserves state & CrowdSec."""
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    ip = "1.2.3.4"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {
                "5": {"created_by_us": True},
                "6": {"created_by_us": False},
            },
        }
    with app._api_rate_limit_lock:
        app._api_rate_limit[(ip, "user-abc", "joe@example.com")] = (
            _time_mod.monotonic(),
            {"pangolin": {"ok": True}, "crowdsec": {"ok": False, "enabled": False}},
        )

    def fake_delete(ip_arg, _rid):
        with app.state_lock:
            app.state[ip_arg]["last_seen"] = app.now_utc_iso()
        return True

    expire_calls = []
    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", fake_delete)
    monkeypatch.setattr(
        app, "expire_ip_from_targets", lambda ip_arg: expire_calls.append(ip_arg)
    )

    app.cleanup_old_ips()

    with app.state_lock:
        assert ip in app.state
        assert "5" in app.state[ip]["resources"]
        assert "6" in app.state[ip]["resources"]
    assert expire_calls == []
    with app._api_rate_limit_lock:
        assert (ip, "user-abc", "joe@example.com") not in app._api_rate_limit


def test_cleanup_toctou_aborts_when_renewed_during_expire(monkeypatch, app_module):
    """Concurrent renewal during expire_ip_from_targets prevents dropping state."""
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    ip = "1.2.3.4"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"6": {"created_by_us": False}},
        }

    def fake_expire(ip_arg):
        with app.state_lock:
            app.state[ip_arg]["last_seen"] = app.now_utc_iso()

    monkeypatch.setattr(app, "expire_ip_from_targets", fake_expire)

    app.cleanup_old_ips()

    with app.state_lock:
        assert ip in app.state
        assert "6" in app.state[ip]["resources"]


def test_ip_lock_stripes_and_concurrent_cleanup_checkin_serialization(
    monkeypatch, app_module
):
    """Fixed-stripe per-IP lock serializes cleanup and add_ip_to_targets without deadlock."""
    app = app_module
    assert len(app._ip_locks) == 64
    assert app._get_ip_lock("2001:0db8::1") is app._get_ip_lock("2001:db8::1")

    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 300)
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "http_json", standard_fake_http_json)

    ip = "1.2.3.4"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"5": {"created_by_us": True}},
        }
    with app._api_rate_limit_lock:
        app._api_rate_limit[(ip, "user-abc", "joe@example.com")] = (
            _time_mod.monotonic(),
            {"pangolin": {"ok": True}, "crowdsec": {"ok": False, "enabled": False}},
        )

    delete_started = threading.Event()
    allow_delete_finish = threading.Event()
    events: list[str] = []
    expire_calls: list[str] = []

    def fake_delete(_ip_arg, _rid):
        delete_started.set()
        assert allow_delete_finish.wait(timeout=5)
        events.append("delete_done")
        return True

    orig_ensure = app.pg_ensure_ip_rule

    def tracked_ensure(ctx, ip_arg):
        events.append("ensure_called")
        return orig_ensure(ctx, ip_arg)

    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", fake_delete)
    monkeypatch.setattr(app, "pg_ensure_ip_rule", tracked_ensure)
    monkeypatch.setattr(
        app, "expire_ip_from_targets", lambda ip_arg: expire_calls.append(ip_arg)
    )

    cleanup_thread = threading.Thread(target=app.cleanup_old_ips)
    cleanup_thread.start()
    assert delete_started.wait(timeout=5)

    # Simulate request handler stamping last_seen under state_lock before add_ip_to_targets
    with app.state_lock:
        app.state[ip]["last_seen"] = app.now_utc_iso()

    checkin_results = {}

    def run_checkin():
        checkin_results["res"] = app.add_ip_to_targets(
            ip, remote_user_id="user-abc", remote_user="joe@example.com"
        )

    checkin_thread = threading.Thread(target=run_checkin)
    checkin_thread.start()
    _time_mod.sleep(0.05)

    assert events == [], "add_ip_to_targets must block on per-IP lock during cleanup"

    allow_delete_finish.set()
    cleanup_thread.join(timeout=5)
    checkin_thread.join(timeout=5)
    assert not cleanup_thread.is_alive()
    assert not checkin_thread.is_alive()

    assert events == ["delete_done", "ensure_called"]
    assert expire_calls == []
    assert checkin_results["res"]["pangolin"]["ok"] is True
    with app.state_lock:
        assert ip in app.state
        assert "5" in app.state[ip]["resources"]


def test_cleanup_naive_last_seen_treated_as_utc_with_warning(
    monkeypatch, app_module, capsys
):
    """Naive ISO timestamps in state.json are treated as UTC with a warning and expired."""
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    ip = "4.5.6.7"
    with app.state_lock:
        app.state[ip] = {
            "last_seen": "2000-01-01T00:00:00",
            "resources": {"5": {"created_by_us": True}},
        }

    deleted = []
    monkeypatch.setattr(
        app,
        "delete_ip_rule_if_created_by_us",
        lambda ip_arg, rid: deleted.append((ip_arg, rid)) or True,
    )
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    app.cleanup_old_ips()
    out = capsys.readouterr().out

    assert "Naive datetime" in out
    assert deleted == [(ip, 5)]
    with app.state_lock:
        assert ip not in app.state


def test_cleanup_skips_corrupt_entries_and_continues_other_ips(monkeypatch, app_module):
    """Corrupt last_seen, non-dict records, or non-integer rid_str do not abort cleanup."""
    app = app_module
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    with app.state_lock:
        app.state["1.1.1.1"] = {
            "last_seen": 12345,
            "resources": {"5": {"created_by_us": True}},
        }
        app.state["2.2.2.2"] = "corrupt-non-dict"
        app.state["3.3.3.3"] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {
                "bad-rid": {"created_by_us": True},
                "5": {"created_by_us": True},
            },
        }
        app.state["4.4.4.4"] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"7": {"created_by_us": True}},
        }

    deleted = []
    monkeypatch.setattr(
        app,
        "delete_ip_rule_if_created_by_us",
        lambda ip_arg, rid: deleted.append((ip_arg, rid)) or True,
    )
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    app.cleanup_old_ips()

    assert deleted == [("3.3.3.3", 5), ("4.4.4.4", 7)]
    with app.state_lock:
        assert "1.1.1.1" in app.state
        assert "2.2.2.2" in app.state
        assert "3.3.3.3" in app.state
        assert "5" not in app.state["3.3.3.3"]["resources"]
        assert "bad-rid" in app.state["3.3.3.3"]["resources"]
        assert "4.4.4.4" not in app.state


def test_rate_limit_cache_requires_matching_remote_user(app_module, monkeypatch):
    """Same (ip, remote_user_id) with a different remote_user must not hit the cache."""
    app = app_module
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 300)
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake")

    calls = []

    def fake_filter(_ctx, _org_id, user_id, username):
        calls.append((user_id, username))
        return [{"resourceId": 5, "name": "Res", "fullDomain": "d.com", "ssl": True}]

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_filter)
    for t in app.TARGETS:
        monkeypatch.setattr(t, "add_ip", lambda ip, resource_ids=None: None)

    res1 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="alice@example.com"
    )
    assert res1["pangolin"]["ok"] is True
    assert len(calls) == 1

    res2 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="renamed@example.com"
    )
    assert res2["pangolin"]["ok"] is True
    assert len(calls) == 2

    res3 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="alice@example.com"
    )
    assert res3["pangolin"]["ok"] is True
    assert len(calls) == 2


def test_rate_limit_skips_caching_on_crowdsec_failure(app_module, monkeypatch):
    """When CROWDSEC_ENABLED=True and CrowdSec fails, result must not be cached."""
    app = app_module
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 300)
    monkeypatch.setattr(app, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake")

    filter_calls = []

    def fake_filter(_ctx, _org_id, user_id, username):
        filter_calls.append((user_id, username))
        return [{"resourceId": 5, "name": "Res", "fullDomain": "d.com", "ssl": True}]

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_filter)

    crowdsec_state = {"fail": True}

    class _FakeCrowdSecTarget(app.Target):
        name = "crowdsec"

        def add_ip(self, _ip, resource_ids=None):
            if crowdsec_state["fail"]:
                raise RuntimeError("cscli failed")

    monkeypatch.setattr(app.TARGETS[0], "add_ip", lambda ip, resource_ids=None: None)
    monkeypatch.setattr(app, "TARGETS", [app.TARGETS[0], _FakeCrowdSecTarget()])

    res1 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="alice@example.com"
    )
    assert res1["pangolin"]["ok"] is True
    assert res1["crowdsec"]["ok"] is False
    assert len(filter_calls) == 1

    # Second attempt must retry because CrowdSec failed
    crowdsec_state["fail"] = False
    res2 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="alice@example.com"
    )
    assert res2["pangolin"]["ok"] is True
    assert res2["crowdsec"]["ok"] is True
    assert len(filter_calls) == 2

    # Third attempt within window hits cache now that both targets succeeded
    res3 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="alice@example.com"
    )
    assert res3["crowdsec"]["ok"] is True
    assert len(filter_calls) == 2


def test_cleanup_evicts_rate_limit_cache_so_recheckin_recreates_rule(
    monkeypatch, app_module
):
    """cleanup_old_ips must evict expired IP from _api_rate_limit."""
    app = app_module
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 300)
    monkeypatch.setattr(app, "RETENTION_MINUTES", 1)

    ensure_calls = []
    orig_ensure = app.pg_ensure_ip_rule

    def counting_ensure(ctx, ip_arg):
        ensure_calls.append(ip_arg)
        return orig_ensure(ctx, ip_arg)

    monkeypatch.setattr(app, "pg_ensure_ip_rule", counting_ensure)
    monkeypatch.setattr(app, "http_json", standard_fake_http_json)
    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", lambda _ip, _rid: True)
    monkeypatch.setattr(app, "expire_ip_from_targets", lambda _ip: None)

    ip = "1.2.3.4"
    first = app.add_ip_to_targets(
        ip, remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert first["pangolin"]["ok"] is True
    assert len(ensure_calls) == 1

    # Back-date state so IP expires cleanly
    with app.state_lock:
        app.state[ip]["last_seen"] = "2000-01-01T00:00:00Z"

    app.cleanup_old_ips()
    with app.state_lock:
        assert ip not in app.state
    with app._api_rate_limit_lock:
        assert (ip, "user-abc", "joe@example.com") not in app._api_rate_limit

    # Simulate rules_cache eviction that real delete_ip_rule_if_created_by_us performs
    with app.state_lock:
        app.rules_cache.clear()

    second = app.add_ip_to_targets(
        ip, remote_user_id="user-abc", remote_user="joe@example.com"
    )
    assert second["pangolin"]["ok"] is True
    assert len(ensure_calls) == 2


def test_rate_limit_cache_max_size_and_deepcopy_isolation(app_module, monkeypatch):
    """_api_rate_limit enforces max size (evicting oldest) and isolates mutations."""
    app = app_module
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 300)
    monkeypatch.setattr(app, "_API_RATE_LIMIT_MAX_ENTRIES", 2)
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake")

    monkeypatch.setattr(
        app,
        "pg_filter_resources_for_user",
        lambda _ctx, _org, _uid, _user: [
            {"resourceId": 5, "name": "Res", "fullDomain": "d.com", "ssl": True}
        ],
    )
    for t in app.TARGETS:
        monkeypatch.setattr(t, "add_ip", lambda ip, resource_ids=None: None)

    mono_times = iter([100.0, 100.0, 101.0, 101.0, 102.0, 102.0, 103.0, 103.0])
    monkeypatch.setattr(app.time, "monotonic", lambda: next(mono_times, 104.0))

    r1 = app.add_ip_to_targets(
        "1.1.1.1", remote_user_id="id-1", remote_user="alice@example.com"
    )
    # Mutate initial returned dict — must not corrupt cache
    r1["pangolin"]["ok"] = False
    r1["resources"].clear()

    app.add_ip_to_targets(
        "2.2.2.2", remote_user_id="id-2", remote_user="bob@example.com"
    )
    app.add_ip_to_targets(
        "3.3.3.3", remote_user_id="id-3", remote_user="carol@example.com"
    )

    with app._api_rate_limit_lock:
        assert len(app._api_rate_limit) == 2
        assert ("1.1.1.1", "id-1", "alice@example.com") not in app._api_rate_limit
        assert ("2.2.2.2", "id-2", "bob@example.com") in app._api_rate_limit
        assert ("3.3.3.3", "id-3", "carol@example.com") in app._api_rate_limit

    cached = app.add_ip_to_targets(
        "2.2.2.2", remote_user_id="id-2", remote_user="bob@example.com"
    )
    assert cached["pangolin"]["ok"] is True
    assert len(cached["resources"]) == 1
    cached["pangolin"]["ok"] = False
    cached["resources"].clear()

    cached_again = app.add_ip_to_targets(
        "2.2.2.2", remote_user_id="id-2", remote_user="bob@example.com"
    )
    assert cached_again["pangolin"]["ok"] is True
    assert len(cached_again["resources"]) == 1


def test_save_state_fsync_fchmod_before_replace_and_load_state_lock_order(
    monkeypatch, app_module, temp_state_file
):
    """save_state fchmod+fsyncs before os.replace; load_state acquires _save_lock then state_lock."""
    import os as _os
    import stat as _stat

    app = app_module
    monkeypatch.setattr(app, "STATE_FILE", temp_state_file)

    with app.state_lock:
        app.state.clear()
        app.state["1.2.3.4"] = {
            "last_seen": "2025-01-01T00:00:00+00:00",
            "resources": {"5": {"created_by_us": True}},
        }

    ops: list[str] = []
    orig_fchmod = _os.fchmod
    orig_fsync = _os.fsync
    orig_replace = _os.replace

    def spy_fchmod(fd, mode):
        ops.append(f"fchmod:{oct(mode)}")
        return orig_fchmod(fd, mode)

    def spy_fsync(fd):
        ops.append("fsync")
        return orig_fsync(fd)

    def spy_replace(src, dst):
        ops.append("replace")
        return orig_replace(src, dst)

    def forbid_chmod(*_args, **_kwargs):
        raise AssertionError("post-replace os.chmod must not be called")

    monkeypatch.setattr(app.os, "fchmod", spy_fchmod)
    monkeypatch.setattr(app.os, "fsync", spy_fsync)
    monkeypatch.setattr(app.os, "replace", spy_replace)
    monkeypatch.setattr(app.os, "chmod", forbid_chmod)

    app.save_state()

    assert ops == ["fchmod:0o600", "fsync", "replace"]
    assert _stat.S_IMODE(_os.stat(temp_state_file).st_mode) == 0o600

    # Verify load_state acquires _save_lock before state_lock
    lock_events: list[str] = []

    class _RecordingLock:
        def __init__(self, name, real_lock):
            self._name = name
            self._real_lock = real_lock

        def __enter__(self):
            lock_events.append(f"enter:{self._name}")
            return self._real_lock.__enter__()

        def __exit__(self, exc_type, exc_val, exc_tb):
            lock_events.append(f"exit:{self._name}")
            return self._real_lock.__exit__(exc_type, exc_val, exc_tb)

    monkeypatch.setattr(app, "_save_lock", _RecordingLock("_save_lock", app._save_lock))
    monkeypatch.setattr(app, "state_lock", _RecordingLock("state_lock", app.state_lock))

    with app.state_lock:
        app.state.clear()
    lock_events.clear()

    app.load_state()
    assert lock_events == [
        "enter:_save_lock",
        "enter:state_lock",
        "exit:state_lock",
        "exit:_save_lock",
    ]
    assert "1.2.3.4" in app.state


@pytest.mark.parametrize(
    ("env_var", "bad_val"),
    [
        ("RETENTION_MINUTES", "abc"),
        ("LISTEN_PORT", "not-a-port"),
        ("REDIRECT_DELAY_SECONDS", "soon"),
        ("RESOURCE_IDS", "1,abc"),
        ("CROWDSEC_CACHE_TTL_SECONDS", "invalid"),
    ],
)
def test_invalid_int_env_vars_recorded_and_rejected_by_self_check(
    monkeypatch, temp_state_file, env_var, bad_val
):
    """Non-integer env settings do not crash module import and fail cleanly in self_check()."""
    monkeypatch.setenv("PANGOLIN_URL", "https://pg.test")
    monkeypatch.setenv("PANGOLIN_TOKEN", "tok")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.setenv(env_var, bad_val)

    try:
        app = reload_app_and_dependencies()
        with pytest.raises(RuntimeError, match=env_var):
            app.self_check()
    finally:
        monkeypatch.delenv(env_var, raising=False)
        reload_app_and_dependencies()


def test_self_check_whitespace_proxy_shared_secret_raises(monkeypatch, app_module):
    """Whitespace-only PROXY_SHARED_SECRET is rejected as missing."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PROXY_SHARED_SECRET", "   \t ")
    with pytest.raises(RuntimeError, match="PROXY_SHARED_SECRET"):
        app.self_check()


def test_self_check_short_proxy_shared_secret_warns_without_printing_secret(
    monkeypatch, app_module, capsys, tmp_path
):
    """Short PROXY_SHARED_SECRET (< 32 chars) warns without failing or leaking the value."""
    app = app_module
    short_secret = "short-secret-value"
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))

    monkeypatch.setattr(app, "PROXY_SHARED_SECRET", short_secret)
    app.self_check()
    out_short = capsys.readouterr().out
    assert "PROXY_SHARED_SECRET" in out_short
    assert "32 characters" in out_short
    assert short_secret not in out_short

    monkeypatch.setattr(app, "PROXY_SHARED_SECRET", "s" * 32)
    app.self_check()
    out_long = capsys.readouterr().out
    assert "32 characters" not in out_long


def test_self_check_pangolin_url_empty_netloc_raises(monkeypatch, app_module):
    """PANGOLIN_URL with https:// but no host fails in self_check()."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    with pytest.raises(RuntimeError, match="PANGOLIN_URL"):
        app.self_check()


def test_self_check_listen_port_bounds(monkeypatch, app_module, capsys, tmp_path):
    """LISTEN_PORT rejects <0 or >65535, warns on 0, and accepts 1..65535."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "tok")
    monkeypatch.setattr(app, "STATE_FILE", str(tmp_path / "state.json"))

    for bad_port in (-1, 65536):
        monkeypatch.setattr(app, "LISTEN_PORT", bad_port)
        with pytest.raises(RuntimeError, match="LISTEN_PORT"):
            app.self_check()

    monkeypatch.setattr(app, "LISTEN_PORT", 0)
    app.self_check()
    assert "LISTEN_PORT=0" in capsys.readouterr().out

    monkeypatch.setattr(app, "LISTEN_PORT", 8080)
    app.self_check()
    assert "LISTEN_PORT=0" not in capsys.readouterr().out


@pytest.mark.parametrize("bad_ids", [[0], [-1], [5, 0], [5, 5]])
def test_self_check_resource_ids_non_positive_or_duplicate_raises(
    monkeypatch, app_module, bad_ids
):
    """RESOURCE_IDS rejects non-positive and duplicate resource IDs."""
    app = app_module
    monkeypatch.setattr(app, "PANGOLIN_URL", "https://pg.test")
    monkeypatch.setattr(app, "RESOURCE_IDS", bad_ids)
    with pytest.raises(RuntimeError, match="RESOURCE_IDS"):
        app.self_check()


@pytest.mark.parametrize(
    "pangolin_url",
    [
        "https://pangolin.example.com/api/v1",
        "https://pangolin.example.com/v1/api",
        "https://pangolin.example.com/v2/api/",
    ],
)
def test_dashboard_url_derivation_suffix_order_and_org_encoding(
    monkeypatch, pangolin_url
):
    """PANGOLIN_DASHBOARD_URL strips /v1, /v2, /api in any order and percent-encodes ORG_ID."""
    import importlib

    import app as _app

    monkeypatch.setenv("PANGOLIN_URL", pangolin_url)
    monkeypatch.setenv("ORG_ID", "my org/1")
    monkeypatch.setenv("PANGOLIN_DASHBOARD_URL", "")
    reloaded = importlib.reload(_app)
    assert (
        reloaded.PANGOLIN_DASHBOARD_URL == "https://pangolin.example.com/my%20org%2F1"
    )
