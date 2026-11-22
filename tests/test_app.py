import contextlib
import http.client
import json
import threading
import time as _time_mod

import pytest

TEST_PROXY_SECRET = "test-proxy-secret"


def org_users_response(*users, total=None, page=1, page_size=100, success=True):
    """Build the current Pangolin List Users response shape."""
    return {
        "data": {
            "users": list(users),
            "pagination": {
                "total": len(users) if total is None else total,
                "page": page,
                "pageSize": page_size,
            },
        },
        "success": success,
        "error": not success,
    }


def org_user(user_id, username, role_ids):
    return {
        "id": user_id,
        "username": username,
        "roles": [{"roleId": role_id, "roleName": ""} for role_id in role_ids],
    }


def proxy_request(conn, method, path, *, headers=None):
    """Send a request through the test proxy boundary."""
    request_headers = {"X-Proxy-Secret": TEST_PROXY_SECRET}
    request_headers.update(headers or {})
    conn.request(method, path, headers=request_headers)


@contextlib.contextmanager
def start_server(handler_cls):
    from http.server import HTTPServer

    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_port

    t = threading.Thread(
        target=httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    )
    t.start()
    try:
        yield (httpd, port)
    finally:
        httpd.shutdown()
        t.join(timeout=5)


@pytest.fixture
def temp_state_file(tmp_path):
    # create an empty temp state file path
    p = tmp_path / "state.json"
    return str(p)


@pytest.fixture(autouse=True)
def required_proxy_secret(monkeypatch):
    monkeypatch.setenv("PROXY_SHARED_SECRET", TEST_PROXY_SECRET)


def _reload_app_and_dependencies():
    import importlib
    import sys

    if "crowdsec_connector" in sys.modules:
        import crowdsec_connector

        importlib.reload(crowdsec_connector)
    import app as _app

    return importlib.reload(_app)


@pytest.fixture
def app_module(monkeypatch, temp_state_file):
    # Ensure env is set before import
    monkeypatch.setenv("PANGOLIN_TOKEN", "")  # avoid network calls in ensure_ip_rule
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.setenv("PROXY_SHARED_SECRET", TEST_PROXY_SECRET)

    # Import or reload module to apply env
    app = _reload_app_and_dependencies()
    # Reset runtime state
    with app.state_lock:
        app.state.clear()
    with app.state_lock:
        app.rules_cache.clear()
    with app._api_rate_limit_lock:
        app._api_rate_limit.clear()
    return app


def test_banner_serves_png_and_updates_state(app_module):
    app = app_module

    test_ip = "1.2.3.4"

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            # This test only covers image/state behavior; authorization fails closed
            # because the identity pair is intentionally incomplete.
            "Remote-User": "alice",
        }
        proxy_request(conn, "GET", "/anything-can-work-123.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == app.BANNER_PNG

    # state should have been updated for the real ip
    with app.state_lock:
        assert test_ip in app.state
        rec = app.state[test_ip]
        assert isinstance(rec.get("resources"), dict)
        assert "last_seen" in rec


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


def test_gif_serves_gif_and_updates_state(app_module):
    app = app_module

    test_ip = "6.7.8.9"

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
        }
        proxy_request(conn, "GET", "/beacon.gif", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == app.BANNER_GIF

    # state should have been updated for the real ip
    with app.state_lock:
        assert test_ip in app.state


def test_invalid_paths_denied(app_module):
    app = app_module

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

        # Test root path
        proxy_request(conn, "GET", "/")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403

        # Test path without file extension
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/some-random-path")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 404


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


def _reload_app_with_env(monkeypatch, temp_state_file, update_enabled: bool):
    # Helper to load app with standard env and update endpoint toggle
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "9")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.setenv("UPDATE_ENDPOINT_ENABLED", "true" if update_enabled else "false")
    return _reload_app_and_dependencies()


def _configure_authorized_update_user(monkeypatch, app, resource_id: int = 9):
    """Configure mocked Pangolin auth + rule creation for /update tests."""
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [resource_id])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=alice%40example.com" in url:
            return org_users_response(
                org_user("user-alice", "alice@example.com", [resource_id])
            )
        if f"/resource/{resource_id}/roles" in url:
            return {
                "data": {"roles": [{"roleId": resource_id, "name": "TV"}]},
                "success": True,
            }
        if f"/resource/{resource_id}/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith(f"/resource/{resource_id}"):
            return {
                "data": {
                    "resourceId": resource_id,
                    "name": "TV",
                    "fullDomain": "tv.example.com",
                    "ssl": True,
                },
                "success": True,
            }
        if "/rules" in url:
            return {"data": {"rules": []}, "success": True}
        if method == "PUT":
            return {"success": True, "data": {"rule": {"ruleId": 99}}}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)
    return {
        "Remote-User-Id": "user-alice",
        "Remote-User": "alice@example.com",
    }


def test_update_endpoint_enabled_adds_arbitrary_ip(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with app.state_lock:
        app.state.clear()
    auth_headers = _configure_authorized_update_user(monkeypatch, app)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update?ip=1.2.3.4", headers=auth_headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert "application/json" in resp.getheader("Content-Type", "")
        parsed = json.loads(data)
        assert parsed == {
            "ok": True,
            "ip": "1.2.3.4",
            "retention_minutes": app.RETENTION_MINUTES,
            "pangolin": {"ok": True},
            "crowdsec": {"ok": False, "enabled": False},
        }

    with app.state_lock:
        assert "1.2.3.4" in app.state
        assert "last_seen" in app.state["1.2.3.4"]
        assert "9" in app.state["1.2.3.4"]["resources"]


def test_update_endpoint_disabled_returns_404(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=False)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update?ip=1.2.3.4")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 404


def test_update_endpoint_missing_ip_param_400(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 400
        assert "application/json" in resp.getheader("Content-Type", "")
        parsed = json.loads(body)
        assert parsed["ok"] is False
        assert parsed["error"]


def test_update_endpoint_invalid_ip_400(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update?ip=999.999.999.999")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 400
        assert "application/json" in resp.getheader("Content-Type", "")
        parsed = json.loads(body)
        assert parsed["ok"] is False
        assert parsed["error"]


def test_update_endpoint_ipv6_success(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    auth_headers = _configure_authorized_update_user(monkeypatch, app)

    ipv6 = "2606:4700:4700::1111"
    encoded = "2606%3A4700%3A4700%3A%3A1111"

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", f"/update?ip={encoded}", headers=auth_headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        parsed = json.loads(data)
        assert parsed["ok"] is True
        assert parsed["ip"] == ipv6
        assert parsed["pangolin"] == {"ok": True}
        assert parsed["crowdsec"] == {"ok": False, "enabled": False}
    with app.state_lock:
        assert ipv6 in app.state


def test_update_endpoint_last_seen_updates(monkeypatch, temp_state_file):
    import time as _time

    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    auth_headers = _configure_authorized_update_user(monkeypatch, app)

    ip = "5.6.7.8"
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", f"/update?ip={ip}", headers=auth_headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200
    with app.state_lock:
        first_seen = app.state[ip]["last_seen"]
        assert first_seen
    # Wait at least 1 second to ensure timestamp changes (now_utc_iso resolution is 1s)
    _time.sleep(1.1)
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", f"/update?ip={ip}", headers=auth_headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200
    with app.state_lock:
        second_seen = app.state[ip]["last_seen"]
    assert second_seen != first_seen


def test_update_endpoint_returns_html_when_accepted(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        proxy_request(conn, "GET", "/update?ip=1.2.3.4", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert b"text/html" in resp.getheader("Content-Type", "").encode()
        assert b"Network Check-in" in data
        assert b"1.2.3.4" in data


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

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=denise%40example.com" in url:
            return org_users_response(
                org_user("user-denise", "denise@example.com", [5])
            )
        if "/resource/5/roles" in url:
            return {
                "data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]},
                "success": True,
            }
        if "/resource/6/roles" in url:
            return {
                "data": {"roles": [{"roleId": 1, "name": "Admin"}]},
                "success": True,
            }
        if "/resource/5/users" in url:
            return {"data": {"users": []}, "success": True}
        if "/resource/6/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith("/resource/5"):
            return {
                "data": {
                    "resourceId": 5,
                    "name": "Jellyfin",
                    "fullDomain": "jellyfin.example.com",
                    "ssl": True,
                },
                "success": True,
            }
        if "/rules" in url:
            return {"data": {"rules": []}, "success": True}
        if method == "PUT":
            return {"success": True, "data": {"rule": {"ruleId": 99}}}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

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


def _reload_app_with_crowdsec(monkeypatch, temp_state_file):
    """Reload app with CrowdSec enabled so TARGETS includes CrowdSecTarget."""
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.setenv("CROWDSEC_ENABLED", "true")
    return _reload_app_and_dependencies()


def _standard_fake_http_json(method, url, body=None):
    """Shared fake http_json for resource 5 with roleId 5 — used in CrowdSec tests."""
    if "/org/test-org/users?query=joe%40example.com" in url:
        return org_users_response(org_user("user-abc", "joe@example.com", [5]))
    if "/resource/5/roles" in url:
        return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
    if "/resource/5/users" in url:
        return {"data": {"users": []}, "success": True}
    if url.endswith("/resource/5"):
        return {
            "data": {
                "resourceId": 5,
                "name": "Jellyfin",
                "fullDomain": "jellyfin.example.com",
                "ssl": True,
            },
            "success": True,
        }
    if "/rules" in url:
        return {"data": {"rules": []}, "success": True}
    if method == "PUT":
        return {"success": True, "data": {"rule": {"ruleId": 99}}}
    return {}


def test_add_ip_to_targets_fails_closed_empty_intersection(monkeypatch, app_module):
    """User exists but none of their roles match any configured resource — fail-closed."""
    app = app_module

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=nobody%40example.com" in url:
            # User has roleId 99 which matches no resource, and is not directly assigned
            return org_users_response(
                org_user("user-nobody", "nobody@example.com", [99])
            )
        if "/resource/5/roles" in url:
            # Resource 5 only allows roleId 5
            return {
                "data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]},
                "success": True,
            }
        if "/resource/5/users" in url:
            # User is not directly assigned either
            return {"data": {"users": []}, "success": True}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

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

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=joe%40example.com" in url:
            return org_users_response(org_user("user-joe", "joe@example.com", [5]))
        if "/resource/5/roles" in url:
            raise RuntimeError(
                "HTTP 403 Forbidden: key lacks List Allowed Resource Roles permission"
            )
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

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

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=joe%40example.com" in url:
            return org_users_response(org_user("user-joe", "joe@example.com", [5]))
        if "/resource/5/roles" in url:
            return {
                "data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]},
                "success": True,
            }
        if "/resource/5/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith("/resource/5"):
            raise RuntimeError("HTTP 403 Forbidden: key lacks Get Resource permission")
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

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

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=joe%40example.com" in url:
            return org_users_response(org_user("user-joe", "joe@example.com", [5]))
        if "/resource/5/roles" in url:
            return {
                "data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]},
                "success": True,
            }
        if "/resource/5/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith("/resource/5"):
            return {
                "data": {
                    "resourceId": 5,
                    "name": "Jellyfin",
                    "fullDomain": "jellyfin.example.com",
                    "ssl": True,
                },
                "success": True,
            }
        if "/rules" in url:
            return {"data": {"rules": []}, "success": True}
        if method == "PUT":
            raise RuntimeError("HTTP 500 Internal Server Error: rule creation failed")
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets(
        "1.2.3.4", remote_user_id="user-joe", remote_user="joe@example.com"
    )

    assert results["pangolin"]["ok"] is False
    assert "500" in results["pangolin"]["detail"]


def test_add_ip_to_targets_crowdsec_called_when_enabled(monkeypatch, temp_state_file):
    """CrowdSec add is called alongside Pangolin when CROWDSEC_ENABLED=true."""
    app = _reload_app_with_crowdsec(monkeypatch, temp_state_file)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "http_json", _standard_fake_http_json)

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
    app = _reload_app_with_crowdsec(monkeypatch, temp_state_file)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(app, "http_json", _standard_fake_http_json)

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


# ---------------------------------------------------------------------------
# Tests for authorisation logic and passthrough header removal
# ---------------------------------------------------------------------------


def test_add_ip_to_targets_authorised_via_direct_user_assignment(
    monkeypatch, app_module
):
    """User has no matching role but IS directly assigned to the resource — must be authorised."""
    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=direct%40example.com" in url:
            # User has a role that does NOT match the resource
            return org_users_response(
                org_user("user-direct", "direct@example.com", [99])
            )
        if "/resource/5/roles" in url:
            # Resource only allows roleId 5 — no role match
            return {
                "data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]},
                "success": True,
            }
        if "/resource/5/users" in url:
            # But user IS directly assigned
            return {
                "data": {
                    "users": [
                        {"userId": "user-direct", "username": "direct@example.com"}
                    ]
                },
                "success": True,
            }
        if url.endswith("/resource/5"):
            return {
                "data": {
                    "resourceId": 5,
                    "name": "Jellyfin",
                    "fullDomain": "jellyfin.example.com",
                    "ssl": True,
                },
                "success": True,
            }
        if "/rules" in url:
            return {"data": {"rules": []}, "success": True}
        if method == "PUT":
            return {"success": True, "data": {"rule": {"ruleId": 99}}}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

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

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users?query=joe%40example.com" in url:
            return org_users_response(org_user("user-joe", "joe@example.com", [5]))
        if "/resource/5/roles" in url:
            return {
                "data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]},
                "success": True,
            }
        if "/resource/5/users" in url:
            raise RuntimeError(
                "HTTP 403 Forbidden: key lacks List Resource Users permission"
            )
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

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
        return _standard_fake_http_json(method, url, body)

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

    monkeypatch.setattr(app, "http_json", _standard_fake_http_json)

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
        return _standard_fake_http_json(method, url, body)

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
        return _standard_fake_http_json(method, url, body)

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
    app = _reload_app_and_dependencies()
    assert app is not None


def test_request_without_custom_header_reaches_handler(monkeypatch, temp_state_file):
    """The removed legacy custom-header settings are not required.

    The request still includes the mandatory X-Proxy-Secret through proxy_request.
    """
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", raising=False)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", raising=False)

    app = _reload_app_and_dependencies()
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        # No legacy custom header is sent; proxy_request adds X-Proxy-Secret.
        proxy_request(conn, "GET", "/checkin.png", headers={"X-Real-IP": "1.2.3.4"})
        resp = conn.getresponse()
        _ = resp.read()
        # Must not be 403 — handler logic should have run
        assert resp.status != 403, (
            "The removed legacy passthrough-header settings must not affect requests"
        )
        assert resp.status == 200


def test_no_remote_user_fails_closed_no_ip_added(monkeypatch, temp_state_file):
    """Without Remote-User, the identity check fails closed: no IP is added to state,
    and the response is still 200 (error page rendered).
    """
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", raising=False)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", raising=False)

    app = _reload_app_and_dependencies()
    with app.state_lock:
        app.state.clear()

    test_ip = "9.9.9.9"
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        # Remote-User-Id alone is insufficient — identity check must fail closed.
        proxy_request(
            conn,
            "GET",
            "/checkin.png",
            headers={"X-Real-IP": test_ip, "Remote-User-Id": "user-1"},
        )
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200

    # No IP rule should have been created
    with app.state_lock:
        rec = app.state.get(test_ip, {})
        # last_seen will be set (state is updated before add_ip_to_targets is called),
        # but no resources should have been whitelisted
        resources = rec.get("resources", {})
        assert resources == {}, (
            f"No resources should be whitelisted when Remote-User is absent, got: {resources}"
        )


# ---------------------------------------------------------------------------
# Unit tests for _retry() auth-error abort (Item 2 — v2.2.2)
# ---------------------------------------------------------------------------


def test_retry_aborts_immediately_on_401():
    """_retry() must not sleep or retry on HTTP 401 — raise on first attempt."""
    import pangolin_connector

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
    import pangolin_connector

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


# ---------------------------------------------------------------------------
# redact_headers_for_log — pure function, security-relevant
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# save_state / load_state round-trip
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _retry — retry behaviour and exception propagation
# ---------------------------------------------------------------------------


def test_retry_retries_on_non_auth_error():
    """_retry must attempt the function the full number of times on non-auth errors."""
    import pangolin_connector

    attempts = {"count": 0}
    sleep_calls = []

    def fn():
        attempts["count"] += 1
        raise RuntimeError("HTTP 500 Internal Server Error")

    original = pangolin_connector.time.sleep
    pangolin_connector.time.sleep = lambda s: sleep_calls.append(s)
    try:
        try:
            pangolin_connector._retry(fn, attempts=3, backoff=1.0, label="test-500")
        except RuntimeError:
            pass
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
    import pangolin_connector

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


# ---------------------------------------------------------------------------
# _build_cscli_cmd — pure function
# ---------------------------------------------------------------------------


def test_build_cscli_cmd_no_prefix(monkeypatch):
    """Without a CMD_PREFIX, result must be [bin] + args."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_CMD_PREFIX", "")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_CSCLI_BIN", "cscli")
    result = crowdsec_connector._build_cscli_cmd(["allowlist", "list"])
    assert result == ["cscli", "allowlist", "list"]


def test_build_cscli_cmd_with_single_word_prefix(monkeypatch):
    """Single-word CMD_PREFIX must be prepended as one element."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_CMD_PREFIX", "sudo")
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_CSCLI_BIN", "cscli")
    result = crowdsec_connector._build_cscli_cmd(["allowlist", "list"])
    assert result == ["sudo", "cscli", "allowlist", "list"]


def test_build_cscli_cmd_with_multi_word_prefix(monkeypatch):
    """Multi-word CMD_PREFIX must be shell-split into separate elements."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector, "CROWDSEC_CMD_PREFIX", "docker exec crowdsec"
    )
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_CSCLI_BIN", "cscli")
    result = crowdsec_connector._build_cscli_cmd(
        ["allowlist", "add", "my-list", "1.2.3.4"]
    )
    assert result == [
        "docker",
        "exec",
        "crowdsec",
        "cscli",
        "allowlist",
        "add",
        "my-list",
        "1.2.3.4",
    ]


def test_build_cscli_cmd_custom_bin(monkeypatch):
    """Custom CROWDSEC_CSCLI_BIN path must appear in the command."""
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_CMD_PREFIX", "")
    monkeypatch.setattr(
        crowdsec_connector, "CROWDSEC_CSCLI_BIN", "/usr/local/bin/cscli"
    )
    result = crowdsec_connector._build_cscli_cmd(["allowlist", "list"])
    assert result == ["/usr/local/bin/cscli", "allowlist", "list"]


def test_build_cscli_cmd_malformed_prefix_warns_and_falls_back(monkeypatch, capsys):
    """Malformed prefix (unterminated quote) logs a WARNING and falls back to single token."""
    import crowdsec_connector

    monkeypatch.setattr(
        crowdsec_connector, "CROWDSEC_CMD_PREFIX", "docker exec 'crowdsec"
    )
    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_CSCLI_BIN", "cscli")
    result = crowdsec_connector._build_cscli_cmd(["allowlist", "list"])
    assert result[0] == "docker exec 'crowdsec"
    assert result[-2:] == ["allowlist", "list"]
    out = capsys.readouterr().out
    assert "WARNING" in out


# ---------------------------------------------------------------------------
# _parse_crowdsec_entries_from_json — pure function, multiple input shapes
# ---------------------------------------------------------------------------


def test_parse_crowdsec_list_of_strings():
    """Plain list of IP strings must be parsed correctly."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json(
        '["1.2.3.4", "5.6.7.8"]'
    )
    assert result == {"1.2.3.4", "5.6.7.8"}


def test_parse_crowdsec_list_of_dicts_ip_key():
    """List of dicts with 'ip' key must extract IP values."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json(
        '[{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]'
    )
    assert result == {"1.2.3.4", "5.6.7.8"}


def test_parse_crowdsec_list_of_dicts_value_key():
    """List of dicts with 'value' key must extract IP values."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json(
        '[{"value": "9.9.9.9"}]'
    )
    assert result == {"9.9.9.9"}


def test_parse_crowdsec_dict_with_entries_key():
    """Dict with 'entries' key containing IP list must be parsed."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json(
        '{"entries": ["1.1.1.1", "2.2.2.2"]}'
    )
    assert result == {"1.1.1.1", "2.2.2.2"}


def test_parse_crowdsec_dict_with_ips_key():
    """Dict with 'ips' key must be parsed."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json(
        '{"ips": ["3.3.3.3"]}'
    )
    assert result == {"3.3.3.3"}


def test_parse_crowdsec_cidr_normalised_to_network_address():
    """CIDR notation must be accepted and normalised to the canonical CIDR block."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json('["10.0.0.5/24"]')
    assert result == {"10.0.0.0/24"}


def test_parse_crowdsec_invalid_json_returns_empty():
    """Malformed JSON must return an empty set without raising."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json("not json at all")
    assert result == set()


def test_parse_crowdsec_invalid_ip_skipped():
    """Invalid IP strings in the list must be silently skipped."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json(
        '["1.2.3.4", "not-an-ip", "5.6.7.8"]'
    )
    assert result == {"1.2.3.4", "5.6.7.8"}


def test_parse_crowdsec_empty_list():
    """Empty list must return empty set."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json("[]")
    assert result == set()


def test_parse_crowdsec_unknown_structure_returns_empty():
    """Dict with no recognised key must return empty set."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json(
        '{"unknown_key": ["1.2.3.4"]}'
    )
    assert result == set()


# ---------------------------------------------------------------------------
# cleanup_old_ips — invalid last_seen format
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _get_real_ip — IP header extraction and fallback chain
# ---------------------------------------------------------------------------


def _make_handler_for_ip_test(
    headers: dict,
    socket_ip: str = "10.20.30.40",
    proxy_shared_secret: str = "",
):
    """Return an ImageRequestHandler instance with fake headers and socket address.
    Uses object.__new__ to bypass BaseHTTPRequestHandler.__init__ (which requires
    a live socket).
    """
    from request_handler import RequestHandlerContext, create_image_request_handler

    ctx = RequestHandlerContext(
        update_enabled=False,
        retention_minutes=1440,
        crowdsec_enabled=False,
        site_name="",
        proxy_shared_secret=proxy_shared_secret,
        state={},
        state_lock=threading.Lock(),
        now_utc_iso=lambda: "2025-01-01T00:00:00+00:00",
        save_state=lambda: None,
        add_ip_to_targets=(lambda ip, remote_user_id="", remote_user="": {}),
        banner_png=b"",
        banner_gif=b"",
        redact_headers_for_log=lambda h: h,
    )
    HandlerClass = create_image_request_handler(ctx)
    instance = object.__new__(HandlerClass)
    instance.headers = headers
    instance.client_address = (socket_ip, 54321)
    return instance


def test_get_real_ip_x_real_ip_global():
    """Valid global X-Real-IP → returned directly."""
    h = _make_handler_for_ip_test({"X-Real-IP": "1.2.3.4"})
    assert h._get_real_ip() == "1.2.3.4"


def test_get_real_ip_private_x_real_ip_falls_to_xff():
    """Private X-Real-IP rejected; valid X-Forwarded-For first entry returned."""
    h = _make_handler_for_ip_test(
        {"X-Real-IP": "192.168.1.1", "X-Forwarded-For": "5.6.7.8"},
    )
    assert h._get_real_ip() == "5.6.7.8"


def test_get_real_ip_xff_first_entry_used():
    """X-Forwarded-For with multiple entries: only the first is used."""
    h = _make_handler_for_ip_test({"X-Forwarded-For": "1.2.3.4, 5.6.7.8, 9.9.9.9"})
    assert h._get_real_ip() == "1.2.3.4"


def test_get_real_ip_private_xff_falls_to_socket():
    """Private X-Forwarded-For rejected; socket address returned."""
    h = _make_handler_for_ip_test(
        {"X-Forwarded-For": "10.0.0.1"},
        socket_ip="9.9.9.9",
    )
    assert h._get_real_ip() == "9.9.9.9"


def test_get_real_ip_no_headers_socket_fallback():
    """Both headers absent; socket address returned."""
    h = _make_handler_for_ip_test({}, socket_ip="8.8.8.8")
    assert h._get_real_ip() == "8.8.8.8"


def test_get_real_ip_both_headers_non_global_socket_fallback():
    """Both headers carry non-global IPs; socket address returned."""
    h = _make_handler_for_ip_test(
        {"X-Real-IP": "192.168.0.1", "X-Forwarded-For": "172.16.0.1"},
        socket_ip="7.7.7.7",
    )
    assert h._get_real_ip() == "7.7.7.7"


def test_get_real_ip_malformed_x_real_ip_skipped():
    """Unparseable X-Real-IP rejected; valid X-Forwarded-For used instead."""
    h = _make_handler_for_ip_test(
        {"X-Real-IP": "not-an-ip", "X-Forwarded-For": "3.3.3.3"},
    )
    assert h._get_real_ip() == "3.3.3.3"


def test_get_real_ip_ipv6_accepted():
    """Valid global IPv6 in X-Real-IP → returned normalised."""
    h = _make_handler_for_ip_test({"X-Real-IP": "2606:4700:4700::1111"})
    assert h._get_real_ip() == "2606:4700:4700::1111"


def test_identity_header_rejects_duplicate_values():
    headers = http.client.HTTPMessage()
    headers.add_header("Remote-User-Id", "victim-id")
    headers.add_header("Remote-User-Id", "attacker-id")
    h = _make_handler_for_ip_test(headers)
    assert h._get_identity_header("Remote-User-Id") == ""


@pytest.mark.parametrize("value", ["", " user-1", "user-1 ", "x" * 513])
def test_identity_header_rejects_invalid_value(value):
    headers = http.client.HTTPMessage()
    headers.add_header("Remote-User-Id", value)
    h = _make_handler_for_ip_test(headers)
    assert h._get_identity_header("Remote-User-Id") == ""


# ---------------------------------------------------------------------------
# Proxy shared-secret gate (Finding H-3)
# ---------------------------------------------------------------------------


def _reload_app_with_secret(monkeypatch, temp_state_file, secret: str):
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.setenv("PROXY_SHARED_SECRET", secret)
    return _reload_app_and_dependencies()


def test_proxy_secret_missing_header_rejected(monkeypatch, temp_state_file):
    """When PROXY_SHARED_SECRET is set, a request without X-Proxy-Secret gets 403
    and no IP is written to state."""
    app = _reload_app_with_secret(monkeypatch, temp_state_file, "s3cret")
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/checkin.png", headers={"X-Real-IP": "1.2.3.4"})
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403

    with app.state_lock:
        assert "1.2.3.4" not in app.state, "no state write when secret gate fails"


def test_proxy_secret_wrong_header_rejected(monkeypatch, temp_state_file):
    """A mismatched X-Proxy-Secret is rejected with 403."""
    app = _reload_app_with_secret(monkeypatch, temp_state_file, "s3cret")

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "GET",
            "/checkin.png",
            headers={"X-Real-IP": "1.2.3.4", "X-Proxy-Secret": "wrong"},
        )
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403


def test_proxy_secret_correct_header_allowed(monkeypatch, temp_state_file):
    """A matching X-Proxy-Secret passes the gate and reaches the handler (200)."""
    app = _reload_app_with_secret(monkeypatch, temp_state_file, "s3cret")
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "GET",
            "/checkin.png",
            headers={"X-Real-IP": "1.2.3.4", "X-Proxy-Secret": "s3cret"},
        )
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200


def test_proxy_secret_unset_rejects_request(monkeypatch, temp_state_file):
    """An invalid empty configuration remains fail-closed at request time."""
    app = _reload_app_with_secret(monkeypatch, temp_state_file, "")
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "GET",
            "/checkin.png",
            headers={"X-Real-IP": "1.2.3.4", "X-Proxy-Secret": TEST_PROXY_SECRET},
        )
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403


def test_proxy_secret_duplicate_headers_rejected():
    headers = http.client.HTTPMessage()
    headers.add_header("X-Proxy-Secret", "s3cret")
    headers.add_header("X-Proxy-Secret", "s3cret")
    h = _make_handler_for_ip_test(
        headers,
        proxy_shared_secret="s3cret",
    )
    assert h._proxy_secret_ok() is False


def test_healthz_ok_and_bypasses_secret_gate(monkeypatch, temp_state_file):
    """/healthz returns 200 with no auth, even when the proxy-secret gate is armed,
    and does not write any state."""
    app = _reload_app_with_secret(monkeypatch, temp_state_file, "s3cret")
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == b"ok"

    with app.state_lock:
        assert app.state == {}, "healthz must not mutate state"


def test_favicon_returns_204_and_no_state(monkeypatch, temp_state_file):
    """/favicon.ico returns an empty 204 (not the invalid-path 404) even when the
    proxy-secret gate is armed, and does not write any state."""
    app = _reload_app_with_secret(monkeypatch, temp_state_file, "s3cret")
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/favicon.ico", headers={"X-Real-IP": "1.2.3.4"})
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 204
        assert data == b""

    with app.state_lock:
        assert app.state == {}, "favicon must not mutate state"


# ---------------------------------------------------------------------------
# HTML rendering — reflected XSS escaping (Finding H-1)
# ---------------------------------------------------------------------------


def test_checkin_html_escapes_pangolin_detail():
    """Attacker-controlled detail text must be HTML-escaped, not reflected raw."""
    import request_handler

    payload = "<script>alert(1)</script>"
    results = {
        "pangolin": {"ok": False, "detail": payload},
        "crowdsec": {"ok": False, "detail": "disabled"},
    }
    body = request_handler._build_checkin_html(
        ip="1.2.3.4",
        results=results,
        retention_minutes=1440,
        last_seen="2025-01-01T00:00:00+00:00",
        crowdsec_enabled=False,
    )
    assert payload not in body, "Raw <script> payload must not appear in rendered HTML"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


def test_checkin_html_escapes_site_name():
    """site_name must be HTML-escaped in the check-in header."""
    import request_handler

    results = {
        "pangolin": {"ok": True, "detail": "ok"},
        "crowdsec": {"ok": False, "detail": "disabled"},
    }
    body = request_handler._build_checkin_html(
        ip="1.2.3.4",
        results=results,
        retention_minutes=1440,
        last_seen="2025-01-01T00:00:00+00:00",
        crowdsec_enabled=False,
        site_name="<img src=x onerror=alert(1)>",
    )
    assert "<img src=x onerror=alert(1)>" not in body
    assert "&lt;img src=x onerror=alert(1)&gt;" in body


def test_error_html_escapes_site_name():
    """site_name must be HTML-escaped in the error page header and footer."""
    import request_handler

    body = request_handler._build_error_html(
        "Bad request", "Something went wrong.", site_name="<b>x</b>"
    )
    assert "<b>x</b>" not in body
    assert "&lt;b&gt;x&lt;/b&gt;" in body


# ---------------------------------------------------------------------------
# Pangolin 1.24 compatibility scenarios
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# pangolin_connector unit tests
# ---------------------------------------------------------------------------


def _make_pg_ctx(
    http_json=None,
    token="test-token",
    resource_ids=None,
    rules_cache=None,
    state=None,
    save_calls=None,
):
    """Construct a PangolinContext with all injected dependencies faked."""
    import pangolin_connector

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


# --- delete_ip_rule_if_created_by_us ---


def test_delete_rule_absent_returns_true():
    """GET returns no matching IP rules — rule already gone, returns True."""
    import pangolin_connector

    ctx = _make_pg_ctx(
        http_json=lambda m, u, b=None: {"data": {"rules": []}, "success": True}
    )
    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True


def test_delete_rule_success_returns_true():
    """Rule with ruleId=42 found; DELETE issued and succeeds; returns True."""
    import pangolin_connector

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
    assert any("DELETE" == m and "rule/42" in u for m, u in calls), (
        "DELETE must be called with the correct rule URL"
    )


def test_delete_rule_evicts_ip_from_rules_cache():
    """A successful delete must remove the IP from rules_cache so a later check-in
    re-creates the rule instead of trusting a stale 'already exists' entry."""
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    def fake_http(method, url, body=None):
        raise RuntimeError("HTTP 500 Internal Server Error")

    ctx = _make_pg_ctx(http_json=fake_http)
    assert (
        pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is False
    )


# --- ensure_ip_rule ---


def test_ensure_ip_rule_no_token_raises():
    """Empty token raises RuntimeError immediately — http_json never called."""
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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


# --- get_ip_set_for_resource_cached ---


def test_cache_expired_triggers_refresh():
    """Cache entry with ts=0 (epoch) is expired — http_json called, fresh ip_set returned."""
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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


# --- no-token guards ---


def test_get_user_info_external_oidc_uses_org_user_search():
    """Issue #108 OIDC identity resolves through the current List Users route."""
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

    ctx = _make_pg_ctx(
        http_json=lambda method, url, body=None: {
            "data": data,
            "success": True,
        }
    )
    with pytest.raises(RuntimeError, match="unexpected response shape"):
        pangolin_connector.get_user_info(ctx, "primary", "user-1", "alice")


def test_get_user_info_rejects_api_failure_even_with_data():
    import pangolin_connector

    ctx = _make_pg_ctx(
        http_json=lambda method, url, body=None: {
            "data": org_users_response(org_user("user-1", "alice", [1]))["data"],
            "success": False,
        }
    )
    with pytest.raises(RuntimeError, match="API reported failure"):
        pangolin_connector.get_user_info(ctx, "primary", "user-1", "alice")


def test_get_user_info_paginates_until_exact_identity_match():
    import pangolin_connector

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
    import pangolin_connector

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
    import pangolin_connector

    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_user_info(ctx, "org1", "user-123", "user@test.com")


def test_get_resource_allowed_role_ids_no_token_raises():
    """get_resource_allowed_role_ids raises RuntimeError immediately when token is empty."""
    import pangolin_connector

    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_resource_allowed_role_ids(ctx, 5)


def test_get_resource_allowed_user_ids_no_token_raises():
    """get_resource_allowed_user_ids raises RuntimeError immediately when token is empty."""
    import pangolin_connector

    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_resource_allowed_user_ids(ctx, 5)


def test_get_resource_no_token_raises():
    """get_resource raises RuntimeError immediately when token is empty."""
    import pangolin_connector

    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_resource(ctx, 5)


# ---------------------------------------------------------------------------
# cleanup_old_ips — multiple resources per IP
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# http_json — error handling
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# self_check — startup validation
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# /update — non-global IP rejection
# ---------------------------------------------------------------------------


def test_update_endpoint_non_global_ip_400(monkeypatch, temp_state_file):
    """/update?ip= with a private IP → 400."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update?ip=192.168.1.1")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 400
        assert "application/json" in resp.getheader("Content-Type", "")
        parsed = json.loads(body)
        assert parsed["ok"] is False
        assert parsed["error"]


# ---------------------------------------------------------------------------
# _build_checkin_html — unit tests
# ---------------------------------------------------------------------------

_RESULTS_OK = {
    "pangolin": {"ok": True, "detail": "ok"},
    "crowdsec": {"ok": False, "detail": "disabled"},
}
_RESULTS_FAIL = {
    "pangolin": {"ok": False, "detail": "auth error"},
    "crowdsec": {"ok": False, "detail": "not reached"},
}
_LAST_SEEN_ISO = "2025-01-01T00:00:00+00:00"


def test_checkin_html_success_hero_and_dot():
    """Success path → access hero text and green dot class, details collapsed."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
    )
    assert "<strong>access</strong>" in page
    assert 'class="status-dot">' in page
    assert 'class="status-dot err">' not in page
    assert 'class="status-dot warn">' not in page
    assert 'aria-expanded="false"' in page
    assert 'class="details-body "' in page


def test_checkin_html_warning_hero_and_dot():
    """Warning path (partial failure) → warning hero, warn dot class, details expanded."""
    from request_handler import _build_checkin_html

    partial_results = {
        "pangolin": {"ok": True, "detail": "ok"},
        "crowdsec": {"ok": False, "detail": "failed"},
    }
    page = _build_checkin_html(
        ip="1.2.3.4",
        results=partial_results,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=True,
    )
    assert "but security rules failed" in page
    assert 'class="status-dot warn">' in page
    assert 'aria-expanded="true"' in page
    assert 'class="details-body open"' in page


def test_checkin_html_failure_hero_and_dot():
    """Failure path → 'may not work' hero text, error dot class, details expanded."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_FAIL,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
    )
    assert "may not work" in page
    assert 'class="status-dot err">' in page
    assert 'aria-expanded="true"' in page
    assert 'class="details-body open"' in page


def test_checkin_html_crowdsec_disabled_badge():
    """crowdsec_enabled=False → 'Not enabled' badge rendered."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
    )
    assert "Not enabled" in page


def test_checkin_html_crowdsec_ok_badge():
    """crowdsec_enabled=True and ok=True → both Pangolin and CrowdSec show 'Added'."""
    from request_handler import _build_checkin_html

    results = {
        "pangolin": {"ok": True, "detail": "ok"},
        "crowdsec": {"ok": True, "detail": "ok"},
    }
    page = _build_checkin_html(
        ip="1.2.3.4",
        results=results,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=True,
    )
    assert page.count('<span class="badge ok">Added</span>') == 2


def test_checkin_html_resource_link_rendered():
    """Resource with fullDomain → anchor href present in output."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
        resources=[
            {"name": "Jellyfin", "fullDomain": "jellyfin.example.com", "ssl": True}
        ],
    )
    assert 'href="https://jellyfin.example.com"' in page
    assert "Jellyfin" in page


def test_checkin_html_resource_name_xss_escaped():
    """Resource name with HTML special chars → escaped in output, raw tag absent."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
        resources=[
            {
                "name": "<script>alert(1)</script>",
                "fullDomain": "t.example.com",
                "ssl": True,
            }
        ],
    )
    assert "<script>alert(1)</script>" not in page  # raw injection must not appear
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page  # must be escaped


def test_checkin_html_malformed_last_seen_shows_unknown():
    """Malformed last_seen → expiry falls back to 'unknown'."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen="not-a-datetime",
        crowdsec_enabled=False,
    )
    assert "unknown" in page


def test_checkin_html_site_name_present():
    """site_name set → appears in the sub div under the header."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
        site_name="My Home",
    )
    assert 'class="sub"' in page
    assert "My Home" in page


def test_checkin_html_site_name_absent():
    """site_name empty → no sub div rendered."""
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
        site_name="",
    )
    assert 'class="sub"' not in page


# ---------------------------------------------------------------------------
# _build_error_html — unit tests
# ---------------------------------------------------------------------------


def test_build_error_html_site_name_in_footer():
    """site_name set → name and middot separator appear in footer."""
    from request_handler import _build_error_html

    page = _build_error_html("Oops", "Something broke", site_name="My Site")
    assert "My Site" in page
    assert "&middot;" in page


def test_build_error_html_no_site_name_footer():
    """site_name empty → no separator in footer, only 'Requests are logged'."""
    from request_handler import _build_error_html

    page = _build_error_html("Oops", "Something broke", site_name="")
    assert "Requests are logged" in page
    assert "&middot;" not in page


def test_build_error_html_title_injected_as_is():
    """title is injected into the page without HTML-escaping — documents current behaviour."""
    from request_handler import _build_error_html

    page = _build_error_html("Error <b>type</b>", "details")
    assert "<b>type</b>" in page


# ---------------------------------------------------------------------------
# _format_retention — pure function
# ---------------------------------------------------------------------------


def test_format_retention_1_minute_singular():
    from request_handler import _format_retention

    assert _format_retention(1) == "1 minute"


def test_format_retention_plural_minutes():
    from request_handler import _format_retention

    assert _format_retention(59) == "59 minutes"


def test_format_retention_non_divisible_by_60_stays_minutes():
    from request_handler import _format_retention

    assert _format_retention(90) == "90 minutes"


def test_format_retention_1_hour_singular():
    from request_handler import _format_retention

    assert _format_retention(60) == "1 hour"


def test_format_retention_plural_hours():
    from request_handler import _format_retention

    assert _format_retention(120) == "2 hours"


def test_format_retention_non_divisible_by_1440_uses_hours():
    from request_handler import _format_retention

    assert _format_retention(1500) == "25 hours"


def test_format_retention_1_day_singular():
    from request_handler import _format_retention

    assert _format_retention(1440) == "1 day"


def test_format_retention_plural_days():
    from request_handler import _format_retention

    assert _format_retention(43200) == "30 days"


def test_format_retention_2_minutes():
    from request_handler import _format_retention

    assert _format_retention(2) == "2 minutes"


# ---------------------------------------------------------------------------
# _load_template — token substitution
# ---------------------------------------------------------------------------


def test_load_template_substitutes_single_token(tmp_path, monkeypatch):
    import request_handler

    (tmp_path / "t.html").write_text("hello {{NAME}}", encoding="utf-8")
    monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(tmp_path))
    from request_handler import _load_template

    assert _load_template("t.html", {"NAME": "world"}) == "hello world"


def test_load_template_substitutes_multiple_tokens(tmp_path, monkeypatch):
    import request_handler

    (tmp_path / "t.html").write_text("{{A}} and {{B}}", encoding="utf-8")
    monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(tmp_path))
    from request_handler import _load_template

    assert _load_template("t.html", {"A": "foo", "B": "bar"}) == "foo and bar"


def test_load_template_unknown_placeholder_left_intact(tmp_path, monkeypatch):
    import request_handler

    (tmp_path / "t.html").write_text("{{UNKNOWN}}", encoding="utf-8")
    monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(tmp_path))
    from request_handler import _load_template

    assert "{{UNKNOWN}}" in _load_template("t.html", {})


def test_load_template_empty_value_replaces_token(tmp_path, monkeypatch):
    import request_handler

    (tmp_path / "t.html").write_text("before{{X}}after", encoding="utf-8")
    monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(tmp_path))
    from request_handler import _load_template

    assert _load_template("t.html", {"X": ""}) == "beforeafter"


# ---------------------------------------------------------------------------
# _render_resource_rows — link generation and XSS escaping
# ---------------------------------------------------------------------------


def test_render_resource_rows_empty_list_returns_empty():
    from request_handler import _render_resource_rows

    assert _render_resource_rows([], overall_ok=True) == ""


def test_render_resource_rows_overall_not_ok_returns_empty():
    from request_handler import _render_resource_rows

    rows = [{"name": "Jellyfin", "fullDomain": "j.example.com", "ssl": True}]
    assert _render_resource_rows(rows, overall_ok=False) == ""


def test_render_resource_rows_https_when_ssl_true():
    from request_handler import _render_resource_rows

    result = _render_resource_rows(
        [{"name": "Jellyfin", "fullDomain": "j.example.com", "ssl": True}],
        overall_ok=True,
    )
    assert 'href="https://j.example.com"' in result


def test_render_resource_rows_http_when_ssl_false():
    from request_handler import _render_resource_rows

    result = _render_resource_rows(
        [{"name": "Jellyfin", "fullDomain": "j.example.com", "ssl": False}],
        overall_ok=True,
    )
    assert 'href="http://j.example.com"' in result


def test_render_resource_rows_xss_in_name_escaped():
    from request_handler import _render_resource_rows

    result = _render_resource_rows(
        [
            {
                "name": "<script>alert(1)</script>",
                "fullDomain": "t.example.com",
                "ssl": True,
            }
        ],
        overall_ok=True,
    )
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


def test_render_resource_rows_xss_in_domain_escaped():
    from request_handler import _render_resource_rows

    result = _render_resource_rows(
        [{"name": "Evil", "fullDomain": 'evil.com"><script>', "ssl": True}],
        overall_ok=True,
    )
    assert "<script>" not in result


def test_render_resource_rows_missing_domain_skipped():
    from request_handler import _render_resource_rows

    result = _render_resource_rows(
        [
            {"name": "NoDomain", "fullDomain": "", "ssl": True},
            {"name": "Valid", "fullDomain": "v.example.com", "ssl": True},
        ],
        overall_ok=True,
    )
    assert "NoDomain" not in result
    assert 'href="https://v.example.com"' in result


def test_render_resource_rows_multiple_resources():
    from request_handler import _render_resource_rows

    result = _render_resource_rows(
        [
            {"name": "Jellyfin", "fullDomain": "j.example.com", "ssl": True},
            {"name": "Radarr", "fullDomain": "r.example.com", "ssl": True},
        ],
        overall_ok=True,
    )
    assert 'href="https://j.example.com"' in result
    assert 'href="https://r.example.com"' in result


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


def test_dashboard_redirection_and_button(temp_state_file, monkeypatch):
    import importlib

    import app as _app

    test_ip = "1.2.3.4"

    # Scenario 1: REDIRECT_TO_LAUNCHER = False (default), check-in succeeds.
    # Should return 200 OK and HTML containing the Resource Launcher button and resource links.
    monkeypatch.setenv("PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setenv("ORG_ID", "example-org")
    monkeypatch.setenv("PANGOLIN_URL", "https://pangolin.example.com")
    monkeypatch.setenv("REDIRECT_TO_LAUNCHER", "false")
    monkeypatch.setenv("REDIRECT_DELAY_SECONDS", "3")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    app = importlib.reload(_app)

    state_mock = {"succeed": True}

    def fake_filter(ctx, org_id, user_id, username):
        if state_mock["succeed"]:
            return [
                {
                    "resourceId": 5,
                    "name": "Jellyfin",
                    "fullDomain": "d.com",
                    "ssl": True,
                }
            ]
        else:
            raise RuntimeError("Authorization failed")

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_filter)

    class FakeTarget:
        name = "pangolin"

        def add_ip(self, ip, resource_ids=None):
            pass

        def ensure_ready(self):
            pass

    monkeypatch.setattr(app, "TARGETS", [FakeTarget()])

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            "Remote-User-Id": "user-alice",
            "Remote-User": "alice",
            "Accept": "text/html",
        }
        proxy_request(conn, "GET", "/check.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 200
        assert "Open Resource Launcher" not in data
        assert "https://pangolin.example.com/example-org" not in data
        assert "Open Jellyfin" in data

    # Scenario 2a: REDIRECT_TO_LAUNCHER = True, REDIRECT_DELAY_SECONDS = 0, check-in succeeds.
    # Should redirect immediately with 302 to the dashboard URL.
    monkeypatch.setenv("REDIRECT_TO_LAUNCHER", "true")
    monkeypatch.setenv("REDIRECT_DELAY_SECONDS", "0")
    app = importlib.reload(_app)

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_filter)
    monkeypatch.setattr(app, "TARGETS", [FakeTarget()])

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            "Remote-User-Id": "user-alice",
            "Remote-User": "alice",
            "Accept": "text/html",
        }
        proxy_request(conn, "GET", "/check.png", headers=headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 302
        assert resp.getheader("Location") == "https://pangolin.example.com/example-org"

    # Scenario 2b: REDIRECT_TO_LAUNCHER = True, REDIRECT_DELAY_SECONDS = 3, check-in succeeds.
    # Should return 200 OK with redirection notice, countdown script, launcher button,
    # but NO individual resource links (Open Jellyfin).
    monkeypatch.setenv("REDIRECT_TO_LAUNCHER", "true")
    monkeypatch.setenv("REDIRECT_DELAY_SECONDS", "3")
    app = importlib.reload(_app)

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_filter)
    monkeypatch.setattr(app, "TARGETS", [FakeTarget()])

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            "Remote-User-Id": "user-alice",
            "Remote-User": "alice",
            "Accept": "text/html",
        }
        proxy_request(conn, "GET", "/check.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 200
        assert "Redirecting to Resource Launcher in" in data
        assert "countdown" in data
        assert "window.location.href" in data
        assert "Open Resource Launcher" in data
        assert "Open Jellyfin" not in data

    # Scenario 3: REDIRECT_TO_LAUNCHER = True, check-in fails (Pangolin error).
    # Should NOT redirect, should return 200 OK with details page.
    state_mock["succeed"] = False
    with app._api_rate_limit_lock:
        app._api_rate_limit.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            "Remote-User-Id": "user-alice",
            "Remote-User": "alice",
            "Accept": "text/html",
        }
        proxy_request(conn, "GET", "/check.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 200
        assert "Authorization failed" in data
        assert "Open Resource Launcher" not in data
        assert "Redirecting to Resource Launcher" not in data

    # Scenario 4: REDIRECT_TO_LAUNCHER = True, Pangolin succeeds, but CrowdSec is enabled and fails.
    # Should NOT redirect, should return 200 OK showing CrowdSec failure details.
    state_mock["succeed"] = True
    import crowdsec_connector

    monkeypatch.setattr(crowdsec_connector, "CROWDSEC_ENABLED", True)
    monkeypatch.setenv("CROWDSEC_ENABLED", "true")
    monkeypatch.setenv("REDIRECT_TO_LAUNCHER", "true")
    monkeypatch.setenv("REDIRECT_DELAY_SECONDS", "3")
    app = importlib.reload(_app)

    monkeypatch.setattr(app, "pg_filter_resources_for_user", fake_filter)

    # Mock CrowdSec failure by letting CrowdSecTarget raise an error
    class FailingCrowdSecTarget:
        name = "crowdsec"

        def add_ip(self, ip, resource_ids=None):
            raise RuntimeError("crowdsec command failed")

        def ensure_ready(self):
            pass

    monkeypatch.setattr(app, "TARGETS", [FakeTarget(), FailingCrowdSecTarget()])
    with app._api_rate_limit_lock:
        app._api_rate_limit.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            "Remote-User-Id": "user-alice",
            "Remote-User": "alice",
            "Accept": "text/html",
        }
        proxy_request(conn, "GET", "/check.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 200
        assert "crowdsec command failed" in data
        assert "Redirecting to Resource Launcher" not in data


# ---------------------------------------------------------------------------
# Phase 1 / Batch 3 — HTML/JS/Template & Redirect Hardening
# ---------------------------------------------------------------------------


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


def test_load_template_single_pass_blocks_second_order_expansion(tmp_path, monkeypatch):
    import request_handler

    (tmp_path / "t.html").write_text("{{A}} | {{B}} | {{UNKNOWN}}", encoding="utf-8")
    monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(tmp_path))

    rendered = request_handler._load_template(
        "t.html",
        {"A": "{{B}} \\1 literal", "B": "expanded"},
    )
    assert rendered == "{{B}} \\1 literal | expanded | {{UNKNOWN}}"


def test_build_checkin_html_blocks_second_order_token_expansion():
    from request_handler import _build_checkin_html

    results = {
        "pangolin": {"ok": False, "detail": "prefix {{IP}} {{LAST_SEEN}}"},
        "crowdsec": {"ok": False, "detail": "disabled"},
    }
    page = _build_checkin_html(
        ip="203.0.113.10",
        results=results,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
        site_name="Site {{IP}}",
    )
    assert '<div class="sub">Site {{IP}}</div>' in page
    assert "prefix {{IP}} {{LAST_SEEN}}" in page


@pytest.mark.parametrize(
    "valid_domain",
    [
        "jellyfin.example.com",
        "jellyfin.example.com:8443",
        "192.0.2.1",
        "192.0.2.1:8080",
        "[2001:db8::1]",
        "[2001:db8::1]:8443",
        "localhost",
    ],
)
def test_render_resource_rows_accepts_valid_domains(valid_domain):
    from request_handler import _render_resource_rows

    rendered = _render_resource_rows(
        [{"name": "App", "fullDomain": valid_domain, "ssl": True}],
        overall_ok=True,
    )
    assert f'href="https://{valid_domain}"' in rendered


@pytest.mark.parametrize(
    "invalid_domain",
    [
        "https://evil.com",
        "evil.com/path",
        "evil.com?q=1",
        "evil.com#frag",
        "user@evil.com",
        "evil.com foo",
        "evil.com\r\n",
        'evil.com"><script>',
        "evil.com:0",
        "evil.com:65536",
        "evil.com:abc",
        "2001:db8::1",
        "[fe80::1%eth0]",
        "999.999.999.999",
    ],
)
def test_render_resource_rows_skips_invalid_domains_with_warning(
    capsys, invalid_domain
):
    from request_handler import _render_resource_rows

    rendered = _render_resource_rows(
        [{"name": "EvilApp", "fullDomain": invalid_domain, "ssl": True}],
        overall_ok=True,
    )
    assert rendered == ""
    out = capsys.readouterr().out
    assert "Skipping resource with invalid fullDomain" in out


def test_checkin_html_static_redirect_attributes_preserve_query_and_backslashes():
    from html.parser import HTMLParser

    from request_handler import _build_checkin_html

    target_url = "https://dashboard.example.com:8443/org?a=1&b=c\\d"
    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
        dashboard_url=target_url,
        redirect_to_launcher=True,
        redirect_delay_seconds=5,
    )

    assert page.count("<script>") == 1
    assert "var url =" not in page
    assert 'url.startsWith("https://")' in page
    assert "countdownEl.textContent" in page

    captured = {}

    class _BannerParser(HTMLParser):
        def handle_starttag(self, tag, attrs):
            attr_map = dict(attrs)
            if tag == "div" and "redirect-banner" in attr_map.get("class", ""):
                captured.update(attr_map)

    _BannerParser().feed(page)
    assert captured.get("data-redirect-url") == target_url
    assert captured.get("data-redirect-delay") == "5"


@pytest.mark.parametrize(
    "bad_url",
    [
        "javascript:alert(1)",
        "http://evil.example.com/org",
        "https://evil.example.com/a\r\nX-Injected: 1",
    ],
)
def test_checkin_html_suppresses_invalid_dashboard_url(capsys, bad_url):
    from request_handler import _build_checkin_html

    page = _build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
        resources=[
            {"name": "Jellyfin", "fullDomain": "jellyfin.example.com", "ssl": True}
        ],
        dashboard_url=bad_url,
        redirect_to_launcher=True,
        redirect_delay_seconds=5,
    )
    assert 'class="redirect-banner"' not in page
    assert "data-redirect-url=" not in page
    assert "Redirecting to Resource Launcher" not in page
    assert "launcher-link" not in page
    assert "Open Resource Launcher" not in page
    assert 'href="https://jellyfin.example.com"' in page
    out = capsys.readouterr().out
    assert "Ignoring invalid dashboard_url" in out


@pytest.mark.parametrize("request_path", ["/check.png", "/update?ip=1.2.3.4"])
@pytest.mark.parametrize(
    "bad_url",
    [
        "javascript:alert(1)",
        "http://evil.example.com/org",
        "https://evil.example.com/a\r\nX-Injected: 1",
    ],
)
def test_handler_refuses_302_redirect_for_invalid_dashboard_url(
    monkeypatch, app_module, capsys, request_path, bad_url
):
    app = app_module

    monkeypatch.setattr(app, "UPDATE_ENDPOINT_ENABLED", True)
    monkeypatch.setattr(app, "REDIRECT_TO_LAUNCHER", True)
    monkeypatch.setattr(app, "REDIRECT_DELAY_SECONDS", 0)
    monkeypatch.setattr(app, "PANGOLIN_DASHBOARD_URL", bad_url)
    monkeypatch.setattr(
        app,
        "add_ip_to_targets",
        lambda ip, remote_user_id="", remote_user="": {
            "pangolin": {"ok": True, "detail": "ok", "enabled": True},
            "crowdsec": {"ok": False, "detail": "disabled", "enabled": False},
            "resources": [
                {
                    "resourceId": 5,
                    "name": "Jellyfin",
                    "fullDomain": "jellyfin.example.com",
                    "ssl": True,
                }
            ],
        },
    )

    handler_cls = app.create_image_request_handler(app._make_image_handler_context())
    with start_server(handler_cls) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(
            conn,
            "GET",
            request_path,
            headers={
                "X-Real-IP": "1.2.3.4",
                "Remote-User-Id": "user-alice",
                "Remote-User": "alice",
                "Accept": "text/html",
            },
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")

    assert resp.status == 200
    assert resp.getheader("Location") is None
    assert 'class="redirect-banner"' not in body
    assert "data-redirect-url=" not in body
    assert "Redirecting to Resource Launcher" not in body
    assert "Open Resource Launcher" not in body
    assert 'href="https://jellyfin.example.com"' in body
    out = capsys.readouterr().out
    assert "Refusing 302 redirect to invalid dashboard_url" in out


def test_build_checkin_html_escapes_ip_tokens(monkeypatch):
    import request_handler

    captured_tokens = {}
    orig_load = request_handler._load_template

    def spy_load(name, tokens):
        captured_tokens.update(tokens)
        return orig_load(name, tokens)

    monkeypatch.setattr(request_handler, "_load_template", spy_load)

    raw_ip = '<script>alert("xss")</script>'
    page = request_handler._build_checkin_html(
        ip=raw_ip,
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
    )

    expected = "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
    assert captured_tokens["IP"] == expected
    assert raw_ip not in page
    assert expected in page


# ---------------------------------------------------------------------------
# Batch 4 — Debug Header Logging, Log Sanitization & /update Fail-Closed JSON
# ---------------------------------------------------------------------------


def test_debug_log_headers_preserves_duplicates_and_redacts_secrets(
    monkeypatch, app_module, capsys
):
    """DEBUG_LOG_HEADERS logs duplicate headers while redacting all secret values."""
    app = app_module
    monkeypatch.setattr(app, "DEBUG_LOG_HEADERS", True)
    handler_cls = app.create_image_request_handler(app._make_image_handler_context())

    with start_server(handler_cls) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("GET", "/checkin.png")
        for name, value in (
            ("X-Proxy-Secret", TEST_PROXY_SECRET),
            ("X-Real-IP", "1.2.3.4"),
            ("Remote-User-Id", "user-1"),
            ("Remote-User-Id", "user-2"),
            ("Cookie", "session=cookie-secret-1"),
            ("Cookie", "other=cookie-secret-2"),
            ("X-Auth-Token", "auth-token-secret"),
            ("X-Api-Key", "api-key-secret"),
            ("X-Custom-Password", "pw-secret"),
        ):
            conn.putheader(name, value)
        conn.endheaders()
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200

    out = capsys.readouterr().out
    assert "[http] headers:" in out
    assert "('Remote-User-Id', 'user-1')" in out
    assert "('Remote-User-Id', 'user-2')" in out
    assert out.count("('Cookie', '<redacted>')") == 2
    assert "('X-Proxy-Secret', '<redacted>')" in out
    assert "('X-Auth-Token', '<redacted>')" in out
    assert "('X-Api-Key', '<redacted>')" in out
    assert "('X-Custom-Password', '<redacted>')" in out
    for secret in (
        TEST_PROXY_SECRET,
        "cookie-secret-1",
        "cookie-secret-2",
        "auth-token-secret",
        "api-key-secret",
        "pw-secret",
    ):
        assert secret not in out


def test_sanitize_for_log_escapes_control_and_unicode_line_separators():
    """sanitize_for_log escapes CR/LF, ASCII controls, and Unicode separators."""
    from request_handler import sanitize_for_log

    assert sanitize_for_log("normal/path?ip=1.2.3.4") == "normal/path?ip=1.2.3.4"
    payload = "a\rb\nc\td\x00e\x1bf\x7fg\u2028h\u2029i"
    expected = "a\\rb\\nc\\td\\x00e\\x1bf\\x7fg\\u2028h\\u2029i"
    assert sanitize_for_log(payload) == expected
    assert sanitize_for_log(12345) == "12345"


def test_log_message_sanitizes_control_chars(capsys):
    """ImageRequestHandler.log_message strips/escapes CRLF and control characters."""
    h = _make_handler_for_ip_test({}, socket_ip="127.0.0.1")
    h.log_message(
        '"%s" %s %s',
        "GET /bad\r\nFAKE_LOG\x1b[31m\x7f\u2028\u2029 HTTP/1.1",
        "400",
        "-",
    )
    out = capsys.readouterr().out
    assert "\r" not in out
    assert "\x1b" not in out
    assert "\x7f" not in out
    assert "\u2028" not in out
    assert "\u2029" not in out
    assert out.count("\n") == 1
    assert "\\r\\nFAKE_LOG\\x1b[31m\\x7f\\u2028\\u2029" in out


def test_handler_logs_sanitize_crlf_in_path_and_query(
    monkeypatch, temp_state_file, capsys
):
    """HTTP error logs sanitize URL-decoded raw_ip and raw self.path control chars."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(
            conn,
            "GET",
            "/update?ip=bad%0d%0aFAKE_LOG%1b%7f%e2%80%a8%e2%80%a9end",
            headers={
                "Remote-User-Id": "uid-1",
                "Remote-User": "alice@example.com",
            },
        )
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 400

    out = capsys.readouterr().out
    assert "\r" not in out
    assert "\x1b" not in out
    assert "\x7f" not in out
    assert "\u2028" not in out
    assert "\u2029" not in out
    assert (
        "[error] Invalid IP address: bad\\r\\nFAKE_LOG\\x1b\\x7f\\u2028\\u2029end"
        in out
    )


def test_handler_direct_do_get_sanitizes_control_chars_in_path_and_headers(
    monkeypatch, app_module, capsys
):
    """Direct handler execution sanitizes control chars in self.path and headers."""
    from email.message import Message
    from io import BytesIO

    app = app_module
    monkeypatch.setattr(app, "UPDATE_ENDPOINT_ENABLED", True)
    handler_cls = app.create_image_request_handler(app._make_image_handler_context())

    def _run_direct(path: str, headers_list: list[tuple[str, str]]):
        h = object.__new__(handler_cls)
        h.path = path
        h.request_version = "HTTP/1.1"
        h.requestline = f"GET {path} HTTP/1.1"
        h.command = "GET"
        h.client_address = ("198.51.100.1", 12345)
        msg = Message()
        for k, v in headers_list:
            msg[k] = v
        h.headers = msg
        h.wfile = BytesIO()
        h.send_response = lambda code, message=None: None
        h.send_header = lambda k, v: None
        h.end_headers = lambda: None
        h.do_GET()

    _run_direct("/secret\r\nFAKE_PATH\x1b\u2028", [])
    _run_direct(
        "/not-an-image\r\nFAKE\u2029",
        [
            ("X-Proxy-Secret", TEST_PROXY_SECRET),
            ("Remote-User-Id", "uid\r\nFAKE"),
            ("Remote-User", "user\x1b\u2028@example.com"),
        ],
    )

    out = capsys.readouterr().out
    assert "\r" not in out
    assert "\x1b" not in out
    assert "\u2028" not in out
    assert "\u2029" not in out
    assert "FAKE_PATH" in out
    assert "\\r\\nFAKE_PATH\\x1b\\u2028" in out
    assert "uid\\r\\nFAKE" in out
    assert "user\\x1b\\u2028@example.com" in out


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


def test_update_json_success_with_crowdsec_enabled_and_additive(
    monkeypatch, temp_state_file
):
    """/update JSON returns 200 with crowdsec status whether CrowdSec succeeds or fails."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    auth_headers = _configure_authorized_update_user(monkeypatch, app)

    class _FakeCrowdSecTarget(app.Target):
        name = "crowdsec"

        def __init__(self, should_fail: bool):
            self._should_fail = should_fail

        def add_ip(self, ip: str, resource_ids=None) -> None:
            if self._should_fail:
                raise RuntimeError("cscli failed")

    monkeypatch.setattr(app, "CROWDSEC_ENABLED", True)
    monkeypatch.setattr(app, "RATE_LIMIT_SECONDS", 0)
    monkeypatch.setattr(
        app,
        "TARGETS",
        [app.PangolinTarget(app.make_pangolin_context), _FakeCrowdSecTarget(False)],
    )
    handler_cls = app.create_image_request_handler(app._make_image_handler_context())
    with start_server(handler_cls) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update?ip=1.2.3.4", headers=auth_headers)
        resp = conn.getresponse()
        body = json.loads(resp.read())
        assert resp.status == 200
        assert body == {
            "ok": True,
            "ip": "1.2.3.4",
            "retention_minutes": app.RETENTION_MINUTES,
            "pangolin": {"ok": True},
            "crowdsec": {"ok": True, "enabled": True},
        }

    # CrowdSec failure does not fail Pangolin /update response
    monkeypatch.setattr(
        app,
        "TARGETS",
        [app.PangolinTarget(app.make_pangolin_context), _FakeCrowdSecTarget(True)],
    )
    handler_cls = app.create_image_request_handler(app._make_image_handler_context())
    with start_server(handler_cls) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update?ip=1.2.3.5", headers=auth_headers)
        resp = conn.getresponse()
        body = json.loads(resp.read())
        assert resp.status == 200
        assert body == {
            "ok": True,
            "ip": "1.2.3.5",
            "retention_minutes": app.RETENTION_MINUTES,
            "pangolin": {"ok": True},
            "crowdsec": {"ok": False, "enabled": True},
        }


@pytest.mark.parametrize(
    "case_name,header_pairs",
    [
        ("missing_remote_user_id", [("Remote-User", "alice@example.com")]),
        ("missing_remote_user", [("Remote-User-Id", "user-alice")]),
        (
            "duplicate_remote_user_id",
            [
                ("Remote-User-Id", "user-alice"),
                ("Remote-User-Id", "user-alice"),
                ("Remote-User", "alice@example.com"),
            ],
        ),
        (
            "user_not_found",
            [
                ("Remote-User-Id", "user-ghost"),
                ("Remote-User", "ghost@example.com"),
            ],
        ),
        (
            "identity_mismatch",
            [
                ("Remote-User-Id", "user-bob"),
                ("Remote-User", "alice@example.com"),
            ],
        ),
        (
            "empty_authorized_resources",
            [
                ("Remote-User-Id", "user-noaccess"),
                ("Remote-User", "noaccess@example.com"),
            ],
        ),
    ],
)
def test_update_json_returns_403_on_auth_denial(
    monkeypatch, temp_state_file, case_name, header_pairs
):
    """Non-HTML /update returns 403 JSON on auth/access denial with empty resources."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [9])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "query=alice%40example.com" in url:
            return org_users_response(org_user("user-alice", "alice@example.com", [9]))
        if "query=noaccess%40example.com" in url:
            return org_users_response(
                org_user("user-noaccess", "noaccess@example.com", [99])
            )
        if "query=ghost%40example.com" in url:
            return org_users_response()
        if "/resource/9/roles" in url:
            return {"data": {"roles": [{"roleId": 9, "name": "TV"}]}, "success": True}
        if "/resource/9/users" in url:
            return {"data": {"users": []}, "success": True}
        raise AssertionError(f"Unexpected Pangolin call in {case_name}: {method} {url}")

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.putrequest("GET", "/update?ip=1.2.3.4")
        conn.putheader("X-Proxy-Secret", TEST_PROXY_SECRET)
        for name, value in header_pairs:
            conn.putheader(name, value)
        conn.endheaders()
        resp = conn.getresponse()
        body = json.loads(resp.read())

    assert resp.status == 403
    assert "application/json" in resp.getheader("Content-Type", "")
    assert body["ok"] is False
    assert body["ip"] == "1.2.3.4"
    assert body["error"]
    # Intentional pre-auth last_seen audit stamp with empty resources
    with app.state_lock:
        assert app.state["1.2.3.4"]["last_seen"]
        assert app.state["1.2.3.4"]["resources"] == {}


@pytest.mark.parametrize(
    "failure_mode",
    [
        "missing_token",
        "users_http_500",
        "users_success_false",
        "roles_http_500",
        "put_rule_500",
        "unexpected_exception",
    ],
)
def test_update_json_returns_502_on_upstream_failure(
    monkeypatch, temp_state_file, failure_mode
):
    """Non-HTML /update returns 502 JSON on upstream Pangolin or target failure."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [9])
    monkeypatch.setattr(
        app, "PANGOLIN_TOKEN", "" if failure_mode == "missing_token" else "fake-token"
    )

    def fake_http_json(method, url, body=None):
        if "/org/test-org/users" in url:
            if failure_mode == "users_http_500":
                raise RuntimeError("HTTP 500 Internal Server Error")
            if failure_mode == "users_success_false":
                return org_users_response(success=False)
            return org_users_response(org_user("user-alice", "alice@example.com", [9]))
        if "/resource/9/roles" in url:
            if failure_mode == "roles_http_500":
                raise RuntimeError("HTTP 500 Internal Server Error")
            return {"data": {"roles": [{"roleId": 9, "name": "TV"}]}, "success": True}
        if "/resource/9/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith("/resource/9"):
            return {
                "data": {
                    "resourceId": 9,
                    "name": "TV",
                    "fullDomain": "tv.example.com",
                    "ssl": True,
                },
                "success": True,
            }
        if "/rules" in url:
            return {"data": {"rules": []}, "success": True}
        if method == "PUT" and failure_mode == "put_rule_500":
            raise RuntimeError("HTTP 500 Internal Server Error")
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    if failure_mode == "unexpected_exception":
        monkeypatch.setattr(
            app,
            "add_ip_to_targets",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        handler_cls = app.create_image_request_handler(
            app._make_image_handler_context()
        )
    else:
        handler_cls = app.ImageRequestHandler

    with start_server(handler_cls) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(
            conn,
            "GET",
            "/update?ip=1.2.3.4",
            headers={
                "Remote-User-Id": "user-alice",
                "Remote-User": "alice@example.com",
            },
        )
        resp = conn.getresponse()
        body = json.loads(resp.read())

    assert resp.status == 502
    assert "application/json" in resp.getheader("Content-Type", "")
    assert body["ok"] is False
    assert body["ip"] == "1.2.3.4"
    assert body["error"]
    with app.state_lock:
        assert app.state["1.2.3.4"]["resources"] == {}


@pytest.mark.parametrize(
    "path",
    [
        "/update",
        "/update?ip=%3Cscript%3Ealert(1)%3C/script%3E",
        "/update?ip=192.168.1.1",
    ],
)
def test_update_bad_ip_returns_escaped_html_when_accepted(
    monkeypatch, temp_state_file, path
):
    """HTML callers on bad/missing/non-global /update?ip= get escaped HTML 400."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", path, headers={"Accept": "text/html"})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")

    assert resp.status == 400
    assert "text/html" in resp.getheader("Content-Type", "")
    assert "<script>alert(1)</script>" not in body
    if "script" in path:
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body


# ---------------------------------------------------------------------------
# Batch 5: Bounded HTTP concurrency, response hygiene, and graceful shutdown
# ---------------------------------------------------------------------------


def _start_bounded_server(app, handler_cls, *, max_workers=None):
    @contextlib.contextmanager
    def _ctx():
        httpd = app.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), handler_cls, max_workers=max_workers
        )
        port = httpd.server_port
        t = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        t.start()
        try:
            yield (httpd, port)
        finally:
            httpd.shutdown()
            httpd.server_close()
            httpd.join_workers(2.0)
            t.join(timeout=2.0)

    return _ctx()


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

    with _start_bounded_server(app_module, _BlockingHandler, max_workers=2) as (
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

    with _start_bounded_server(app_module, _FlakyHandler, max_workers=1) as (
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

    with _start_bounded_server(app_module, _HoldHandler, max_workers=1) as (
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


def test_image_request_handler_socket_timeout_configured(app_module):
    """ImageRequestHandler enforces a 10-second per-connection socket timeout."""
    assert app_module.ImageRequestHandler.timeout == 10


def test_slowloris_client_times_out_and_releases_worker(app_module):
    """Incomplete request headers time out and free the worker slot."""
    import socket

    class _FastTimeoutHandler(app_module.ImageRequestHandler):
        timeout = 0.2

    with _start_bounded_server(app_module, _FastTimeoutHandler, max_workers=1) as (
        _httpd,
        port,
    ):
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.settimeout(2.0)
            sock.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
            assert sock.recv(1024) == b""

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b"ok"
        conn.close()


def test_server_header_omits_python_and_version(app_module):
    """Server header reports bare 'BannerServer' without Python or version."""
    handler_cls = app_module.ImageRequestHandler
    assert handler_cls.server_version == "BannerServer"
    assert handler_cls.sys_version == ""

    with start_server(handler_cls) as (_httpd, port):
        checks = [
            ("/healthz", {}),
            ("/", {"X-Proxy-Secret": TEST_PROXY_SECRET}),
            ("/unknown", {"X-Proxy-Secret": TEST_PROXY_SECRET}),
            ("/banner.png", {"X-Proxy-Secret": TEST_PROXY_SECRET}),
        ]
        for path, hdrs in checks:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", path, headers=hdrs)
            resp = conn.getresponse()
            resp.read()
            conn.close()
            server_hdr = resp.getheader("Server", "")
            assert server_hdr == "BannerServer"
            assert "Python" not in server_hdr
            assert "1.0" not in server_hdr


@pytest.mark.parametrize(
    ("path", "headers", "expected_status", "expected_body"),
    [
        ("/banner.png", {}, 403, b"Forbidden"),
        ("/", {"X-Proxy-Secret": TEST_PROXY_SECRET}, 403, b"Forbidden"),
        (
            "/update?ip=1.2.3.4",
            {"X-Proxy-Secret": TEST_PROXY_SECRET},
            404,
            b"Not found",
        ),
        ("/nope", {"X-Proxy-Secret": TEST_PROXY_SECRET}, 404, b"Not found"),
    ],
)
def test_bare_403_and_404_responses_have_plain_and_security_headers(
    monkeypatch, temp_state_file, path, headers, expected_status, expected_body
):
    """Bare 403 and 404 responses emit plain text, no-store, and security headers."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=False)
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()

    assert resp.status == expected_status
    assert body == expected_body
    assert resp.getheader("Server") == "BannerServer"
    assert resp.getheader("Content-Type") == "text/plain; charset=utf-8"
    assert resp.getheader("Content-Length") == str(len(expected_body))
    assert (
        resp.getheader("Cache-Control")
        == "no-store, no-cache, must-revalidate, max-age=0"
    )
    assert resp.getheader("Pragma") == "no-cache"
    assert resp.getheader("Expires") == "0"
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    assert resp.getheader("X-Frame-Options") == "DENY"
    assert resp.getheader("Referrer-Policy") == "no-referrer"
    assert resp.getheader("Content-Security-Policy")


def test_send_plain_supports_503_with_extra_headers(app_module):
    """_send_plain emits plain-text 503 with Retry-After and security headers."""

    class _Plain503Handler(app_module.ImageRequestHandler):
        def do_GET(self):
            self._send_plain(
                503,
                "Service Unavailable",
                extra_headers=(("Retry-After", "5"),),
            )

    with start_server(_Plain503Handler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()

    assert resp.status == 503
    assert body == b"Service Unavailable"
    assert resp.getheader("Retry-After") == "5"
    assert resp.getheader("Server") == "BannerServer"
    assert resp.getheader("Content-Type") == "text/plain; charset=utf-8"
    assert resp.getheader("Content-Length") == str(len(b"Service Unavailable"))
    assert (
        resp.getheader("Cache-Control")
        == "no-store, no-cache, must-revalidate, max-age=0"
    )
    assert resp.getheader("Pragma") == "no-cache"
    assert resp.getheader("Expires") == "0"
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    assert resp.getheader("X-Frame-Options") == "DENY"
    assert resp.getheader("Referrer-Policy") == "no-referrer"
    assert resp.getheader("Content-Security-Policy")


def test_healthz_and_favicon_headers(app_module):
    """/healthz and /favicon.ico emit Cache-Control: no-store and nosniff."""
    with start_server(app_module.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz")
        health_resp = conn.getresponse()
        health_body = health_resp.read()

        conn.request("GET", "/favicon.ico")
        fav_resp = conn.getresponse()
        fav_body = fav_resp.read()
        conn.close()

    assert health_resp.status == 200
    assert health_body == b"ok"
    assert health_resp.getheader("Cache-Control") == "no-store"
    assert health_resp.getheader("X-Content-Type-Options") == "nosniff"
    assert health_resp.getheader("Server") == "BannerServer"

    assert fav_resp.status == 204
    assert fav_body == b""
    assert fav_resp.getheader("Cache-Control") == "no-store"
    assert fav_resp.getheader("X-Content-Type-Options") == "nosniff"
    assert fav_resp.getheader("Server") == "BannerServer"


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


# ---------------------------------------------------------------------------
# Phase 2 / Batch 7 — Cleanup TOCTOU, rate-limit cache, durable persistence
# ---------------------------------------------------------------------------


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
    monkeypatch.setattr(app, "http_json", _standard_fake_http_json)

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
    monkeypatch.setattr(app, "http_json", _standard_fake_http_json)
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


# ---------------------------------------------------------------------------
# Phase 4 / Batch 10 — Deduplication, Template Caching & Config Validation
# ---------------------------------------------------------------------------


def test_build_checkin_html_details_label_by_status():
    """CrowdSec-warning and Pangolin-failure states show 'What went wrong?'."""
    from request_handler import _build_checkin_html

    full_ok = _build_checkin_html(
        ip="1.2.3.4",
        results={
            "pangolin": {"ok": True, "detail": "ok"},
            "crowdsec": {"ok": True, "detail": "ok"},
        },
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=True,
    )
    assert "Technical details" in full_ok
    assert "What went wrong?" not in full_ok

    crowdsec_warn = _build_checkin_html(
        ip="1.2.3.4",
        results={
            "pangolin": {"ok": True, "detail": "ok"},
            "crowdsec": {"ok": False, "detail": "cscli error"},
        },
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=True,
    )
    assert "status-dot warn" in crowdsec_warn
    assert "What went wrong?" in crowdsec_warn
    assert "Technical details" not in crowdsec_warn

    pangolin_fail = _build_checkin_html(
        ip="1.2.3.4",
        results={
            "pangolin": {"ok": False, "detail": "upstream error"},
            "crowdsec": {"ok": False, "detail": "not reached"},
        },
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
    )
    assert "status-dot err" in pangolin_fail
    assert "What went wrong?" in pangolin_fail
    assert "Technical details" not in pangolin_fail


def test_templates_interpolate_base_css_and_cache_by_dir(tmp_path, monkeypatch):
    """_base.css is lazily interpolated and raw template reads cache per (_TEMPLATE_DIR, name)."""
    import builtins

    import request_handler

    checkin_html = request_handler._build_checkin_html(
        ip="1.2.3.4",
        results=_RESULTS_OK,
        retention_minutes=1440,
        last_seen=_LAST_SEEN_ISO,
        crowdsec_enabled=False,
    )
    error_html = request_handler._build_error_html("Bad request", "Invalid input")
    for page in (checkin_html, error_html):
        assert "{{BASE_CSS}}" not in page
        assert "--accent:" in page
        assert "@keyframes rise" in page

    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_c = tmp_path / "c"
    dir_a.mkdir()
    dir_b.mkdir()
    dir_c.mkdir()
    (dir_a / "t.html").write_text("from-a {{X}}", encoding="utf-8")
    (dir_b / "t.html").write_text("from-b {{X}}", encoding="utf-8")
    (dir_c / "_base.css").write_text("body { color: red; }", encoding="utf-8")
    (dir_c / "t.html").write_text("<style>{{BASE_CSS}}</style>{{X}}", encoding="utf-8")

    request_handler._read_template_file.cache_clear()
    try:
        opened: list[str] = []
        orig_open = builtins.open

        def spy_open(file, *args, **kwargs):
            opened.append(str(file))
            return orig_open(file, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", spy_open)

        monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(dir_a))
        assert request_handler._load_template("t.html", {"X": "1"}) == "from-a 1"
        assert request_handler._load_template("t.html", {"X": "2"}) == "from-a 2"
        assert len(opened) == 1

        monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(dir_b))
        assert request_handler._load_template("t.html", {"X": "3"}) == "from-b 3"
        assert len(opened) == 2

        monkeypatch.setattr(request_handler, "_TEMPLATE_DIR", str(dir_c))
        assert (
            request_handler._load_template("t.html", {"X": "4"})
            == "<style>body { color: red; }</style>4"
        )
        assert len(opened) == 4
    finally:
        request_handler._read_template_file.cache_clear()


def test_update_html_calls_now_utc_iso_once(monkeypatch, temp_state_file):
    """/update HTML check-in stamps state and renders expiry using a single now_utc_iso() call."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    now_calls: list[str] = []
    fixed_iso = "2026-01-02T03:04:05+00:00"

    def spy_now_utc_iso() -> str:
        now_calls.append(fixed_iso)
        return fixed_iso

    monkeypatch.setattr(app, "now_utc_iso", spy_now_utc_iso)
    monkeypatch.setattr(
        app,
        "add_ip_to_targets",
        lambda _ip, remote_user_id="", remote_user="": {
            "pangolin": {"ok": True, "detail": "ok"},
            "crowdsec": {"ok": False, "detail": "disabled", "enabled": False},
            "resources": [],
        },
    )
    handler_cls = app.create_image_request_handler(app._make_image_handler_context())

    with start_server(handler_cls) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(
            conn,
            "GET",
            "/update?ip=1.2.3.4",
            headers={
                "Remote-User-Id": "user-alice",
                "Remote-User": "alice@example.com",
                "Accept": "text/html",
            },
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")

    assert resp.status == 200
    assert len(now_calls) == 1
    assert app.state["1.2.3.4"]["last_seen"] == fixed_iso
    assert fixed_iso in body


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
        app = _reload_app_and_dependencies()
        with pytest.raises(RuntimeError, match=env_var):
            app.self_check()
    finally:
        monkeypatch.delenv(env_var, raising=False)
        _reload_app_and_dependencies()


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
