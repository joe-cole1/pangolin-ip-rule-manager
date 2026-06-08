import contextlib
import http.client
import importlib
import threading

import pytest


@contextlib.contextmanager
def start_server(handler_cls):
    from http.server import HTTPServer

    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_port

    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
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


@pytest.fixture
def app_module(monkeypatch, temp_state_file):
    # Ensure env is set before import
    monkeypatch.setenv("PANGOLIN_TOKEN", "")  # avoid network calls in ensure_ip_rule
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    # Import or reload module to apply env
    if "app" in globals():
        import app as _app
        app = importlib.reload(_app)
    else:
        import app  # type: ignore
    # Reset runtime state
    with app.state_lock:
        app.state.clear()
    with app.state_lock:
        app.rules_cache.clear()
    return app


def test_banner_serves_png_and_updates_state(app_module):
    app = app_module

    test_ip = "1.2.3.4"

    with start_server(app.ImageRequestHandler) as (httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            # Remote-User is optional; include to ensure logging path works
            "Remote-User": "alice",
        }
        conn.request("GET", "/anything-can-work-123.png", headers=headers)
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
        return {"data": {"rules": [
            {"match": "IP", "value": "9.8.7.6"},
            {"match": "IP", "value": "1.2.3.4"},
        ]}}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    # First call should hit http_json
    s1 = app._get_ip_set_for_resource_cached(5)
    assert "9.8.7.6" in s1
    assert calls["count"] == 1

    # Second call within TTL should use cache
    s2 = app._get_ip_set_for_resource_cached(5)
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
            "resources": {"3": {"created_by_us": True}}
        }

    # Do not perform real HTTP calls for deletion; pretend success
    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", lambda ip, rid: True)

    app.cleanup_old_ips()

    with app.state_lock:
        assert old_ip not in app.state


def test_gif_serves_gif_and_updates_state(app_module):
    app = app_module

    test_ip = "6.7.8.9"

    with start_server(app.ImageRequestHandler) as (httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
        }
        conn.request("GET", "/beacon.gif", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == app.BANNER_GIF

    # state should have been updated for the real ip
    with app.state_lock:
        assert test_ip in app.state


def test_invalid_paths_denied(app_module):
    app = app_module

    with start_server(app.ImageRequestHandler) as (httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)

        # Test root path
        conn.request("GET", "/")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403

        # Test path without file extension
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/some-random-path")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 404


def test_cleanup_longer_scenario_mixed_outcomes(monkeypatch, app_module):
    app = app_module

    # Expire old IPs, keep one fresh
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    ip_removed = "1.1.1.1"             # created_by_us=True, delete succeeds -> fully removed
    ip_delete_failed = "2.2.2.2"       # created_by_us=True, delete fails -> remains in state
    ip_not_created = "3.3.3.3"         # created_by_us=False -> never attempted, remains
    ip_fresh = "4.4.4.4"               # not expired -> remains

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
        pytest.fail("delete_ip_rule_if_created_by_us must not be called for non-created rules")

    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", delete_should_not_be_called)
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
    import app as _app
    return importlib.reload(_app)


def test_update_endpoint_enabled_adds_arbitrary_ip(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/update?ip=1.2.3.4")
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert b'"ok":true' in data
        assert b'"ip":"1.2.3.4"' in data

    with app.state_lock:
        assert "1.2.3.4" in app.state
        assert "last_seen" in app.state["1.2.3.4"]


def test_update_endpoint_disabled_returns_404(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=False)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/update?ip=1.2.3.4")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 404


def test_update_endpoint_missing_ip_param_400(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/update")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 400


def test_update_endpoint_invalid_ip_400(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/update?ip=999.999.999.999")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 400


def test_update_endpoint_ipv6_success(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    ipv6 = "2606:4700:4700::1111"
    encoded = "2606%3A4700%3A4700%3A%3A1111"

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"/update?ip={encoded}")
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert f'"ip":"{ipv6}"'.encode() in data
    with app.state_lock:
        assert ipv6 in app.state


def test_update_endpoint_last_seen_updates(monkeypatch, temp_state_file):
    import time as _time
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    ip = "5.6.7.8"
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"/update?ip={ip}")
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
        conn.request("GET", f"/update?ip={ip}")
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
        conn.request("GET", "/update?ip=1.2.3.4", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert b"text/html" in resp.getheader("Content-Type", "").encode()
        assert b"Network Check-in" in data
        assert b"1.2.3.4" in data


def test_add_ip_to_targets_fails_closed_without_remote_user(app_module):
    """No targets should be touched when Remote-User is absent."""
    app = app_module
    results = app.add_ip_to_targets("1.2.3.4", remote_user="")
    assert results["pangolin"]["ok"] is False
    assert "Remote-User" in results["pangolin"]["detail"]
    assert results["crowdsec"]["detail"] == "not reached"


def test_add_ip_to_targets_intersection_filters_by_role(monkeypatch, app_module):
    """Only resources where the user's role matches should be whitelisted."""
    app = app_module

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5, 6])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "user-by-username" in url:
            return {"data": {"userId": "user-denise", "roleIds": [5]}, "success": True, "error": False}
        if "/resource/5/roles" in url:
            return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
        if "/resource/6/roles" in url:
            return {"data": {"roles": [{"roleId": 1, "name": "Admin"}]}, "success": True}
        if "/resource/5/users" in url:
            return {"data": {"users": []}, "success": True}
        if "/resource/6/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith("/resource/5"):
            return {"data": {"resourceId": 5, "name": "Jellyfin",
                             "fullDomain": "jellyfin.example.com", "ssl": True}, "success": True}
        if "/rules" in url:
            return {"data": {"rules": []}}
        if method == "PUT":
            return {"success": True, "data": {"rule": {"ruleId": 99}}}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets("1.2.3.4", remote_user="denise@example.com")

    assert results["pangolin"]["ok"] is True
    assert "resources" in results, "results should include resource metadata"
    assert len(results["resources"]) == 1, "only resource 5 should be authorised"
    assert results["resources"][0]["name"] == "Jellyfin"
    assert results["resources"][0]["fullDomain"] == "jellyfin.example.com"

    with app.state_lock:
        rec = app.state.get("1.2.3.4", {})
        state_resources = rec.get("resources", {})
        assert "5" in state_resources, "resource 5 should be whitelisted (role matches)"
        assert "6" not in state_resources, "resource 6 should be skipped (role mismatch)"


import time as _time_mod


def _reload_app_with_crowdsec(monkeypatch, temp_state_file):
    """Reload app with CrowdSec enabled so TARGETS includes CrowdSecTarget."""
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.setenv("CROWDSEC_ENABLED", "true")
    import app as _app
    return importlib.reload(_app)


def _standard_fake_http_json(method, url, body=None):
    """Shared fake http_json for resource 5 with roleId 5 — used in CrowdSec tests."""
    if "user-by-username" in url:
        return {"data": {"userId": "user-abc", "roleIds": [5]}, "success": True, "error": False}
    if "/resource/5/roles" in url:
        return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
    if "/resource/5/users" in url:
        return {"data": {"users": []}, "success": True}
    if url.endswith("/resource/5"):
        return {"data": {"resourceId": 5, "name": "Jellyfin",
                         "fullDomain": "jellyfin.example.com", "ssl": True}, "success": True}
    if "/rules" in url:
        return {"data": {"rules": []}}
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
        if "user-by-username" in url:
            # User has roleId 99 which matches no resource, and is not directly assigned
            return {"data": {"userId": "user-nobody", "roleIds": [99]}, "success": True, "error": False}
        if "/resource/5/roles" in url:
            # Resource 5 only allows roleId 5
            return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
        if "/resource/5/users" in url:
            # User is not directly assigned either
            return {"data": {"users": []}, "success": True}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    results = app.add_ip_to_targets("1.2.3.4", remote_user="nobody@example.com")

    assert results["pangolin"]["ok"] is False
    assert "not authorised" in results["pangolin"]["detail"]
    assert results["crowdsec"]["detail"] == "not reached"


def test_add_ip_to_targets_fails_closed_user_not_found(monkeypatch, app_module):
    """user-by-username returns no roleIds field (user not in org) — fail-closed."""
    app = app_module

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "user-by-username" in url:
            # No roleIds in response — user not found
            return {"data": {}, "success": False, "error": True}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    results = app.add_ip_to_targets("1.2.3.4", remote_user="ghost@example.com")

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
        if "user-by-username" in url:
            return {"data": {"userId": "user-joe", "roleIds": [5]}, "success": True, "error": False}
        if "/resource/5/roles" in url:
            raise RuntimeError("HTTP 403 Forbidden: key lacks List Allowed Resource Roles permission")
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")

    assert results["pangolin"]["ok"] is False
    assert "authorization failed" in results["pangolin"]["detail"].lower()
    assert results["crowdsec"]["detail"] == "not reached"
    # No state entry should have been written
    with app.state_lock:
        assert "1.2.3.4" not in app.state


def test_add_ip_to_targets_fails_closed_on_resource_metadata_error(monkeypatch, app_module):
    """get_resource raises after successful role intersection — fail-closed, no rule created."""
    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "user-by-username" in url:
            return {"data": {"userId": "user-joe", "roleIds": [5]}, "success": True, "error": False}
        if "/resource/5/roles" in url:
            return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
        if "/resource/5/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith("/resource/5"):
            raise RuntimeError("HTTP 403 Forbidden: key lacks Get Resource permission")
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")

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
        if "user-by-username" in url:
            return {"data": {"userId": "user-joe", "roleIds": [5]}, "success": True, "error": False}
        if "/resource/5/roles" in url:
            return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
        if "/resource/5/users" in url:
            return {"data": {"users": []}, "success": True}
        if url.endswith("/resource/5"):
            return {"data": {"resourceId": 5, "name": "Jellyfin",
                             "fullDomain": "jellyfin.example.com", "ssl": True}, "success": True}
        if "/rules" in url:
            return {"data": {"rules": []}}
        if method == "PUT":
            raise RuntimeError("HTTP 500 Internal Server Error: rule creation failed")
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")

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

    results = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")

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

    results = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")

    assert results["pangolin"]["ok"] is True, "Pangolin should succeed regardless of CrowdSec"
    assert results["crowdsec"]["ok"] is False
    assert "cscli" in results["crowdsec"]["detail"]


# ---------------------------------------------------------------------------
# Tests for authorisation logic and passthrough header removal
# ---------------------------------------------------------------------------

def test_add_ip_to_targets_authorised_via_direct_user_assignment(monkeypatch, app_module):
    """User has no matching role but IS directly assigned to the resource — must be authorised."""
    app = app_module
    monkeypatch.setattr(_time_mod, "sleep", lambda _: None)

    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [5])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")

    def fake_http_json(method, url, body=None):
        if "user-by-username" in url:
            # User has a role that does NOT match the resource
            return {"data": {"userId": "user-direct", "roleIds": [99]}, "success": True, "error": False}
        if "/resource/5/roles" in url:
            # Resource only allows roleId 5 — no role match
            return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
        if "/resource/5/users" in url:
            # But user IS directly assigned
            return {"data": {"users": [{"userId": "user-direct", "username": "direct@example.com"}]}, "success": True}
        if url.endswith("/resource/5"):
            return {"data": {"resourceId": 5, "name": "Jellyfin",
                             "fullDomain": "jellyfin.example.com", "ssl": True}, "success": True}
        if "/rules" in url:
            return {"data": {"rules": []}}
        if method == "PUT":
            return {"success": True, "data": {"rule": {"ruleId": 99}}}
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets("1.2.3.4", remote_user="direct@example.com")

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
        if "user-by-username" in url:
            return {"data": {"userId": "user-joe", "roleIds": [5]}, "success": True, "error": False}
        if "/resource/5/roles" in url:
            return {"data": {"roles": [{"roleId": 5, "name": "Jellyfin"}]}, "success": True}
        if "/resource/5/users" in url:
            raise RuntimeError("HTTP 403 Forbidden: key lacks List Resource Users permission")
        return {}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    with app.state_lock:
        app.state.clear()

    results = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")

    assert results["pangolin"]["ok"] is False
    assert "authorization failed" in results["pangolin"]["detail"].lower()
    assert results["crowdsec"]["detail"] == "not reached"
    with app.state_lock:
        assert "1.2.3.4" not in app.state



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

    import app as _app
    # Should not raise — if it does the test fails
    app = importlib.reload(_app)
    assert app is not None


def test_request_without_custom_header_reaches_handler(monkeypatch, temp_state_file):
    """A request with no passthrough header must no longer be rejected with 403.
    It should proceed to the handler logic and return 200 (serving the image or error page).
    Previously the custom header check fired first and returned 403 unconditionally.
    """
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", raising=False)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", raising=False)

    import app as _app
    app = importlib.reload(_app)
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        # No custom header sent — previously this would be 403
        conn.request("GET", "/checkin.png", headers={"X-Real-IP": "1.2.3.4"})
        resp = conn.getresponse()
        _ = resp.read()
        # Must not be 403 — handler logic should have run
        assert resp.status != 403, (
            "Request without custom header should no longer be rejected with 403 "
            "— the passthrough header check has been removed"
        )
        assert resp.status == 200


def test_no_remote_user_fails_closed_no_ip_added(monkeypatch, temp_state_file):
    """Without Remote-User, the identity check fails closed: no IP is added to state,
    and the response is still 200 (error page rendered). This is now the primary gate,
    replacing the removed custom header check.
    """
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", raising=False)
    monkeypatch.delenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", raising=False)

    import app as _app
    app = importlib.reload(_app)
    with app.state_lock:
        app.state.clear()

    test_ip = "9.9.9.9"
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        # No Remote-User header — identity check must fail closed
        conn.request("GET", "/checkin.png", headers={"X-Real-IP": test_ip})
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
    import time as _time

    sleep_calls = []
    original_sleep = _time.sleep

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
