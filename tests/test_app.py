import contextlib
import http.client
import importlib
import threading
import time as _time_mod

import pytest


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
    with app._api_rate_limit_lock:
        app._api_rate_limit.clear()
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
        return {
            "data": {
                "rules": [
                    {"match": "IP", "value": "9.8.7.6"},
                    {"match": "IP", "value": "1.2.3.4"},
                ]
            }
        }

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
            return {
                "data": {"userId": "user-denise", "roleIds": [5]},
                "success": True,
                "error": False,
            }
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
    import app as _app

    return importlib.reload(_app)


def _standard_fake_http_json(method, url, body=None):
    """Shared fake http_json for resource 5 with roleId 5 — used in CrowdSec tests."""
    if "user-by-username" in url:
        return {
            "data": {"userId": "user-abc", "roleIds": [5]},
            "success": True,
            "error": False,
        }
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
            return {
                "data": {"userId": "user-nobody", "roleIds": [99]},
                "success": True,
                "error": False,
            }
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
            return {
                "data": {"userId": "user-joe", "roleIds": [5]},
                "success": True,
                "error": False,
            }
        if "/resource/5/roles" in url:
            raise RuntimeError(
                "HTTP 403 Forbidden: key lacks List Allowed Resource Roles permission"
            )
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
        if "user-by-username" in url:
            return {
                "data": {"userId": "user-joe", "roleIds": [5]},
                "success": True,
                "error": False,
            }
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
            return {
                "data": {"userId": "user-joe", "roleIds": [5]},
                "success": True,
                "error": False,
            }
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
        if "user-by-username" in url:
            # User has a role that does NOT match the resource
            return {
                "data": {"userId": "user-direct", "roleIds": [99]},
                "success": True,
                "error": False,
            }
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
            return {
                "data": {"userId": "user-joe", "roleIds": [5]},
                "success": True,
                "error": False,
            }
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

    results = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")

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

    first = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")
    assert first["pangolin"]["ok"] is True
    calls_after_first = api_calls["count"]
    assert calls_after_first > 0

    second = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")
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

    first = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")
    assert first["pangolin"]["ok"] is True

    # Back-date the cache entry so it looks expired
    with app._api_rate_limit_lock:
        ts, result = app._api_rate_limit["1.2.3.4"]
        app._api_rate_limit["1.2.3.4"] = (ts - 400, result)

    api_calls = {"count": 0}

    def counting_http_json(method, url, body=None):
        api_calls["count"] += 1
        return _standard_fake_http_json(method, url, body)

    monkeypatch.setattr(app, "http_json", counting_http_json)

    second = app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")
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

    app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")
    calls_after_first = api_calls["count"]
    assert calls_after_first > 0

    app.add_ip_to_targets("1.2.3.4", remote_user="joe@example.com")
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


def test_redact_headers_case_insensitive(app_module):
    """Redaction must match header names case-insensitively."""
    app = app_module
    result = app.redact_headers_for_log(
        {
            "authorization": "Bearer lower",
            "AUTHORIZATION": "Bearer upper",
            "Authorization": "Bearer mixed",
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
    """CIDR notation must be accepted and normalised to the network address."""
    import crowdsec_connector

    result = crowdsec_connector._parse_crowdsec_entries_from_json('["10.0.0.5/24"]')
    assert result == {"10.0.0.0"}


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


def _make_handler_for_ip_test(headers: dict, socket_ip: str = "10.20.30.40"):
    """Return an ImageRequestHandler instance with fake headers and socket address.
    Uses object.__new__ to bypass BaseHTTPRequestHandler.__init__ (which requires
    a live socket).
    """
    from request_handler import create_image_request_handler

    ctx = {
        "update_enabled": False,
        "retention_minutes": 1440,
        "crowdsec_enabled": False,
        "site_name": "",
        "state": {},
        "state_lock": threading.Lock(),
        "now_utc_iso": lambda: "2025-01-01T00:00:00+00:00",
        "save_state": lambda: None,
        "add_ip_to_targets": lambda ip, remote_user="": {},
        "banner_png": b"",
        "banner_gif": b"",
        "redact_headers_for_log": lambda h: h,
    }
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

    ctx = _make_pg_ctx(http_json=lambda m, u, b=None: {"data": {"rules": []}})
    assert pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5) is True


def test_delete_rule_success_returns_true():
    """Rule with ruleId=42 found; DELETE issued and succeeds; returns True."""
    import pangolin_connector

    calls = []

    def fake_http(method, url, body=None):
        calls.append((method, url))
        if method == "GET":
            return {
                "data": {"rules": [{"match": "IP", "value": "1.2.3.4", "ruleId": 42}]}
            }
        return {}

    ctx = _make_pg_ctx(http_json=fake_http)
    result = pangolin_connector.delete_ip_rule_if_created_by_us(ctx, "1.2.3.4", 5)
    assert result is True
    assert any("DELETE" == m and "rule/42" in u for m, u in calls), (
        "DELETE must be called with the correct rule URL"
    )


def test_delete_rule_no_rule_id_returns_false():
    """Matching rule has no ruleId field — skipped, deleted_any stays False, returns False."""
    import pangolin_connector

    def fake_http(method, url, body=None):
        if method == "GET":
            return {"data": {"rules": [{"match": "IP", "value": "1.2.3.4"}]}}
        return {}

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
                        {"match": "IP", "value": "1.2.3.4", "ruleId": 10},
                        {"match": "IP", "value": "1.2.3.4", "ruleId": 11},
                    ]
                }
            }
        if method == "DELETE":
            deleted_ids.append(url.split("/")[-1])
        return {}

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
    rules_cache = {5: {"ts": _time_mod.time(), "ip_set": {"1.2.3.4"}}}
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
            return {"data": {"rules": []}}
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
        return {"data": {"rules": [{"match": "IP", "value": "fresh-ip"}]}}

    rules_cache = {5: {"ts": 0, "ip_set": {"stale-ip"}}}
    ctx = _make_pg_ctx(http_json=fake_http, rules_cache=rules_cache)

    result = pangolin_connector.get_ip_set_for_resource_cached(ctx, 5)
    assert "fresh-ip" in result
    assert "stale-ip" not in result
    assert call_count["n"] == 1, "http_json must be called exactly once for the refresh"


# --- no-token guards ---


def test_get_user_info_no_token_raises():
    """get_user_info raises RuntimeError immediately when token is empty."""
    import pangolin_connector

    ctx = _make_pg_ctx(token="")
    with pytest.raises(RuntimeError, match="PANGOLIN_TOKEN"):
        pangolin_connector.get_user_info(ctx, "org1", "user@test.com")


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


def test_http_json_http_error_raises(monkeypatch, app_module):
    """HTTPError from urlopen → RuntimeError with status code and body in message."""
    from io import BytesIO
    from urllib.error import HTTPError as _HTTPError

    app = app_module

    def fake_urlopen(req, timeout=None):
        raise _HTTPError(
            url="https://pg.test/foo",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(b"something went wrong"),
        )

    monkeypatch.setattr(app, "urlopen", fake_urlopen)
    with pytest.raises(RuntimeError) as exc_info:
        app.http_json("GET", "https://pg.test/foo")
    assert "HTTP 500" in str(exc_info.value)
    assert "something went wrong" in str(exc_info.value)


def test_http_json_url_error_raises(monkeypatch, app_module):
    """URLError from urlopen → RuntimeError with 'Network error' in message."""
    from urllib.error import URLError as _URLError

    app = app_module

    monkeypatch.setattr(
        app,
        "urlopen",
        lambda req, timeout=None: (_ for _ in ()).throw(
            _URLError("connection refused")
        ),
    )
    with pytest.raises(RuntimeError, match="Network error"):
        app.http_json("GET", "https://pg.test/foo")


def test_http_json_non_json_response_returns_raw(monkeypatch, app_module):
    """Non-JSON response body → returns {'raw': text} without raising."""
    app = app_module

    class _FakeResp:
        class headers:
            @staticmethod
            def get_content_charset():
                return "utf-8"

        def read(self):
            return b"not json at all"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

    monkeypatch.setattr(app, "urlopen", lambda req, timeout=None: _FakeResp())
    result = app.http_json("GET", "https://pg.test/foo")
    assert result == {"raw": "not json at all"}


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


# ---------------------------------------------------------------------------
# /update — non-global IP rejection
# ---------------------------------------------------------------------------


def test_update_endpoint_non_global_ip_400(monkeypatch, temp_state_file):
    """/update?ip= with a private IP → 400."""
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/update?ip=192.168.1.1")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 400


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
    """Success path → access hero text and green (non-error) dot class."""
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


def test_checkin_html_failure_hero_and_dot():
    """Failure path → 'may not work' hero text and error dot class."""
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
