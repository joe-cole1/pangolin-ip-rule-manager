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
    # Mandatory custom header configuration
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "X-Test-Key")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "v123")

    # Import or reload module to apply env
    if "app" in globals():
        import app as _app
        app = importlib.reload(_app)
    else:
        import app  # type: ignore
    # As a safety for client header construction in tests, ensure these are non-empty strings
    if not getattr(app, "EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", ""):
        app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY = "X-Test-Key"
    if not getattr(app, "EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", ""):
        app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE = "v123"
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
            app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE,
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


def test_security_header_enforced(monkeypatch, temp_state_file):
    # Set required header env and reload module
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "X-Test-Key")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "v123")
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "8")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    import app as _app
    app = importlib.reload(_app)
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (httpd, port):
        # Missing header -> 403
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/banner.png")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403

        # With correct custom header -> 200
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", "/some-file.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == app.BANNER_PNG

        # Root path with correct header -> 403
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", "/", headers=headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403


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


def test_security_header_misconfigured_only_key(monkeypatch, temp_state_file):
    # Only key is set -> since custom header is mandatory, importing app should fail
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "X-Only-Key")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "")
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "8")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    import app as _app
    with pytest.raises(RuntimeError):
        importlib.reload(_app)


def test_security_header_misconfigured_only_value(monkeypatch, temp_state_file):
    # Only value is set -> importing app should fail
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "v123")
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "8")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    import app as _app
    with pytest.raises(RuntimeError):
        importlib.reload(_app)



def test_gif_serves_gif_and_updates_state(app_module):
    app = app_module

    test_ip = "6.7.8.9"

    with start_server(app.ImageRequestHandler) as (httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE,
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
        headers = {
            app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE,
        }

        # Test root path
        conn.request("GET", "/", headers=headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403

        # Test path without file extension
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/some-random-path", headers=headers)
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

        # Not created by us -> never attempted -> remains
        assert ip_not_created in app.state
        assert "5" in app.state[ip_not_created]["resources"]

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
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "X-Test-Key")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "v123")
    monkeypatch.setenv("UPDATE_ENDPOINT_ENABLED", "true" if update_enabled else "false")
    import app as _app
    return importlib.reload(_app)


def test_update_endpoint_enabled_adds_arbitrary_ip(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", "/update?ip=1.2.3.4", headers=headers)
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
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", "/update?ip=1.2.3.4", headers=headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 404


def test_update_endpoint_missing_header_403(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/update?ip=1.2.3.4")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403


def test_update_endpoint_missing_ip_param_400(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", "/update", headers=headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 400


def test_update_endpoint_invalid_ip_400(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", "/update?ip=999.999.999.999", headers=headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 400


def test_update_endpoint_ipv6_success(monkeypatch, temp_state_file):
    app = _reload_app_with_env(monkeypatch, temp_state_file, update_enabled=True)

    ipv6 = "2001:db8::1"
    encoded = "2001%3Adb8%3A%3A1"
    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", f"/update?ip={encoded}", headers=headers)
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
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", f"/update?ip={ip}", headers=headers)
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
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", f"/update?ip={ip}", headers=headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200
    with app.state_lock:
        second_seen = app.state[ip]["last_seen"]
    assert second_seen != first_seen
