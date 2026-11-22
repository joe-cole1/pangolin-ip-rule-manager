"""Unit and integration tests for request_handler.py.

Covers IP extraction, proxy-secret and identity header gates, /update,
HTML template rendering/escaping, redirects, security headers, and log
sanitization.
"""

import http.client
import json
import threading
import time as _time_mod

import pytest
from helpers import (
    TEST_PROXY_SECRET,
    configure_authorized_update_user,
    org_user,
    org_users_response,
    proxy_request,
    reload_app,
    reload_app_and_dependencies,
    start_bounded_server,
    start_server,
)

_RESULTS_OK = {
    "pangolin": {"ok": True, "detail": "ok"},
    "crowdsec": {"ok": False, "detail": "disabled"},
}
_RESULTS_FAIL = {
    "pangolin": {"ok": False, "detail": "auth error"},
    "crowdsec": {"ok": False, "detail": "not reached"},
}
_LAST_SEEN_ISO = "2025-01-01T00:00:00+00:00"


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


def test_update_endpoint_enabled_adds_arbitrary_ip(monkeypatch, temp_state_file):
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
    with app.state_lock:
        app.state.clear()
    auth_headers = configure_authorized_update_user(monkeypatch, app)

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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=False
    )

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", "/update?ip=1.2.3.4")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 404


def test_update_endpoint_missing_ip_param_400(monkeypatch, temp_state_file):
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )

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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )

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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
    auth_headers = configure_authorized_update_user(monkeypatch, app)

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


def test_update_endpoint_ipv4_mapped_ipv6_unwrapped(monkeypatch, temp_state_file):
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
    with app.state_lock:
        app.state.clear()
    auth_headers = configure_authorized_update_user(monkeypatch, app)

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(
            conn,
            "GET",
            "/update?ip=%3A%3Affff%3A1.1.1.1",
            headers=auth_headers,
        )
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        parsed = json.loads(data)
        assert parsed["ok"] is True
        assert parsed["ip"] == "1.1.1.1"
    with app.state_lock:
        assert "1.1.1.1" in app.state
        assert "::ffff:1.1.1.1" not in app.state


@pytest.mark.parametrize(
    "encoded",
    ["%3A%3Affff%3A10.0.0.1", "%3A%3Affff%3A127.0.0.1"],
)
def test_update_endpoint_private_ipv4_mapped_ipv6_rejected_400(
    monkeypatch, temp_state_file, encoded
):
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", f"/update?ip={encoded}")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 400
        parsed = json.loads(body)
        assert parsed["ok"] is False
    with app.state_lock:
        assert app.state == {}


def test_update_endpoint_private_ipv4_mapped_ipv6_html_rejected_400(
    monkeypatch, temp_state_file
):
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
    with app.state_lock:
        app.state.clear()

    with start_server(app.ImageRequestHandler) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(
            conn,
            "GET",
            "/update?ip=%3A%3Affff%3A10.0.0.1",
            headers={"Accept": "text/html"},
        )
        resp = conn.getresponse()
        html_body = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "text/html" in resp.getheader("Content-Type", "")
        assert "10.0.0.1" in html_body
    with app.state_lock:
        assert app.state == {}


def test_update_endpoint_last_seen_updates(monkeypatch, temp_state_file):
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
    auth_headers = configure_authorized_update_user(monkeypatch, app)

    clock = {"ts": "2026-01-01T00:00:00+00:00"}
    monkeypatch.setattr(app, "now_utc_iso", lambda: clock["ts"])
    handler_cls = app.create_image_request_handler(app._make_image_handler_context())

    ip = "5.6.7.8"
    with start_server(handler_cls) as (_httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        proxy_request(conn, "GET", f"/update?ip={ip}", headers=auth_headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200
        with app.state_lock:
            first_seen = app.state[ip]["last_seen"]
        assert first_seen == "2026-01-01T00:00:00+00:00"

        clock["ts"] = "2026-01-01T00:00:05+00:00"
        proxy_request(conn, "GET", f"/update?ip={ip}", headers=auth_headers)
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 200
    with app.state_lock:
        second_seen = app.state[ip]["last_seen"]
    assert second_seen == "2026-01-01T00:00:05+00:00"
    assert second_seen != first_seen


def test_update_endpoint_returns_html_when_accepted(monkeypatch, temp_state_file):
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
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

    app = reload_app_and_dependencies()
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

    app = reload_app_and_dependencies()
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


@pytest.mark.parametrize("raw", ["::ffff:1.1.1.1", "::ffff:0101:0101"])
def test_get_real_ip_ipv4_mapped_ipv6_in_x_real_ip(raw):
    """Global IPv4-mapped IPv6 in X-Real-IP → unwrapped to canonical IPv4."""
    h = _make_handler_for_ip_test({"X-Real-IP": raw})
    assert h._get_real_ip() == "1.1.1.1"


def test_get_real_ip_ipv4_mapped_ipv6_in_xff():
    """Global IPv4-mapped IPv6 in X-Forwarded-For → unwrapped to canonical IPv4."""
    h = _make_handler_for_ip_test({"X-Forwarded-For": "::ffff:1.1.1.1, 10.0.0.1"})
    assert h._get_real_ip() == "1.1.1.1"


@pytest.mark.parametrize(
    "raw",
    ["::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:192.168.1.1"],
)
def test_get_real_ip_private_ipv4_mapped_ipv6_rejected(raw):
    """Non-global IPv4-mapped IPv6 in X-Real-IP is rejected; falls back to XFF."""
    h = _make_handler_for_ip_test(
        {"X-Real-IP": raw, "X-Forwarded-For": "5.6.7.8"},
    )
    assert h._get_real_ip() == "5.6.7.8"


@pytest.mark.parametrize(
    ("socket_ip", "expected"),
    [("::ffff:1.1.1.1", "1.1.1.1"), ("::ffff:127.0.0.1", "127.0.0.1")],
)
def test_get_real_ip_socket_fallback_unwraps_ipv4_mapped_ipv6(socket_ip, expected):
    """Socket address fallback unwraps IPv4-mapped IPv6 without .is_global filter."""
    h = _make_handler_for_ip_test({}, socket_ip=socket_ip)
    assert h._get_real_ip() == expected


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


def test_proxy_secret_missing_header_rejected(monkeypatch, temp_state_file):
    """When PROXY_SHARED_SECRET is set, a request without X-Proxy-Secret gets 403
    and no IP is written to state."""
    app = reload_app(monkeypatch, temp_state_file, proxy_shared_secret="s3cret")
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
    app = reload_app(monkeypatch, temp_state_file, proxy_shared_secret="s3cret")

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
    app = reload_app(monkeypatch, temp_state_file, proxy_shared_secret="s3cret")
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
    app = reload_app(monkeypatch, temp_state_file, proxy_shared_secret="")
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
    app = reload_app(monkeypatch, temp_state_file, proxy_shared_secret="s3cret")
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
    app = reload_app(monkeypatch, temp_state_file, proxy_shared_secret="s3cret")
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


def test_update_endpoint_non_global_ip_400(monkeypatch, temp_state_file):
    """/update?ip= with a private IP → 400."""
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
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


def test_update_json_success_with_crowdsec_enabled_and_additive(
    monkeypatch, temp_state_file
):
    """/update JSON returns 200 with crowdsec status whether CrowdSec succeeds or fails."""
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
    auth_headers = configure_authorized_update_user(monkeypatch, app)

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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )
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


def test_image_request_handler_socket_timeout_configured(app_module):
    """ImageRequestHandler enforces a 10-second per-connection socket timeout."""
    assert app_module.ImageRequestHandler.timeout == 10


def test_slowloris_client_times_out_and_releases_worker(app_module):
    """Incomplete request headers time out and free the worker slot."""
    import socket

    class _FastTimeoutHandler(app_module.ImageRequestHandler):
        timeout = 0.2

    with start_bounded_server(app_module, _FastTimeoutHandler, max_workers=1) as (
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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=False
    )
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
    app = reload_app(
        monkeypatch, temp_state_file, resource_ids="9", update_enabled=True
    )

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
