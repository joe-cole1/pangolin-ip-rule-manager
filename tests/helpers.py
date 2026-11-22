import contextlib
import importlib
import sys
import threading
from http.server import HTTPServer
from urllib.parse import quote

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


@contextlib.contextmanager
def start_bounded_server(app, handler_cls, *, max_workers=None):
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


def reload_app_and_dependencies():
    if "crowdsec_connector" in sys.modules:
        import crowdsec_connector

        importlib.reload(crowdsec_connector)
    import app as _app

    return importlib.reload(_app)


def reload_app(
    monkeypatch,
    temp_state_file,
    *,
    resource_ids="5",
    token="",
    listen_port="0",
    proxy_shared_secret=None,
    update_enabled=None,
    crowdsec_enabled=None,
    env=None,
):
    """Set common test env vars, reload app + dependencies, and return the module."""
    monkeypatch.setenv("PANGOLIN_TOKEN", token)
    monkeypatch.setenv("RESOURCE_IDS", str(resource_ids))
    monkeypatch.setenv("LISTEN_PORT", str(listen_port))
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    if proxy_shared_secret is not None:
        monkeypatch.setenv("PROXY_SHARED_SECRET", proxy_shared_secret)
    if update_enabled is not None:
        monkeypatch.setenv(
            "UPDATE_ENDPOINT_ENABLED", "true" if update_enabled else "false"
        )
    if crowdsec_enabled is not None:
        monkeypatch.setenv("CROWDSEC_ENABLED", "true" if crowdsec_enabled else "false")
    for k, v in (env or {}).items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    return reload_app_and_dependencies()


def make_fake_http_json(
    *,
    org_id="test-org",
    user_id="user-abc",
    username="joe@example.com",
    role_ids=(5,),
    allowed_role_ids=None,
    resource_id=5,
    resource_name="Jellyfin",
    full_domain="jellyfin.example.com",
    ssl=True,
    direct_users=(),
    rules=(),
    put_rule_id=99,
    extra_resource_roles=None,
    roles_error=None,
    users_error=None,
    resource_error=None,
    put_error=None,
):
    """Build a parameterized fake http_json callable for Pangolin API mock tests."""
    encoded_user = quote(username, safe="")
    user_query = f"/org/{org_id}/users?query={encoded_user}"
    effective_allowed_roles = (
        (resource_id,) if allowed_role_ids is None else allowed_role_ids
    )
    role_list = [
        {"roleId": rid, "name": resource_name} for rid in effective_allowed_roles
    ]

    def fake_http_json(method, url, body=None):
        if user_query in url:
            return org_users_response(org_user(user_id, username, list(role_ids)))
        if f"/resource/{resource_id}/roles" in url:
            if roles_error is not None:
                raise roles_error
            return {"data": {"roles": role_list}, "success": True}
        for extra_rid, extra_roles in (extra_resource_roles or {}).items():
            if f"/resource/{extra_rid}/roles" in url:
                return {"data": {"roles": extra_roles}, "success": True}
            if f"/resource/{extra_rid}/users" in url:
                return {"data": {"users": []}, "success": True}
        if f"/resource/{resource_id}/users" in url:
            if users_error is not None:
                raise users_error
            return {"data": {"users": list(direct_users)}, "success": True}
        if url.endswith(f"/resource/{resource_id}"):
            if resource_error is not None:
                raise resource_error
            return {
                "data": {
                    "resourceId": resource_id,
                    "name": resource_name,
                    "fullDomain": full_domain,
                    "ssl": ssl,
                },
                "success": True,
            }
        if "/rules" in url:
            return {"data": {"rules": list(rules)}, "success": True}
        if method == "PUT":
            if put_error is not None:
                raise put_error
            return {"success": True, "data": {"rule": {"ruleId": put_rule_id}}}
        return {}

    return fake_http_json


standard_fake_http_json = make_fake_http_json()


def configure_authorized_update_user(monkeypatch, app, resource_id: int = 9):
    """Configure mocked Pangolin auth + rule creation for /update tests."""
    monkeypatch.setattr(app, "ORG_ID", "test-org")
    monkeypatch.setattr(app, "RESOURCE_IDS", [resource_id])
    monkeypatch.setattr(app, "PANGOLIN_TOKEN", "fake-token")
    monkeypatch.setattr(
        app,
        "http_json",
        make_fake_http_json(
            user_id="user-alice",
            username="alice@example.com",
            role_ids=(resource_id,),
            resource_id=resource_id,
            resource_name="TV",
            full_domain="tv.example.com",
        ),
    )
    return {
        "Remote-User-Id": "user-alice",
        "Remote-User": "alice@example.com",
    }
