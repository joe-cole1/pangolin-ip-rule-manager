"""Real connector checks, invoked only inside the isolated compatibility runner.

Not collected by ordinary pytest. No network mocks, production URLs or CrowdSec.
HTTP-handler identity headers below are synthetic; Badger is not in this topology.
"""

from __future__ import annotations

import http.client
import json
import os
import secrets
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run_checks(admin, api, role_resource: int, org: str, actions):
    import pangolin_connector as pg

    role = admin.call("PUT", f"/org/{org}/role", {"name": "Allowed"})["roleId"]
    other_role = admin.call("PUT", f"/org/{org}/role", {"name": "No access"})["roleId"]
    users = {}
    for label, assigned_role in (
        ("role", role),
        ("direct", other_role),
        ("denied", other_role),
    ):
        email = f"{label}@compatibility.invalid"
        invitation = admin.call(
            "POST",
            f"/org/{org}/create-invite",
            {
                "email": email,
                "roleIds": [assigned_role],
                "validHours": 1,
                "sendEmail": False,
            },
        )
        invite_id, token = parse_qs(urlsplit(invitation["inviteLink"]).query)["token"][
            0
        ].split("-", 1)
        user = type(admin)(admin.base)
        user.call(
            "PUT",
            "/auth/signup",
            {
                "email": email,
                "password": secrets.token_urlsafe(32) + "aA1!",
                "inviteId": invite_id,
                "inviteToken": token,
            },
        )
        accepted = user.call(
            "POST", "/invite/accept", {"inviteId": invite_id, "token": token}
        )
        require(
            accepted["accepted"] is True and accepted["orgId"] == org,
            "User invitation was not accepted",
        )
        found = api.call(
            "GET", f"/org/{org}/users?query={quote(email, safe='')}&pageSize=100&page=1"
        )["users"]
        matches = [entry for entry in found if entry["username"] == email]
        require(len(matches) == 1, "Expected exactly one provisioned organization user")
        users[label] = (matches[0]["id"], email)

    def resource(name):
        return admin.call(
            "PUT",
            f"/org/{org}/resource",
            {
                "name": name,
                "mode": "http",
                "domainId": "compat",
                "subdomain": name,
            },
        )["resourceId"]

    direct_resource = resource("direct")
    denied_resource = resource("denied")
    resource_ids = [role_resource, direct_resource, denied_resource]
    admin.call("POST", f"/resource/{role_resource}/roles", {"roleIds": [role]})
    admin.call("POST", f"/resource/{direct_resource}/roles", {"roleIds": []})
    admin.call(
        "POST", f"/resource/{direct_resource}/users", {"userIds": [users["direct"][0]]}
    )
    admin.call("POST", f"/resource/{denied_resource}/roles", {"roleIds": []})

    def rules(rid):
        data = api.call("GET", f"/resource/{rid}/rules?limit=10000")
        require(
            isinstance(data.get("rules"), list), "Rule enumeration contract changed"
        )
        for row in data["rules"]:
            require(
                isinstance(row.get("ruleId"), int)
                and isinstance(row.get("match"), str)
                and isinstance(row.get("value"), str)
                and isinstance(row.get("priority"), int)
                and isinstance(row.get("enabled"), bool)
                and row.get("action") in ("ACCEPT", "PASS", "DROP"),
                "Rule fields consumed by the application changed",
            )
        return sorted(data["rules"], key=lambda row: row["ruleId"])

    def snapshot():
        return {rid: rules(rid) for rid in resource_ids}

    def matching(rid, ip):
        return [
            row for row in rules(rid) if row["match"] == "IP" and row["value"] == ip
        ]

    require(
        all(not rules(rid) for rid in resource_ids),
        "Fresh resources must start without rules",
    )
    # Created by an administrative actor, outside the application's ownership state.
    external_ip = "198.51.100.20"
    for match, value, action, priority in (
        ("METHOD", "POST,PUT", "PASS", 30),
        ("IP", external_ip, "ACCEPT", 40),
    ):
        admin.call(
            "PUT",
            f"/resource/{role_resource}/rule",
            {
                "match": match,
                "value": value,
                "action": action,
                "priority": priority,
                "enabled": True,
            },
        )
    original = snapshot()
    proxy_secret = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="ip-rule-state-") as state_dir:
        os.environ.update(
            {
                "PANGOLIN_URL": api.base.removesuffix("/v1"),
                "PANGOLIN_TOKEN": api.token,
                "ORG_ID": org,
                "RESOURCE_IDS": ",".join(map(str, resource_ids)),
                "STATE_FILE": str(Path(state_dir) / "state.json"),
                "PROXY_SHARED_SECRET": proxy_secret,
                "RULE_PRIORITY": "7",
                "RATE_LIMIT_SECONDS": "0",
                "CROWDSEC_ENABLED": "false",
                "DEBUG_LOG_HEADERS": "false",
                "REDIRECT_TO_LAUNCHER": "false",
            }
        )
        # Import real application functions, not main(): this is an internal HTTP API
        # boundary test, not the production HTTPS startup/Traefik deployment.
        import app

        require(
            not app.CROWDSEC_ENABLED and len(app.TARGETS) == 1,
            "CrowdSec must be unreachable",
        )
        ctx = app.make_pangolin_context()
        for label, (uid, username) in users.items():
            actual_uid, roles = pg.get_user_info(ctx, org, uid, username)
            require(
                actual_uid == uid and isinstance(roles, list),
                f"{label}: identity lookup contract changed",
            )
        require(
            role in pg.get_resource_allowed_role_ids(ctx, role_resource),
            "Allowed role not returned",
        )
        require(
            users["direct"][0]
            in pg.get_resource_allowed_user_ids(ctx, direct_resource),
            "Direct user not returned",
        )
        for rid in resource_ids:
            meta = pg.get_resource(ctx, rid)
            require(
                meta["resourceId"] == rid
                and isinstance(meta["name"], str)
                and isinstance(meta["fullDomain"], str)
                and isinstance(meta["ssl"], bool),
                "Resource metadata contract changed",
            )
        pg.list_org_resources(ctx, org)
        require(
            external_ip in pg.get_ip_set_for_resource_cached(ctx, role_resource),
            "Existing IP not detected",
        )
        print(
            "PASS User and role lookup: verified identity, role, direct-user and metadata contracts"
        )

        def checkin(ip, label):
            uid, username = users[label]
            return app.add_ip_to_targets(ip, remote_user_id=uid, remote_user=username)

        def expire():
            for entry in app.state.values():
                entry["last_seen"] = "2000-01-01T00:00:00+00:00"
            app.save_state()
            app.cleanup_old_ips()

        for label, rid, ip in (
            ("role", role_resource, "192.0.2.10"),
            ("direct", direct_resource, "192.0.2.11"),
        ):
            require(not matching(rid, ip), "Test IP unexpectedly already has a rule")
            result = checkin(ip, label)
            require(
                result["pangolin"]["ok"] is True
                and [r["resourceId"] for r in result["resources"]] == [rid],
                f"{label}: authorized registration failed or exceeded resource access",
            )
            created = matching(rid, ip)
            require(
                len(created) == 1
                and created[0]["action"] == "ACCEPT"
                and created[0]["priority"] == 7
                and created[0]["enabled"] is True,
                "IP creation action, value, priority or enabled contract changed",
            )
            require(
                app.state[ip]["resources"] == {str(rid): {"created_by_us": True}},
                "Application ownership was not recorded",
            )
            saved = json.loads(Path(app.STATE_FILE).read_text())
            require(saved == app.state, "Persisted application state is inconsistent")
            app.rules_cache.clear()  # Force the repeat to enumerate real upstream rules.
            require(
                checkin(ip, label)["pangolin"]["ok"] is True
                and matching(rid, ip) == created,
                "Repeat registration created a duplicate",
            )
            saved = json.loads(Path(app.STATE_FILE).read_text())
            app.state.clear()
            app.rules_cache.clear()
            app.load_state()
            require(app.state == saved, "Ownership did not survive simulated restart")
            require(
                checkin(ip, label)["pangolin"]["ok"] is True
                and matching(rid, ip) == created,
                "Restart registration created a duplicate",
            )
            require(
                app.state[ip]["resources"][str(rid)]["created_by_us"] is True,
                "Restart lost rule ownership",
            )
            expire()
            require(
                not matching(rid, ip) and ip not in app.state,
                "Owned IP rule was not removed",
            )
            expire()
            require(snapshot() == original, "Cleanup affected another actor's rules")
        print(
            "PASS IP rule creation: role and direct-user access, IP ACCEPT, priority and enabled state"
        )
        print("PASS Duplicate prevention: fresh enumeration and simulated restart")
        print("PASS Rule deletion: TTL cleanup, state consistency and repeated cleanup")

        require(
            checkin(external_ip, "role")["pangolin"]["ok"] is True,
            "Existing-rule registration failed",
        )
        require(
            app.state[external_ip]["resources"][str(role_resource)]["created_by_us"]
            is False,
            "Application claimed an external rule",
        )
        app.state.clear()
        app.rules_cache.clear()
        app.load_state()
        require(
            app.state[external_ip]["resources"][str(role_resource)]["created_by_us"]
            is False,
            "Restart claimed an external rule",
        )
        expire()
        require(
            snapshot() == original and external_ip not in app.state,
            "External IP or METHOD rule was deleted or duplicated",
        )
        print(
            "PASS Rule ownership: pre-existing IP and METHOD rules survive cleanup and restart"
        )

        negative_ip = "203.0.113.40"
        for uid, username in (
            ("", ""),
            ("", users["role"][1]),
            (users["role"][0], ""),
            ("missing-user", users["role"][1]),
            (users["role"][0], users["direct"][1]),
            users["denied"],
        ):
            denied = app.add_ip_to_targets(
                negative_ip, remote_user_id=uid, remote_user=username
            )
            require(
                denied["pangolin"]["ok"] is False, "Unauthorized identity was accepted"
            )
            require(
                snapshot() == original
                and not app.state.get(negative_ip, {}).get("resources"),
                "Unauthorized request created a rule or ownership state",
            )

        server = ThreadingHTTPServer(("127.0.0.1", 0), app.ImageRequestHandler)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        thread.start()
        uid, username = users["role"]
        cases = [
            ([], 403),
            (
                [
                    ("X-Proxy-Secret", secrets.token_urlsafe(32)),
                    ("Remote-User-Id", uid),
                    ("Remote-User", username),
                ],
                403,
            ),
            ([("X-Proxy-Secret", proxy_secret)], 200),
            ([("X-Proxy-Secret", proxy_secret), ("Remote-User-Id", uid)], 200),
            ([("X-Proxy-Secret", proxy_secret), ("Remote-User", username)], 200),
            (
                [
                    ("X-Proxy-Secret", proxy_secret),
                    ("Remote-User-Id", uid),
                    ("Remote-User-Id", uid),
                    ("Remote-User", username),
                ],
                200,
            ),
            (
                [
                    ("X-Proxy-Secret", proxy_secret),
                    ("Remote-User-Id", uid),
                    ("Remote-User", users["direct"][1]),
                ],
                200,
            ),
        ]
        try:
            for headers, status in cases:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_port, timeout=30
                )
                try:
                    connection.putrequest("GET", "/checkin.png")
                    for name, value in headers:
                        connection.putheader(name, value)
                    connection.endheaders()
                    response = connection.getresponse()
                    response.read()
                    require(
                        response.status == status,
                        "HTTP identity/proxy-secret gate changed",
                    )
                finally:
                    connection.close()
                require(
                    snapshot() == original
                    and not app.state.get("127.0.0.1", {}).get("resources"),
                    "HTTP authorization failure created a rule",
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        print(
            "PASS Authorization: role/direct grants; denied, invalid, mismatched and missing identities; synthetic HTTP secret/header rejection"
        )

        key_id = api.token.split(".", 1)[0]

        def permissions(values):
            admin.call(
                "POST",
                f"/org/{org}/api-key/{key_id}/actions",
                {"actionIds": list(values)},
            )

        def rejected(expected_http):
            app.rules_cache.clear()
            result = checkin(negative_ip, "role")
            require(
                result["pangolin"]["ok"] is False
                and f"HTTP {expected_http}" in result["pangolin"]["detail"],
                f"Expected live API HTTP {expected_http} failure",
            )
            require(
                snapshot() == original
                and not app.state.get(negative_ip, {}).get("resources"),
                "Failed API request granted access",
            )

        original_token = app.PANGOLIN_TOKEN
        try:
            app.PANGOLIN_TOKEN = key_id + "." + secrets.token_urlsafe(32)
            rejected(401)
        finally:
            app.PANGOLIN_TOKEN = original_token
        # Use a separate restricted key for error cases so the observer can still
        # enumerate rules using the original correctly scoped application token.
        error_key = admin.call(
            "PUT", f"/org/{org}/api-key", {"name": "Negative permission tests"}
        )
        key_id = error_key["apiKeyId"]
        try:
            app.PANGOLIN_TOKEN = key_id + "." + error_key["apiKey"]
            for missing in ("listUsers", "createResourceRule"):
                permissions(action for action in actions if action != missing)
                rejected(403)
                rejected(403)
            permissions(actions)
            app.RESOURCE_IDS = [max(resource_ids) + 1000]
            rejected(404)
        finally:
            app.RESOURCE_IDS = resource_ids
            app.PANGOLIN_TOKEN = original_token
        retry_ip = "203.0.113.41"
        require(
            checkin(retry_ip, "role")["pangolin"]["ok"] is True,
            "Deletion retry fixture was not created",
        )
        try:
            permissions(action for action in actions if action != "deleteResourceRule")
            app.PANGOLIN_TOKEN = key_id + "." + error_key["apiKey"]
            expire()
            require(
                app.state[retry_ip]["resources"][str(role_resource)]["created_by_us"]
                is True
                and len(matching(role_resource, retry_ip)) == 1,
                "Failed deletion lost retry ownership or removed the rule",
            )
            saved = json.loads(Path(app.STATE_FILE).read_text())
            app.state.clear()
            app.rules_cache.clear()
            app.load_state()
            require(
                app.state == saved,
                "Failed-deletion retry state did not survive restart",
            )
        finally:
            app.PANGOLIN_TOKEN = original_token
        expire()
        expire()
        require(
            snapshot() == original
            and not app.state
            and json.loads(Path(app.STATE_FILE).read_text()) == {},
            "Retry cleanup left rules or inconsistent state",
        )
        print(
            "PASS Error handling: real API 401/403/404, repeated rejection, creation denial and deletion retry across restart"
        )
        print(
            "PASS Application cleanup: only owned rules removed; external rules preserved"
        )
