"""Bootstrap and test our disposable Compose service; never accept an external URL."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

API = "http://pangolin:3003/v1"
ADMIN = "http://pangolin:3000/api/v1"
ORG = "compatibility"
ACTIONS = (
    "getResource",
    "listResources",
    "listUsers",
    "listResourceRoles",
    "listResourceUsers",
    "listResourceRules",
    "createResourceRule",
    "deleteResourceRule",
)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    """Bootstrap transport: fixed local origins, no redirects/proxies/body logging."""

    def __init__(self, base: str, token: str = ""):
        if base not in (API, ADMIN):
            raise ValueError("Only the disposable Pangolin service is allowed")
        self.base = base
        self.token = token
        self.cookies = http.cookiejar.CookieJar()
        self.opener = build_opener(
            ProxyHandler({}), NoRedirects(), HTTPCookieProcessor(self.cookies)
        )

    def call(self, method: str, path: str, body=None):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Expected a local API path")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.base == ADMIN:
            headers["X-CSRF-Token"] = "x-csrf-protection"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = json.dumps(body).encode() if body is not None else None
        req = Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as result:
                payload = json.load(result)
        except HTTPError as exc:
            raise RuntimeError(f"{method} {path}: HTTP {exc.code}") from None
        except (URLError, TimeoutError, ValueError):
            raise RuntimeError(f"{method} {path}: transport or JSON failure") from None
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise RuntimeError(f"{method} {path}: unsuccessful API response")
        return payload["data"]


def bootstrap(version: str, credentials):
    admin = Client(ADMIN)
    deadline = time.monotonic() + 45
    while True:
        try:
            complete = admin.call("GET", "/auth/initial-setup-complete")["complete"]
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "Initial setup endpoint did not become ready"
                ) from None
            time.sleep(2)
    if complete:
        raise RuntimeError("Refusing to bootstrap a previously initialized instance")
    identity = {
        "email": "admin@compatibility.invalid",
        "password": credentials["password"],
    }
    admin.call(
        "PUT",
        "/auth/set-server-admin",
        {**identity, "setupToken": credentials["setup_token"]},
    )
    admin.call("POST", "/auth/login", identity)
    if admin.call("GET", "/server-info")["version"] != version:
        raise RuntimeError("Running Pangolin version does not match requested release")
    admin.call(
        "PUT",
        "/org",
        {
            "orgId": ORG,
            "name": "Disposable compatibility tests",
            "subnet": "100.90.128.0/24",
            "utilitySubnet": "100.96.128.0/24",
        },
    )
    admin.call("PUT", f"/org/{ORG}/site", {"name": "Local test site", "type": "local"})
    resource = admin.call(
        "PUT",
        f"/org/{ORG}/resource",
        {
            "name": "Disposable resource",
            "mode": "http",
            "domainId": "compat",
            "subdomain": "resource",
        },
    )
    key = admin.call("PUT", f"/org/{ORG}/api-key", {"name": "IP rule manager"})
    admin.call(
        "POST",
        f"/org/{ORG}/api-key/{key['apiKeyId']}/actions",
        {"actionIds": list(ACTIONS)},
    )
    if admin.call("GET", f"/org/{ORG}/api-key/{key['apiKeyId']}")["isRoot"]:
        raise RuntimeError("Application test key must not be root")
    granted = admin.call("GET", f"/org/{ORG}/api-key/{key['apiKeyId']}/actions")
    if {item["actionId"] for item in granted["actions"]} != set(ACTIONS):
        raise RuntimeError(
            "Application test key does not have exactly the required actions"
        )
    api = Client(API, f"{key['apiKeyId']}.{key['apiKey']}")
    rid = resource["resourceId"]
    if api.call("GET", f"/resource/{rid}")["resourceId"] != rid:
        raise RuntimeError("Authenticated resource lookup returned the wrong resource")
    if not any(
        item["resourceId"] == rid
        for item in api.call("GET", f"/org/{ORG}/resources")["resources"]
    ):
        raise RuntimeError("Authenticated resource listing omitted the test resource")
    print("PASS Bootstrap: admin, organization, local site, resource, scoped token")
    print(f"PASS API authentication and resource discovery against Pangolin {version}")
    return admin, api, rid


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    # The host validates the tag; bootstrap verifies the actual server version.
    parser.add_argument("--version", required=True)
    parser.add_argument("--fail-after-bootstrap", action="store_true")
    args = parser.parse_args()
    try:
        admin, api, rid = bootstrap(args.version, json.load(sys.stdin))
        if args.fail_after_bootstrap:
            raise RuntimeError(
                "Intentional failure after bootstrap: teardown rehearsal"
            )
        from live_checks import run_checks

        run_checks(admin, api, rid, ORG, ACTIONS)
        return 0
    except (RuntimeError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"FAIL Compatibility: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
