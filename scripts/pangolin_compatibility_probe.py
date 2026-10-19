"""Read-only probes of the Pangolin Integration API response contracts.

Only run against a dedicated, disposable test instance and resource.
No rule creation or deletion is performed in this first phase.
"""
from __future__ import annotations

import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> int:
    base = os.environ["PANGOLIN_URL"].rstrip("/")
    token = os.environ["PANGOLIN_TOKEN"]
    resource_id = int(os.environ["COMPAT_RESOURCE_ID"])

    # Keep this probe read-only. A separate phase will provision a fully
    # disposable Pangolin instance before testing mutations.
    paths = (
        (f"/v1/resource/{resource_id}", "resource"),
        (f"/v1/resource/{resource_id}/rules?limit=10000", "rules"),
        (f"/v1/resource/{resource_id}/roles", "roles"),
        (f"/v1/resource/{resource_id}/users", "users"),
    )
    failed = False
    for path, field in paths:
        request = Request(
            base + path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=15) as response:
                data = json.load(response)
            if not isinstance(data, dict) or not isinstance(data.get("data"), dict):
                raise ValueError("missing data object")
            payload = data["data"]
            if field != "resource" and not isinstance(payload.get(field), list):
                raise ValueError(f"missing {field} list")
            if field == "resource" and not payload:
                raise ValueError("empty resource metadata")
            print(f"PASS {path}")
        except (HTTPError, URLError, ValueError, TimeoutError, json.JSONDecodeError) as exc:
            # Avoid echoing API response bodies, tokens, or sensitive URLs.
            print(f"FAIL {field}: {type(exc).__name__}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
