"""Check an image with disposable state and loopback-only HTTP; requires Docker."""

import argparse
import json
import secrets
import subprocess
import uuid

from python_version import docker_python_version

# Run these checks inside the real container, using its normal user and stdlib.
PROBE = """
import json
import os
import platform
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

action, expected_version, architecture = sys.argv[1:4]
assert platform.python_version() == expected_version, platform.python_version()
assert platform.machine() == {"amd64": "x86_64", "arm64": "aarch64"}[architecture]
assert (os.geteuid(), os.getegid()) == (100, 101)
assert not Path("/var/run/docker.sock").exists()
state_file = Path(os.environ["STATE_FILE"])

if action == "health":
    deadline = time.monotonic() + 90
    while True:
        try:
            with urlopen("http://127.0.0.1:8080/healthz", timeout=2) as response:
                assert response.status == 200
                assert response.read() == b"ok"
            break
        except (URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    print("Health HTTP 200; interpreter, architecture and UID/GID verified")
elif action == "fresh":
    assert not state_file.exists(), "Expected fresh disposable state storage"
    assert stat.S_IMODE(state_file.parent.stat().st_mode) == 0o700
elif action == "checkin":
    # Global header IPs are labels only: requests go exclusively to loopback.
    # Missing identity headers exercise the intentional fail-closed audit write.
    request = Request("http://127.0.0.1:8080/smoke.png", headers={
        "X-Proxy-Secret": os.environ["PROXY_SHARED_SECRET"],
        "X-Real-IP": sys.argv[4],
    })
    with urlopen(request, timeout=5) as response:
        assert response.status == 200
        assert response.headers["Content-Type"] == "image/png"
        assert response.read().startswith(b"\\x89PNG")
elif action == "state":
    data = json.loads(state_file.read_text())
    assert set(data) == set(sys.argv[4:]), data
    for record in data.values():
        assert record["resources"] == {}, "Unauthenticated check-in granted resources"
        timestamp = datetime.fromisoformat(record["last_seen"])
        assert timestamp.tzinfo is not None
        assert abs((datetime.now(timezone.utc) - timestamp).total_seconds()) < 300
    metadata = state_file.stat()
    assert (metadata.st_uid, metadata.st_gid) == (100, 101)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    print(json.dumps(data, sort_keys=True))
else:
    raise AssertionError(f"Unknown action: {action}")
"""


def docker(*args, check=True, **kwargs):
    return subprocess.run(
        ["docker", *args],
        check=check,
        text=True,
        capture_output=True,
        timeout=120,
        **kwargs,
    ).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument(
        "--platform", choices=["linux/amd64", "linux/arm64"], required=True
    )
    args = parser.parse_args()
    architecture = args.platform.split("/")[1]
    version = docker_python_version()
    name = f"pangolin-smoke-{uuid.uuid4().hex}"
    volume = f"{name}-data"

    def probe(action, *values):
        return docker(
            "exec",
            "-i",
            name,
            "python3",
            "-",
            action,
            version,
            architecture,
            *values,
            input=PROBE,
        )

    docker("volume", "create", volume)
    try:
        docker(
            "run",
            "--detach",
            "--pull=never",
            "--name",
            name,
            "--platform",
            args.platform,
            "--network",
            "none",
            "--mount",
            f"type=volume,source={volume},target=/data",
            "--env",
            "PANGOLIN_URL=https://example.invalid",
            "--env",
            "PANGOLIN_TOKEN=",
            "--env",
            "ORG_ID=",
            "--env",
            "RESOURCE_IDS=1",
            "--env",
            f"PROXY_SHARED_SECRET={secrets.token_urlsafe(32)}",
            "--env",
            "CROWDSEC_ENABLED=false",
            "--env",
            "STATE_FILE=/data/state.json",
            args.image,
        )
        container = json.loads(docker("inspect", name))[0]
        assert container["HostConfig"]["NetworkMode"] == "none"
        assert container["HostConfig"]["PortBindings"] in (None, {})
        assert len(container["Mounts"]) == 1
        assert container["Mounts"][0]["Name"] == volume
        print(probe("health"))
        probe("fresh")
        probe("checkin", "1.1.1.1")
        before = json.loads(probe("state", "1.1.1.1"))
        docker("restart", "--timeout", "5", name)
        print(probe("health"))
        assert json.loads(probe("state", "1.1.1.1")) == before
        # A second write must retain the first record, proving startup loaded it
        # into the running service, rather than merely leaving the file on disk.
        probe("checkin", "8.8.8.8")
        after = json.loads(probe("state", "1.1.1.1", "8.8.8.8"))
        assert after["1.1.1.1"] == before["1.1.1.1"]
        print(
            f"PASS {args.platform}: fresh state, HTTP writes, restart and state reload"
        )
    except Exception as error:
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout + error.stderr)
        logs = subprocess.run(
            ["docker", "logs", name], check=False, text=True, capture_output=True
        )
        print(logs.stdout + logs.stderr)
        raise
    finally:
        docker("rm", "--force", name, check=False)
        docker("volume", "rm", volume)


if __name__ == "__main__":
    main()
