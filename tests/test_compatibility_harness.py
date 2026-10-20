"""Harness security checks; these mocks are never evidence of live compatibility."""

import http.server
import json
import secrets
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from scripts import pangolin_compatibility as harness
from scripts import pangolin_compatibility_probe as probe


@pytest.mark.parametrize(
    "url",
    [
        "https://production.invalid",
        "http://127.0.0.1:3003/v1",
        "https://pangolin:3003/v1",
    ],
)
def test_compatibility_client_rejects_external_or_alternate_origin(url):
    with pytest.raises(ValueError, match="disposable"):
        probe.Client(url)


def test_compatibility_client_does_not_follow_redirects(monkeypatch):
    paths = []

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/credential-trap")
            self.end_headers()

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}
    )
    thread.start()
    try:
        monkeypatch.setattr(probe, "API", f"http://127.0.0.1:{server.server_port}/v1")
        with pytest.raises(RuntimeError, match="HTTP 302"):
            probe.Client(probe.API, secrets.token_urlsafe(32)).call(
                "GET", "/resource/1"
            )
        assert paths == ["/v1/resource/1"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_failed_compatibility_run_redacts_secrets_and_removes_only_its_project(
    monkeypatch, capsys
):
    project = "pangolin-compat-unit-fixture"
    monkeypatch.setattr(sys, "argv", ["compat", "--project", project])
    monkeypatch.setattr(harness.shutil, "which", lambda _: "/test/docker")
    monkeypatch.setenv("PANGOLIN_URL", "https://production.invalid")
    monkeypatch.setenv("DOCKER_HOST", "tcp://production.invalid:2375")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    remaining = {"container": [], "volume": [], "network": []}
    generated = {}
    removed = []

    def fake_docker(args, *, env, timeout=60, input=None):
        assert "PANGOLIN_URL" not in env and "DOCKER_HOST" not in env
        if args[:2] == ["context", "inspect"]:
            return "unix:///var/run/docker.sock"
        if args[0] == "compose":
            directory = Path(env["COMPAT_DIR"])
            generated["directory"] = directory
            assert {p.name for p in directory.iterdir()} == {"config.yml"}
            assert (
                env["COMPAT_SERVER_SECRET"]
                not in (directory / "config.yml").read_text()
            )
            if "up" in args:
                remaining.update(
                    container=["container-id"],
                    volume=["volume-id"],
                    network=["network-id"],
                )
            if "run" in args:
                generated.update(json.loads(input))
                generated["server_secret"] = env["COMPAT_SERVER_SECRET"]
                raise subprocess.CalledProcessError(
                    1,
                    ["docker"],
                    output="FAIL intentional fixture error\n",
                    stderr=input + env["COMPAT_SERVER_SECRET"],
                )
            return ""
        if args[:2] == ["network", "inspect"]:
            return "true"
        if "--filter" in args:
            assert args[-1] == f"label=com.docker.compose.project={project}"
            kind = "container" if args[0] == "ps" else args[0]
            return "\n".join(remaining[kind])
        assert args[1] == "rm"
        kind = args[0]
        assert args[-1] == f"{kind}-id"
        remaining[kind] = []
        removed.append(kind)
        return ""

    monkeypatch.setattr(harness, "docker", fake_docker)
    assert harness.main() == 1
    output = capsys.readouterr()
    logs = output.out + output.err
    assert "FAIL" in logs and "removed: PASS" in logs
    assert "[REDACTED]" in logs
    for name in ("setup_token", "password", "server_secret"):
        assert generated[name] not in logs
    assert removed == ["container", "volume", "network"]
    assert not generated["directory"].exists()


def test_compatibility_cleanup_cannot_report_success_if_resources_remain(monkeypatch):
    def fake_docker(args, **_):
        return "container-id" if "--filter" in args else ""

    monkeypatch.setattr(harness, "docker", fake_docker)
    with pytest.raises(RuntimeError, match="cleanup could not be verified"):
        harness.clean("pangolin-compat-leftovers", {})
