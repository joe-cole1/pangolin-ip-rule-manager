"""Harness security checks; these mocks are never evidence of live compatibility."""

import argparse
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
    ("value", "expected"),
    [
        ("1.25.0-rc.0", "1.25.0-rc.0"),
        ("v1.26.0", "1.26.0"),
        (" 9.8.7-beta.2 \n", "9.8.7-beta.2"),
    ],
)
def test_release_tag_accepts_future_versions(value, expected):
    assert harness.release_version(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "latest",
        "both",
        "1.25",
        "01.25.0",
        "ghcr.io/another/image:1.25.0",
        "https://github.com/fosrl/pangolin/releases/tag/1.25.0",
        "1.25.0@sha256:" + "a" * 64,
        "1.25.0; touch /tmp/unwanted",
        "$(id)",
        '1.25.0"]',
        "1.25.0\n::error::untrusted",
        "1.25.0-" + "a" * 128,
    ],
)
def test_release_tag_rejects_image_overrides_and_untrusted_syntax(value):
    with pytest.raises(argparse.ArgumentTypeError):
        harness.release_version(value)


@pytest.mark.parametrize(
    ("version", "compare", "expected"),
    [
        ("v9.8.7-rc.2", False, ["9.8.7-rc.2"]),
        ("v9.8.7-rc.2", True, ["1.24.0", "9.8.7-rc.2"]),
        ("v1.24.0", True, ["1.24.0"]),
    ],
)
def test_matrix_validates_input_without_docker(
    monkeypatch, capsys, version, compare, expected
):
    args = ["compat", "--matrix", "--version", version]
    if compare:
        args.append("--compare-baseline")
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.setattr(harness.shutil, "which", lambda _: pytest.fail("Docker used"))
    assert harness.main() == 0
    assert json.loads(capsys.readouterr().out) == expected


def test_invalid_matrix_input_fails_before_docker_without_echoing_it(
    monkeypatch, capsys
):
    value = '1.25.0"]\n::error::untrusted'
    monkeypatch.setattr(sys, "argv", ["compat", "--matrix", "--version", value])
    monkeypatch.setattr(harness.shutil, "which", lambda _: pytest.fail("Docker used"))
    with pytest.raises(SystemExit) as exc:
        harness.main()
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "Expected a release tag" in output.err
    assert value not in output.err


def test_baseline_keeps_its_known_digest(monkeypatch):
    monkeypatch.setattr(harness, "docker", lambda *_, **__: pytest.fail("Tag resolved"))
    assert harness.resolve_image("1.24.0", {}) == harness.BASELINE_IMAGE


@pytest.mark.parametrize("digests", [None, [], ["other/image@sha256:" + "a" * 64]])
def test_image_resolution_requires_an_official_digest(monkeypatch, digests):
    def fake_docker(args, **_):
        return "" if args[0] == "pull" else json.dumps(digests)

    monkeypatch.setattr(harness, "docker", fake_docker)
    with pytest.raises((RuntimeError, TypeError), match="digest"):
        harness.resolve_image("9.8.7", {})


def test_missing_image_does_not_substitute_another_version(monkeypatch):
    calls = []

    def fake_docker(args, **_):
        calls.append(args)
        raise subprocess.CalledProcessError(1, ["docker", *args])

    monkeypatch.setattr(harness, "docker", fake_docker)
    with pytest.raises(subprocess.CalledProcessError):
        harness.resolve_image("9.8.7", {})
    assert calls == [["pull", "--quiet", "ghcr.io/fosrl/pangolin:9.8.7"]]


def test_bootstrap_rejects_a_different_running_version(monkeypatch):
    calls = []

    class WrongVersion:
        def __init__(self, *_):
            pass

        def call(self, method, path, body=None):
            calls.append(path)
            if path.endswith("initial-setup-complete"):
                return {"complete": False}
            return {"version": "1.24.0"}

    monkeypatch.setattr(probe, "Client", WrongVersion)
    with pytest.raises(RuntimeError, match="does not match requested release"):
        probe.bootstrap(
            "9.8.7",
            {
                "setup_token": secrets.token_hex(16),
                "password": secrets.token_urlsafe(32),
            },
        )
    assert calls[-1] == "/server-info"
    assert "/org" not in calls


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
    monkeypatch.setattr(
        sys, "argv", ["compat", "--project", project, "--version", "v9.8.7-rc.2"]
    )
    monkeypatch.setattr(harness.shutil, "which", lambda _: "/test/docker")
    monkeypatch.setenv("PANGOLIN_URL", "https://production.invalid")
    monkeypatch.setenv("DOCKER_HOST", "tcp://production.invalid:2375")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    remaining = {"container": [], "volume": [], "network": []}
    generated = {}
    removed = []
    tag = "ghcr.io/fosrl/pangolin:9.8.7-rc.2"
    digest = "sha256:" + "a" * 64

    def fake_docker(args, *, env, timeout=60, input=None):
        assert "PANGOLIN_URL" not in env and "DOCKER_HOST" not in env
        if args[:2] == ["context", "inspect"]:
            return "unix:///var/run/docker.sock"
        if args[0] == "pull":
            assert args == ["pull", "--quiet", tag]
            return ""
        if args[:2] == ["image", "inspect"]:
            assert args[2] == tag
            return json.dumps([f"ghcr.io/fosrl/pangolin@{digest}"])
        if args[0] == "compose":
            assert env["COMPAT_PANGOLIN_IMAGE"] == f"{tag}@{digest}"
            assert env["COMPAT_VERSION"] == "9.8.7-rc.2"
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
