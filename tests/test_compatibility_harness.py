"""Harness security checks; these mocks are never evidence of live compatibility."""

import argparse
import http.server
import json
import os
import secrets
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from scripts import image_smoke
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


@pytest.mark.parametrize("version", ["1.24.0", "1.26.0"])
def test_ee_resolution_pulls_the_enterprise_image_and_pins_its_digest(
    monkeypatch, version
):
    calls = []
    tag = f"ghcr.io/fosrl/pangolin:ee-{version}"
    digest = "sha256:" + "a" * 64

    def fake_docker(args, **_):
        calls.append(args)
        return (
            ""
            if args[0] == "pull"
            else json.dumps([f"ghcr.io/fosrl/pangolin@{digest}"])
        )

    monkeypatch.setattr(harness, "docker", fake_docker)
    assert harness.resolve_image(version, {}, "ee") == f"{tag}@{digest}"
    assert calls[0] == ["pull", "--quiet", tag]
    assert calls[1][2] == tag


def test_missing_ee_image_cannot_fall_back_to_community(monkeypatch):
    calls = []

    def missing(args, **_):
        calls.append(args)
        raise subprocess.CalledProcessError(1, ["docker", *args])

    monkeypatch.setattr(harness, "docker", missing)
    with pytest.raises(subprocess.CalledProcessError):
        harness.resolve_image("1.26.0", {}, "ee")
    assert calls == [["pull", "--quiet", "ghcr.io/fosrl/pangolin:ee-1.26.0"]]


def test_unknown_edition_is_rejected_before_docker(monkeypatch):
    monkeypatch.setattr(harness, "docker", lambda *_, **__: pytest.fail("Docker used"))
    with pytest.raises(ValueError, match="edition"):
        harness.resolve_image("1.26.0", {}, "both")


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


@pytest.mark.parametrize(("edition", "build"), [("ee", "oss"), ("ce", "enterprise")])
def test_bootstrap_rejects_the_wrong_running_edition(monkeypatch, edition, build):
    calls = []

    class WrongEdition:
        def __init__(self, *_):
            pass

        def call(self, method, path, body=None):
            calls.append(path)
            if path.endswith("initial-setup-complete"):
                return {"complete": False}
            return {"version": "1.26.0", "build": build}

    monkeypatch.setattr(probe, "Client", WrongEdition)
    with pytest.raises(RuntimeError, match="does not match requested edition"):
        probe.bootstrap(
            "1.26.0", {"setup_token": "fixture", "password": "fixture"}, edition
        )
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


@pytest.mark.parametrize("edition", ["ce", "ee"])
def test_failed_compatibility_run_redacts_secrets_and_removes_only_its_project(
    monkeypatch, capsys, edition
):
    project = "pangolin-compat-unit-fixture"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compat",
            "--project",
            project,
            "--version",
            "v9.8.7-rc.2",
            "--edition",
            edition,
        ],
    )
    monkeypatch.setattr(harness.shutil, "which", lambda _: "/test/docker")
    monkeypatch.setenv("PANGOLIN_URL", "https://production.invalid")
    monkeypatch.setenv("DOCKER_HOST", "tcp://production.invalid:2375")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    remaining = {"container": [], "volume": [], "network": []}
    generated = {}
    removed = []
    tag = f"ghcr.io/fosrl/pangolin:{'ee-' if edition == 'ee' else ''}9.8.7-rc.2"
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
            assert env["COMPAT_EDITION"] == edition
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


def test_sanitize_output_redacts_bearer_tokens_and_proxy_secrets():
    bearer_header = secrets.token_urlsafe(18)
    bearer_lower = secrets.token_urlsafe(18)
    bearer_json = secrets.token_urlsafe(18)
    proxy_header = secrets.token_urlsafe(18)
    proxy_eq = secrets.token_urlsafe(18)
    proxy_json = secrets.token_urlsafe(18)
    proxy_dict = secrets.token_urlsafe(18)
    exact_secret = secrets.token_hex(16)

    raw = "\n".join(
        [
            f"Authorization: Bearer {bearer_header}",
            f"authorization: bearer {bearer_lower}",
            json.dumps({"Authorization": f"Bearer {bearer_json}"}),
            f"X-Proxy-Secret: {proxy_header}",
            f"x-proxy-secret={proxy_eq}",
            json.dumps({"X-Proxy-Secret": proxy_json}),
            f"{{'X-Proxy-Secret': '{proxy_dict}'}}",
            f"raw secret {exact_secret}",
        ]
    )

    sanitized = harness.sanitize_output(raw, (exact_secret, ""))
    lines = sanitized.splitlines()

    assert len(lines) == 8
    assert all(line.startswith("[compat] ") for line in lines)
    for token in (
        bearer_header,
        bearer_lower,
        bearer_json,
        proxy_header,
        proxy_eq,
        proxy_json,
        proxy_dict,
        exact_secret,
    ):
        assert token not in sanitized
    assert "[compat] Authorization: Bearer [REDACTED]" in lines
    assert "[compat] authorization: bearer [REDACTED]" in lines
    assert "[compat] X-Proxy-Secret: [REDACTED]" in lines
    assert "[compat] x-proxy-secret=[REDACTED]" in lines
    assert '[compat] {"X-Proxy-Secret": [REDACTED]}' in lines
    assert "[compat] {'X-Proxy-Secret': [REDACTED]}" in lines
    assert "[compat] raw secret [REDACTED]" in lines


def test_failed_compatibility_run_redacts_bearer_and_proxy_secret_headers(
    monkeypatch, capsys
):
    project = "pangolin-compat-header-redaction"
    bearer_tok = secrets.token_urlsafe(18)
    proxy_tok = secrets.token_urlsafe(18)
    monkeypatch.setattr(
        sys,
        "argv",
        ["compat", "--project", project, "--version", "9.8.7", "--edition", "ce"],
    )
    monkeypatch.setattr(harness.shutil, "which", lambda _: "/test/docker")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    remaining = {"container": [], "volume": [], "network": []}
    digest = "sha256:" + "a" * 64

    def fake_docker(args, *, env, timeout=60, input=None):
        if args[:2] == ["context", "inspect"]:
            return "unix:///var/run/docker.sock"
        if args[0] == "pull":
            return ""
        if args[:2] == ["image", "inspect"]:
            return json.dumps([f"ghcr.io/fosrl/pangolin@{digest}"])
        if args[0] == "compose":
            if "up" in args:
                remaining.update(container=["c1"], volume=["v1"], network=["n1"])
            if "run" in args:
                raise subprocess.CalledProcessError(
                    1,
                    ["docker"],
                    output="FAIL header leak check\n",
                    stderr=(
                        f"Authorization: Bearer {bearer_tok}\n"
                        f"X-Proxy-Secret: {proxy_tok}\n"
                    ),
                )
            return ""
        if args[:2] == ["network", "inspect"]:
            return "true"
        if "--filter" in args:
            kind = "container" if args[0] == "ps" else args[0]
            return "\n".join(remaining[kind])
        remaining[args[0]] = []
        return ""

    monkeypatch.setattr(harness, "docker", fake_docker)
    assert harness.main() == 1
    output = capsys.readouterr()
    logs = output.out + output.err
    assert bearer_tok not in logs
    assert proxy_tok not in logs
    assert "[compat] Authorization: Bearer [REDACTED]" in logs
    assert "[compat] X-Proxy-Secret: [REDACTED]" in logs


def test_image_smoke_passes_proxy_secret_via_env_not_argv(monkeypatch):
    monkeypatch.delenv("PROXY_SHARED_SECRET", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "image_smoke.py",
            "--image",
            "pangolin-smoke:test",
            "--platform",
            "linux/amd64",
        ],
    )
    monkeypatch.setattr(image_smoke, "docker_python_version", lambda: "3.14.10")

    calls = []
    created_volume = []

    def fake_docker(*args, check=True, **kwargs):
        calls.append((args, kwargs))
        if args[:2] == ("volume", "create"):
            created_volume.append(args[2])
            return ""
        if args[0] == "inspect":
            return json.dumps(
                [
                    {
                        "HostConfig": {"NetworkMode": "none", "PortBindings": {}},
                        "Mounts": [{"Name": created_volume[0]}],
                    }
                ]
            )
        if args[0] == "exec":
            action = args[5]
            if action == "state":
                return json.dumps(
                    {
                        ip: {
                            "resources": {},
                            "last_seen": "2026-01-01T00:00:00+00:00",
                        }
                        for ip in args[8:]
                    }
                )
            return ""
        return ""

    monkeypatch.setattr(image_smoke, "docker", fake_docker)
    image_smoke.main()

    run_calls = [(args, kwargs) for args, kwargs in calls if args[0] == "run"]
    assert len(run_calls) == 1
    run_args, run_kwargs = run_calls[0]

    assert not any(str(arg).startswith("PROXY_SHARED_SECRET=") for arg in run_args)
    idx = run_args.index("PROXY_SHARED_SECRET")
    assert idx > 0 and run_args[idx - 1] == "--env"

    run_env = run_kwargs["env"]
    assert isinstance(run_env["PROXY_SHARED_SECRET"], str)
    assert len(run_env["PROXY_SHARED_SECRET"]) >= 32
    assert run_env["PROXY_SHARED_SECRET"] not in " ".join(str(a) for a in run_args)
    assert "PROXY_SHARED_SECRET" not in os.environ

    assert any(args[:2] == ("rm", "--force") for args, _ in calls)
    assert any(args[:2] == ("volume", "rm") for args, _ in calls)
