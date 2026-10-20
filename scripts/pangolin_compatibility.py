"""Resolve an official Pangolin release, test it in isolation, then remove it."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "tests/compatibility/compose.yml"
IMAGE_REPOSITORY = "ghcr.io/fosrl/pangolin"
BASELINE_VERSION = "1.24.0"
# Keep the known baseline immutable even if upstream changes its tag.
BASELINE_IMAGE = (
    IMAGE_REPOSITORY
    + ":1.24.0@sha256:17774ddbb4bf13f4a2b9e813cc2dfc3ca8ded1c5745823624af632bab0376488"
)


def release_version(value: str) -> str:
    """Accept release tags, never image names, URLs, moving tags or CLI options."""
    version = value.strip().removeprefix("v")
    if len(version) > 128 or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
        r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        version,
    ):
        raise argparse.ArgumentTypeError(
            "Expected a release tag such as 1.25.0 or 1.25.0-rc.0 (optional v prefix)"
        )
    return version


def docker(args, *, env, timeout=60, input=None):
    return subprocess.run(
        ["docker", "--context", "default", *args],
        env=env,
        capture_output=True,
        text=True,
        input=input,
        timeout=timeout,
        check=True,
    ).stdout.strip()


def resolve_image(version: str, env) -> str:
    version = release_version(version)
    if version == BASELINE_VERSION:
        return BASELINE_IMAGE
    tag = f"{IMAGE_REPOSITORY}:{version}"
    docker(["pull", "--quiet", tag], env=env, timeout=240)
    try:
        digests = json.loads(
            docker(
                ["image", "inspect", tag, "--format", "{{json .RepoDigests}}"],
                env=env,
            )
        )
    except ValueError:
        raise RuntimeError("Docker did not return image digests") from None
    if not isinstance(digests, list):
        raise TypeError("Docker did not return image digests")
    matches = {
        item
        for item in digests
        if isinstance(item, str)
        and re.fullmatch(re.escape(IMAGE_REPOSITORY) + r"@sha256:[a-f0-9]{64}", item)
    }
    if len(matches) != 1:
        raise RuntimeError("Expected one digest for the official Pangolin image")
    return f"{tag}@{matches.pop().split('@')[1]}"


def clean(project: str, env) -> None:
    """Fallback teardown uses only this exact generated Compose project label."""
    label = f"label=com.docker.compose.project={project}"
    for kind, listing in (
        ("container", ["ps", "-aq"]),
        ("volume", ["volume", "ls", "-q"]),
        ("network", ["network", "ls", "-q"]),
    ):
        ids = docker([*listing, "--filter", label], env=env).split()
        if ids:
            flags = ["-f"] if kind == "container" else []
            docker([kind, "rm", *flags, *ids], env=env)
        if docker([*listing, "--filter", label], env=env):
            raise RuntimeError(f"Temporary {kind} cleanup could not be verified")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", type=release_version, default=BASELINE_VERSION)
    parser.add_argument("--project", default="pangolin-compat-" + secrets.token_hex(8))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup", action="store_true")
    mode.add_argument(
        "--matrix", action="store_true", help="Print validated CI versions"
    )
    parser.add_argument("--compare-baseline", action="store_true")
    parser.add_argument("--fail-after-bootstrap", action="store_true")
    args = parser.parse_args()
    if args.matrix:
        versions = [BASELINE_VERSION] if args.compare_baseline else []
        print(json.dumps(list(dict.fromkeys([*versions, args.version]))))
        return 0
    if args.compare_baseline:
        parser.error("--compare-baseline requires --matrix")
    if not re.fullmatch(r"pangolin-compat-[a-z0-9-]+", args.project):
        parser.error("Expected a generated pangolin-compat- project name")
    if not shutil.which("docker"):
        parser.error("Docker Engine and Compose v2 are required")
    # Do not inherit production settings, remote Docker hosts, proxies, or .env files.
    env = {
        k: os.environ[k] for k in ("PATH", "HOME", "DOCKER_CONFIG") if k in os.environ
    }
    endpoint = docker(
        ["context", "inspect", "default", "--format", "{{.Endpoints.docker.Host}}"],
        env=env,
    )
    if not endpoint.startswith("unix://"):
        parser.error("Only a local Unix Docker socket is allowed")
    if args.cleanup:
        clean(args.project, env)
        return 0
    if docker(
        ["ps", "-aq", "--filter", f"label=com.docker.compose.project={args.project}"],
        env=env,
    ):
        parser.error("Refusing to reuse an existing project")
    failed = False
    stage = "configuration"
    results = []
    with tempfile.TemporaryDirectory(prefix=args.project + "-") as temp:
        directory = Path(temp)
        setup_token = "".join(
            secrets.choice(string.ascii_lowercase + string.digits) for _ in range(32)
        )
        server_secret = secrets.token_hex(32)
        password = secrets.token_urlsafe(32) + "aA1!"
        credentials = {"setup_token": setup_token, "password": password}
        config = {
            "app": {
                "dashboard_url": "http://pangolin:3000",
                "log_level": "warn",
                "telemetry": {"anonymous_usage": False},
                "notifications": {"product_updates": False, "new_releases": False},
            },
            "domains": {"compat": {"base_domain": "compatibility.invalid"}},
            "gerbil": {"base_endpoint": "pangolin.invalid"},
            "server": {"trust_proxy": 0},
            "flags": {
                "enable_integration_api": True,
                "require_email_verification": False,
                "disable_signup_without_invite": True,
                "enable_acme_cert_sync": False,
            },
        }
        (directory / "config.yml").write_text(json.dumps(config))
        (directory / "config.yml").chmod(0o644)
        python_image = re.search(
            r"^FROM (python:\S+@sha256:[a-f0-9]{64})",
            (REPO / "Dockerfile").read_text(),
            re.MULTILINE,
        )
        if not python_image:
            parser.error("Dockerfile must pin the Python base image by digest")
        env.update(
            {
                "COMPAT_PYTHON_IMAGE": python_image[1],
                "COMPAT_DIR": temp,
                "COMPAT_UID": str(os.getuid()),
                "COMPAT_GID": str(os.getgid()),
                "COMPAT_VERSION": args.version,
                "COMPAT_REPO": str(REPO),
                "COMPAT_SETUP_TOKEN": setup_token,
                "COMPAT_SERVER_SECRET": server_secret,
            }
        )
        compose = [
            "compose",
            "--env-file",
            "/dev/null",
            "-f",
            str(COMPOSE),
            "--project-name",
            args.project,
        ]

        def sanitized(value):
            for secret in (setup_token, server_secret, password):
                value = value.replace(secret, "[REDACTED]")
            # Prefix every line so container output cannot execute workflow commands.
            return "\n".join("[compat] " + line for line in value.splitlines())

        try:
            stage = "image resolution"
            image = resolve_image(args.version, env)
            env["COMPAT_PANGOLIN_IMAGE"] = image
            results.append(f"Image: `{image}`")
            print(f"[compat] Resolved image: {image}", flush=True)
            stage = "configuration"
            docker([*compose, "config", "--quiet"], env=env)
            stage = "image pull"
            docker([*compose, "pull", "--quiet"], env=env, timeout=240)
            stage = "startup"
            docker(
                [*compose, "up", "-d", "--wait", "--wait-timeout", "180", "pangolin"],
                env=env,
                timeout=200,
            )
            network = docker(
                [
                    "network",
                    "ls",
                    "-q",
                    "--filter",
                    f"label=com.docker.compose.project={args.project}",
                ],
                env=env,
            )
            if (
                docker(
                    ["network", "inspect", network, "--format", "{{.Internal}}"],
                    env=env,
                )
                != "true"
            ):
                raise RuntimeError("Test network must be internal")
            stage = "bootstrap / live compatibility"
            command = [*compose, "run", "--rm", "--no-deps", "-T", "runner"]
            if args.fail_after_bootstrap:
                command.extend(
                    [
                        "python",
                        "-B",
                        "scripts/pangolin_compatibility_probe.py",
                        "--version",
                        args.version,
                        "--fail-after-bootstrap",
                    ]
                )
            output = docker(
                command,
                env=env,
                timeout=300,
                input=json.dumps(credentials),
            )
            print(sanitized(output))
            results.extend(
                line for line in output.splitlines() if line.startswith("PASS ")
            )
        except (subprocess.SubprocessError, OSError, RuntimeError, TypeError) as exc:
            failed = True
            results.append(f"{stage}: FAIL ({type(exc).__name__})")
            print(f"FAIL {stage}: {type(exc).__name__}", file=sys.stderr)
            if isinstance(exc, subprocess.CalledProcessError):
                print(sanitized(exc.stdout + exc.stderr))
                results.extend(
                    line
                    for line in (exc.stdout + exc.stderr).splitlines()
                    if line.startswith(("PASS ", "FAIL "))
                )
            try:
                print(
                    sanitized(
                        docker(
                            [
                                *compose,
                                "logs",
                                "--no-color",
                                "--tail",
                                "100",
                                "pangolin",
                            ],
                            env=env,
                        )
                    )
                )
            except (subprocess.SubprocessError, OSError):
                print("Pangolin diagnostics unavailable")
        finally:
            try:
                clean(args.project, env)
                results.append("Containers, volumes and networks removed: PASS")
            except (subprocess.SubprocessError, OSError, RuntimeError):
                failed = True
                results.append("Cleanup: FAIL; use the workflow fallback teardown")
    summary = (
        f"### Pangolin {args.version}\n\n"
        + "\n".join(f"- {item}" for item in results)
        + "\n"
    )
    print(summary)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(path).open("a") as output:
            output.write(summary)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
