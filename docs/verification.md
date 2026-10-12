# Interpreter and image verification

`Dockerfile` is the source of truth for the exact Python patch version.
`scripts/python_version.py` reads it for `actions/setup-python`, and `--check`
fails if the selected interpreter differs. CI installs the pinned development
tools from `requirements.txt` and runs `ruff check`, `ruff format --check`, and
`pytest` against the submitted source without rewriting it.

Docker Image CI builds and loads both `linux/amd64` and `linux/arm64` images on
native GitHub runners. Each image must pass `scripts/image_smoke.py`. The smoke
test uses the image's normal UID/GID (100:101), a fresh disposable named `/data`
volume, no published ports, `--network none`, no Docker socket, a generated dummy
proxy secret, `https://example.invalid`, empty Pangolin credentials, and disabled
CrowdSec. The startup upstream-unreachable warning is expected.

The checks cover the exact image interpreter and architecture, health HTTP 200,
state permissions, an HTTP check-in's intentional unauthenticated `last_seen`
write with empty authorized resources, health and unchanged state after restart,
and a second write that retains the first record. This last check verifies that
the running service loaded persisted state. No live upstream authorization or
Pangolin/CrowdSec rule changes are exercised. The container and test volume are
removed on completion or failure.

To repeat locally with Docker and a host Python interpreter:

```sh
python3 scripts/python_version.py
# Use that exact version in a disposable virtual environment for source checks:
python -m pip install -r requirements.txt
python scripts/python_version.py --check
python -m ruff check .
python -m ruff format --check .
python -m pytest

docker buildx build --load --platform linux/amd64 -t pangolin-smoke:amd64 .
python3 scripts/image_smoke.py --image pangolin-smoke:amd64 --platform linux/amd64
```

Use `linux/arm64` and `pangolin-smoke:arm64` for an arm64 host (or a Docker engine
with arm64 emulation already configured). Local architecture coverage depends on
the engine; CI requires both native architecture jobs to pass. Image publication
and production deployment are separate from these checks.

The initial smoke test in PR #136 exposed that existing HTTP handlers retained
the pre-load state mapping, so new check-ins were not persisted after restart.
The state-loading correction in merged
[PR #137](https://github.com/joe-cole1/pangolin-ip-rule-manager/pull/137) preserves
the shared mapping and is included in #136's updated branch. The restart checks
and HTTP regression test protect this behavior on subsequent image updates.
