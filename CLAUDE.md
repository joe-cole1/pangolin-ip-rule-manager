# CLAUDE.md

## What this project is

`pangolin-ip-rule-manager` bootstraps network trust for devices that cannot authenticate
through SSO. A family member visits a trigger URL on their phone (already authenticated
via Pangolin). The app reads their public IP, adds a temporary bypass rule in Pangolin
for specific protected resources (e.g., Jellyfin), and optionally adds the IP to the
CrowdSec allowlist. A TV on the same network can then reach Jellyfin without going
through SSO. Rules expire automatically via a configurable TTL.

This runs in production with no staging environment on an Oracle VPS alongside Pangolin,
Traefik, CrowdSec, and Portainer. Pangolin going down means all services go offline.
Every change is high-stakes.

---

## Repository structure

```
pangolin-ip-rule-manager/
├── app.py                   # Entry point: config, state, cleanup loop, target coordination
├── request_handler.py       # HTTP handler (factory pattern): IP extraction, routing, HTML pages
├── pangolin_connector.py    # All Pangolin API interaction: PangolinContext dataclass, retry logic
├── crowdsec_connector.py    # CrowdSec integration via cscli subprocess
├── requirements.txt         # Dev dependencies (pytest, ruff) — not used in the runtime image
├── Dockerfile               # python:3.14-alpine; includes docker-cli for CrowdSec integration
├── docker-compose.yml       # Reference compose file — actual deployment uses Portainer
├── config.env.sample        # Every environment variable with inline documentation
└── tests/
    ├── conftest.py          # sys.path setup for pytest
    └── test_app.py          # All tests (unit + integration)
```

There is no `Makefile` and no `pyproject.toml`. The application uses Python stdlib only —
no pip dependencies at runtime.

---

## Environment variables

All configuration is injected at runtime via environment variables.
**Never hardcode credentials.** See `config.env.sample` for the canonical reference.

### Hard required — startup aborts without these

| Variable | Description |
|---|---|
| `PANGOLIN_URL` | Pangolin Integration API base URL, e.g. `https://api.yourdomain.com` |
| `RESOURCE_IDS` | Comma-separated resource IDs to protect, e.g. `1,2` |

### Required for core functionality — startup warns and continues without these

| Variable | Description |
|---|---|
| `PANGOLIN_TOKEN` | Pangolin API token. Missing → prominent warning; all API calls raise immediately. |
| `ORG_ID` | Pangolin organisation ID. Missing → startup resource listing skipped. |

### Optional with defaults

| Variable | Default | Description |
|---|---|---|
| `LISTEN_PORT` | `8080` | HTTP listen port inside the container |
| `RETENTION_MINUTES` | `1440` | Minutes before an IP rule expires (default: 1 day) |
| `CLEANUP_INTERVAL_MINUTES` | `60` | How often the cleanup loop runs |
| `RULE_PRIORITY` | `0` | Pangolin rule priority |
| `RULES_CACHE_TTL_SECONDS` | `3600` | Cache TTL for Pangolin rule existence checks |
| `STATE_FILE` | `/data/state.json` | Persistent state path — must be on a mounted volume |
| `SITE_NAME` | _(empty)_ | Optional label shown in the HTML check-in and error pages |
| `UPDATE_ENDPOINT_ENABLED` | `false` | Enables `/update?ip=...` endpoint (disabled by default) |

### CrowdSec (all optional, disabled by default)

| Variable | Default | Description |
|---|---|---|
| `CROWDSEC_ENABLED` | `false` | Enable CrowdSec integration |
| `CROWDSEC_ALLOWLIST_NAME` | `pangolin-ip-rule-manager` | Allowlist name in CrowdSec |
| `CROWDSEC_CSCLI_BIN` | `cscli` | Path to the cscli binary |
| `CROWDSEC_CMD_PREFIX` | _(empty)_ | Command prefix, e.g. `docker exec crowdsec` |
| `CROWDSEC_CACHE_TTL_SECONDS` | `3600` | Cache TTL for CrowdSec allowlist membership checks |

---

## Running tests

```bash
pytest
```

Tests live in `tests/test_app.py`. `conftest.py` handles `sys.path`. All tests use
`monkeypatch` to avoid real network calls — no live instance or credentials are needed
to run the suite.

`tests/test_crowdsec.py` does not exist yet. CrowdSec unit tests are explicitly
deferred pending a CrowdSec refactor.

---

## Linting

The project uses **ruff** (not flake8).

Check for violations:

```bash
ruff check .
ruff format --check .
```

Auto-fix and reformat:

```bash
ruff check --fix .
ruff format .
```

The CI workflow (`python-package.yml`) auto-fixes on push and opens a PR for any
changes. On a PR build it checks without fixing and fails if violations remain.

---

## Current state and next release

**Current release:** `v2.3.0` on `master`

No outstanding planned changes. Start the next release cycle by creating a fresh
`dev` branch from `master`.

---

## Behavioral rules for Claude

These apply to every session. Do not deviate without explicit instruction.

### Before generating anything

- **Read every file before suggesting changes.** Never work from memory on file
  contents. When a zip is uploaded, extract and read the relevant files first.
- **Verify before stating.** Do not assume version numbers, import names, or
  variable names — check the source.
- **Ask rather than assume** when intent is ambiguous or scope is unclear.
- **State the plan before acting.** Name which files will be touched and why.
  Wait for confirmation before generating code.

### When making changes

- **Diffs before full files.** For small changes, present a unified diff with
  2–3 lines of context. Follow with a clean copy block. Full file artifacts are
  appropriate only when changes are numerous or the file is small.
- **One concern per commit.** Lint fixes, logic changes, and new features each
  get their own commit and their own PR. Do not bundle.
- **Commit message format:** single subject line only — no body text.
  Multi-line commit messages collapse in the GitHub web UI.
- **Flag anything that needs test validation.** Changes touching IP extraction,
  TTL logic, Pangolin API calls, CrowdSec integration, or the authorization
  chain must be validated against the test instance before going to production.
- **Never rewrite a file unnecessarily.** Prefer targeted edits.

### Code conventions

- **Python 3.14, stdlib only.** No new pip runtime dependencies.
- **Linter:** ruff. Run `ruff check .` before presenting changes.
- **Fail-closed everywhere.** If `Remote-User` is absent or any Pangolin API
  call fails, nothing is whitelisted and no resources are written to state.
  (`last_seen` is stamped before auth so the request is logged, but `resources`
  remains empty. This is intentional and must be preserved.)
- **OR logic for access.** A user is authorised for a resource if their role
  matches OR they are directly assigned. Both paths must be checked.
  This mirrors Pangolin's `isUserAllowedToAccessResource()`.

### Commit and PR description format

Commit title inside a code block. Description in plain text below (never inside
a code block). Each item on its own line starting with a dash. A full blank line
between items.

---

## Secrets discipline

- All secrets (Pangolin token, API credentials) live in Bitwarden first, then
  are injected at runtime via Docker environment variables or Portainer secrets.
- **Never suggest hardcoding a credential** — not in code, not in a test, not
  as a placeholder value.
- If a credential appears anywhere in code, a log line, an error message, or a
  diff: **flag it immediately before continuing.**
- Test credentials are in a separate Bitwarden note from live credentials.
  The test container runs on a different port behind a throwaway Pangolin URL.
  **Never mix test and live credentials.**
- Any suggested change touching live API calls should specify which environment
  to validate against before deploying to production.

---

## Release flow

1. Create the `dev` branch fresh from `master`. Never reuse a dev branch across
   release cycles — Dependabot PRs land on `master` and accumulated divergence
   causes merge pain.
2. Make changes on `dev`.
3. Open PR: `dev` → `master`.
4. Squash merge.
5. Tag the release (e.g., `v2.2.3`).
6. GitHub Actions (`docker-publish.yml`) triggers on release publish and builds
   a multi-arch image (`linux/amd64`, `linux/arm64`) pushed to
   `ghcr.io/joe-cole1/pangolin-ip-rule-manager:<version>`.

Branch protection is active on `master` (PR required, no force push, no
deletion). A GitHub Actions workflow auto-force-resets `dev` to `master` on
release publish. Release notes are auto-generated from PR labels per
`.github/release.yml`.

---

## Architecture notes

These are load-bearing design decisions. Do not change them without explicit
discussion.

### IP extraction (`request_handler.py` → `_get_real_ip`)

Header precedence: `X-Real-IP` → `X-Forwarded-For` (first value only) →
socket address. Each header value is validated with `ipaddress.ip_address()`
and rejected if not globally routable. Non-global or unparseable header values
are logged and skipped. The socket address fallback is not validated (it is
OS-controlled, not caller-controlled).

### Authorization chain (`app.py` → `add_ip_to_targets`)

1. `Remote-User` header must be present (set by Pangolin SSO).
   Absent → fail-closed. No rules are created; no resources are written to state.
   (`last_seen` is stamped for logging purposes, but `resources` stays empty.)
2. `pg_filter_resources_for_user` is called: username → role IDs → for each
   configured resource, role match OR direct-user assignment is checked.
   Any API error → fail-closed.
3. Empty effective resource list → fail-closed.
4. Only resources the user is authorised for receive the rule.

### State and cleanup

State persists to `STATE_FILE` as JSON. Each IP entry records `last_seen`
(UTC ISO) and a `resources` dict tracking `created_by_us` per resource.
The cleanup thread runs every `CLEANUP_INTERVAL_MINUTES`. Pangolin rules are
only deleted if `created_by_us: true`. If deletion fails, the record is
retained and retried next cycle. CrowdSec expiration is always attempted
regardless of `created_by_us`.

When `ensure_ip_rule` finds a pre-existing rule in Pangolin (created externally
or from a previous run), it records `created_by_us: false` and calls
`save_state()` immediately. This keeps the on-disk state consistent with
in-memory state even when no new rule is created.

### Late import in `app.py`

`from request_handler import create_image_request_handler` at the bottom of
`app.py` carries `# noqa: E402`. This is intentional: importing `request_handler`
triggers module-level code that depends on functions defined earlier in `app.py`.
Moving the import to the top of the file would break startup. Do not move it;
do not remove the `# noqa` suppression.

### XSS guard in `/update` error page (`request_handler.py`)

User-supplied values embedded in HTML responses must be escaped with
`html.escape()`. The `raw_ip` parameter in the `/update?ip=...` error path
is a deliberate example — it uses `html.escape(raw_ip)` to prevent reflected
XSS. Do not remove this or inline user-controlled strings into HTML without
escaping them first.

### Known limitations (not bugs, do not treat as defects)

- Phone and TV must share the same public IP. Inherent to the design.
- No structured logging. `print()` to stdout only. Improvement deferred.
- CrowdSec is optional and additive. A CrowdSec failure does not block a
  Pangolin success from being reported to the user.

---

## Test environment

- A test container is available on a separate port with a throwaway Pangolin URL.
- Test credentials are in a separate Bitwarden note from live credentials.
- **Never mix test and live credentials.**
- Before running any test that would touch the CrowdSec allowlist, confirm
  whether the test environment is using a mock or a live CrowdSec instance.
- Any change to IP extraction, TTL logic, or API interactions must be validated
  in the test environment before deploying to production.
