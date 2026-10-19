# Pangolin compatibility testing

Status: baseline bootstrap passed on GitHub; the live compatibility matrix is
under validation. This replaces PR #141's external-instance probe. No
production endpoints, credentials, CrowdSec, or deployment files are used.

## Architecture decision

Use Docker Compose with two containers: an official Pangolin SQLite image and
a Python runner using the application's digest-pinned Python base image. Both
join a fresh `internal: true` network. No ports are published, no socket is
mounted, and neither container needs elevated capabilities. Pangolin's database
and generated files occupy a disposable named volume. Credentials are randomly
generated for each run, passed through process memory/environment and stdin,
and discarded after teardown. No credential files are written. The repository is mounted read-only.

The selected versions are allowlisted and pinned by tag plus multi-platform
manifest digest in `scripts/pangolin_compatibility.py`. The running server's
`/api/v1/server-info` version is checked independently after login. A missing
artifact or version mismatch fails; there is no replacement image or external
endpoint fallback.

Supported bootstrap sequence, verified in both upstream release sources:

1. Enable `flags.enable_integration_api`; provide `PANGOLIN_SETUP_TOKEN` and
   `SERVER_SECRET`. Wait for the Integration API health endpoint with a bounded
   timeout. Explicitly check that initial setup is incomplete.
2. `PUT /api/v1/auth/set-server-admin`, with the generated setup token, creates
   the administrator. `POST /api/v1/auth/login` establishes a cookie session.
   Mutating dashboard requests supply Pangolin's required CSRF header.
3. Use that authenticated dashboard API to create the organization, local site,
   public HTTP resource, and organization-scoped API key. Assign exactly the
   application's eight action permissions and verify that the key is not root.
4. Authenticate to the Integration API with `Bearer <keyId>.<keySecret>` and
   look up/list the new resource.
5. Run the real application connector, state cleanup, and HTTP-handler checks
   described below, then remove and verify removal of every container, volume,
   and network bearing this exact generated Compose project label.

No database editing, browser bootstrap, interactive CLI, mail server, or public
DNS is required. `compatibility.invalid` is metadata only. Traefik and Gerbil
are unnecessary for these API checks; the local site has no tunnel. Pangolin
still tries public-IP discovery at startup; lack of egress is expected and the
readiness budget accommodates those bounded attempts. Telemetry, update
notifications, and ACME synchronization are disabled in this test config.

The environment root-key hook `PANGOLIN_ROOT_API_KEY` exists in both versions,
but does not grant action permissions by itself. The authenticated dashboard
API avoids needing a root API key at all. The removed `USERS_SERVERADMIN_*`
bootstrap method is explicitly unsupported upstream and is not used here.

Source references (review the matching paths at each pinned release):

- [1.24.0 source](https://github.com/fosrl/pangolin/tree/a235635d9e5a6431ea426431e3e862e965928cd3)
- [1.25.0-rc.0 source](https://github.com/fosrl/pangolin/tree/0842e6df53e898759ed05b77086ddd3c673b6149)
- `server/setup/ensureSetupToken.ts`, `server/routers/auth/setServerAdmin.ts`,
  `server/routers/auth/login.ts`, `server/routers/external.ts`,
  `server/routers/apiKeys/`, `server/lib/readConfigFile.ts`,
  `server/integrationApiServer.ts`, and `install/config/docker-compose.yml`.

## Manual execution

On a disposable Linux development machine with Docker Engine, Compose v2, and
Python 3.12 or newer:

```sh
python3 scripts/pangolin_compatibility.py --version 1.24.0
python3 scripts/pangolin_compatibility.py --version 1.25.0-rc.0
```

The script uses the local default Docker context, rejects a remote TCP endpoint,
ignores production environment variables and `.env`, and creates its own unique
project. Never run the inner probe directly against another deployment.

After this workflow exists on `master`, use Actions → Pangolin compatibility →
Run workflow. Select `both` (default), `1.24.0`, or `1.25.0-rc.0`. The choice
selects actual pinned containers, not an informational version label. Before merge, the repository owner can manually apply the
`pangolin-compatibility` label to a same-repository PR. This **label event only**
launches both release jobs; commits and ordinary PR events do not launch it.
Remove and reapply the label to run again. The workflow has read-only repository
permissions, does not receive repository secrets, and does not persist checkout
credentials. No schedule is enabled.

## Coverage and diagnosis

The suite verifies installation, unattended admin/resource/user provisioning,
scoped-token authentication, all eight runtime API contracts, role and direct-user
authorization, IP ACCEPT creation/priority/enabled state, repeated registration,
owned-rule expiry, external IP/METHOD preservation, and state reload across a
simulated restart. The real application functions and HTTP handler are used.
Negative cases verify invalid keys (401), missing permissions (403), missing
resources (404), repeated rejection, creation denial, and deletion retry state
retained across restart. Invalid identity pairs and denied roles must create no
rules; missing/invalid proxy secrets and missing/duplicate/mismatched identity
headers are sent to the actual local HTTP handler with synthetic headers. The host script reports whether configuration, image
pull, startup, or bootstrap failed and prints a redacted tail of Pangolin logs.
It never dumps container environments, API response bodies, or configuration.
An unconditional workflow step repeats project-scoped teardown after failure
or cancellation. Runner disposal is the final fallback for a forcibly killed job.

Existing `pytest` tests are synthetic API/HTTP tests and do not prove a live
Pangolin release works. Image smoke tests in `docs/verification.md` verify the
application image in a network-disabled container, also without live Pangolin.
Neither is a Traefik/Badger end-to-end authentication test. No SSO login, OIDC
provider, forwarded identity header authenticity, tunnel traffic, or actual
resource bypass enforcement is tested by this two-container topology.

To rehearse failure handling, select `exercise_failure` when dispatching, or
apply the owner-only `pangolin-compatibility-failure` PR label. This deliberately
fails after real bootstrap and must produce a failed run, visible summary,
redacted diagnostics, and successful teardown. It is also available locally:

```sh
python3 scripts/pangolin_compatibility.py --version 1.24.0 --fail-after-bootstrap
```

API unavailability, malformed response injection, partial multi-resource failures,
rate-limit internals, IP-header validation, and optional CrowdSec behavior remain
in ordinary unit tests. Live checks use no mocked API responses. Test IPs at the
connector boundary are documentation-reserved; HTTP rejection tests use their
loopback socket address. The simulated restart reloads the real JSON state and
clears caches; it does not restart a deployed application container. Production
HTTPS startup is not run or relaxed. See [API inventory](pangolin-api-contracts.md)
for consumed fields, existing unit coverage, and pre-existing limitations.

To add a live check, extend `tests/compatibility/live_checks.py`, use the generated
fixtures and actual application calls, verify upstream effects as well as state,
and emit a named PASS only after all assertions in that category finish. Add a
new release only after verifying its official manifest digest and source bootstrap
contracts, then extend the version allowlist and workflow choice/matrix. Never
add an arbitrary API URL override.

After both versions pass reliably, add a weekly
schedule and narrowly scoped infrastructure-change triggers in a separate
reviewed change. Keep compatibility execution separate from ordinary unit and
container CI.

Result interpretation: both pass means no regression in tested functionality;
baseline pass/candidate fail needs upstream investigation; both fail suggests a
harness or common application issue; baseline fail/candidate pass needs review
of version-specific behavior or baseline setup. A bootstrap, image-pull, or
cleanup failure is not itself evidence of an upstream API regression.
