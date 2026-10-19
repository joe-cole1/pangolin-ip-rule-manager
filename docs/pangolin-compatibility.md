# Pangolin compatibility testing

Status: bootstrap milestone under validation; live rule and authorization tests
are not implemented yet. This replaces PR #141's external-instance probe. No
production endpoints, credentials, CrowdSec, or deployment files are used.

## Architecture decision

Use Docker Compose with two containers: an official Pangolin SQLite image and
a Python runner using the application's digest-pinned Python base image. Both
join a fresh `internal: true` network. No ports are published, no socket is
mounted, and neither container needs elevated capabilities. Pangolin's database
and generated files occupy a disposable named volume. Credentials are randomly
generated for each run, kept in a private temporary directory, and removed
after teardown. The repository is mounted read-only.

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
5. Remove and verify removal of every container, volume, and network bearing
   this exact generated Compose project label. Remove temporary credentials.

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
Run workflow. Before merge, the repository owner can manually apply the
`pangolin-compatibility` label to a same-repository PR. This **label event only**
launches the bootstrap check; commits and ordinary PR events do not launch it.
Remove and reapply the label to run again. The workflow has read-only repository
permissions, does not receive repository secrets, and does not persist checkout
credentials. No schedule is enabled.

## Coverage and diagnosis

The bootstrap milestone currently verifies installation, unattended admin and
resource provisioning, scoped-token authentication, resource discovery, and
environment teardown. The host script reports whether configuration, image
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

Do not add complex compatibility tests until baseline bootstrap has succeeded.
After live tests are implemented and both versions pass reliably, add a weekly
schedule and narrowly scoped infrastructure-change triggers in a separate
reviewed change. Keep compatibility execution separate from ordinary unit and
container CI.
