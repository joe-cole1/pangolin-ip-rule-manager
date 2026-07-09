# STATE_BLOCK — Architecture & Context Understanding

One major finding/fact per line.

## Architecture / data flow
- A1: Entry point `app.py` — loads env config at import, builds `PangolinContext` factory, registers `TARGETS` (Pangolin always, CrowdSec optional), starts daemon cleanup thread, serves via stdlib `ThreadingHTTPServer` bound to `0.0.0.0:LISTEN_PORT` (app.py:594-600).
- A2: `request_handler.py` — factory `create_image_request_handler(ctx)` returns a `BaseHTTPRequestHandler`; routes: `/update?ip=` (opt-in), any `*.png`/`*.gif` (check-in beacon), `/` → 403, everything else → 404.
- A3: IP extraction precedence: `X-Real-IP` → first `X-Forwarded-For` value → socket address; header values must parse and be globally routable; socket fallback unvalidated (request_handler.py:229-262).
- A4: Authorization chain: `Remote-User` header (set by Pangolin SSO) required → `pg_filter_resources_for_user` (role match OR direct-user assignment per resource, fail-closed on any API error) → rules created only for authorised resources (app.py:256-330, pangolin_connector.py:202-235).
- A5: `pangolin_connector.py` — all Pangolin REST calls through injected `http_json` (urllib, Bearer token, 20s timeout, HTTPS enforced at startup); `_retry` 3 attempts exp backoff, aborts immediately on 401/403.
- A6: `crowdsec_connector.py` — shells out to `cscli` via `subprocess.run` (list args, no shell), optional `docker exec` prefix split with `shlex`; IPs validated with `ipaddress`, allowlist name regex-validated.
- A7: State: JSON at `STATE_FILE` (`/data/state.json`), per-IP `last_seen` + `resources.{rid}.created_by_us`; chmod 600; atomic-ish write via `.tmp` + `os.replace` (app.py:121-152).
- A8: Cleanup thread runs every `CLEANUP_INTERVAL_MINUTES`; deletes Pangolin rules only when `created_by_us: true`; retries on failure; always attempts CrowdSec expiry (app.py:347-432).
- A9: Two TTL caches: per-resource Pangolin rule IP sets (`rules_cache`, 1h default) and CrowdSec allowlist membership; plus per-(IP, user) rate-limit result cache (`RATE_LIMIT_SECONDS`, 300s default) (app.py:89-99, 281-330).
- A10: Runtime is Python 3.14 stdlib only; `requirements.txt` (pytest, ruff) is dev-only; `pyproject.toml` configures tools; 197 tests pass; `ruff check`/`format --check` clean.

## Deployment / infrastructure
- D4: `docker-image.yml` — CI build on push/PR, multi-arch, no cache, image tagged `my-image-name:$(date +%s)` and discarded (build-only smoke test).
- D5: `python-package.yml` — single job with `contents: write` + `pull-requests: write`; on push it auto-fixes with ruff and opens a PR (peter-evans/create-pull-request); on PR it checks only; pytest runs after.
- D7: Production runs on an Oracle VPS next to Pangolin/Traefik/CrowdSec/Portainer; no staging; Pangolin outage = all services down (per CLAUDE.md).
