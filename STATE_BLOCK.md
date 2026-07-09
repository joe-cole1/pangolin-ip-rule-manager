# STATE_BLOCK — Architecture & Context Understanding

One major finding/fact per line, referenced by ID from the remediation plan.

## Architecture / data flow
- A1: Entry point `app.py` — loads env config at import, builds `PangolinContext` factory, registers `TARGETS` (Pangolin always, CrowdSec optional), starts daemon cleanup thread, serves via stdlib `HTTPServer` bound to `0.0.0.0:LISTEN_PORT` (app.py:576-582).
- A2: `request_handler.py` — factory `create_image_request_handler(ctx)` returns a `BaseHTTPRequestHandler`; routes: `/update?ip=` (opt-in), any `*.png`/`*.gif` (check-in beacon), `/` → 403, everything else → 404.
- A3: IP extraction precedence: `X-Real-IP` → first `X-Forwarded-For` value → socket address; header values must parse and be globally routable; socket fallback unvalidated (request_handler.py:221-254).
- A4: Authorization chain: `Remote-User` header (set by Pangolin SSO) required → `pg_filter_resources_for_user` (role match OR direct-user assignment per resource, fail-closed on any API error) → rules created only for authorised resources (app.py:246-320, pangolin_connector.py:298-331).
- A5: `pangolin_connector.py` — all Pangolin REST calls through injected `http_json` (urllib, Bearer token, 20s timeout, HTTPS enforced at startup); `_retry` 3 attempts exp backoff, aborts immediately on 401/403.
- A6: `crowdsec_connector.py` — shells out to `cscli` via `subprocess.run` (list args, no shell), optional `docker exec` prefix split with `shlex`; IPs validated with `ipaddress`, allowlist name regex-validated.
- A7: State: JSON at `STATE_FILE` (`/data/state.json`), per-IP `last_seen` + `resources.{rid}.created_by_us`; chmod 600; atomic-ish write via `.tmp` + `os.replace` (app.py:118-141).
- A8: Cleanup thread runs every `CLEANUP_INTERVAL_MINUTES`; deletes Pangolin rules only when `created_by_us: true`; retries on failure; always attempts CrowdSec expiry (app.py:337-422).
- A9: Two TTL caches: per-resource Pangolin rule IP sets (`rules_cache`, 1h default) and CrowdSec allowlist membership; plus per-IP rate-limit result cache (`RATE_LIMIT_SECONDS`, 300s default) (app.py:84-96, 271-318).
- A10: Runtime is Python 3.14 stdlib only; `requirements.txt` (pytest, ruff) is dev-only; 185 tests pass; `ruff check`/`format --check` clean as of this audit.

## Deployment / infrastructure
- D1: `Dockerfile` — `python:3.14-alpine` (tag-pinned, not digest-pinned), installs `docker-cli` unconditionally, non-root `appuser`, HEALTHCHECK is `pgrep -f app.py` (process-alive only, not HTTP).
- D2: `docker-compose.yml` — pulls `ghcr.io/joe-cole1/pangolin-ip-rule-manager:latest`; cpu/mem limits set; socket-proxy pattern documented but commented out; no `cap_drop`/`no-new-privileges`/`read_only` hardening.
- D3: `docker-publish.yml` — on release publish, buildx multi-arch push to GHCR; actions SHA-pinned; tags ONLY `type=semver,pattern={{version}}` — a `latest` tag is never produced/updated, yet compose references `:latest`.
- D4: `docker-image.yml` — CI build on push/PR, multi-arch, no cache, image tagged `my-image-name:$(date +%s)` and discarded (build-only smoke test).
- D5: `python-package.yml` — single job with `contents: write` + `pull-requests: write`; on push it auto-fixes with ruff and opens a PR (peter-evans/create-pull-request); on PR it checks only; pytest runs after.
- D6: `.github/dependabot.yml` — covers `github-actions` (daily) and `docker` (weekly) only; NO `pip` ecosystem despite `requirements.txt` (git history shows past pip Dependabot PRs, so coverage regressed).
- D7: Production runs on an Oracle VPS next to Pangolin/Traefik/CrowdSec/Portainer; no staging; Pangolin outage = all services down (per CLAUDE.md).

## Key security-relevant observations (expanded in REMEDIATION_PLAN.md)
- S1: Trust in `Remote-User`/`X-Real-IP` headers is purely topological — no shared-secret verification that requests traversed Pangolin/Traefik; a former custom-header check (`EXPECTED_PANGOLIN_CUSTOM_HEADER_*`) was removed (tests/test_app.py:976-1024 document the removal).
- S2: `_build_checkin_html` interpolates `PANGOLIN_DETAIL`/`CROWDSEC_DETAIL` (exception text, includes `Remote-User` and upstream API response bodies) into HTML without `html.escape` (request_handler.py:174-176); `site_name` unescaped in `SITE_NAME_SUB` (request_handler.py:155, 184).
- S3: Server is single-threaded `HTTPServer` with blocking upstream calls (3 retries × 20s timeouts) — one slow request/upstream stalls all traffic (app.py:577).
- S6: `save_state` uses a single shared `.tmp` path; cleanup thread and request handling can race the temp file (app.py:131-141).
- S7: `last_seen` is stamped and persisted to disk before authorization on both the beacon and `/update` paths (documented intentional; still a per-request disk write from unauthenticated traffic) (request_handler.py:341-347, 429-436).
- S8: `redact_headers_for_log` exists and is injected into the handler context but is never called in the request path (app.py:103-115, 441).
- S9: Templates `@import` Google Fonts (external fetch, user-IP disclosure to Google); no Content-Security-Policy header (templates/checkin.html:8, templates/error.html:8; request_handler.py:260-262).
- S10: `crowdsec_allowlist_exists` plain-text fallback uses substring match (`name in out3`) — false positive for prefix names (crowdsec_connector.py:194-198).
- S13: `Target` polymorphism defeated by `isinstance` checks and divergent `add_ip` signature (app.py:296-302, 184-198).
- S14: No LICENSE, no SECURITY.md, no pyproject.toml (ruff runs on defaults).
