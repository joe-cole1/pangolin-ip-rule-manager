![Build and Publish](https://github.com/joe-cole1/pangolin-ip-rule-manager/actions/workflows/docker-publish.yml/badge.svg?branch=master)

# Pangolin IP Rule Manager

A lightweight Python service that automatically manages Pangolin IP bypass rules and (optionally) CrowdSec allowlist entries based on observed client IPs. Originally built to solve a specific problem with Jellyfin and native TV apps, but applicable to any resource behind Pangolin that needs IP-based access bootstrapping.

> **Roadmap note:** A future release will generalize the service away from its Jellyfin-specific framing so it can be used more cleanly with any application behind Pangolin.

---

## The Problem It Solves

Jellyfin's native apps (Roku, Android TV, Fire TV, etc.) cannot authenticate through Pangolin's SSO flow — they have no browser context to complete the challenge. This service bridges that gap:

1. A **check-in URL** is placed behind Pangolin authentication (your phone can reach it)
2. You visit that URL on your phone — already authenticated via Pangolin
3. The service records your public IP and creates a Pangolin bypass rule for the target resource (e.g., Jellyfin) and optionally adds your IP to a CrowdSec allowlist
4. Your TV, on the same network and sharing the same public IP, can now reach Jellyfin without needing to authenticate
5. Rules expire automatically after a configurable TTL

**Known limitation:** This approach requires the phone and TV to share the same public IP address (e.g., both on home Wi-Fi). This is a known design constraint, not a bug.

The service is not limited to Jellyfin — Pangolin rules can target any resource, and `RESOURCE_IDS` accepts multiple IDs. Any app with the same native-app authentication problem can be addressed the same way.

---

## How Pangolin IP Rules Enable Selective Bypass

To understand what this service does, it helps to understand how Pangolin protects resources and what an IP rule actually changes.

### The normal Pangolin flow

When a resource (like Jellyfin) is placed behind Pangolin, every request to it is intercepted. Pangolin checks whether the requester is authenticated — typically via SSO. If they're not, they're redirected to a login page before they can reach the service at all.

This works perfectly for browsers and apps that can complete a login flow. It's the right default. Your service is protected; only authenticated users get through.

### The problem with native apps

Native apps on devices like Roku, Android TV, or Apple TV have no concept of a browser-based SSO flow. When Jellyfin's Android TV app tries to reach `jellyfin.yourdomain.com`, Pangolin intercepts it and redirects it to an auth page the app cannot render or interact with. The app sees an error. There's no way around this within the native app itself.

The standard workaround — making Jellyfin fully public — removes authentication entirely, which is not acceptable if you want your service protected by default.

### What an IP rule does

Pangolin supports IP-based bypass rules on a per-resource basis. When an IP rule exists for a given resource, Pangolin skips the authentication check for requests originating from that IP and forwards them directly to the service.

This is the mechanism this service manages. It doesn't weaken your overall Pangolin setup — Jellyfin remains behind auth for everyone else. It selectively grants pass-through for specific IPs, for a configurable period of time, and then automatically revokes it.

### The full picture

```
Without an IP rule:
  TV → Pangolin → [auth required] → ✗ (app can't authenticate)

With an IP rule for your home IP:
  TV → Pangolin → [IP rule match: bypass auth] → Jellyfin ✓
  Phone/browser → Pangolin → [auth required] → SSO login → Jellyfin ✓
  Anyone else → Pangolin → [auth required] → SSO login → Jellyfin ✓
```

The check-in step — visiting the URL on your phone — is what creates the IP rule. Your phone is already authenticated through Pangolin, so it can reach the check-in service. The service sees your public IP, creates the rule, and from that point your TV (sharing the same public IP) can reach Jellyfin directly.

Jellyfin never becomes public. The rule applies only to the specific resource IDs you configure, and it expires automatically after `RETENTION_MINUTES`. The rest of your Pangolin setup is untouched.

---

## How It Works

- Serves any request path ending in `.png` or `.gif` with a 1×1 transparent image
- Every such request is treated as a check-in: the client IP is extracted, a Pangolin IP rule is created for each configured resource, and (if enabled) the IP is added to a CrowdSec allowlist
- Browser requests (those sending `Accept: text/html`) receive a styled status page confirming the check-in result instead of the raw image
- A background thread runs cleanup on a configurable interval, removing rules and allowlist entries for IPs that haven't checked in within the retention window
- State is persisted to a JSON file so rule ownership survives container restarts

---

## Quickstart with Docker Compose

> **Recommended:** Pull the pre-built image from GHCR rather than building locally. Multi-arch images (`linux/amd64`, `linux/arm64`) are published automatically on each release.

### 1. Create your compose file

Use the provided `docker-compose.yml` as a starting point, or reference it below. Set your environment variables via a `.env` file or directly in Portainer/your orchestration tool. **Never hardcode credentials.**

### 2. Configure environment variables

See the [Environment Variables](#environment-variables) section below. At minimum you need:
- `PANGOLIN_URL`, `PANGOLIN_TOKEN`, `ORG_ID`, `RESOURCE_IDS`
- `EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY` and `EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE`

The app will **refuse to start** if the custom header variables are missing or empty.

### 3. Find your Resource IDs

Start the container once with `RESOURCE_IDS` set to any placeholder. On startup, the service queries Pangolin and prints all resources for your org with their IDs:

```
[pangolin] These are the resources for org 'your_org_id'. Use the resourceId numbers for your configuration:
  - Jellyfin (resourceId=3)
  - Immich (resourceId=5)
```

Set `RESOURCE_IDS` to the correct IDs and restart.

### 4. Configure the Pangolin resource

Create a resource in Pangolin pointing to this container (e.g., `checkin.yourdomain.com`). On that resource, configure a **custom passthrough header** — this is the shared secret that proves a request was forwarded by Pangolin rather than sent directly. See [Pangolin API and Resource Setup](#pangolin-api-and-resource-setup).

### 5. Test the check-in

Visit `https://checkin.yourdomain.com/checkin.png` from a browser. You should see the styled confirmation page. Your IP should now appear in the Pangolin bypass rules for the configured resources.

---

## Docker Compose Reference

```yaml
services:
  pangolin-ip-rule-manager:
    image: ghcr.io/joe-cole1/pangolin-ip-rule-manager:latest
    container_name: pangolin-ip-rule-manager

    environment:
      # Network
      LISTEN_PORT: "8080"

      # Pangolin connection — inject via secrets, not hardcoded
      PANGOLIN_URL: ${PANGOLIN_URL}
      PANGOLIN_TOKEN: ${PANGOLIN_TOKEN}
      ORG_ID: ${ORG_ID}
      RESOURCE_IDS: ${RESOURCE_IDS}

      # Custom header gate — REQUIRED, app will not start without these
      EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: ${EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY}
      EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE: ${EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}

      # Retention and cleanup
      RETENTION_MINUTES: "43200"       # 30 days
      CLEANUP_INTERVAL_MINUTES: "60"
      RULE_PRIORITY: "0"
      RULES_CACHE_TTL_SECONDS: "3600"

      # State
      STATE_FILE: /data/state.json

      # CrowdSec integration
      CROWDSEC_ENABLED: "true"
      CROWDSEC_ALLOWLIST_NAME: pangolin-ip-rule-manager
      CROWDSEC_CSCLI_BIN: cscli
      CROWDSEC_CMD_PREFIX: docker exec crowdsec
      CROWDSEC_CACHE_TTL_SECONDS: "3600"

      # Branding
      SITE_NAME: ""                  # shown in HTML page header/footer; leave empty to omit

      # Optional endpoints (disabled by default)
      UPDATE_ENDPOINT_ENABLED: "false"

    volumes:
      - pangolin-ip-rule-manager-data:/data
      # Required only for CrowdSec integration via `docker exec`. See security note below.
      # - /var/run/docker.sock:/var/run/docker.sock:ro

    restart: unless-stopped

volumes:
  pangolin-ip-rule-manager-data: {}
```

---

## Environment Variables

### Core — Pangolin Connection

| Variable | Default | Required | Description |
|---|---|---|---|
| `PANGOLIN_URL` | — | **Yes** | The URL of your Pangolin Integration API endpoint. This is the dedicated API URL you configure when enabling the Integration API — not your general Pangolin instance URL. For example: `https://api.yourdomain.com`. All API calls are made to `/v1/` paths under this URL. See [Pangolin Integration API docs](https://docs.pangolin.net/self-host/advanced/integration-api) for setup. |
| `PANGOLIN_TOKEN` | — | **Yes** | Bearer token for the Pangolin API. Rules will not be created or deleted without this. |
| `ORG_ID` | — | **Yes** | Your Pangolin organization ID. Used at startup to list available resources. |
| `RESOURCE_IDS` | — | **Yes** | Comma-separated list of Pangolin resource IDs to manage (e.g., `3,5,12`). Start the container once to discover IDs from the startup log. |

### Core — Security

| Variable | Default | Required | Description |
|---|---|---|---|
| `EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY` | — | **Yes** | The header name configured under **Custom Request Headers** on the Pangolin resource fronting this service. The app will not start without this. Recommended value: `pangoliniprulemanager` |
| `EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE` | — | **Yes** | The expected value of that header. Requests without this exact value receive a `403`. The app will not start without this. Recommended value: `pangolin_ip_rule_manager_authorized` — or generate a stronger secret with `openssl rand -hex 32`. |

### Core — Behaviour

| Variable | Default | Required | Description |
|---|---|---|---|
| `LISTEN_PORT` | `8080` | No | Port the HTTP server listens on inside the container. |
| `RETENTION_MINUTES` | `1440` (1 day) | No | How long after the last check-in before a rule is considered stale and removed. The compose example uses `43200` (30 days). |
| `CLEANUP_INTERVAL_MINUTES` | `60` | No | How frequently the cleanup background thread runs. |
| `RULE_PRIORITY` | `0` | No | Priority assigned to created Pangolin IP rules. |
| `RULES_CACHE_TTL_SECONDS` | `3600` | No | How long to cache Pangolin rule existence checks before re-querying the API. Reduces API traffic. |
| `STATE_FILE` | `/data/state.json` | No | Path to the persistent state file. Mount a volume at the parent directory to survive restarts. |

### CrowdSec Integration (Optional)

CrowdSec integration is disabled by default. When enabled, the service adds IPs to a named CrowdSec allowlist on check-in and removes them on expiry.

This integration uses `cscli` on the Docker host. If CrowdSec runs in a container (the typical case), set `CROWDSEC_CMD_PREFIX` to `docker exec crowdsec` and mount the Docker socket read-only.

| Variable | Default | Required | Description |
|---|---|---|---|
| `CROWDSEC_ENABLED` | `false` | No | Set to `true` to enable CrowdSec integration. |
| `CROWDSEC_ALLOWLIST_NAME` | `pangolin-ip-rule-manager` | No | Name of the CrowdSec allowlist to manage. Created automatically if it doesn't exist. |
| `CROWDSEC_CSCLI_BIN` | `cscli` | No | Path or name of the `cscli` binary. |
| `CROWDSEC_CMD_PREFIX` | _(empty)_ | No | Optional command prefix for running `cscli` in a container. Example: `docker exec crowdsec`. |
| `CROWDSEC_CACHE_TTL_SECONDS` | `3600` | No | How long to cache the CrowdSec allowlist membership before re-querying via `cscli`. |

### Optional Features

| Variable | Default | Required | Description |
|---|---|---|---|
| `SITE_NAME` | _(empty)_ | No | Name shown in the card header and footer of the HTML check-in and error pages (e.g. `yourdomain.com`). When left empty, the subtitle and footer domain are omitted entirely. |
| `UPDATE_ENDPOINT_ENABLED` | `false` | No | Enables the `/update?ip=...` endpoint. See [Manual IP Override](#manual-ip-override-update-endpoint). |
| `ACCESS_CHECK_ENABLED` | `false` | No | Enables a confirmation link on the HTML success page. |
| `ACCESS_CHECK_URL` | _(empty)_ | No | The URL to link to on the success page (e.g., `https://jellyfin.yourdomain.com`). Only used when `ACCESS_CHECK_ENABLED=true`. |

---

## Pangolin API and Resource Setup

### API Token Permissions

This service uses the [Pangolin Integration API](https://docs.pangolin.net/self-host/advanced/integration-api). You will need to enable it and generate a token in your Pangolin instance before proceeding.

Create a Pangolin API token with the following permissions — no more, no less:

- Read (list) resources in the organization
- Read (list) existing access rules for the managed resources
- Create IP-based access rules for those resources
- Delete IP-based access rules for those resources

The following screenshot shows the correct permission selections in the Pangolin UI:

![Pangolin API key permissions](pangolin-api-key-permissions.png)

### Setting Up the Pangolin Resource

This service must be exposed through a Pangolin **public resource** so that Pangolin handles authentication and forwards requests to the container.

1. In Pangolin, create a new resource (e.g., `checkin.yourdomain.com`) pointing to this container on the configured `LISTEN_PORT` (default `8080`)
2. Set the resource type to **Public** — this is intentional. The service handles its own request validation via the custom header gate described below; Pangolin authentication is not required on this resource since the check-in URL needs to be reachable by unauthenticated native apps

### Custom Passthrough Header

This is the mechanism that prevents anyone from bypassing the IP rule manager by hitting the service directly, without going through Pangolin.

Pangolin injects a configured header into every request it forwards. The service rejects any request that arrives without this header and exact value, returning `403` immediately — before any rule logic runs.

**In Pangolin:** open the resource you created above, scroll to **Custom Request Headers**, and add:

| Header name | Value |
|---|---|
| `pangoliniprulemanager` | `pangolin_ip_rule_manager_authorized` |

You may use any header name and value you choose, but they must match exactly what you set in `EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY` and `EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE`. For a stronger secret value, generate one with `openssl rand -hex 32` and use that instead.

**In your environment variables**, set:
```
EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY=pangoliniprulemanager
EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE=pangolin_ip_rule_manager_authorized
```

Any request arriving without this header — or with the wrong value — receives an immediate `403`. This applies to every path, including `.png` and `.gif` check-in URLs.

---

## Detailed Behaviour

### Startup

On startup the service:
1. Validates that `EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY` and `EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE` are set — exits with an error if not
2. Warns (but does not exit) if `PANGOLIN_TOKEN` is empty or `RESOURCE_IDS` is empty
3. Checks that the state file directory exists and is writable
4. Queries Pangolin and prints all resources for `ORG_ID` with their IDs to help with initial configuration
5. If CrowdSec is enabled, ensures the named allowlist exists (creates it if needed)
6. Loads existing state from the state file
7. Starts the background cleanup thread
8. Begins serving HTTP on `LISTEN_PORT`

### On Each Check-in Request

1. The mandatory custom header is validated — `403` if missing or wrong
2. The client IP is extracted in priority order: `X-Real-IP` → first entry of `X-Forwarded-For` → socket address. IPs from headers are validated and must be globally routable (RFC-1918, loopback, link-local, and multicast addresses are rejected and the next candidate is tried)
3. The IP is recorded in state with a `last_seen` timestamp
4. For each configured resource ID, the service checks whether a Pangolin rule already exists for this IP (using a cached result, refreshed every `RULES_CACHE_TTL_SECONDS`). If no rule exists, one is created
5. If CrowdSec is enabled and the IP is not already in the allowlist cache, it is added via `cscli`
6. The response depends on the request's `Accept` header:
   - `Accept: text/html` → styled status page showing per-target results (Pangolin, CrowdSec), the IP, and the expiry time
   - All other requests → 1×1 transparent image (PNG or GIF depending on the path extension)

### Cleanup

The background cleanup thread runs every `CLEANUP_INTERVAL_MINUTES`. For each IP in state:
- If `last_seen` is older than `RETENTION_MINUTES`, the service deletes any Pangolin rules it created (rules that were already present before the service touched them are left alone)
- If CrowdSec is enabled, the IP is removed from the allowlist
- The IP is removed from state

Only rules created by this service (tracked via `created_by_us` in state) are deleted. Pre-existing rules are never touched.

### State File

State is stored as JSON at `STATE_FILE` (default `/data/state.json`). Mount a named Docker volume at `/data` to persist it across restarts. The file is written atomically (write to `.tmp`, then `os.replace`) to prevent corruption.

---

## Optional Features

### Manual IP Override (`/update` endpoint)

When `UPDATE_ENDPOINT_ENABLED=true`, a `/update?ip=<address>` endpoint is available. This lets you manually specify which IP to allowlist rather than using the requester's IP — useful when the phone and TV are on different networks.

The endpoint is protected by the same custom header gate as all other requests. When disabled (the default), the endpoint returns `404` and gives no indication it exists.

```
GET /update?ip=203.0.113.42
```

The IP must be a valid, globally routable address. Loopback, private, and link-local addresses are rejected.

### Access Check Link

When `ACCESS_CHECK_ENABLED=true` and `ACCESS_CHECK_URL` is set, the HTML success page includes a direct link to the target resource. This lets you confirm that access is actually working after check-in — particularly useful during initial setup. The link opens in a new tab and does not involve any server-side redirect or additional request from the service.

---

## Triggering Check-in via CSS (Invisible Request)

If you want the check-in to happen automatically whenever someone loads the Jellyfin web UI — without any user action — you can embed a CSS-triggered image request. The browser fetches the check-in URL invisibly as part of rendering the page, which registers the IP without any visible change to the interface.

This is the original motivation for the 1×1 transparent image design.

Add the following to your Jellyfin custom CSS (Dashboard → General → Custom CSS):

```css
body::after {
  content: "";
  position: fixed;
  inset: -9999px;
  width: 1px;
  height: 1px;
  pointer-events: none;
  background-image: url("https://checkin.yourdomain.com/jellyfin-checkin.png");
  background-repeat: no-repeat;
}
```

Replace `https://checkin.yourdomain.com` with your actual check-in domain. The path can be anything as long as it ends in `.png` or `.gif`.

**Note:** This approach only works in the Jellyfin web UI. Native apps (Roku, Android TV, etc.) do not execute CSS, which is why the phone-based check-in flow exists in the first place. The two approaches complement each other.

---

## Security Notes

- **Custom header gate:** All requests — regardless of path — are rejected with `403` if the Pangolin passthrough header is absent or incorrect. This prevents rule injection by anyone who can reach the container directly.
- **IP validation:** IPs extracted from `X-Real-IP` and `X-Forwarded-For` headers are validated and must be globally routable. Non-global addresses are rejected and the next candidate is tried. The socket address fallback is not validated, as it is controlled by the OS/kernel rather than the caller.
- **Header redaction in logs:** `Authorization` and `Proxy-Authorization` headers are redacted in all log output. The custom passthrough header value is replaced with `<present>` or `<missing>` so the secret never appears in logs.
- **Secrets:** All credentials (`PANGOLIN_TOKEN`, `EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE`) should be stored in a secrets manager (e.g., Bitwarden) and injected at runtime. Never hardcode them in compose files or Dockerfiles.
- **Scope of deletions:** The service only deletes Pangolin rules it created itself, tracked by a `created_by_us` flag in state. It will never touch rules that existed before it ran.
- **Docker socket:** If CrowdSec is running in a container, the Docker socket must be mounted read-only (`/var/run/docker.sock:/var/run/docker.sock:ro`). Be aware that socket access grants significant host-level capability — ensure the container is otherwise locked down and not exposed to untrusted input.

---

## Key Properties

- **No external dependencies:** Python standard library only. No pip install required.
- **Multi-arch:** Published images support `linux/amd64` and `linux/arm64`.
- **Endpoints:** Any path ending in `.png` or `.gif` triggers a check-in and returns a 1×1 transparent image. Root (`/`) returns `403`. All other paths return `404`.
- **Caching:** Pangolin rule existence and CrowdSec allowlist membership are both cached in memory to minimize API and `cscli` calls. Cache TTLs are configurable.
- **Atomic state writes:** State is written via a `.tmp` → `os.replace()` pattern to prevent file corruption on crash or restart.
- **Partial failure handling:** If Pangolin succeeds but CrowdSec fails (or vice versa), the result is logged per-target. The HTML success page shows the status of each integration independently.

---

## Disclaimer

This project was created and is largely maintained with the assistance of AI tools. All generated code has been reviewed, tested, and quality-checked by the project owner before being committed. While kept intentionally simple and audited for security and correctness, it may still contain mistakes or omissions.

Always review the code, configuration, and security posture before deploying to production. Use at your own risk. Contributions, bug reports, and independent review are welcome.
