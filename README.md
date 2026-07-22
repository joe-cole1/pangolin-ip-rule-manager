![GitHub release](https://img.shields.io/github/v/release/joe-cole1/pangolin-ip-rule-manager)
![Python](https://img.shields.io/badge/python-3.14-blue)
[![Build and Publish Docker Image](https://github.com/joe-cole1/pangolin-ip-rule-manager/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/joe-cole1/pangolin-ip-rule-manager/actions/workflows/docker-publish.yml)

# Pangolin IP Rule Manager

A lightweight Python service that automatically manages Pangolin IP bypass rules and (optionally) CrowdSec allowlist entries based on observed client IPs. It bootstraps trust from an authenticated device (like a phone) to a device that cannot authenticate (like a TV), while honoring each user's role-based permissions in Pangolin.

---

## Table of Contents

- [Overview](#overview)
- [The Problem It Solves](#the-problem-it-solves)
- [How It Works](#how-it-works)
  - [Pangolin IP Rules Explained](#pangolin-ip-rules-explained)
  - [Role-Based Access Control](#role-based-access-control)
  - [The Full Check-in Flow](#the-full-check-in-flow)
- [Prerequisites](#prerequisites)
  - [Pangolin Integration API](#pangolin-integration-api)
  - [API Token Permissions](#api-token-permissions)
- [Quick Start](#quick-start)
  - [Docker Compose Reference](#docker-compose-reference)
  - [Finding Your Resource IDs](#finding-your-resource-ids)
  - [Minimum Required Variables](#minimum-required-variables)
- [Configuration Reference](#configuration-reference)
  - [Pangolin Connection](#pangolin-connection)
  - [Behaviour](#behaviour)
  - [Resource Launcher Integration](#resource-launcher-integration)
  - [CrowdSec](#crowdsec)
  - [Optional](#optional)
- [Pangolin Resource Setup](#pangolin-resource-setup)
  - [SSO Authentication Requirement](#sso-authentication-requirement)
  - [Resource Setup Steps](#resource-setup-steps)
- [CrowdSec Integration](#crowdsec-integration)
- [Advanced Features](#advanced-features)
  - [Manual IP Override](#manual-ip-override-update-endpoint)
  - [Invisible Check-in via CSS](#invisible-check-in-via-css)
- [Behaviour Reference](#behaviour-reference)
  - [Startup](#startup)
  - [On Each Check-in Request](#on-each-check-in-request)
  - [Cleanup](#cleanup)
  - [State File](#state-file)
- [Security Notes](#security-notes)
- [Disclaimer](#disclaimer)

---

## Overview

When a service sits behind Pangolin's SSO, every request must be authenticated. That works for browsers, but native TV apps (Roku, Android TV, Fire TV) have no way to complete a browser-based login flow. This service solves that by letting an already-authenticated device register its public IP, which creates a temporary, per-resource bypass rule so other devices sharing that IP can reach the service directly.

Crucially, it does this **without weakening your security posture**: it identifies who is checking in, intersects their Pangolin role permissions against the resources you've configured, and only ever whitelists resources that user is actually entitled to. If it cannot positively identify the user, it creates nothing.

---

## The Problem It Solves

Jellyfin's native apps (and many others like it) cannot authenticate through Pangolin's SSO flow — they have no browser context to complete the challenge. The standard workaround, making the service fully public, removes authentication entirely. That is not acceptable if you want your service protected by default.

This service bridges the gap:

1. A **check-in URL** is placed behind Pangolin SSO authentication — your phone can reach it after logging in
2. You visit that URL on your phone and authenticate with Pangolin
3. The service identifies you, confirms which resources you are permitted in Pangolin, records your public IP, and creates a bypass rule for each permitted resource
4. Your TV, on the same network and sharing the same public IP, can now reach those services without authenticating
5. Rules expire automatically after a configurable TTL

**Known limitation:** This approach requires the phone and TV to share the same public IP address (e.g., both on home Wi-Fi). This is a known design constraint, not a bug. Carrier-grade NAT (CGNAT) weakens the trust model but does not cause a functional failure.

---

## How It Works

To understand what this service does, it helps to understand how Pangolin protects resources, what an IP rule changes, and how the service uses your Pangolin roles to decide what to whitelist.

### Pangolin IP Rules Explained

When a resource is placed behind Pangolin, every request to it is intercepted. Pangolin checks whether the requester is authenticated — typically via SSO — and if not, redirects them to a login page before they can reach the service. This is what you want... your service is protected, and only authenticated users get through.

Pangolin also supports **IP-based bypass rules** on a per-resource basis. When an IP rule exists for a given resource, Pangolin skips the authentication check for requests originating from that IP and forwards them directly to the service. This is the mechanism this service manages.

It does not weaken your overall setup. The protected resource remains behind auth for everyone else. The service selectively grants pass-through for specific IPs, for a configurable period, then automatically revokes it.

### Role-Based Access Control

The service does not blindly whitelist every configured resource for every visitor. It enforces a two-layer model:

- **`RESOURCE_IDS`** is the administrative safety gate — the complete set of resources that the service is *ever* permitted to manage.
- **Each user's Pangolin account** is the per-user entitlement filter — what that specific person is allowed to reach, either via their role or by adding them in the resource's user's access control.

On each check-in, the service computes the **intersection** of these two: the resources you've configured to allow whitelisting *and* the resources the checking-in user's account in Pangolin permits. Only that intersection is whitelisted.

This means a family member with a limited role only ever bootstraps access to the resources their role allows, even if the service is configured to manage many more. An administrator with broader permissions bootstraps access to more of them.

**Fail-closed by design.** If the service cannot identify the user (the `Remote-User` header is absent) or any required Pangolin API call fails, it whitelists nothing and returns an error. It never falls back to whitelisting everything. This is a deliberate security property: a misconfiguration or API hiccup results in *no access granted*, never *over-broad access granted*.

---

## Prerequisites

### Pangolin Integration API

This service uses the [Pangolin Integration API](https://docs.pangolin.net/self-host/advanced/integration-api). You must enable it and generate a token in your Pangolin instance before proceeding.

`PANGOLIN_URL` is the dedicated **Integration API endpoint** you configure when enabling the API (e.g., `https://api.yourdomain.com`) — not your general Pangolin instance URL. All API calls are made to `/v1/` paths under this URL.

### API Token Permissions

Create a Pangolin API token with the following permissions:
- **Get Organization User** — look up a user by username to read their roles
- **List Resources** — discover resources in the organization (used at startup)
- **Get Resource** — fetch each resource's name and public domain
- **List Allowed Resource Roles** — read which roles are permitted on each resource
- **List Resource Rules** — read existing rules for managed resources
- **List Resource Users** — read users directly assigned to a resource
- **Create Resource Rule** — create IP bypass rules
- **Delete Resource Rule** — remove expired rules during cleanup
- **Update Resource Rule** — manage existing rules

---

## Quick Start

Accomplish the Pangolin pre-requisites above.

> **Recommended:** Pull the pre-built image from GHCR rather than building locally. Multi-arch images (`linux/amd64`, `linux/arm64`) are published automatically on each release.

### Docker Compose Reference

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

      # Retention and cleanup
      RETENTION_MINUTES: "43200"       # 30 days
      CLEANUP_INTERVAL_MINUTES: "60"
      RULE_PRIORITY: "0"
      RULES_CACHE_TTL_SECONDS: "3600"

      # State
      STATE_FILE: /data/state.json

      # Branding
      SITE_NAME: ""                  # shown in HTML page header/footer; leave empty to omit

      # ---------------------------------------------------------------------------
      # Resource Launcher Integration
      # ---------------------------------------------------------------------------
      REDIRECT_TO_LAUNCHER: "false"
      REDIRECT_DELAY_SECONDS: "3"
      # PANGOLIN_DASHBOARD_URL: "https://pangolin.yourdomain.com/your_org_id"

      # ---------------------------------------------------------------------------
      # CrowdSec integration (optional — disabled by default)
      # ---------------------------------------------------------------------------
      # Use the socket-proxy block in docker-compose.yml when enabling this.
      CROWDSEC_ENABLED: "false"
      CROWDSEC_ALLOWLIST_NAME: pangolin-ip-rule-manager
      CROWDSEC_CACHE_TTL_SECONDS: "3600"
      CROWDSEC_CMD_PREFIX: "docker exec crowdsec"
      CROWDSEC_CSCLI_BIN: cscli

      # Optional endpoints (disabled by default)
      UPDATE_ENDPOINT_ENABLED: "false"

    user: "100:101"
    init: true
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777
    pids_limit: 128
    cpus: "0.5"
    mem_limit: "256M"

    volumes:
      - pangolin-ip-rule-manager-data:/data

    restart: unless-stopped

    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  pangolin-ip-rule-manager-data: {}
```

Set environment variables via a `.env` file or directly in Portainer/your orchestration tool. **Never hardcode credentials.**

The named volume is created and permissioned by Docker from the image metadata;
the non-root entrypoint also tightens volumes from earlier releases to mode
`0700` automatically. Fresh installs and upgrades require no host-side `chmod`,
`chown`, directory creation, or other setup commands.

The image includes its own `/healthz` health check, so Docker and Compose report
container health without a `healthcheck` override in the Compose file.

### Finding Your Resource IDs

Start the container once with `RESOURCE_IDS` set to any placeholder. On startup, the service queries Pangolin and prints all resources for your org with their IDs:

```
[pangolin] These are the resources for org 'your_org_id'. Use the resourceId numbers for your configuration:
  - Jellyfin (resourceId=3)
  - Immich (resourceId=5)
```

Set `RESOURCE_IDS` to the correct IDs and restart.

### Minimum Required Variables

At minimum you need:

- `PANGOLIN_URL`, `PANGOLIN_TOKEN`, `ORG_ID`, `RESOURCE_IDS`

The app will **refuse to start** if `PANGOLIN_URL` or `RESOURCE_IDS` are missing or empty.

---

## Configuration Reference

### Pangolin Connection

| Variable | Default | Required | Description |
|---|---|---|---|
| `PANGOLIN_URL` | — | **Yes** | The URL of your Pangolin Integration API endpoint (e.g. `https://api.yourdomain.com`) — not your general instance URL. All API calls are made to `/v1/` paths under this URL. |
| `PANGOLIN_TOKEN` | — | **Yes** | Bearer token for the Pangolin API. Rules will not be created or deleted without this. |
| `ORG_ID` | — | **Yes** | Your Pangolin organization ID. Used to list resources at startup and to look up users during check-in. |
| `RESOURCE_IDS` | — | **Yes** | Comma-separated list of Pangolin resource IDs the service is permitted to manage (e.g., `3,5,12`). This is the administrative safety gate; per-user role permissions further filter it. |

### Behaviour

| Variable | Default | Required | Description |
|---|---|---|---|
| `LISTEN_PORT` | `8080` | No | Port the HTTP server listens on inside the container. |
| `RETENTION_MINUTES` | `1440` | No | How long after the last check-in (in minutes) before a rule is considered stale and removed. |
| `CLEANUP_INTERVAL_MINUTES` | `60` | No | How frequently (in minutes) the cleanup background thread runs. |
| `RULE_PRIORITY` | `0` | No | Priority assigned to created Pangolin IP rules. |
| `RULES_CACHE_TTL_SECONDS` | `3600` | No | How long (in seconds) to cache Pangolin rule existence checks before re-querying. Reduces API traffic. |
| `RATE_LIMIT_SECONDS` | `300` | No | Minimum seconds between Pangolin API fan-out calls for the same IP. Repeat check-ins within this window return a cached result without calling Pangolin. Set to `0` to disable. |
| `STATE_FILE` | `/data/state.json` | No | Path to the persistent state file. Mount a volume at the parent directory to survive restarts. |

### Resource Launcher Integration

This feature allows you to seamlessly redirect users to the **Pangolin Resource Launcher** (dashboard) after a successful check-in. Instead of showing the check-in confirmation page indefinitely, users are bounced to the launcher where they can launch the resources they just unlocked. If a check-in fails, the redirection is bypassed so the user can see the error.

| Variable | Default | Required | Description |
|---|---|---|---|
| `REDIRECT_TO_LAUNCHER` | `false` | No | Set to `true` to enable automatic redirection to the Pangolin Resource Launcher upon successful check-in. |
| `REDIRECT_DELAY_SECONDS` | `3` | No | How long (in seconds) to display the check-in success page before redirecting. Set to `0` for an immediate, invisible HTTP 302 redirect. When `> 0`, a visual countdown timer is shown, and the individual app list is hidden. |
| `PANGOLIN_DASHBOARD_URL` | _(empty)_ | No | Explicitly override the destination URL for the launcher. If left empty, it is automatically derived from `PANGOLIN_URL` by stripping API paths and appending your `ORG_ID`. Example: `https://pangolin.yourdomain.com/your_org_id`. |

### CrowdSec

CrowdSec integration is disabled by default. When enabled, the service adds IPs to a named CrowdSec allowlist on check-in and removes them on expiry. See [CrowdSec Integration](#crowdsec-integration) for setup details.

| Variable | Default | Required | Description |
|---|---|---|---|
| `CROWDSEC_ENABLED` | `false` | No | Set to `true` to enable CrowdSec integration. |
| `CROWDSEC_ALLOWLIST_NAME` | `pangolin-ip-rule-manager` | No | Name of the CrowdSec allowlist to manage. Created automatically if it doesn't exist. |
| `CROWDSEC_CACHE_TTL_SECONDS` | `3600` | No | How long (in seconds) to cache CrowdSec allowlist membership before re-querying via `cscli`. |
| `CROWDSEC_CMD_PREFIX` | _(empty)_ | No | Command prefix for running `cscli`. Example: `docker exec crowdsec`. |
| `CROWDSEC_CSCLI_BIN` | `cscli` | No | Path or name of the `cscli` binary inside the CrowdSec container. |

### Optional

| Variable | Default | Required | Description |
|---|---|---|---|
| `SITE_NAME` | _(empty)_ | No | Name shown in the card header and footer of the HTML check-in and error pages (e.g. `yourdomain.com`). When empty, the subtitle and footer domain are omitted. |
| `UPDATE_ENDPOINT_ENABLED` | `false` | No | Enables the `/update?ip=...` endpoint. See [Manual IP Override](#manual-ip-override-update-endpoint). |

---

## Pangolin Resource Setup

This service must be exposed through a Pangolin resource so that Pangolin handles authentication and forwards requests to the container.

### SSO Authentication Requirement

**This is the most important and most easily missed part of the setup.**

The resource fronting this service **must use SSO/platform authentication**, not a resource password or pincode. SSO is what causes Pangolin to forward the `Remote-User` header that identifies the checking-in user.

Requiring SSO on the check-in resource is what makes role-based access control possible and what guarantees the service never grants access to an unidentified caller.

### Resource Setup Steps

1. In Pangolin, create a new resource (e.g., `checkin.yourdomain.com`) pointing to this container on the configured `LISTEN_PORT` (default `8080`)
2. Configure the resource for **SSO authentication** (see above) so `Remote-User` is forwarded
3. Confirm your API token has all the [required permissions](#api-token-permissions)

---

## CrowdSec Integration

CrowdSec integration is optional and disabled by default. When enabled, the service adds each checked-in IP to a named CrowdSec allowlist on check-in and removes it when the rule expires.

Pangolin and CrowdSec are handled independently. If one succeeds and the other fails, the HTML success page shows the status of each integration separately. A CrowdSec failure does not roll back a successful Pangolin rule, and vice versa.

### Setup

Runs `cscli` inside the CrowdSec container via `docker exec`; `docker-cli` is
always available in the image. Use the socket-proxy block in the checked-in
`docker-compose.yml` so the application receives only the Docker API operations
needed for `exec`.

```yaml
CROWDSEC_ENABLED: "true"
CROWDSEC_CMD_PREFIX: "docker exec crowdsec"
CROWDSEC_CSCLI_BIN: cscli
```

> **Security note:** A read-only bind mount does not make the Docker API
> read-only. Direct access to `/var/run/docker.sock` is effectively host-root
> access; the isolated socket proxy in `docker-compose.yml` is strongly
> recommended.

---

## Advanced Features

### Manual IP Override (`/update` endpoint)

When `UPDATE_ENDPOINT_ENABLED=true`, a `/update?ip=<address>` endpoint is available. This lets you manually specify which IP to allowlist rather than using the requester's IP — useful when the phone and TV are on different networks.

The endpoint is protected by the same role-based, fail-closed identity check as all other requests. When disabled (the default), the endpoint returns `404` and gives no indication it exists.

```
GET /update?ip=203.0.113.42
```

The IP must be a valid, globally routable address. Loopback, private, and link-local addresses are rejected.

> ***WARNING:*** THIS FEATURE IS SIGNIFICANTLY CHANGING IN A FUTURE UPDATE TO ONLY ALLOW SPECIFIC PANGOLIN ROLES (e.g. Administrator) TO UTILIZE THIS ENDPOINT. THIS WILL BE A BREAKING CHANGE ON RELEASE.

### Invisible Check-in via CSS

If you want check-in to happen automatically whenever someone loads a service's web UI — without any user action — you can embed a CSS-triggered image request. The browser fetches the check-in URL invisibly as part of rendering the page, registering the IP without any visible change to the interface. This is the original motivation for the 1×1 transparent image design.

Add the following to the web UI's custom CSS (in Jellyfin: Dashboard → General → Custom CSS):

```css
body::after {
  content: "";
  position: fixed;
  inset: -9999px;
  width: 1px;
  height: 1px;
  pointer-events: none;
  background-image: url("https://checkin.yourdomain.com/checkin.png");
  background-repeat: no-repeat;
}
```

Replace the URL with your actual check-in domain. The path can be anything as long as it ends in `.png` or `.gif`.

**Note:** This only works in a web UI. Native apps (Roku, Android TV, etc.) do not execute CSS, which is why the phone-based check-in flow exists in the first place. The two approaches complement each other.

> ***NOTE:*** This functionality will likely be removed in the future. It is causing significant conflicts with the rest of the workflow.

---

## Behaviour Reference

### Startup

On startup the service:

1. Validates that `PANGOLIN_URL` and `RESOURCE_IDS` are set — exits with an error if not
2. Warns (but does not exit) if `PANGOLIN_TOKEN` is empty or `ORG_ID` is unset
3. Checks that the state file directory exists and is writable
4. Loads existing state from the state file
5. Queries Pangolin and prints all resources for `ORG_ID` with their IDs, which also serves as a startup connectivity/auth check
6. If CrowdSec is enabled, ensures the named allowlist exists (creates it if needed)
7. Starts the background cleanup thread
8. Begins serving HTTP on `LISTEN_PORT`

### On Each Check-in Request

1. The `Remote-User` header is read. If absent, the service **fails closed**: it whitelists nothing and returns an error result with the reason in the technical details
2. The client IP is extracted in priority order: `X-Real-IP` → first entry of `X-Forwarded-For` → socket address. Header IPs must be globally routable (private, loopback, link-local, and multicast addresses are rejected and the next candidate is tried)
3. The user's `roleIds` and `userId` are looked up in Pangolin. For each resource in `RESOURCE_IDS`, the service checks whether the user's role is permitted on that resource **or** whether the user is directly assigned to it — mirroring Pangolin's own OR logic. **Any API failure here causes a fail-closed error — nothing is whitelisted**
4. For each authorized resource, a Pangolin IP rule is created (if one does not already exist), and the resource's name and domain are fetched for the success-page link
5. If CrowdSec is enabled and the IP is not already in the allowlist cache, it is added via `cscli`
6. The response depends on the request's `Accept` header:
   - `Accept: text/html` → styled status page showing per-target results, the IP, the expiry time, and an **"Open &lt;Name&gt;"** link for each whitelisted resource
   - All other requests → 1×1 transparent image (PNG or GIF depending on the path extension)

### Cleanup

The background cleanup thread runs every `CLEANUP_INTERVAL_MINUTES`. For each IP in state whose `last_seen` is older than `RETENTION_MINUTES`:

- The service deletes any Pangolin rules **it created** (tracked by a `created_by_us` flag). Rules that existed before the service touched them are left alone
- If CrowdSec is enabled, the IP is removed from the allowlist
- The IP is removed from state

The delete logic distinguishes "rule already absent" (safe to clear from state) from "delete failed" (retained for retry on the next cycle), so a transient API failure never strands a permanent state entry.

### State File

State is stored as JSON at `STATE_FILE` (default `/data/state.json`). Mount a named Docker volume at `/data` to persist it across restarts. The file is written atomically (write to `.tmp`, then `os.replace`) to prevent corruption on crash or restart.

---

## Security Notes

- **Fail-closed identity:** If the `Remote-User` header is absent or any Pangolin API call fails during authorization, the service whitelists nothing. It never falls back to granting broad access.
- **Role intersection:** A user only ever bootstraps access to resources their Pangolin account permits, regardless of how many resources `RESOURCE_IDS` contains.
- **Live user validation:** Every check-in performs a real-time lookup of the `Remote-User` value against the Pangolin API. A request with a forged or unknown username is rejected before any rule is created.
- **IP validation:** IPs from `X-Real-IP` and `X-Forwarded-For` are validated and must be globally routable. The socket address fallback is not validated, as it is controlled by the OS/kernel rather than the caller.
- **Header redaction in logs:** `Authorization` and `Proxy-Authorization` headers are redacted in all log output.
- **Secrets:** All credentials should be stored in a secrets manager (e.g., Bitwarden) and injected at runtime. Never hardcode them in compose files or Dockerfiles.
- **Scope of deletions:** The service only deletes Pangolin rules it created itself. It will never touch rules that existed before it ran.
- **Docker socket:** Only required for CrowdSec integration (`docker exec crowdsec cscli ...`). Prefer the isolated socket proxy in `docker-compose.yml`; mounting the raw socket read-only does not restrict Docker API operations.

---

## Disclaimer

This project was created and is largely maintained with the assistance of AI tools. All generated code has been reviewed, tested, and quality-checked by the project owner before being committed. While kept intentionally simple and audited for security and correctness, it may still contain mistakes or omissions.

Always review the code, configuration, and security posture before deploying to production. Use at your own risk. Contributions, bug reports, and independent review are welcome.
