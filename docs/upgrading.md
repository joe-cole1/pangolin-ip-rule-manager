# Upgrade guide

Choose the instructions for the version you are running, rather than repeating
every historical migration. [GitHub Releases](https://github.com/joe-cole1/pangolin-ip-rule-manager/releases)
lists published versions and their release notes.

| Upgrade path | Migration required |
|---|---|
| v3.0.0 or v3.0.1 → v3.0.2 | None. Follow the deployment and verification steps below. |
| v2.x or earlier → v3.x | Complete the v3.0.0 breaking changes below before replacing the container. |

## v3.0.2: upgrading from v3.0.x

This patch release fixes state persistence after restart and updates the Python
3.14 runtime. It introduces no new environment variables, API permissions,
Compose requirements, or state-file format changes. Python is included in the
image; the Docker host does not need a Python upgrade.

### Deploy

1. Record the currently deployed image tag or digest. Stop the app briefly and
   back up its persistent `/data` volume and deployment configuration using your
   normal backup process. Preserve the existing volume throughout the upgrade.
2. After the release image is published, set the app's image to
   `ghcr.io/joe-cole1/pangolin-ip-rule-manager:3.0.2`. Explicit version tags make
   deployment and rollback easier to track than `latest`.
3. Pull the image and recreate only the app service. From the directory
   containing your existing Compose configuration:

   ```sh
   docker compose pull pangolin-ip-rule-manager
   docker compose up -d --no-deps --force-recreate pangolin-ip-rule-manager
   ```

   In Portainer, update the existing stack's image and redeploy with image
   pulling enabled. Keep the existing environment, network, and volume settings.
   A normal container restart does not install a new image. Do not delete the
   data volume or run `docker compose down -v`.
4. Verify the deployment before removing the previous image or backup.

### Verify

- Confirm the container becomes healthy and startup logs contain no state-load
  or state-write errors. Container health alone does not test Pangolin access.
- Open the check-in URL through normal Pangolin user authentication. Check the
  HTML result and inspect the managed resource's IP rule; HTTP 200 or a returned
  image alone does not prove access was granted.
- Confirm the reported public IP is correct, only resources permitted to that
  user gain access, and the saved state reflects the check-in. If CrowdSec is
  enabled, verify its result too.
- Use the [disposable compatibility suite](pangolin-compatibility.md) to exercise
  rule creation, expiry, ownership preservation, and state reload before changing
  Pangolin versions. Proxy authentication still requires the
  [manual proxy checks](../README.md#upgrade-validation).

The state-persistence fix keeps the HTTP handler and cleanup code attached to the
same loaded state. It preserves valid records already on disk, but cannot
reconstruct records or timestamps lost before this upgrade. If you observed
missing registrations or stale expiry times, compare saved state with the rules
on managed resources before relying on their cleanup. An existing rule without
ownership state is treated as external and is not automatically claimed or
deleted by the manager.

### Roll back

Select the previously recorded image tag or digest and repeat the pull/recreate
steps with the same configuration and persistent volume. No state-format
conversion is needed between v3.0.x versions. Restore the backup only if the
state itself needs recovery, with the app stopped; restoring it discards
registrations made after that backup. Rolling back also restores that version's
known bugs, including the restart persistence issue in v3.0.1.

## v3.0.0 breaking changes: upgrading from v2.x

These requirements were introduced in **v3.0.0**. They also apply when skipping
directly from v2.x or an older release to v3.0.2. Existing v3 installations that
already completed the migration do not need new credentials or permissions.

1. **Upgrade Badger to v1.4.1 or newer.** It must forward both `Remote-User-Id`
   and `Remote-User` after Pangolin user authentication. Keep the check-in
   resource behind user authentication; PIN, passcode, email, or header-only
   resource authentication does not provide this user identity.
2. **Add List Users to the app's existing organization API key.** In Pangolin,
   open **Organization → API Keys**, select the key, open **Permissions**, enable
   **List Users** under **Organization**, and save. The token value does not
   change, so `PANGOLIN_TOKEN` does not need replacement. Keep the key limited
   to the [documented permissions](../README.md#api-token-permissions); do not
   enable **Allow All** or use a root key. The old **Get Organization User**
   permission is no longer used and may be removed after the upgrade.
3. **Configure the proxy secret.** Follow
   [Set the Pangolin Proxy Secret](../README.md#set-the-pangolin-proxy-secret).
   Set `PROXY_SHARED_SECRET` in the app and the identical value as the check-in
   resource's `X-Proxy-Secret` **Custom Request Header**. Keep the secret out of
   Custom Response Headers and keep the app port private.
4. Back up state, pull the target image, recreate the container, and verify an
   authenticated check-in as described above. A missing prerequisite makes
   check-ins fail closed rather than granting broader access.

For the original release context, see the
[v3.0.0 release notes](https://github.com/joe-cole1/pangolin-ip-rule-manager/releases/tag/v3.0.0).
