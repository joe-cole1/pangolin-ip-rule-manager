# Pangolin API contracts consumed by the application

Inventory from `pangolin_connector.py`, `app.py`, and `request_handler.py` at
the PR #141 base. These are all eight Integration API operations the runtime
uses. Standalone organization-role listing and dashboard/bootstrap routes are
test provisioning operations, not additional runtime requirements.

Every request sends `Authorization: Bearer <apiKeyId>.<apiKeySecret>`,
`Accept: application/json`, and `Content-Type: application/json`. The key must
belong to `ORG_ID`; resource operations are checked against the resource's
organization by upstream `verifyApiKeyResourceAccess`. The action permission
in each row is also required. No root key is required by the application.

Responses normally use `{success, error, status, message, data}`. The table
describes the fields actually consumed, not every field upstream may return.
Additional response fields must not break the compatibility suite.

| Method and path | Required action | Request body | Consumed response (`data`) | Runtime handling / compatibility risk | Existing tests (`tests/test_app.py`) |
|---|---|---|---|---|---|
| `GET /v1/org/{orgId}/resources` | `listResources` | None | `resources[]`: display `name` or `resourceName`; `resourceId` or `id`. A top-level `resources` fallback is also accepted. | Startup helper, no connector retry. Failure is logged; server continues with a warning. Listing is not an authorization fallback. Pagination is not followed here. | `test_http_json_http_error_raises`, image smoke startup checks; live bootstrap tests this listing. |
| `GET /v1/org/{orgId}/users?query={username}&pageSize=100&page={page}` | `listUsers` | None | `users[]`: string `id`, exact string `username`, `roles[]` with integer `roleId`; `pagination`: integer `total`, `page`, `pageSize`. Top-level `success` must be exactly `true`. | Organization and username are URL-encoded. Exact stable ID **and** username must match before roles are trusted. Pages advance until identity is found or exhausted. Invalid schema, identity mismatch, missing key, and API errors reject authorization. A renamed ID field, changed pagination, search semantics, or missing permission will break check-in. The broken get-organization-user route is intentionally unused. | `test_get_user_info_external_oidc_uses_org_user_search`, `test_get_user_info_internal_user_uses_same_search_and_exact_match`, `test_get_user_info_rejects_spoofed_identity_pair`, `test_get_user_info_rejects_malformed_response`, `test_get_user_info_rejects_api_failure_even_with_data`, `test_get_user_info_paginates_until_exact_identity_match`, `test_get_user_info_list_users_permission_error_fails_closed`. |
| `GET /v1/resource/{resourceId}/roles` | `listResourceRoles` | None | `roles[]`: `roleId` | Role IDs intersect the verified user's current roles. Exceptions reject the whole authorization pass. Missing list defaults to empty; this parser does not independently validate the full envelope. Inline/shared-policy inheritance semantics are an upstream dependency. | `test_add_ip_to_targets_intersection_filters_by_role`, `test_add_ip_to_targets_fails_closed_on_roles_api_error`, `test_get_resource_allowed_role_ids_no_token_raises`. |
| `GET /v1/resource/{resourceId}/users` | `listResourceUsers` | None | `users[]`: `userId` | Direct-user access is ORed with role access. Both lists are fetched even if a role matches, so an HTTP failure on either denies check-in. Missing list defaults to empty. Stable user ID and inherited policy changes are compatibility risks. | `test_add_ip_to_targets_authorised_via_direct_user_assignment`, `test_add_ip_to_targets_fails_closed_on_users_api_error`, `test_get_resource_allowed_user_ids_no_token_raises`. |
| `GET /v1/resource/{resourceId}` | `getResource` | None | Direct metadata object: `name` (fallback to configured numeric ID), `fullDomain` (default empty string), `ssl` (default `true`). Returned display `resourceId` is the requested ID. | Empty `data` rejects authorization. Only authorized resources have metadata fetched. Additional request/response header fields are deliberately not returned to the user. Schema nesting or domain/TLS type changes can break links or authorization completion. | `test_add_ip_to_targets_fails_closed_on_resource_metadata_error`, `test_pangolin_124_checkin_expiry_and_recheckin_preserve_other_rules`, `test_get_resource_no_token_raises`. |
| `GET /v1/resource/{resourceId}/rules?limit=10000` | `listResourceRules` | None | `rules[]`: `match`, string `value`; delete path also consumes `ruleId`. | Existence cache accepts parseable individual IP values for `match == IP`. It does not evaluate CIDRs, action, or enabled state. No pagination beyond limit 10000. Cleanup always fetches live rules. Missing `rules` defaults to empty; live tests must assert the contract before relying on absence. Rule-ID or IP encoding changes risk duplicate creation or missed deletion. | `test_rules_cache_uses_cache`, `test_cache_expired_triggers_refresh`, `test_ensure_ip_rule_existing_rule_not_created_by_us`, `test_delete_rule_no_rule_id_returns_false`. |
| `PUT /v1/resource/{resourceId}/rule` | `createResourceRule` | `{action: "ACCEPT", match: "IP", value: ip, priority: RULE_PRIORITY, enabled: true}` | Response body not consumed; successful transport is treated as creation. | Creates only after user filtering in the application flow. On success, updates the cache, records `created_by_us: true`, and saves state. Other configured resources are still attempted after a creation error; aggregate result reports failure. A changed success envelope, non-HTTP rejection, or changed priority/action semantics must be caught by live post-create enumeration. | `test_add_ip_to_targets_pangolin_rule_creation_failure`, `test_ensure_ip_rule_partial_failure_raises`, `test_pangolin_124_checkin_expiry_and_recheckin_preserve_other_rules`. |
| `DELETE /v1/resource/{resourceId}/rule/{ruleId}` | `deleteResourceRule` | None | Response body not consumed. | Called by TTL cleanup only for state marked `created_by_us: true`. Live rule enumeration locates matching IP rule IDs. Already absent returns success; request failure returns false and state is retained for retry. Deletion evicts the existence cache. Ownership protection is enforced by the cleanup caller, not by the connector function's name. | `test_cleanup_does_not_remove_non_created_rules`, `test_delete_rule_absent_returns_true`, `test_delete_rule_success_returns_true`, `test_delete_rule_evicts_ip_from_rules_cache`, `test_cleanup_multi_resource_partial_delete`, `test_cleanup_multi_resource_full_delete`. |

`app.http_json` uses a 20-second timeout and raises a `RuntimeError` for HTTP
and URL errors. Connector calls except startup listing use up to three attempts
with 1- and 2-second backoffs. HTTP 401/403 abort retries immediately. Non-JSON
HTTP-success responses become `{raw: ...}`; this is **not** general schema
validation. Existing tests include `test_retry_aborts_immediately_on_401`,
`test_retry_aborts_immediately_on_403`, `test_retry_retries_on_non_auth_error`,
`test_retry_propagates_last_exception`, `test_http_json_url_error_raises`, and
`test_http_json_non_json_response_returns_raw`.

## Security and state boundaries

The real HTTP handler checks the proxy secret before recording state or making
API calls. It accepts exactly one canonical `Remote-User-Id` and `Remote-User`
header each. Missing, duplicate, padded, or oversized values fail closed.
Requests with a valid proxy secret may record `last_seen` before identity
authorization; an empty `resources` map is intentional and is not an access
grant. HTTP 200/image delivery alone is also not evidence of authorization.

Test anchors include `test_proxy_secret_missing_header_rejected`,
`test_proxy_secret_wrong_header_rejected`, `test_identity_header_rejects_duplicate_values`,
`test_identity_header_rejects_invalid_value`, and
`test_pangolin_124_checkin_without_identity_cannot_grant_access`.

An existing rule is recorded with `created_by_us: false` and saved immediately.
Cleanup must preserve it and other rule types such as METHOD. State load must
preserve the mapping shared with the handler; PR #137 corrected this restart
behavior. Existing coverage includes `test_pangolin_124_existing_ip_rule_is_not_claimed_or_deleted`,
`test_save_and_load_state_round_trip`, and
`test_checkin_after_load_preserves_and_saves_state`.

CrowdSec uses `cscli` subprocesses, not a Pangolin endpoint. The compatibility
runner explicitly disables it and has no Docker socket or `cscli` access.
Its validation, retry, cache, and optional-target failure behavior remain in
`tests/test_crowdsec.py` and the existing application tests.

## Pre-existing limitations, not changes in this PR

Most parsers are more permissive than `get_user_info`; malformed success bodies
are not universally rejected. The live suite must check actual API contracts
and effects rather than equate a successful HTTP request with a rule mutation.
Also, deletion of multiple matching rules returns whether **any** deletion
succeeded; a mixed per-rule deletion failure can therefore clear ownership
state early. This is distinct from per-resource failure retention already
covered by tests. Neither behavior should be silently changed to accommodate
the harness; any production fix requires a separate focused review.
