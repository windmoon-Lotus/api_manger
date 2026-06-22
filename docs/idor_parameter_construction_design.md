# IDOR Parameter Construction Design

## Current Foundation

The original api_manger design already has the right base pieces:

- `req_data` / `res_data`: flattened request and response parameters, including
  position, required flag, type, description, and source metadata.
- `parameter_data`: global parameter aggregation across request and response
  paths.
- `parameter_archive`: account-scoped real values collected from traffic and
  readonly harvests.
- `parameter_relation`: weak request/response relation inference based on
  value intersection or name fallback.
- `request_snapshot`: reproducible request composition from endpoint asset plus
  account-bound parameter values.
- `security_test_result.evidence_summary`: per-case evidence, including
  `parameterSources` from the current IDOR runner.

This is enough to run basic IDOR checks, but it is not enough to explain and
reuse the construction decision.

## Gap

The missing layer is an IDOR-specific parameter construction record. It should
answer:

- Which parameter was selected as a resource identifier?
- Why is it considered a resource, tenant, owner, or auth-bound parameter?
- Which account supplied the value?
- Which account is used as attacker?
- Which parameters must stay unchanged because they are auth/session/context
  parameters?
- Which parameters are replaced, replayed, omitted, or fuzzed?
- Which response fields validated or invalidated the hypothesis?

Without this layer, future runs can misjudge a parameter, and we will not know
whether the error came from parameter classification, value source, account
mixing, endpoint construction, or response judgment.

## Parameter Roles

Each request parameter should receive one security role. A role can be inferred
automatically and corrected manually.

- `resource_id`: object/resource identifier, likely safe to swap for IDOR tests.
  Examples: `remoteid`, `clientid`, `tagid`, `policy_id`, `seatid`,
  `blacklist_user_id`, `packageid`, `order_id`.
- `tenant_id`: tenant or enterprise boundary. Swap only in tenant-bound tests.
  Examples: `entid`, `ent_id`, `enterprise_id`.
- `owner_id`: account/user ownership boundary. Swap carefully; may be both
  resource selector and authorization boundary. Examples: `userid`, `user_id`,
  `account`.
- `auth_context`: authentication/session/anti-CSRF values. Do not swap during
  resource IDOR tests. Examples: `Authorization`, `Cookie`, `token`, `session`,
  `csrf`, `sign`, `timestamp`, `nonce`.
- `pagination_filter`: low-security paging and filtering values. Do not use as
  IDOR pivots. Examples: `page`, `limit`, `offset`, `keyword`, `sort`.
- `business_config`: setting/config values. Useful for mutation tests, not
  readonly IDOR pivots.
- `unknown`: needs more traffic or manual classification.

## Evidence Sources

Parameter role should be scored from multiple signals:

- Name signal: suffixes such as `id`, `ids`, `remoteid`, `userid`,
  `policy_id`, `client_id`.
- Position signal: path parameters and required query parameters are stronger
  resource candidates than optional body fields.
- Value signal: account-scoped values in `parameter_archive`.
- Relation signal: `parameter_relation` proves a value appears in a response of
  another endpoint, making it a usable construction source.
- Response signal: owner response contains the same value or related object
  fields.
- Sensitivity signal: names such as token, cookie, sign, csrf, nonce are auth
  context, not resource IDs.
- Endpoint action signal: read endpoints support readonly IDOR; write endpoints
  require cleanup or idempotent mutation strategy.

## Suggested Persistent Records

Do not overload `parameter_archive` with IDOR reasoning. Keep the raw values
there, and add two IDOR-specific collections.

### `idor_parameter_candidate`

One record per endpoint parameter.

Fields:

- `pathid`
- `method`
- `path`
- `parameter`
- `position`
- `param_type`
- `required`
- `role`
- `role_confidence`
- `reason_codes`
- `source_meta`
- `sample_values_by_account`
- `relation_refs`
- `manual_role`
- `manual_note`
- `ctime`
- `mtime`

### `idor_construction_trace`

One record per generated test case.

Fields:

- `run_id`
- `pathid`
- `case_name`
- `owner_account`
- `attacker_account`
- `selected_parameters`
- `kept_parameters`
- `mutations`
- `value_sources`
- `request_before`
- `request_after`
- `strategy`
- `strategy_reason`
- `judge_inputs`
- `verdict`
- `reason_codes`
- `evidence_ref`
- `ctime`

`selected_parameters` should include role and confidence, not only parameter
names. Example:

```json
{
  "remoteid": {
    "position": "path",
    "role": "resource_id",
    "confidence": 0.92,
    "owner_value_source": "parameter_archive:account[0]",
    "attacker_value_source": "parameter_archive:account[1]",
    "reason_codes": ["PATH_REQUIRED", "RESOURCE_NAME", "ACCOUNT_SCOPED_VALUE"]
  }
}
```

## Construction Strategies

Readonly IDOR:

1. Build owner request using owner account auth and owner resource ID.
2. Replay same owner resource ID using attacker account auth.
3. Keep auth/session context from attacker account.
4. Keep pagination/filter/default parameters stable.
5. Compare owner and attacker status, business error, object count, response
   keys, and owner value leakage.

List isolation:

1. Build the same list endpoint for account A and account B.
2. Do not force resource IDs.
3. Compare whether responses are empty, account-specific, identical public data,
   or suspicious shared business data.

Tenant boundary:

1. Treat `entid`/tenant parameters as a separate test class.
2. Only swap tenant parameters when both accounts have tenant-scoped values.
3. Higher risk, higher priority, and stricter evidence requirements.

Mutation IDOR:

1. Prefer idempotent update first: read current config, write the same body,
   attacker writes the same body.
2. For create/delete pairs, create test object with unique prefix, verify owner
   sees it, attacker attempts read/update/delete, then cleanup.
3. Store cleanup result as part of `idor_construction_trace`.

## Judgment Notes

HTTP status alone is not enough:

- `200` plus XML `API_NOT_IMPLEMENT` is `not_evaluable`, likely route mismatch
  or deprecated endpoint.
- Public configuration, advertisement, generic copywriting, module lists, and
  version data should be deprioritized or classified as public data.
- A finding becomes strong only when attacker obtains non-empty victim-owned
  business data, or attacker mutation succeeds against owner-scoped resource.

## Implementation Order

1. Add parameter candidate scoring and store it in `idor_parameter_candidate`.
2. Backfill candidates from current `raw_data`, `req_data`, `parameter_archive`,
   and `parameter_relation`.
3. Update IDOR runner to consume candidates instead of checking only whether a
   parameter came from `parameter_archive`.
4. Store every generated case in `idor_construction_trace`.
5. Add a web view for candidate role correction and trace review.
6. Use corrected roles to rerun high-sensitivity IDOR and mutation tests.

## Implemented Commands

Build or refresh endpoint parameter roles:

```powershell
py -3.9 tools\build_idor_parameter_candidates.py --out ..\.secrets\idor-parameter-candidates.private.json
```

Backfill construction traces from existing readonly IDOR results without
replaying traffic:

```powershell
py -3.9 tools\backfill_idor_construction_traces.py --check-type readonly_idor
```

The readonly IDOR runner now writes `idor_construction_trace` for new cases and
uses `idor_parameter_candidate` roles when deciding whether a request is
resource-bound. If candidates are missing, it falls back to the old
`parameter_archive` heuristic so the tool remains usable during bootstrap.
