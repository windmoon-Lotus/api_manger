# Internal High-Risk Security Testing Rules Of Engagement

This document defines how to run authorized internal high-risk security testing
with api_manger and local methodology libraries such as Claude-BugHunter.

The goal is to find and fix serious risks internally before external discovery,
while keeping tests controlled, attributable, reversible, and auditable.

## Core Principles

- Test only company-owned or explicitly authorized assets.
- Prefer internal discovery over external discovery, but do not turn controlled
  testing into blind scanning.
- Every high-risk test must have a clear target, purpose, execution window,
  expected impact, stop condition, and rollback/cleanup plan.
- Evidence must be sufficient for engineering remediation, not excessive.
- Credentials, tokens, cookies, raw responses, and real user/resource IDs stay
  in local private storage such as `D:\接口测试\.secrets`.
- Findings must be validated before escalation; `potential_vuln` is not the
  same as a confirmed vulnerability.

## Authorization Record

Before running a high-risk round, record:

- Project name
- Business owner
- Security owner
- Approved operator
- Date and time window
- Authorized domains, IPs, apps, APIs, tenants, accounts, and environments
- Whether formal domains are mapped by local hosts to test/pre-release backends
- Allowed test levels
- Explicitly forbidden actions
- Emergency contact and stop procedure
- Evidence storage path

Recommended storage:

- RoE summary: `docs\security_profiles\` or project docs
- Secrets and raw evidence: `D:\接口测试\.secrets`
- Persistent conclusions: `security_test_run`, `security_test_result`

## Test Levels

### L1: Passive And Readonly Review

Allowed by default after project authorization.

Examples:

- Apifox/OpenAPI asset import
- endpoint inventory
- parameter and schema analysis
- source/document review
- version and configuration review from provided data
- readonly API requests with approved test accounts
- IDOR/list-isolation checks that do not mutate data

Controls:

- Low request volume
- No broad internet recon unless scoped
- No write/delete/update actions

### L2: Authenticated Functional Security Tests

Allowed when approved test accounts are provided.

Examples:

- horizontal authorization checks
- role/permission comparison
- SSO/session expiration behavior
- tenant boundary checks
- readonly data exposure validation
- controlled negative tests with invalid or missing auth

Controls:

- Use approved accounts only
- Do not brute force, spray, or enumerate at scale
- Record owner/attacker account roles
- Store construction trace for IDOR/authz checks

### L3: Controlled Mutation Tests

Requires explicit approval for the target feature class.

Examples:

- create/delete pair tests
- idempotent update tests
- update then restore tests
- bind/unbind with disposable resources
- limited file upload using benign test files

Controls:

- Small batch only
- Unique test object prefix
- Cleanup endpoint identified before execution
- Cleanup status recorded
- Stop if cleanup fails twice or unknown side effects appear
- Do not run blind payload lists

### L4: High-Risk Single-Point Validation

Requires written approval per target or per test family.

Examples:

- cloud IAM permission-chain validation
- SSO/identity provider edge-case validation
- external perimeter appliance CVE exposure confirmation
- APK dynamic instrumentation against approved builds
- supply-chain exposure verification
- high-impact business logic mutation

Controls:

- One target at a time
- Manual review before execution
- No mass scanning
- No persistence
- No stealth/evasion
- No destructive exploitation
- Clear rollback or safe-stop path
- Security/infra owner notified when appropriate

### L5: Out Of Scope For This Assistant

Do not execute through this workflow.

Examples:

- malware development
- command and control
- persistence
- EDR/AV bypass
- credential theft
- LSASS dumping
- lateral movement
- domain takeover actions
- destructive exploitation
- exfiltration beyond minimal proof
- unauthorized third-party testing

The assistant may help write a governance plan, tabletop scenario, detection
logic, or safe manual checklist for these areas, but should not directly execute
or provide operational steps that enable abuse.

## Domain-Specific Guidance

### API And Web Authz

Default tools:

- api_manger Apifox import
- `parameter_archive`
- `idor_parameter_candidate`
- `idor_construction_trace`
- readonly IDOR/list isolation runners
- controlled mutation runners

Useful Claude-BugHunter references:

- `hunt-idor`
- `hunt-auth-bypass`
- `hunt-business-logic`
- `hunt-api-misconfig`
- `hunt-session`
- `triage-validation`
- `evidence-hygiene`

Allowed examples:

- owner resource replay with attacker auth
- tenant boundary checks with approved accounts
- create/delete pair where cleanup is known
- idempotent config update and restore

Do not:

- brute force IDs at scale
- fuzz every parameter with payload lists
- mutate real customer data
- execute unbounded delete/update tests

### SSO And Identity

Required authorization:

- target identity provider or SSO flow
- test accounts and roles
- MFA/2FA handling rules
- lockout/rate-limit safety threshold

Allowed examples:

- session expiration checks
- role switch validation
- redirect URI validation in controlled clients
- token audience/scope review
- second-factor enforcement on sensitive actions

Do not:

- password spray
- bypass or defeat MFA outside an approved test case
- enumerate real users at scale
- trigger account lockouts
- collect or reuse real user credentials

### APK / Client Testing

Required authorization:

- approved app package or build
- allowed static/dynamic analysis scope
- backend/API scope
- whether instrumentation is allowed

Allowed examples:

- static secret/config/API endpoint extraction
- certificate pinning review
- exported component review
- local storage review on test device/account
- dynamic traffic capture from approved build

Do not:

- tamper with production app distribution
- bypass payment/licensing controls outside explicit scope
- hook user devices or third-party apps
- extract secrets unrelated to the test target

### Cloud IAM

Required authorization:

- cloud account/project/subscription
- read-only vs write permission
- approved identities/roles
- allowed services

Allowed examples:

- IAM policy review
- public bucket/object review
- exposed key detection in provided repositories
- assume-role path analysis using approved accounts
- least-privilege and confused-deputy review

Do not:

- access customer data
- create persistence
- modify production IAM without change approval
- attempt privilege escalation beyond approved validation
- enumerate unrelated cloud accounts

### External Perimeter And Appliances

Required authorization:

- exact IP/domain list
- scan rate
- allowed ports/protocols
- CVE validation policy
- maintenance window if active probes are used

Allowed examples:

- version/banner review
- configuration exposure check
- authenticated admin-panel review with approved accounts
- non-destructive CVE precondition validation

Do not:

- run exploit chains that change state
- DoS, stress, or crash services
- bypass IDS/IPS
- use stealth or evasion
- scan broad ranges outside the approved list

### Supply Chain

Required authorization:

- organization repositories
- package namespaces
- CI/CD systems
- container registries
- third-party boundaries

Allowed examples:

- dependency confusion risk analysis
- GitHub Actions workflow review
- exposed secret scanning in company-owned repos
- package namespace ownership review
- artifact visibility review

Do not:

- publish lookalike packages
- compromise upstream projects
- access private third-party repos
- use real secrets outside validation and rotation flow

## Execution Checklist

Before execution:

- Scope is documented.
- Test level is selected.
- Accounts and roles are known.
- Target list is explicit.
- Expected side effects are understood.
- Cleanup/rollback is defined.
- Evidence path is selected.
- Stop condition is defined.

During execution:

- Run small batches.
- Record commands and tool names.
- Store raw evidence privately.
- Watch for token expiration and route mismatch.
- Stop on unexpected side effects.
- Clean up test objects promptly.

After execution:

- Confirm cleanup status.
- Summarize results by target and verdict.
- Mark `potential_vuln` for validation, not automatic escalation.
- Record skipped cases and missing prerequisites.
- File remediation-ready reports only after validation.

## Evidence Rules

Private evidence may include:

- full request/response bodies
- real resource IDs
- owner/attacker account indexes
- raw error bodies
- cleanup responses

Private evidence must remain under `.secrets`.

Reports and docs should include:

- endpoint method and path
- sanitized request shape
- account role relationship
- status codes
- business error summary
- impact statement
- cleanup result
- evidence reference

Reports and docs should not include:

- passwords
- Bearer tokens
- cookies
- raw private customer data
- unrelated PII
- full HAR files

## Validation Gate For Findings

Before promoting a result to a vulnerability:

1. Is the target in authorized scope?
2. Can the issue be reproduced from a fresh session?
3. Is the attacker account not supposed to access or mutate the resource?
4. Is the response or mutation business-impactful, not only HTTP `200`?
5. Is the behavior not documented or expected for this role?
6. Is the evidence enough for engineering to reproduce?
7. Was cleanup completed or residual state recorded?

If any answer is no, keep the record as `need_review` or `not_evaluable`.

## How To Use Claude-BugHunter

Use it as a reference library:

- API/Web authz: `hunt-idor`, `hunt-auth-bypass`, `hunt-business-logic`
- Evidence: `evidence-hygiene`
- Validation: `triage-validation`
- Reporting: `report-writing`, `redteam-report-template`
- APK: `apk-redteam-pipeline`
- Cloud/identity/perimeter: only after explicit L4 scope approval

Do not use it as:

- a blind scanner
- an automatic payload runner
- a reason to expand scope
- a source of post-exploitation actions

## Recommended New-Session Context

```text
This is an authorized internal company security test. Follow
docs\internal_high_risk_security_testing_roe.md. Use api_manger for controlled
execution and result storage. Use Claude-BugHunter only as a local methodology
and checklist library. Do not run broad recon, blind scanning, destructive
payloads, stealth, persistence, or lateral movement. Keep secrets and raw
evidence under D:\接口测试\.secrets.
```
