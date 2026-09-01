# Public Repository Data Governance

This repository is public. Only product source, public documentation and
synthetic fixtures may enter Git. Authorized testing data remains private even
when the tested product or endpoint is itself publicly reachable.

## Data classes

| Class | Examples | Git policy |
| --- | --- | --- |
| Public | Generic source, public dependency links, synthetic fixtures using reserved domains and addresses | Allowed after the public-data guard passes |
| Internal | Non-public hosts and paths, schemas, topology, error traces, account roles, resource identifiers | Never commit to the public repository |
| Restricted | Passwords, tokens, cookies, session state, real request/response bodies, HAR, evidence, personal data | Store only in the external private data root |

File names and screenshots are data too. A target name, browser accessibility
snapshot, local absolute path or response-derived identifier can disclose an
engagement even when no password is present.

## Storage boundary

Set `API_MANAGER_DATA_DIR` to a directory outside the repository. Existing
installations may continue reading the sibling `.secrets` directory. Fresh
installations use the current user's application-data directory.

Repository-local private storage fails closed. The temporary
`API_MANAGER_ALLOW_UNSAFE_DATA_DIR=1` override exists only for a controlled
migration and is forbidden in a governed baseline or CI.

Recommended layout:

```text
public repository/
  apiAnalysis/
  tests/                 # synthetic fixtures only
  docs/                  # public design and usage documentation only

private data root/
  uploads/
  evidence/
  credentials/
  captures/
  engagements/
```

## Synthetic-data rules

- Use `example.com`, `example.net`, `example.org`, `.test` names and RFC 5737
  documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`).
- Use explicit markers such as `example-token`, `test-password` and
  `redacted`; do not copy and then partially mask a real value.
- Generate fake resource IDs independently. Do not preserve real prefixes,
  lengths or account relationships when those characteristics are internal.
- Keep raw HAR/OpenAPI/Postman exports private. Public examples must be rebuilt
  from a minimal synthetic specification.

## Publication gates

The standard-library guard reports only rule ID, file and line; it never prints
the matched value.

```powershell
# Before staging: include tracked and unignored files.
py -3.9 tools/public_repo_guard.py --worktree

# Pre-commit view: inspect exactly what Git will commit.
py -3.9 tools/public_repo_guard.py --staged

# Public release view.
py -3.9 tools/public_repo_guard.py --tracked

# Explicit historical audit; classify every result before history changes.
py -3.9 tools/public_repo_guard.py --history
```

Install the repository hook once:

```powershell
git config core.hooksPath .githooks
```

CI repeats the tracked-tree guard. Disabling a local hook is not an approval to
publish. Changes to `.public-data-guard.json`, hook code, CI workflow or binary
allowlists require the same review as authentication code.

Local engagement identifiers and private host suffixes belong in
`.git/public-data-guard.local.json`, never in committed configuration. A local
example is created for this working copy; CI can receive equivalent deny terms
through a private runner configuration when needed.

## Binary and evidence policy

Opaque binaries, office documents, screenshots and archives are blocked unless
they are in an approved public static-asset directory and have known
provenance. Renaming a screenshot does not make it public. Evidence references
shown in public output must use an opaque `private://` reference rather than a
local filesystem path.

## Historical audit: commit `57c878f`

The 2026-08-04 history scan reports 15 findings across 14 unique locations.
They were inspected without printing the locally configured engagement terms:

| Guard result | Count | Classification |
| --- | ---: | --- |
| Local engagement term in `.gitignore` / `README.md` | 5 | Historical ignore/example wording; no secret value |
| Developer-specific absolute path | 6 | Local workstation paths; privacy metadata only |
| DOCX path and unreviewed binary | 2 | One file counted by two rules; generic design prose, with creator/last-modifier metadata |
| Unknown literal host | 1 | Public example URL, not an internal host or credential |
| RFC1918 address | 1 | Old form default/example; no authentication material |

No historical finding is a password, Token, Cookie, private key, authentication
header or live secret assignment. The original DOCX contains no embedded file,
media, external relationship, email, URL, RFC1918 address or credential-like
assignment. Its generic product ideas are preserved in
`docs/legacy_api_security_design.md`; the binary remains outside the repository.

These findings do not, by themselves, require a destructive history rewrite.
The history guard remains red so the accepted legacy metadata is not mistaken
for a clean-room history. Current worktree, staged and tracked publication gates
must still pass before every public update.

## Pre-refactor baseline

Data governance and functional refactoring must remain separate:

1. Commit policy, storage boundary, guard, tests and CI as a governance commit.
2. Classify the full worktree and history; rotate any confirmed exposed secret.
3. Stage an explicit sanitized file list, run the full tests and commit the
   runnable baseline.
4. Tag that baseline locally as the pre-refactor checkpoint.
5. Begin each architecture phase on a separate branch or milestone. Never push
   or rewrite public history as an implicit step of local cleanup.

## Incident response

If a live credential or session value enters a public commit:

1. Revoke or rotate it immediately. Deletion and force-push do not restore
   secrecy.
2. Preserve a private incident record without copying the value into issues or
   chat.
3. Remove the data from the current tree and, with explicit repository-owner
   approval, rewrite affected history and public artifacts.
4. Re-run staged, tracked and history scans before publishing again.
5. Add a generic regression rule; do not add the customer or target name to the
   public policy.
