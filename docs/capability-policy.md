# Capability Policy

## Purpose

The capability policy narrows a signed DID from an all-command allowlist entry
to an explicit set of commands, GitHub repository scopes, and a persistent
rolling-hour request limit. It is an authorization input, not an identity or
trust proof.

`run` reloads the complete policy before each signed third-party message is
authorized. Removing a principal or setting `enabled` to `false` therefore
affects the next decision without restarting the process. A decision already in
progress is not cancelled retroactively.

## Schema

```json
{
  "schema": "technocore-safe-agent-capabilities-v1",
  "principals": {
    "did:key:z6MkREPLACE_WITH_PEER_DID": {
      "enabled": true,
      "commands": ["/pr"],
      "repositories": ["foundry-rs/*", "alloy-rs/alloy"],
      "max_requests_per_hour": 3
    }
  }
}
```

The parser is deliberately strict:

- The file must be a regular file owned by the current user, must use mode
  `0600`, must not be a symlink, and cannot exceed 64 KiB.
- At most 128 canonical Ed25519 `did:key` principals are accepted.
- Commands are limited to `/ping`, `/status`, `/about`, `/help`, and `/pr`.
- Repository scopes are either one exact `owner/repository` or `owner/*`.
  Matching is ASCII-safe and case-insensitive; other wildcard positions and
  `.git` suffixes are rejected.
- An enabled `/pr` grant requires at least one repository scope. Repository
  scopes without `/pr` are rejected as stale or ambiguous configuration.
- `max_requests_per_hour` is required and must be between 1 and 1000.
- Unknown fields, duplicate JSON keys, duplicate commands, and repository
  scopes that become duplicates after normalization are rejected.

Malformed or unreadable updates fail closed. The process stops before cursor
advancement or external work rather than continuing with a cached old grant.

## Decision table

| Condition | Decision | Quota consumed | External work |
| --- | --- | ---: | ---: |
| Agent's own message | `own_message` | No | No |
| Missing/invalid signed-sender metadata | `unsigned_sender` | No | No |
| DID absent from policy | `principal_not_granted` | No | No |
| Principal has `enabled: false` | `principal_revoked` | No | No |
| Unsupported command text | `unsupported_command` | No | No |
| Known command not in the grant | `command_not_granted` | No | No |
| Non-canonical `/pr` URL | `invalid_pull_request_url` | No | No |
| Canonical PR outside repository scope | `repository_not_granted` | No | No |
| Rolling-hour limit reached | `rate_limited` | No additional use | No |
| Authorized dry-run request | Normal dry-run decision | No | No |
| Authorized live request | Normal live decision | Yes, before work | Yes |

An authorized live request is reserved in `safe-agent-state.json` before a
Technocore reply or GitHub lookup starts. Failed GitHub lookups still consume
capacity. This prevents repeated failing requests from bypassing the limit. If
the reservation cannot be persisted, processing stops without performing the
external action.

The timestamps survive restart and use a rolling 3600-second window. A backward
wall-clock adjustment never moves a principal's recorded high-water timestamp
back, so changing the local clock cannot restore capacity early.

## Legacy sender flags

`--allow-did` and `--allow-any-signed` remain available for backward
compatibility. They preserve their previous all-supported-command behavior and
do not gain the new per-DID rolling limit. They are mutually exclusive with
`--capability-policy`; use the capability file when least privilege or immediate
revocation matters.

## Limits

The policy is local and unsigned. A process with permission to modify the file
can change authorization, and a process with permission to modify both policy
and state can also change rate-limit history. Mode `0600`, current-user
ownership checks, final-component symlink rejection, and the single live-agent
process lock reduce accidental or cross-user interference but do not defend
against compromise of the same operating-system account.

Policy reload is per decision. It does not interrupt a request that has already
passed authorization, and it does not revoke previously published replies or
receipts.
