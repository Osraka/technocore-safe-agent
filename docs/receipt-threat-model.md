# GitHub PR Receipt Threat Model

## Claim

A `technocore-github-pr-receipt-v1` record proves that the DID in `issuer`
signed the exact canonical JSON payload. The payload is a bounded observation of
one public GitHub pull request at `observed_at`, tied to `head_sha`.

It does not prove that the issuer authored the pull request, that GitHub data is
permanent, that maintainers accepted the contribution, or that the code is safe.

## Input boundary

The room command accepts exactly:

```text
/pr https://github.com/OWNER/REPO/pull/NUMBER
```

The parser rejects HTTP, ports, credentials, query strings, fragments, trailing
paths, `.git` repository suffixes, other hosts, and extra command text. The API
client constructs three fixed paths under `api.github.com`; a room participant
cannot select the API host or path shape. Redirects are returned as errors.

## Data boundary

The signed payload includes only constrained scalar fields:

- canonical repository and PR number
- safe GitHub author login
- PR state, merged flag, and draft flag
- exact head and base SHA
- merge commit SHA only after merge and only when the anonymous API exposes it
- aggregate check/status counts and CI state
- GitHub update time and local observation time

The agent discards titles, descriptions, comments, review text, check names,
external URLs, and all response fields that can carry arbitrary prose.

## Network boundary

- Public GitHub REST only; no token or authentication header
- One PR read, one check-runs read, and one combined-status read
- TLS certificate and hostname verification enabled
- Two MiB response cap per request
- No redirect following and no automatic retry
- Sixty-second in-process cooldown between receipt attempts

The anonymous GitHub REST quota is shared by source IP. A process restart resets
the local cooldown, but does not add authentication or bypass GitHub's server-side
limits.

## CI state table

| Evidence | Receipt `ci` | `ci_data_complete` |
| --- | --- | --- |
| Any observed failure/error | `failure` | True or False |
| More records exist than the bounded response returned | `partial` | False |
| No checks or statuses exist | `no_signals` | True |
| Any observed check/status is pending | `pending` | True |
| All observed terminal signals are successful, neutral, or skipped | `success` | True |

A known failure remains a valid claim even if the result set is incomplete. A
success claim is never emitted from incomplete data.

## Delivery failures

| Failure point | Behavior |
| --- | --- |
| Invalid command or URL | Ignore; no network request |
| GitHub HTTP/schema/rate-limit failure | Emit local `receipt_failed`; advance cursor; no reply |
| Receipt exceeds Technocore limit | Treat as receipt failure; no reply |
| Technocore acknowledgement is missing | Halt; do not advance cursor or auto-retry |
| Reply acknowledged but cursor save fails | Halt for manual room inspection |

Advancing the cursor after a GitHub read failure prevents an allowlisted sender
from causing an unattended retry loop. The sender may submit a new signed command
after the cooldown or external failure is resolved.
