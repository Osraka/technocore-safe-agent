# Least-Privilege Controller Threat Model

## Purpose

The controller is a separate Ed25519 identity for requesting four bounded,
idempotent responder commands. It prevents the responder from authorizing its
own DID and avoids broad `--allow-any-signed` operation.

The controller is not an administrative shell, GitHub writer, or general
message sender. Its accepted command set is fixed in code:

- `/ping`
- `/status`
- `/about`
- `/help`

There is no free-form text option, `/pr`, repository scope, room override, base
URL override, or command selected by a room message.

## Create

```console
technocore-safe-agent controller create
```

The default public record is
`~/Library/Application Support/Technocore/Osraka/controller-identity.json`.
The command requires its existing parent directory to be a real, owner-only
directory. The public JSON is created exclusively with mode `0600` and contains
only the DID, fingerprint, creation time, and Keychain selectors.

The 32-byte seed is generated in process memory. Creation starts the fixed
`/usr/bin/security` binary on a private pseudo-terminal, waits for its two
generic-password prompts, disables terminal echo before each response, and
discards child output. The prompt has a bounded timeout and the child is killed
and reaped on failure. The mutable response buffer is cleared before returning.

The seed is not placed in process arguments, an environment variable, a
temporary file, public JSON, or command output. The implementation cannot
guarantee erasure of immutable Python memory after use and does not claim
protection from compromise of the same operating-system account. Later reads
use the same fixed `security` binary through the existing Keychain provider.

Creation has no update mode. Existing public identities and Keychain items are
not replaced. If public-file creation fails after a new Keychain item was added,
the command attempts to remove only that newly selected service/account item.

## Grant

```console
technocore-safe-agent controller grant \
  --capability-policy /absolute/path/to/safe-agent-capabilities.json
```

The grant command validates both the controller public identity and capability
policy. It refuses every non-empty policy rather than merging with or replacing
an existing principal. The resulting grant is fixed:

| Field | Value |
| --- | --- |
| Enabled | `true` |
| Commands | `/ping`, `/status`, `/about`, `/help` |
| Repository scopes | none |
| Rolling-hour limit | 10 |

The policy remains reloadable by the responder before every decision. Disable
or remove the principal to revoke future requests; revocation cannot cancel a
request that already passed authorization.

## Send

```console
technocore-safe-agent controller send /status
```

`send` loads and verifies the controller's Keychain seed, reads the active agent
config, and uses only its configured HTTPS origin and room. A separate
non-blocking process lock prevents concurrent local controller sends. The nonce
high-water mark is atomically persisted in `controller-state.json` before the
network request, so a crash cannot reuse a previously attempted nonce.

The command validates the server acknowledgement and then exits. It does not
wait for or authenticate a later responder reply. A transport failure can be
ambiguous: the command may already exist remotely. The nonce remains consumed,
and the controller performs no automatic retry. Because all supported commands
are idempotent and have no GitHub side effect, an explicit later request has a
bounded impact, but it can still produce an additional room reply.

## State table

| Condition | Result | Network write |
| --- | --- | --- |
| Controller identity absent/unsafe | Refuse | No |
| Keychain seed missing or mismatched | Refuse | No |
| Config missing, inactive, or malformed | Refuse | No |
| Command outside the exact four-command set | Refuse | No |
| Controller lock held | Refuse | No |
| Nonce state cannot be persisted | Refuse | No |
| Signed command acknowledged | Report `acknowledged` | One |
| Transport result ambiguous | Return error; nonce remains consumed | Never auto-retry |

## Non-goals

- Provisioning or publishing a controller profile
- Allowing arbitrary users or arbitrary text
- Triggering GitHub reads or writes
- Managing repository scopes
- Proving who controls the macOS account
- Protecting the seed after compromise of the login session or Keychain
- Installing or loading the responder's LaunchAgent
