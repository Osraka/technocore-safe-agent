# Technocore Safe Agent

A small, deterministic Technocore responder that reuses an existing Ed25519
`did:key` without exporting its private seed from macOS Keychain.

This is intentionally not a general-purpose autonomous agent. Technocore room
messages are anonymous or third-party input, so they are treated as data rather
than prompts. The responder recognizes five bounded commands and cannot execute
a shell, read files, invoke room-selected tools, or follow instructions embedded
in a message.

## Safety properties

- The production CLI accepts a public identity file, never a raw seed argument.
- The seed is read from macOS Keychain into process memory and matched against
  the public DID before any network operation.
- HTTPS uses Certifi's CA bundle with hostname and certificate verification
  enabled; the agent never falls back to an unverified TLS context.
- Dry-run is the default. `--send` is required for writes.
- Live mode requires either an explicit DID allowlist or the deliberately broad
  `--allow-any-signed` switch. A strict capability file can instead limit each
  DID by command, GitHub repository scope, and persistent rolling-hour quota.
- Unsigned senders, the agent's own messages, unsupported text, and non-allowlisted
  DIDs are ignored.
- GitHub receipts accept only exact `https://github.com/OWNER/REPO/pull/NUMBER`
  URLs. Reads are pinned to `api.github.com`; redirects, credentials, arbitrary
  hosts, private repositories, and GitHub tokens are not supported.
- Each receipt uses exactly three public GET requests and an in-process 60-second
  cooldown. A failed read is recorded locally and is not retried automatically.
- PR titles, bodies, comments, check names, and external links never enter a
  receipt, so GitHub-hosted text cannot become an agent instruction.
- CI is reported as `partial`, rather than `success`, when a response contains
  more records than the bounded request observed.
- First live startup defaults to the current room tail, so historical messages
  cannot unexpectedly trigger replies.
- A write that lacks a verifiable acknowledgement is never retried automatically.
- Before a production `run --send` reply starts, the exact signed envelope is
  stored atomically in `safe-agent-delivery.json`. It is cleared only after both
  the server acknowledgement and the triggering input cursor are durable.
- Production live sending and delivery recovery share a non-blocking process
  lock, preventing two local processes from mutating the same cursor and nonce
  state concurrently.
- Each message processed by production `run --send` creates a DID-signed,
  hash-chained audit record containing only bounded decision metadata. Raw room
  names, message text, PR URLs, and peer DIDs are excluded.
- The optional MCP entry point is stdio-only and read-only. It can verify a
  bounded receipt supplied as data, and exposes an audit summary only when the
  operator fixes one audit path at process startup.
- Short built-in replies use Technocore's primary signed-GET lane; the agent
  refuses an encoded URL above 8000 bytes instead of silently switching transports.
- Cursor and nonce state is written atomically with mode `0600`.
- Retention gaps are surfaced as events instead of being hidden.

## Supported commands

| Command | Reply |
| --- | --- |
| `/ping` | `pong` |
| `/status` | A minimal safety/status statement |
| `/about` | The responder's trust boundary |
| `/help` | The exact command list |
| `/pr https://github.com/OWNER/REPO/pull/NUMBER` | A portable signed public-PR snapshot |

Everything else is ignored. Non-canonical URLs, prefixes, suffixes, extra
arguments, and prompt-like instructions do not match.

## Signed contribution receipts

A receipt binds one observation to the agent's existing Ed25519 DID and the
pull request's exact head commit. It includes the public repository, PR number,
author login, open/closed and merged state, head/base SHA, merge commit SHA when
the anonymous API exposes it, bounded CI counts, GitHub's source update time, and the local
observation time.

The compact JSON wrapper contains a canonical payload, its SHA-256 digest, and a
detached Ed25519 signature. It does **not** prove authorship, code quality,
maintainer approval, or that a contribution remains in the repository later.
It proves only that the named DID signed this bounded observation.

Issue a receipt directly without posting to Technocore:

```console
technocore-safe-agent receipt \
  https://github.com/OWNER/REPO/pull/NUMBER > receipt.json
```

Verify it without Keychain or network access:

```console
technocore-safe-agent verify-receipt receipt.json
```

In room dry-run mode, `/pr` emits `would_issue_receipt` and performs no GitHub
request. In live mode, an allowlisted signed sender can request a receipt. A
GitHub lookup failure advances the input cursor and emits `receipt_failed`
locally; the agent does not loop on the same API request. If the later
Technocore write is ambiguous, the existing manual room-inspection rule still
applies and the cursor is not advanced.

See [docs/receipt-threat-model.md](docs/receipt-threat-model.md) for the evidence
boundary and failure table.

## Install

Python 3.12 and macOS are required for the production Keychain provider.

```console
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Verify custody

The default identity location is:

```text
~/Library/Application Support/Technocore/Osraka/public-identity.json
```

Run:

```console
technocore-safe-agent doctor
```

The command prints only the public DID, fingerprint, and Keychain metadata. It
does not print or export the private seed.

## Dry-run first

Provision an unlisted mailbox once:

```console
technocore-safe-agent provision --name Osraka
```

This writes a signed online marker, then stores non-secret config and cursor
state beside the public identity. It does **not** publish the mailbox in a
world-readable DID profile.

If the write result is ambiguous, provisioning stops with a `pending` config.
Inspect it without retrying:

```console
technocore-safe-agent recover
```

Only after that reports `mailbox_write_not_found`, perform one explicit retry:

```console
technocore-safe-agent recover --retry
```

If the server cannot return the mailbox's complete history, recovery reports
`mailbox_history_incomplete` and refuses the retry. In that state the original
write cannot be proven absent, so sending again could create a duplicate.

Use an allowed peer DID for the first dry-run:

```console
technocore-safe-agent run \
  --allow-did did:key:z6MkREPLACE_WITH_PEER_DID \
  --start-at zero \
  --once
```

The output uses `would_reply` for a command that would be answered. No message
is posted and no state file is written.

## Live mode

Start at the current tail on the first run:

```console
technocore-safe-agent run \
  --allow-did did:key:z6MkREPLACE_WITH_PEER_DID \
  --start-at latest \
  --send
```

After the first live run, the cursor is stored beside the public identity as
`safe-agent-state.json`; later starts resume from it. Use `--start-at saved` when
you want startup to fail rather than initialize a missing room cursor.

Only one live sender can use an identity at a time. A stale `safe-agent.lock` file
is harmless because ownership is enforced by the operating-system lock, not by
the file's presence.

### Recover an interrupted delivery

If a live write times out, the agent stops and leaves
`safe-agent-delivery.json` intact. Inspect the room without mutating state or
resending:

```console
technocore-safe-agent recover-delivery
```

If the command reports `delivery_found` or `delivery_acknowledged`, persist the
recovered nonce and input cursor, then clear the journal:

```console
technocore-safe-agent recover-delivery --apply
```

Only when complete room history proves that the signed envelope is absent does
the command report `delivery_not_found`. Retrying still requires both explicit
flags:

```console
technocore-safe-agent recover-delivery --apply --confirm-retry
```

The retry reuses the exact journaled DID, nonce, text, and signature once; it
does not generate a new envelope. Incomplete retained history or duplicate
matching records always blocks retry and state mutation. The journal contains
the public reply text and signature plus hashes and sequence metadata, never the
private seed or raw mailbox name, and is written with mode `0600`.

`--allow-any-signed` is available for an intentionally public command bot, but
it should not be used for a private collaboration agent without a clear reason.

## Least-privilege capability policy

For command- and repository-level authorization, create a private policy file:

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

Set mode `0600`, then select it instead of a legacy sender flag:

```console
chmod 600 safe-agent-capabilities.json
technocore-safe-agent run \
  --capability-policy safe-agent-capabilities.json \
  --start-at latest \
  --send
```

The file is reloaded before every signed third-party message decision. Removing
a DID or setting its `enabled` field to `false` revokes its next request without
a restart. Invalid updates halt processing before external work; the agent does
not silently retain a cached old grant. Live requests reserve their quota in
`safe-agent-state.json` before a reply or GitHub lookup, while dry-run checks do
not consume capacity.

Repository matching accepts only an exact `owner/repository` or `owner/*` scope.
The capability file is mutually exclusive with `--allow-did` and
`--allow-any-signed`. See [docs/capability-policy.md](docs/capability-policy.md)
for the complete state table, compatibility behavior, and threat boundary.

## Least-privilege controller

Create a separate controller DID rather than reusing the responder's own key:

```console
technocore-safe-agent controller create
technocore-safe-agent controller grant \
  --capability-policy "$HOME/Library/Application Support/Technocore/Osraka/safe-agent-capabilities.json"
```

The seed is generated in process memory and supplied to the fixed
`/usr/bin/security` binary through a private pseudo-terminal with echo disabled.
It is never a subprocess argument, environment variable, output field, or
filesystem value. Creation refuses to overwrite either the public identity or
an existing Keychain item. `grant` works only when the validated policy is empty
and adds exactly `/ping`, `/status`, `/about`, and `/help` with a ten-request
rolling-hour limit. It cannot grant `/pr` or repository access.

Send one exact idempotent command with:

```console
technocore-safe-agent controller send /status
```

The controller nonce is persisted before network access and the command is not
retried automatically after an ambiguous transport failure. An acknowledged
command means the command record reached Technocore; the responder must be
running separately to process it. See
[docs/controller-threat-model.md](docs/controller-threat-model.md) before
creating the persistent controller.

## Offline operational health

Before placing the responder under a process supervisor, verify its local
runtime artifacts without reading Keychain or contacting the network:

```console
technocore-safe-agent health \
  --capability-policy safe-agent-capabilities.json
```

The command validates the public identity, active config binding, cursor and
nonce state, capability policy, delivery journal, signed audit chain, and
process lock. It prints one bounded JSON event containing status codes only;
room names, DIDs, paths, journal text, and private material are omitted.

`ready` and `running` return exit code 0. `unhealthy` returns 2.
`recovery_required` returns 3 and means a valid delivery journal exists while
the live process lock is free; resolve it with `recover-delivery` before a
supervisor restarts the agent. Require a running process explicitly with:

```console
technocore-safe-agent health \
  --capability-policy safe-agent-capabilities.json \
  --expect-running
```

Use `--expected-audit-head SHA256` when an externally preserved checkpoint is
available. A missing audit log is otherwise valid before the first live
decision, but a missing state file is not: managed operation must not silently
discard its cursor or nonce history. Run `technocore-safe-agent doctor`
separately to verify Keychain custody. See
[docs/operational-health.md](docs/operational-health.md) for the full state
table and supervisor boundary.

## Conservative LaunchAgent rendering

On macOS, render a reviewed LaunchAgent definition only after the offline health
preflight succeeds:

```console
technocore-safe-agent launchd render \
  --identity "$HOME/Library/Application Support/Technocore/Osraka/public-identity.json" \
  --capability-policy "$HOME/Library/Application Support/Technocore/Osraka/safe-agent-capabilities.json" \
  --executable /absolute/path/to/.venv/bin/technocore-safe-agent
```

The command prints an XML plist to stdout. It does not create a file, install a
LaunchAgent, call `launchctl`, read Keychain, or contact the network. The
renderer requires an owner-controlled executable and private log directory,
rejects log destinations that could overwrite runtime artifacts, and emits
direct arguments rather than a shell command or environment variables.

The generated job starts from the saved cursor and uses the strict capability
policy. `KeepAlive.Crashed` restarts a signal-crashed process, but deliberate
fail-closed exits such as `unhealthy` (2) and `recovery_required` (3) remain
stopped for operator review instead of entering a restart loop. Validate and
inspect the XML before any manual `launchctl bootstrap` decision. See
[docs/launchd.md](docs/launchd.md) for the state table, safe staging sequence,
and unload/recovery boundary.

## Signed local audit log

Production `run --send` writes `safe-agent-audit.jsonl` beside the public
identity by default. Each mode-`0600` record binds the input sequence, a short
peer-DID fingerprint (or `null` for an unauthenticated sender), policy decision,
outcome, exact rendered-receipt hash when applicable, response sequence, and the
previous canonical record hash to the agent's Ed25519 DID.

Verify every schema invariant, payload digest, DID signature, sequence, and
hash-chain link without Keychain or network access:

```console
technocore-safe-agent audit verify safe-agent-audit.jsonl
```

The command prints the current `head_sha256`. Preserve a trusted checkpoint
outside the log when rollback detection matters, then verify against it:

```console
technocore-safe-agent audit verify safe-agent-audit.jsonl \
  --expected-head SHA256_FROM_A_TRUSTED_CHECKPOINT
```

Without `--expected-head`, signatures and chaining detect record changes,
insertions, reordering, and removal from the middle, but a valid old prefix made
by truncating the tail still verifies. This is a signed local integrity log, not
an externally anchored transparency service. See
[docs/audit-threat-model.md](docs/audit-threat-model.md) for its exact boundary.

## Optional read-only MCP verifier

Install the optional stable MCP SDK separately from the base agent:

```console
python -m pip install -e '.[mcp]'
```

Start the verifier over stdio:

```console
technocore-safe-agent-mcp
```

The default server publishes one tool, `verify_contribution_receipt`. It accepts
at most 4096 bytes of signed receipt JSON and returns only validation status,
the receipt schema, issuer DID, repository, PR number, and payload digest. It
does not refresh GitHub state or echo the receipt's author or raw content.

An operator can additionally expose integrity checks for one fixed audit log:

```console
technocore-safe-agent-mcp \
  --audit-log /absolute/path/to/safe-agent-audit.jsonl
```

This adds `inspect_audit_integrity`. The tool schema has no filesystem-path
argument: the model cannot select another file. Without `--audit-log`, the tool
is absent rather than present in a disabled state.

Configure an MCP host with the absolute path to the virtual environment's
entry point. The exact configuration key varies by host; its command and
arguments are equivalent to:

```json
{
  "command": "/absolute/path/to/.venv/bin/technocore-safe-agent-mcp",
  "args": ["--audit-log", "/absolute/path/to/safe-agent-audit.jsonl"]
}
```

Both tools are annotated read-only, non-destructive, idempotent, and
closed-world. These annotations are descriptive hints for MCP clients, not a
security boundary. The implementation enforces the boundary by exposing no
network transport option, Keychain access, Technocore operation, write path, or
model-selected filesystem path. See
[docs/mcp-threat-model.md](docs/mcp-threat-model.md) before enabling it in a
host that can see private prompts or files.

## Controlled live pilot

The repository includes an opt-in pilot that writes at most five bounded test
records to the configured unlisted mailbox. It creates allowlisted and
unallowlisted peer DIDs only in memory, verifies one exact reply, and confirms
that unsigned, unallowlisted, and prompt-like commands are rejected or ignored.
For an `mb-*` mailbox, the server rejects the unsigned probe with HTTP 403 before
it can become a room record.

Review the script first, then run it explicitly:

```console
PYTHONPATH=src python scripts/run_live_pilot.py --execute-live-pilot
```

The pilot never publishes a DID profile or persists either ephemeral peer key.
An ambiguous write still halts the process for manual inspection; the pilot does
not weaken or bypass that delivery rule.

For a single end-to-end receipt check, use the narrower PR pilot. It creates one
ephemeral allowlisted DID in memory, writes one canonical `/pr` command, and
requires exactly one attributable, portable receipt response:

```console
PYTHONPATH=src python3 scripts/run_live_receipt_pilot.py \
  --pull-request https://github.com/OWNER/REPO/pull/NUMBER \
  --execute-live-receipt-pilot
```

The PR pilot verifies both acknowledged room-message signatures before
transport and the receipt's inner portable signature after reading it back. A
GitHub lookup failure or ambiguous room write is never retried automatically.

## Processing table

| Input/state | Result | Cursor persisted in live mode? |
| --- | --- | --- |
| Own signed message | Ignore | Yes |
| Unsigned message | Ignore | Yes |
| Signed but non-allowlisted DID | Ignore | Yes |
| Unsupported or extended command | Ignore | Yes |
| Valid `/pr` in dry-run | Report intent; do not contact GitHub | No |
| Valid `/pr`, complete public evidence, acknowledged write | Post one signed receipt | Yes |
| Valid `/pr`, incomplete CI pagination | Post receipt with `ci=partial` | Yes |
| GitHub lookup/rate-limit failure | Emit local failure; do not retry or post | Yes |
| Invalid/private/non-canonical PR target | Ignore without network access | Yes |
| Allowed exact command, acknowledged write | Reply once | Yes |
| Allowed command, uncertain write result | Halt with a pending delivery journal | No |
| Reply acknowledged, state persistence fails | Halt with acknowledged evidence | No |
| Recovery finds one exact reply | Apply state without resending | On explicit `--apply` |
| Recovery proves reply absent | Offer one exact-envelope retry | Only with both confirmation flags |
| Recovery sees incomplete history or duplicates | Refuse retry and mutation | No |
| Retention gap | Emit warning and continue with available records | Yes |
| Dry-run | Report decisions only | No |

## Tests

The suite uses temporary directories and a loopback HTTP fixture. It does not
read the real Keychain or contact Technocore.

```console
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests
```

## Non-goals

- Running an LLM over room messages
- Executing arbitrary tools or commands
- Reading arbitrary URLs, private GitHub repositories, review text, or PR bodies
- Commenting, approving, merging, rerunning CI, or otherwise writing to GitHub
- Claiming that a signed observation proves contribution ownership or acceptance
- Automatic retries after ambiguous writes
- Claiming that the local audit log alone detects tail rollback without a trusted
  external head checkpoint
- Treating a local capability policy as protection against compromise of the
  same operating-system account
- Treating a `did:key` as proof of a real-world identity or trustworthiness
- Treating MCP tool annotations as an authorization mechanism
- Storing or publishing the private seed

## License

MIT
