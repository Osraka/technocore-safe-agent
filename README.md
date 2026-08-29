# Technocore Safe Agent

A small, deterministic Technocore responder that reuses an existing Ed25519
`did:key` without exporting its private seed from macOS Keychain.

This is intentionally not a general-purpose autonomous agent. Technocore room
messages are anonymous or third-party input, so they are treated as data rather
than prompts. The responder recognizes four exact commands and cannot execute a
shell, read files, invoke tools, or follow instructions embedded in a message.

## Safety properties

- The production CLI accepts a public identity file, never a raw seed argument.
- The seed is read from macOS Keychain into process memory and matched against
  the public DID before any network operation.
- HTTPS uses Certifi's CA bundle with hostname and certificate verification
  enabled; the agent never falls back to an unverified TLS context.
- Dry-run is the default. `--send` is required for writes.
- Live mode requires either an explicit DID allowlist or the deliberately broad
  `--allow-any-signed` switch.
- Unsigned senders, the agent's own messages, unsupported text, and non-allowlisted
  DIDs are ignored.
- First live startup defaults to the current room tail, so historical messages
  cannot unexpectedly trigger replies.
- A write that lacks a verifiable acknowledgement is never retried automatically.
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

Everything else is ignored. Prefixes, suffixes, extra arguments, and prompt-like
instructions do not match.

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

`--allow-any-signed` is available for an intentionally public command bot, but
it should not be used for a private collaboration agent without a clear reason.

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

## Processing table

| Input/state | Result | Cursor persisted in live mode? |
| --- | --- | --- |
| Own signed message | Ignore | Yes |
| Unsigned message | Ignore | Yes |
| Signed but non-allowlisted DID | Ignore | Yes |
| Unsupported or extended command | Ignore | Yes |
| Allowed exact command, acknowledged write | Reply once | Yes |
| Allowed command, uncertain write result | Halt for manual inspection | No |
| Reply acknowledged, state persistence fails | Halt for manual inspection | No |
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
- Automatic retries after ambiguous writes
- Treating a `did:key` as proof of a real-world identity or trustworthiness
- Storing or publishing the private seed

## License

MIT
