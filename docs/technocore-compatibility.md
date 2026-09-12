# Real-server compatibility gate

The agent's unit suite is not a substitute for exercising the actual upstream
HTTP server. `tests/interop/run.py` runs twelve targeted checks against the
revision in `tests/interop/server-revision.txt`, including the real client and
responder. CI runs the same entry point in a separate Linux job.

## Reproduce from a clean checkout

Use Python 3.12+ for the client, Git, and uv 0.9+ on Linux or macOS. Install the
agent as described in CONTRIBUTING. From the agent repository root:

```sh
git clone https://github.com/flop-labs/technocore-chat .interop-server
git -C .interop-server checkout --detach "$(cat tests/interop/server-revision.txt)"
uv sync --frozen --no-dev --project .interop-server
.venv/bin/python -B tests/interop/run.py \
  --server-checkout .interop-server \
  --server-python .interop-server/.venv/bin/python
```

Setup downloads public source/dependencies. The tests themselves need no
internet, credentials, live account, or Keychain. The server runs under its own
locked environment; server dependencies are not added to the agent package.
Wrong revisions, tracked source changes, missing dependencies, startup failures,
empty discovery and skipped tests fail the explicit gate. Regular unit discovery
does not recurse into this suite or silently skip it when the server is absent.

## Tested promises

| Case | Required observation |
| --- | --- |
| Signed write and Unicode normalization | Real acknowledgement matches a subsequent read |
| Nonce reuse within the tested window | Refusal, no duplicate append |
| Forged signature | Refusal, no stored message |
| Successful responder reply | Durable cursor, cleared delivery journal, verified audit chain |
| Read own reply | No response loop |
| Lost acknowledgement after server commit | Halt, pending journal, read-only recovery finds the write |
| Bootstrap and newest-N window | Start at current tail; surface a skipped prefix as a gap |
| Expired history and new write | Preserve cursor; new sequence continues forward |
| Read rate budget | JSON remains parseable and 429 preserves retry metadata |
| Plaintext budget warning | Prose is confined to the plaintext lane |
| Delegation signature, expiry and narrowing | Use upstream's checker, including large decimal nonces |
| Valid delegation without a local grant | Does not authorize our responder |

The fixture has unit tests for startup failure, deadline expiry, interruption,
cleanup, wrong pins and absent prerequisites. It reserves and inherits a
127.0.0.1 socket, clears server environment inheritance, uses a temporary store
and fresh test identities, and terminates/reaps its subprocess. An explicit
kill follows a bounded unsuccessful termination. No production endpoints or
operator scripts can be selected through the entry point.

## Limits

This is a pinned compatibility check, not certification of every protocol path
or a scan of the hosted service. The suite does not exercise the MCP transport,
all delegation adversaries, replay beyond the retention window, or Windows.
It relies on POSIX socket inheritance and the upstream POSIX server. Unit tests
still exercise the agent independently on the supported Python versions.

The reviewed upstream checkout/interpreter are trusted local test inputs, not
an arbitrary-code sandbox. Update the pin and inspect upstream changes together;
do not follow main automatically in this gate. Keep cryptographic validity,
server acceptance, local authorization and delivery recovery as separate claims.
Never reuse synthetic keys or disposable receipts as production evidence.
