# Offline Work Receipt Threat Model

## Claim

A `work-receipt-v1` artifact proves that the DID in `issuer` signed one bounded
execution observation from a clean checkout whose `origin` is a canonical
GitHub URL. The
observation binds the repository, exact Git commit, command argv, timeout,
result, exit code, and SHA-256 hashes and byte counts of stdout and stderr.

A valid `work-receipt-countersignature-v1` proves that a different DID signed a
claim that it independently reran the same argv at the same repository and
commit and observed the same result, exit code, and output hashes.

Neither signature proves who controlled a machine, who authored the commit,
whether the command is a meaningful test, whether dependencies were trustworthy,
or whether the code is safe.

## Artifact shape

The outer `work-receipt-envelope-v1` object contains:

- one signed `work-receipt-v1` payload
- zero or more signed `work-receipt-countersignature-v1` payloads

The primary payload contains:

- `owner/repository` derived from the checkout's canonical GitHub `origin`
- exact 40-character Git commit
- command as an argv array, never a shell string
- timeout in milliseconds
- `passed`, `failed`, or `timed_out` result
- exit code for completed commands
- SHA-256 and byte count for stdout and stderr
- start, completion, and monotonic duration observations

Raw stdout, stderr, environment variables, local checkout paths, private keys,
and Keychain selectors are not included. Command arguments are included and are
therefore public if the artifact is published; do not place secrets or private
paths in argv.

## State table

| Initial state or outcome | `create` | `countersign` |
| --- | --- | --- |
| Clean public GitHub checkout, exit 0 | Sign `passed` | Sign only on exact rerun match |
| Clean checkout, nonzero exit | Sign `failed` | Sign only on exact rerun match |
| Clean checkout, timeout | Kill the process group and sign `timed_out` | Sign only on exact rerun match |
| Dirty checkout | Refuse before execution | Refuse before execution |
| Origin is not canonical GitHub | Refuse before execution | Refuse before execution |
| Checkout changes during execution | Refuse after execution; emit no artifact | Refuse; emit no signature |
| Receipt payload or signature is modified | N/A | Refuse before execution |
| Repository or commit differs | N/A | Refuse before execution |
| Result, exit code, stdout, or stderr differs | N/A | Refuse; emit no signature |
| Worker tries to countersign | N/A | Refuse before execution |
| Same verifier signs twice | N/A | Refuse before execution |

Failed tests can be countersigned. A countersignature means "I reproduced this
exact observation," not "the work passed."

## Execution boundary

`work-receipt create` and `work-receipt countersign` execute the operator's
explicit argv directly with `shell=False`, an empty stdin, and the repository
root as the working directory. They are local operator commands, not a sandbox.
They inherit the operator's environment and permissions. Never expose either
operation as a Technocore room command, MCP tool, webhook, or other untrusted
input surface.

The runner checks that the checkout is clean before execution and remains at the
same clean commit afterward. It cannot prevent a command from accessing the
network, changing external state, modifying ignored files, or launching work
outside its process group. Timeout handling kills the command's process group,
but it cannot roll back external side effects.

## Reproducibility boundary

The offline preflight validates the origin's shape but does not contact GitHub,
so it cannot prove that the named repository exists or is public.

The artifact does not capture dependencies, compiler versions, operating-system
state, CPU architecture, locale, time, or environment variables. A strict output
hash mismatch therefore rejects many nondeterministic tests. This is deliberate:
the first schema does not normalize or silently discard differing evidence.

Use deterministic, bounded tests and pin dependencies separately. If stdout or
stderr legitimately contains timing, random paths, or unstable ordering, fix or
wrap the test so it emits deterministic output before requesting a
countersignature.

## Verification boundary

`work-receipt verify` is offline. It validates the exact schema, canonical
payload hashes, Ed25519 signatures, distinct countersigner identities, and the
links between countersignatures and primary execution evidence. It does not run
Git, execute the command, read Keychain, or contact GitHub or Technocore.

Verification cannot establish that a signer actually performed the claimed
rerun. It establishes that the DID signed that claim. Trust in the operator,
machine, dependency chain, and test selection remains external to the artifact.

## End-to-end example

Write artifacts outside the checkout so the clean-tree preflight does not treat
them as untracked work:

```console
technocore-safe-agent work-receipt create \
  --identity /private/path/worker-identity.json \
  --repository /clean/checkout \
  --timeout 120 \
  -- python -m unittest tests.test_example \
  > /private/path/worker-receipt.json

technocore-safe-agent work-receipt verify \
  /private/path/worker-receipt.json

technocore-safe-agent work-receipt countersign \
  --identity /private/path/verifier-identity.json \
  --repository /independent/clean/checkout \
  /private/path/worker-receipt.json \
  > /private/path/countersigned-receipt.json

technocore-safe-agent work-receipt verify \
  /private/path/countersigned-receipt.json
```

The two checkouts must resolve to the same public GitHub repository and commit.
The worker and verifier identity files must resolve to different Keychain-backed
DIDs.
