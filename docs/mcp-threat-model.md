# Read-Only MCP Verifier Threat Model

## Purpose

`technocore-safe-agent-mcp` lets an MCP host verify already-created public PR
receipts and, when explicitly configured by the operator, inspect the integrity
of one local signed audit log or compare one local work-evidence input set. It is
a verifier adapter, not an autonomous agent and not a second control surface for
the live Technocore responder.

## Exposed tools

| Startup mode | Tool | Accepted input | Returned data |
| --- | --- | --- | --- |
| Default | `verify_contribution_receipt` | One receipt JSON string, at most 4096 bytes | Validity, bounded error code, schema, issuer DID, repository, PR number, payload digest |
| `--audit-log PATH` | `inspect_audit_integrity` | Optional expected head digest | Validity, bounded error code, entry count, issuer DID, current head digest |
| `--work-expectation PATH` and optional work receipt/output paths | `inspect_work_evidence` | No arguments (`{}`) | Work-evidence status and check tokens, or a generic input error |

The audit tool is not registered unless the operator supplies its path when the
server starts. Its input schema never accepts a path. Receipt verification uses
the supplied string as data and never interprets any receipt field as an
instruction, URL to fetch, or filename.

The work-evidence tool is also absent by default. `--work-receipt`,
`--work-stdout` and `--work-stderr` require `--work-expectation`. The client
cannot choose any of these paths. Both its published schema and its runtime
argument gate reject extra arguments; the runtime gate runs before file reads.

## Runtime boundary

The packaged entry point starts the MCP server with stdio transport only. It
does not expose an HTTP listener or a transport-selection flag. The tool
handlers do not:

- read macOS Keychain or the private Ed25519 seed;
- contact Technocore, GitHub, or another network service;
- send messages, update state, execute commands, or write files;
- accept a model-selected filesystem path;
- return raw receipt or audit-log content.

The MCP host still sees every tool argument and result. Do not put secrets or
private message content in a receipt argument. A host running under the same
operating-system account can independently access anything that account is
permitted to read; this server does not sandbox the host.

## File boundary

`--audit-log` is resolved once at startup and closed over by the audit tool. The
existing `SignedAuditLog.verify()` path enforces a regular file, rejects symlink
following where the platform supports `O_NOFOLLOW`, rejects all group and other
permissions, takes a shared lock, applies the 16 MiB and per-record bounds, and
validates the full schema, signature, sequence, and hash chain.

Missing files, unsafe permissions, symlinks, malformed records, bad signatures,
and expected-head mismatches all produce the same public
`audit_verification_failed` code. The result does not reveal the configured
path or the underlying exception text.

## Receipt boundary

A valid result proves only that the receipt payload and digest match its
detached Ed25519 signature for the stated DID. Verification is offline: it does
not prove that the GitHub PR still has the recorded state, that the DID belongs
to the PR author, or that maintainers accepted the contribution.

Invalid receipt results contain a bounded error code and no parsed metadata.
Inputs larger than 4096 bytes are rejected before JSON or signature validation.

## Work-evidence boundary

Work paths are expanded and made absolute at startup, without opening the files
or resolving their final symlinks. The tool reads that same configured path set
on every call and reuses `inspect_work_evidence`, not a second verifier. It
retains the CLI's regular-file, no-final-symlink, bounded-read and observable
file-change checks: expectation 32 KiB, receipt 128 KiB, each output 16 MiB.
It does not require these inputs to be audit-log files or apply audit-specific
ownership rules to them.

An input error returns `status: input_error` and the generic reason
`work_evidence_input_error`, without the path or underlying exception text.
Invalid receipts return `invalid_receipt` before opening output files. Missing
flags mean unavailable evidence (`incomplete`), while an explicitly selected
unreadable file is an input error. The other status/check values are the same as
the [offline inspector](work-evidence.md#state-table).

The operator must prepare the expectation independently, not copy it from the
delivered receipt. Startup fixes paths, not file contents: later calls inspect
the current bytes, including changes to the expectation. This is not an atomic
snapshot across files, a sandbox against a same-user process, or a proof of
output provenance. Use trusted parent directories and stable inputs; selecting
a different job requires operator reconfiguration, not a model-selected path.

Even `matches_local_expectations` does not establish that the command ran or
that the work is correct. Agreement/payment remain `not_assessed` and independent
execution remains `not_established`. No TCLK transcript, payment rail or reward
claim is verified, and no result triggers an acceptance or payment action.

## Tool annotations

All registered tools declare MCP's read-only, non-destructive, idempotent, and
closed-world annotations. Clients may use those hints for presentation or
policy, but annotations do not enforce behavior. The actual boundary is the
small registered tool set and the absence of network, write, execution,
Keychain, and arbitrary-path operations in the handlers.

## Failure table

| Condition | Result | External side effect |
| --- | --- | --- |
| Valid signed receipt | Public subject metadata | None |
| Invalid or tampered receipt | `valid=false` with bounded code | None |
| Receipt above 4096 bytes | `receipt_too_large` | None |
| Server started without audit path | Audit tool is absent | None |
| Valid configured audit log | Integrity summary | Shared file read only |
| Missing, unsafe, tampered, or mismatched audit log | Generic `audit_verification_failed` | Shared file read only |
| Work tool not configured | Tool absent | None |
| Work tool called with extra arguments | Tool error before inspection | None |
| Configured work evidence matches, differs or is incomplete | Existing work-evidence report | Configured file reads only |
| Invalid work receipt | `invalid_receipt`, outputs not read | Configured expectation/receipt reads only |
| Unreadable, unsafe or oversized work input | Generic `work_evidence_input_error` | Configured file reads only |

## Non-goals

- Acting on a receipt or audit result
- Fetching current GitHub evidence
- Publishing receipts or DIDs
- Reading arbitrary files for an MCP client
- Providing a network-accessible MCP endpoint
- Protecting data from a compromised MCP host or operating-system account
