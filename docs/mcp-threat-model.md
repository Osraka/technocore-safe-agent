# Read-Only MCP Verifier Threat Model

## Purpose

`technocore-safe-agent-mcp` lets an MCP host verify already-created public PR
receipts and, when explicitly configured by the operator, inspect the integrity
of one local signed audit log. It is a verifier adapter, not an autonomous agent
and not a second control surface for the live Technocore responder.

## Exposed tools

| Startup mode | Tool | Accepted input | Returned data |
| --- | --- | --- | --- |
| Default | `verify_contribution_receipt` | One receipt JSON string, at most 4096 bytes | Validity, bounded error code, schema, issuer DID, repository, PR number, payload digest |
| `--audit-log PATH` | `inspect_audit_integrity` | Optional expected head digest | Validity, bounded error code, entry count, issuer DID, current head digest |

The audit tool is not registered unless the operator supplies its path when the
server starts. Its input schema never accepts a path. Receipt verification uses
the supplied string as data and never interprets any receipt field as an
instruction, URL to fetch, or filename.

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

## Tool annotations

Both tools declare MCP's read-only, non-destructive, idempotent, and
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

## Non-goals

- Acting on a receipt or audit result
- Fetching current GitHub evidence
- Publishing receipts or DIDs
- Reading arbitrary files for an MCP client
- Providing a network-accessible MCP endpoint
- Protecting data from a compromised MCP host or operating-system account
