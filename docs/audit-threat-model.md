# Signed Audit Log Threat Model

## Purpose

`safe-agent-audit.jsonl` is a bounded, local account of decisions made by the
production `run --send` responder. It supports offline integrity checks without
macOS Keychain or network access. It is not an authorization source and does not
replace the delivery journal or cursor state.

## Recorded fields

Each fixed-schema payload contains:

- Audit and input sequence numbers
- The agent's public issuer DID
- A UTC observation timestamp
- Whether the sender was authenticated
- A 16-hex-character peer-DID fingerprint, or `null`
- Policy decision and reason
- Final local outcome
- SHA-256 of the exact rendered signed receipt, when one was sent
- Response sequence, when one was acknowledged
- SHA-256 of the previous canonical audit wrapper

The payload is hashed and signed by the agent's Ed25519 identity. The complete
wrapper is then hashed to form the next link.

The log deliberately excludes:

- Room or mailbox names
- Message and reply text
- Full peer DIDs
- Pull-request URLs and repository names
- Private keys, Keychain values, and delivery signatures

The issuer DID remains public because it is required to verify each signature.
The short sender fingerprint is correlation metadata, not proof of a person's
identity and not an authorization decision.

## Detected failures

Offline verification rejects:

- Invalid or unknown schemas and fields
- Duplicate JSON keys, partial JSONL lines, or oversized files/records
- Group- or world-accessible file permissions
- Modified payloads or signatures
- Mixed issuer DIDs
- Non-contiguous audit sequences
- Broken previous-record links
- Inconsistent decision, outcome, receipt-hash, and response-sequence fields
- A head that differs from an explicitly supplied trusted checkpoint

## Important limits

A self-contained valid prefix remains cryptographically valid. An attacker who
can replace the file with an older complete prefix can therefore hide records
from the tail unless the verifier supplies a previously saved
`--expected-head`. Whole-file deletion is likewise visible operationally but
cannot be disproved from a missing file alone.

The log records normal messages processed by production `run --send`. It does
not currently cover provisioning, standalone `receipt`, controlled pilot
scripts, or `recover-delivery`. Delivery recovery remains governed by the
separate exact-envelope journal. If audit persistence fails after a response was
acknowledged, the agent halts before cursor persistence and leaves the
acknowledged delivery journal for explicit recovery; it does not retry the
response automatically.

The file is capped at 16 MiB and each canonical line at 16 KiB. Reaching the
limit fails closed for further audit appends. Rotation and external anchoring
are intentionally not automated in this version.
