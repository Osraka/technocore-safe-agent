# Offline Operational Health

## Purpose

`technocore-safe-agent health` is a local preflight and monitoring probe for a
managed responder. It verifies whether persisted artifacts can be used safely
without reading the private seed, contacting Technocore, or changing any file.

The capability policy is required because managed live operation should have an
explicit, least-privilege authorization source:

```console
technocore-safe-agent health \
  --capability-policy /absolute/path/to/safe-agent-capabilities.json
```

Config, state, journal, audit, and lock paths default beside the selected public
identity and can be overridden with their corresponding flags.

## Checks

| Check | Healthy states | Failure meaning |
| --- | --- | --- |
| `identity` | `valid` | Public identity is missing, malformed, or internally inconsistent |
| `config` | `active` | Config is missing, unsafe, pending, malformed, or bound to another identity |
| `state` | `valid` | State is missing/unsafe, or its room cursor/nonce is absent or behind provisioning |
| `capability_policy` | `valid`, `valid_no_enabled_grants` | Policy is missing, unsafe, malformed, or outside its bounds |
| `delivery` | `clear`; `pending`/`acknowledged` only while process is running | Stopped process has an interrupted delivery requiring recovery |
| `audit` | `not_created`, `valid`, `valid_checkpoint` | Audit is unsafe, malformed, signed by another DID, or misses a requested checkpoint |
| `process` | `stopped`, `running` | Lock path is unsafe or cannot be inspected |

An empty or fully disabled capability policy is a healthy paused state: the
process can run but no peer has an active grant. This supports immediate local
revocation without creating a supervisor restart loop.

## Status and exit codes

| Status | Exit | Meaning |
| --- | ---: | --- |
| `ready` | 0 | Artifacts are valid and the live lock is free |
| `running` | 0 | Artifacts are valid and the live lock is held |
| `unhealthy` | 2 | At least one artifact or requested process expectation failed |
| `recovery_required` | 3 | A valid delivery journal remains after the live lock was released |

`--expect-running` changes a clean stopped process from `ready` to `unhealthy`.
It is intended for an external supervisor probe after startup.

## Delivery state table

| Journal | Process lock | Result |
| --- | --- | --- |
| Absent | Free | `ready` |
| Absent | Held | `running` |
| Valid pending/acknowledged | Held | `running`; delivery is currently in flight |
| Valid pending/acknowledged | Free | `recovery_required` |
| Invalid or unsafe | Either | `unhealthy` |

Health never clears, retries, acknowledges, or resends a journal. Use
`recover-delivery` for the explicit recovery workflow.

## Filesystem boundary

Config, state, policy, journal, audit, and lock checks reject non-regular files,
group/other permissions, wrong ownership where the platform exposes it, and
symlinks at the final path component. Missing state is a failure because an
active provisioned agent is expected to retain its cursor and nonce high-water
marks. Missing audit is allowed only when no trusted audit checkpoint was
requested, covering the interval before the first live decision is recorded.

The lock probe opens an existing lock read-only and briefly attempts a
non-blocking exclusive `flock`. It does not create, truncate, or write the lock.
The result is a point-in-time observation and cannot prove that the lock holder
is the expected binary.

## Privacy boundary

The JSON event contains only overall status, per-check status tokens, bounded
problem codes, and two explicit `false` fields for Keychain and network checks.
It does not include paths, room names, DIDs, capability principals, audit heads,
or delivery content.

Run `technocore-safe-agent doctor` separately when private-key custody must be
verified. A successful health result does not prove Keychain availability,
network reachability, remote room health, or that a process will remain alive.
