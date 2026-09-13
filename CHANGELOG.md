# Changelog

Notable changes to this project are documented in this file.

## 0.3.0 - 2026-09-13

### Added

- Opt-in `work-receipt create --output-directory` stores the original stdout,
  stderr and signed receipt in a new private local directory. Existing targets
  are refused; the receipt is published only after output persistence and
  hash/length checks. Requires local POSIX filesystem semantics.
- Twelve explicit compatibility checks against a pinned real Technocore server,
  with disposable loopback fixtures and a separate CI job. Ordinary unit tests
  do not require an upstream checkout or contact a hosted service.

### Fixed

- Close HTTP error response streams, including when reading the error body fails.
- Track and persist room generations, including empty snapshots, and reject a
  generation that moves backwards. Older state files without generations remain
  readable.
- Respect the complete server retry delay while polling instead of retrying
  after a maximum of 30 seconds; individual sleeps remain bounded.
- Include the pinned server revision in source distributions and verify the
  integration files against the actual built archive in CI.

### Compatibility and operational notes

- Receipt schemas, default output retention and countersigning semantics are
  unchanged. A created receipt can record a failed or timed-out command; CLI
  success is not evidence that the command passed.
- Stored output can contain secrets. Nothing is automatically uploaded, shared
  or submitted for payment. Receipt verification alone does not compare the
  neighboring output files.
- This release does not restart an installed agent or migrate operator state.
  Check health and delivery state before a separately approved deployment. Do
  not restore an old cursor/nonce snapshot as a rollback shortcut.
- Real-server checks cover one pinned HTTP implementation, not the hosted
  service, every protocol path, MCP transport or Windows operation.

## 0.2.1 - 2026-09-04

### Added

- Public positive and tampered-output `work-receipt-v1` implementation
  fixtures backed only by deterministic test identities.
- Regression tests that pin the fixture repository, release commit, command,
  result, signer roles, and tamper rejection behavior.

### Changed

- Source distributions now include the fixture vectors and their trust-boundary
  documentation.

## 0.2.0 - 2026-09-04

### Added

- Keychain-backed Ed25519 identity verification without a raw-seed CLI path.
- Bounded signed commands and public GitHub pull-request receipts.
- Reloadable least-privilege capability policies with persistent quotas.
- Delivery recovery, process locking, and signed hash-chained local audits.
- Offline operational health checks and conservative LaunchAgent rendering.
- A read-only stdio MCP verifier for contribution receipts and fixed audit logs.
- Offline `work-receipt-v1` creation, verification, and exact-match
  countersigning for clean public Git checkouts.
- Cross-version CI, packaging checks, and public contribution/security guidance.

### Changed

- Replaced developer-specific default names, paths, and Keychain selectors with
  the generic `SafeAgent` profile while preserving explicit CLI overrides.
- CI and contributor setup now use a normal package install and smoke-test the
  installed CLI on every supported Python version.
- The README now states the project's independent status and makes no token,
  airdrop, bounty, or reward claim.

### Security

- Live pilots remain explicit, bounded, and excluded from automated tests.
- Runtime state, policy, delivery, audit, and credential artifacts remain local
  and are excluded from version control.
