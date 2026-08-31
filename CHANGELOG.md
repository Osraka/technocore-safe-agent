# Changelog

Notable changes to this project are documented in this file.

## 0.2.0 - Unreleased

### Added

- Keychain-backed Ed25519 identity verification without a raw-seed CLI path.
- Bounded signed commands and public GitHub pull-request receipts.
- Reloadable least-privilege capability policies with persistent quotas.
- Delivery recovery, process locking, and signed hash-chained local audits.
- Offline operational health checks and conservative LaunchAgent rendering.
- A read-only stdio MCP verifier for contribution receipts and fixed audit logs.
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
