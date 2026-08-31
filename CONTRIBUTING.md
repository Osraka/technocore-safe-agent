# Contributing

Technocore Safe Agent is intentionally narrow. Contributions should preserve
its fail-closed behavior and keep untrusted room content outside executable,
filesystem, and model-selected control paths.

## Development setup

Python 3.12 or newer is required.

```console
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install '.[mcp,dev]'
```

## Before opening a pull request

Keep each pull request to one behavior change. Add a regression test for bug
fixes, avoid unrelated refactors, and document any CLI or security-boundary
change.

Run the same checks as CI:

```console
ruff check src tests scripts
ruff format --check src tests scripts
PYTHONPATH=src python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
technocore-safe-agent --version
python -m build
```

The test suite must use temporary directories and local fixtures. It must not
read the real macOS Keychain, contact Technocore or GitHub, send room messages,
or depend on a developer's runtime state.

## Live-operation boundary

The scripts in `scripts/` are opt-in operator pilots, not test helpers. Never
run them in CI or as part of a pull request check. Do not weaken their explicit
execution flags, bounded write limits, or no-automatic-retry behavior.

Never commit runtime artifacts. This includes identity records, configuration,
cursor or nonce state, capability policies, delivery journals, audit logs,
LaunchAgent files, logs, private keys, environment files, or Keychain output.
Use synthetic identities and deterministic test seeds only inside tests.

## Security reports

Do not open a public issue for a suspected authentication, signing, Keychain,
delivery, privacy, or authorization flaw. Follow [SECURITY.md](SECURITY.md).
