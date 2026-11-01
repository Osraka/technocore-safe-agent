# Reproducible offline MCP pilot

This is a community tool, not an official FLOP client. The pilot checks a local
stdio adapter against synthetic public fixtures. It does not create an identity,
run a receipt's job, contact Technocore, access Keychain, sign, accept work or
pay anyone. Review the [MCP boundary](mcp-threat-model.md) before running it.

## Choose the source and interpreter

Use Linux or macOS and Python 3.12, 3.13 or 3.14. Check `python3 --version`
before creating an environment; an older system interpreter is not sufficient.
See the [Python installation options](../README.md#installed-cli) if needed.
For example, with Homebrew on macOS:

```console
brew install python@3.12
python3.12 --version
```

Clone into a fresh directory, then check out the full commit agreed with the
reviewer before running any code. [Issue #24](https://github.com/Osraka/technocore-safe-agent/issues/24)
records the current pilot pin. Do not silently substitute a moving branch.

```console
git clone https://github.com/Osraka/technocore-safe-agent.git technocore-mcp-pilot
cd technocore-mcp-pilot
```

After selecting the reviewed commit, create the environment with your supported
interpreter. If you installed `python3.12` above, use that instead of `python3`:

```console
python3 -m venv .venv
source .venv/bin/activate
python --version
```

## Install the pinned dependencies and local package

The pilot lock includes all runtime dependencies and the local build backend.
It was resolved universally for Python 3.12+ with uv 0.13.6; CI exercises
3.12, 3.13 and 3.14 on Linux. Wheel availability still depends on the platform.
Windows and other platforms are not validated by this pilot.

```console
python -m pip --isolated install --index-url https://pypi.org/simple \
  --only-binary=:all: --require-hashes -r requirements/mcp-pilot.txt
python -m pip --isolated install --no-index --no-deps --no-build-isolation .
python -m pip check
```

The first command downloads only hashed wheels. The second builds only the
reviewed local checkout without downloading a backend or resolving dependencies.
Missing wheels, wrong hashes or a missing backend are failures; do not remove
these flags to work around them. The local source is pinned by its Git commit,
not by a hash entry in the dependency lock. The lock does not pin the operating
system, Python interpreter or pip, and is not a claim of hermetic execution.

This pilot does not replace the package's normal `mcp>=2,<3` support policy.
To refresh the lock deliberately, review the dependency diff and repeat the
clean-install checks:

```console
uv pip compile pyproject.toml requirements/mcp-pilot-build.in \
  --extra mcp --universal --python-version 3.12 --generate-hashes \
  --default-index https://pypi.org/simple --output-file requirements/mcp-pilot.txt
```

## Run the installed checks

From the checkout root, with that environment active:

```console
env -u PYTHONPATH python -B -m unittest discover -s tests -p 'test_mcp*.py' -v
env -u PYTHONPATH python -B -m unittest discover -s tests -p test_work_verifier_imports.py -v
env -u PYTHONPATH python -B -m unittest discover -s tests -p test_work_evidence.py -v
```

Expected: 28 MCP tests, three import-boundary tests and 24 work-evidence tests,
all passing with no skips. The MCP group includes three actual installed stdio
entry-point cases: `matches_local_expectations`, `incomplete` when stderr is
omitted, and `invalid_receipt` for a tampered receipt. These are subprocess
calls, not only in-memory server tests. No model provider is involved.
The pinned CI job also refuses unexpected test counts or any skipped check.

The work-evidence group includes binary stdout/stderr with invalid UTF-8 and
same-length byte mutations. The existing truncation case removes a trailing
newline and must report `does_not_match`; no text decoding or newline
normalization is permitted. The [manual MCP example](work-evidence.md#using-an-mcp-client)
uses the same synthetic fixtures if you want to inspect a call yourself.

## Report only bounded results

- OS, Python and pip versions; exact source commit.
- MCP version (`python -m pip show mcp`, version field only).
- Exact commands, exit statuses, test counts and any skips.
- Whether all three installed stdio cases passed.
- One setup obstruction, if any, or `none`.

Do not post paths, environment variables, DIDs, signatures, keys, fixture
contents or unredacted logs. Code review and our local/CI runs are not an
independent execution by another developer.

## What this does not establish

A match compares receipt claims and exact bytes with an operator-controlled,
unsigned expectation. The synthetic keys are public; no result is production
evidence, proof of job execution, reviewer independence or payment readiness.

An exchange between consumers must first agree the exact expectation bytes and
how that agreement is authenticated, separately from the delivered receipt.
An unauthenticated hash alone does not establish who approved a job. This pilot
does not introduce a signed-expectation schema or verify a TCLK offer/job binding.
Those remain separate interoperability questions, not implicit acceptance or
settlement. Independent execution remains `not_established` in tool reports.
