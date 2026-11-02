# An external consumer example

Use this when a worker hands you a signed test-run receipt and its stdout/stderr,
and you want to compare them with a job you already selected without running the
worker's command. The CLI reports missing evidence and mismatches as well as a
match. It does not need a Technocore account, model provider or operational key.

**The expectation is operator-controlled and unsigned.** A match is not an
authenticated agreement, proof of execution, work acceptance or payment approval.
`work-receipt-v1` is this project's local format, not a native Technocore receipt,
TCR-1 or a TCLK transcript. Do not combine these checks into a "verified job" result.

## Where this fits beside Technocore

The upstream [patterns](https://github.com/flop-labs/technocore-chat/blob/73a732497a19cac11aff4dcb527bae3c52b02f73/src/patterns.md#6-escrowed-deal-htlcptlc)
explain why a payment condition is not proof of delivery. They also require peers
to keep their own records because the room's retained window can expire. The
[bridge guidance](https://github.com/flop-labs/technocore-chat/blob/73a732497a19cac11aff4dcb527bae3c52b02f73/src/interop.md#the-shape-every-bridge-has)
separates signed writer identity from anonymous text and room-lifetime metadata.
This external example uses those boundaries; it adds no server route or native
result-bundle contract.

| Question | Evidence needed | What this tool establishes |
| --- | --- | --- |
| Does a native record verify for its expected author? | Native signed record and the protocol's verification rules | Not checked here; use the upstream checker or a separately reviewed native consumer |
| Do these receipt fields and exact output bytes match my selected job? | Local expectation, local receipt and original streams | The four comparison states below |
| Was the selected job actually agreed? | An existing authenticated agreement binding its exact terms | `agreement: not_assessed`; an unsigned expectation or bare hash is insufficient |
| Was work executed independently, accepted or paid? | Separate execution, acceptance and rail evidence | `independent_execution: not_established`, `payment: not_assessed`; acceptance is not checked |

Keep the original evidence privately when another consumer needs to inspect it.
A room export covers its selected retained window, not necessarily the complete
history. A record signature does not authenticate unsigned sequence labels or
prove first claimant, delivery order or current room generation. Our existing
native-JOB comparison was a separate prose task, not a binding for executable
repository/argv/timeout terms. The missing binding stays deferred.

## A pinned synthetic comparison

Use the reviewed source at
`ac839d30aaef3c98b68bab321c7f89069c561ecf` and the
[pinned install guide](https://github.com/Osraka/technocore-safe-agent/blob/ac839d30aaef3c98b68bab321c7f89069c561ecf/docs/mcp-pilot.md).
It covers the Python version check, hashed dependencies and installed package.
This example then runs only the installed CLI; it does not start an MCP server.

Both consumers should select the public expectation before comparing a delivery:

| Fixture field | Value |
| --- | --- |
| Repository | `Osraka/technocore-safe-agent` |
| Job commit | `104062644fd4ac33037246f49c4c0dafa63391b2` |
| Exact argv | `["python3", "-c", "print('fixture-ok')"]` |
| Timeout | 5000 ms |
| Expected keys | The public test keys in the pinned expectation, including one required verifier |
| Expectation file SHA-256 | `b31015de8f139c8430485e8be729ae395532010777fe27052b29df67dafd50b9` |

The job commit is a receipt claim, distinct from the consumer's source pin above;
this tool neither fetches that job commit nor runs its argv. The fixture keys and
receipt are public synthetic data. Selecting this fixture is not a real work
agreement or evidence that the claimed job ran. The hash identifies bytes only;
it does not authenticate approval. Never derive production expectations from the
worker's receipt and then call the resulting match agreement.

From the pinned checkout root, with its installed environment active, run:

```sh
env -u PYTHONPATH python -B - <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path.cwd()
expectation = root / "fixtures/work-evidence-v1/expectation.json"
receipt = root / "fixtures/work-receipt-v1/valid.json"
stdout = root / "fixtures/work-evidence-v1/stdout.txt"
stderr = root / "fixtures/work-evidence-v1/stderr.txt"
if hashlib.sha256(expectation.read_bytes()).hexdigest() != (
    "b31015de8f139c8430485e8be729ae395532010777fe27052b29df67dafd50b9"
):
    raise SystemExit(
        "unexpected fixture expectation; stop rather than substitute another job"
    )

with tempfile.TemporaryDirectory() as temporary:
    temporary = Path(temporary)
    no_newline = temporary / "no-newline.bin"
    no_newline.write_bytes(stdout.read_bytes().removesuffix(b"\n"))
    binary = temporary / "binary.bin"
    binary.write_bytes(b"\xff" + stdout.read_bytes()[1:])
    changed_job = temporary / "changed-expectation.json"
    changed = json.loads(expectation.read_bytes())
    changed["command"] = ["python3", "-c", "print('different-job')"]
    changed_job.write_text(json.dumps(changed), encoding="utf-8")
    cases = [
        (
            "original",
            expectation,
            receipt,
            stdout,
            stderr,
            "matches_local_expectations",
            0,
        ),
        ("missing-stderr", expectation, receipt, stdout, None, "incomplete", 1),
        (
            "tampered",
            expectation,
            root / "fixtures/work-receipt-v1/tampered-output.json",
            stdout,
            stderr,
            "invalid_receipt",
            1,
        ),
        ("newline", expectation, receipt, no_newline, stderr, "does_not_match", 1),
        ("binary", expectation, receipt, binary, stderr, "does_not_match", 1),
        ("different-job", changed_job, receipt, stdout, stderr, "does_not_match", 1),
    ]
    for name, expected, delivered, out, err, status, exit_code in cases:
        argv = [
            sys.executable,
            "-B",
            "-m",
            "technocore_safe_agent",
            "work-evidence",
            "--expectation",
            str(expected),
            "--receipt",
            str(delivered),
            "--stdout",
            str(out),
        ]
        if err is not None:
            argv += ["--stderr", str(err)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        report = json.loads(result.stdout)
        if (report["status"], result.returncode) != (status, exit_code):
            raise SystemExit(f"{name}: unexpected status or exit")
        boundary = (
            report["agreement"],
            report["payment"],
            report["independent_execution"],
        )
        if boundary != ("not_assessed", "not_assessed", "not_established"):
            raise SystemExit(f"{name}: unexpected evidence boundary")
        print(f"{name}: {report['status']} exit={result.returncode}")
PY
```

The script makes six installed-CLI calls and checks all four comparison states.
It changes only temporary copies, preserves the public fixtures, and never runs
the receipt's command. The binary case is a same-length byte mismatch, not a
claim that this fixture contains valid signed binary output. The ordinary
work-evidence tests cover valid non-UTF-8 output separately.

## What another consumer can usefully report

Report the exact consumer source/fixture pin, OS/Python version, the six status
and exit pairs, and one setup obstruction or usefulness observation. An adapter
that does not read `work-receipt-v1` should report that incompatibility rather
than reinterpret this receipt as its own format. Code review is not execution,
and the author's local run is not a second independent consumer.

Do not post raw evidence, identities, signatures, personal paths or environment
variables. A successful synthetic exchange would validate comparison behavior,
not supply the missing authenticated agreement or justify acceptance/payment.
No new Technocore job, message, identity or signing profile is needed for it.
