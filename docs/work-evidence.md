# Local work evidence inspection

`work-evidence` answers a narrow question: does a signed `work-receipt-v1`
match the operator's expectations and the supplied stdout/stderr bytes?
It does not run the job, sign anything, contact a server, access Keychain, or
modify an input file. It is a local CLI, not a chat command or MCP tool.

## Trust and input contract

Prepare the expectation independently, using the repository, commit, exact argv,
timeout, worker key, and verifier keys you intended to accept. Do not copy these
fields from an untrusted delivery and treat the resulting match as approval.
The expectation is operator-controlled and unsigned; it is not an authenticated
offer, acceptance, capability, or TCLK agreement.

Every field in the following table is required. Unknown fields are rejected.

| Field | Meaning |
| --- | --- |
| `schema` | Exactly `work-evidence-expectation-v1` |
| `repository` | Canonical GitHub `owner/repository`, without `.git` |
| `commit` | Full lowercase 40-character commit hash |
| `command` | Exact argv array; no shell expansion or execution |
| `timeout_ms` | Integer from 1 to 3,600,000, not a boolean |
| `issuer` | Expected canonical Ed25519 DID |
| `required_verifiers` | Up to 16 unique expected DIDs, excluding the issuer |

Repository, commit, argv, timeout, and issuer comparisons are exact. All
countersignatures are checked by the existing work-receipt verifier. Additional
valid countersigners are allowed, but cannot substitute for a required key.
An empty `required_verifiers` list explicitly opts out of that requirement and
reports `not_requested`; it does not establish independent verification.

Pass files through explicit CLI flags only:

```console
technocore-safe-agent work-evidence \
  --expectation /private/job/expectation.json \
  --receipt /private/job/receipt.json \
  --stdout /private/job/stdout.bin \
  --stderr /private/job/stderr.bin \
  --format markdown
```

Default output is JSON. The report contains only status tokens, not identifiers,
paths, hashes, argv, signatures, or raw output. Input errors return a small JSON
error even when Markdown was selected. Reports are not signed and can be edited;
retain the original evidence privately if another operator needs to verify it.

**Output availability:** `work-receipt create --output-directory` preserves the
same execution's original streams in a private bundle outside the checkout.
Pass that bundle's `receipt.json`, `stdout.bin` and `stderr.bin` to this command.
Without the opt-in bundle, the runner discards its temporary output streams;
this inspector cannot recover them. If bytes are unavailable, omit their flags
and accept an `incomplete` report. Do not substitute later rerun output and
claim it came from the original run. Only byte equality is checked, not the
provenance of a supplied output file. See [private output bundles](work-output-bundles.md).

## State table

| Input state | Overall status | Exit |
| --- | --- | --- |
| Valid receipt, passed result, exact expected metadata/keys and both outputs | `matches_local_expectations` | 0 |
| Receipt omitted | `incomplete` | 1 |
| Output flag omitted or required countersigner absent | `incomplete` | 1 |
| Valid signed failed or timed-out result | `does_not_match` | 1 |
| Metadata, stdout, or stderr mismatch | `does_not_match` | 1 |
| Invalid signature, counter, schema, or receipt JSON | `invalid_receipt` | 1 |
| Invalid expectation, unreadable/nonregular/oversized input, detected file change | `input_error` | 2 |

A mismatch takes precedence over missing evidence. An invalid receipt stops
inspection before any output file is opened. Omitting a flag is different from
passing a nonexistent file: the latter is an input error. Zero bytes is a valid
output, not a missing output.

## Limits and threat model

- Only explicitly selected local regular files are read. No paths embedded in
  receipts or expectations are followed. No repository is fetched or resolved.
- Expectation limit: 32 KiB; receipt limit: 128 KiB; each output limit: 16 MiB.
  JSON must be UTF-8 objects, with no duplicate keys or nonfinite constants.
- Final-component symlinks and special files are rejected. Nonblocking open
  prevents a regular-file/FIFO replacement from hanging on POSIX. Opened inode
  identity, size, and modification metadata are checked for observable changes.
- This is not a filesystem sandbox or an atomic snapshot across files. Parent
  directories are operator-trusted and may contain symlinks; concurrent local
  attackers and hostile/network filesystems are outside the guarantee. Use an
  owner-only local directory with stable inputs. Windows filesystem semantics
  have not been live-tested; FIFO checks apply only on POSIX.
- A valid signature binds a key to a claim. It does not prove the command ran,
  that tests were sufficient, that two keys represent independent people, that
  a commit is public/merged, or that an output is truthful. A passing command
  could simply be a no-op. `execution: passed` is the validated signed claim,
  not a new execution performed by this tool.
- The receipt binds stdout/stderr, not arbitrary source trees or build artifacts.
  Matching output does not prove an independently delivered binary is correct.
- No deal ID, freshness window, anti-replay ledger, or environment/dependency
  identity is checked. The same evidence can match again. This is not an
  authorization decision or an automatic acceptance/payment trigger.
- `agreement` and `payment` are always `not_assessed`; `independent_execution`
  is always `not_established`. This is not a TCLK receipt or settlement proof.
  TCLK transcript validation and any format mapping remain separate work.

## Offline example

From the repository root, using an environment with the project dependencies:

```console
PYTHONPATH=src python -m technocore_safe_agent work-evidence \
  --expectation fixtures/work-evidence-v1/expectation.json \
  --receipt fixtures/work-receipt-v1/valid.json \
  --stdout fixtures/work-evidence-v1/stdout.txt \
  --stderr fixtures/work-evidence-v1/stderr.txt \
  --format markdown
```

Expected: `matches_local_expectations`, exit 0. Omit `--stderr` and its value
to obtain `incomplete`, exit 1. Use `fixtures/work-receipt-v1/tampered-output.json`
as the receipt to obtain `invalid_receipt`, exit 1.

The fixture expectation and output were derived from the existing public test
vector **for demonstration only**. Its signing seeds are public; its timestamps
are synthetic. It is not an independent pilot or production evidence.

Focused checks:

```console
PYTHONPATH=src python -m unittest discover -s tests -p test_work_evidence.py -v
```

Tests include success/failure/timeout, each metadata mismatch, changed/truncated
outputs, absent/wrong/invalid countersigners, malformed/oversized inputs, special
files and file replacement, safe reports, and CLI no-network/no-execution/no-key
access guards. Existing work-receipt behavior and wire formats are unchanged.
