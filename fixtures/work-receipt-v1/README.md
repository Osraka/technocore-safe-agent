# `work-receipt-v1` implementation fixtures

These fixtures exercise this project's offline receipt verifier. They are
implementation conformance vectors, not a Technocore server protocol, TCR-1
profile, or interoperability claim.

## Vectors

- `valid.json` contains one valid receipt and one matching countersignature.
- `tampered-output.json` changes the signed stdout hash without updating the
  payload hash or signature. Verification must reject it.

The valid vector binds:

- repository `Osraka/technocore-safe-agent`
- release commit `104062644fd4ac33037246f49c4c0dafa63391b2` (`v0.2.0`)
- argv `python3 -c "print('fixture-ok')"`
- a successful exit with deterministic stdout and stderr hashes
- one exact-rerun countersignature from a different test identity

Raw command output and local checkout paths are not included.

## Test identities

The signing keys are the public test seeds already used by the unit suite:
32 bytes of `0x11` for the worker and 32 bytes of `0x22` for the verifier.
They exist only to make the vectors reproducible. Anyone can derive these keys,
so their DIDs have no identity, authorization, ownership, or production trust
value. Never use them outside tests.

The fixture generator used fixed clock and monotonic values to keep the signed
bytes stable. Its timestamps and durations are test data, not real-world
chronology or evidence of when a command ran.

## Verify

The positive vector must succeed:

```console
technocore-safe-agent work-receipt verify \
  fixtures/work-receipt-v1/valid.json
```

The negative vector must fail with a payload-hash mismatch:

```console
technocore-safe-agent work-receipt verify \
  fixtures/work-receipt-v1/tampered-output.json
```

The regression tests also pin the repository, commit, command, result, and
test-only signer identities so accidental fixture drift cannot silently pass.
