# Private original-output bundles

A work receipt contains output hashes, not output bytes. By default the runner
discards its temporary stdout/stderr streams. `--output-directory` opts in to
preserving the exact captured streams from that same command, so a later local
inspection need not substitute output from a different execution.

```sh
technocore-safe-agent work-receipt create \
  --repository /clean/checkout \
  --timeout 120 \
  --output-directory /private/work/new-evidence \
  -- python -m unittest tests.test_example

technocore-safe-agent work-receipt verify /private/work/new-evidence/receipt.json
```

Use an existing trusted parent directory owned by you, without group/other write
permission. The new directory must be outside the checkout, even if ignored by
Git. An existing directory, file or symlink is refused before executing anything.
Only `create` accepts this option; countersigning, the receipt schema, default
stdout JSON and verification behavior are unchanged.

## Storage and state

The directory is reserved with mode `0700`; all three output files use `0600`.
The runner copies its temporary streams, checks their hashes/lengths against the
signed observation and flushes them before publishing `receipt.json` last.
File publication refuses replacement, and directory entries are fsynced.

| State | Evidence behavior | CLI result |
| --- | --- | --- |
| No output option | No output files retained | Existing receipt behavior |
| Command succeeds | Receipt plus exact original stdout/stderr | 0; receipt says `passed` |
| Command fails | Same bundle, with failed result/exit code | 0; receipt says `failed` |
| Command times out | Process group killed; captured output preserved | 0; receipt says `timed_out` |
| Empty stdout/stderr | Zero-byte file and matching hash, not missing evidence | Unchanged |
| Existing target or invalid parent | Refuse before execution; never overwrite | 2 |
| Dirty/changed checkout, signing error, excessive or mismatched output | Refuse; remove newly reserved bundle | 2 |
| Copy/fsync/publication failure | Refuse; clean up the new bundle | 2 |
| Interrupted command wait | Kill/reap launched process group; clean up | 130 |
| Cleanup itself fails | Report incomplete bundle requiring manual inspection | 2 |
| Hard kill or power loss | May leave a private partial directory; no auto-resume | No success guarantee |

Exit 0 means a receipt was created, not that the selected command passed. Inspect
the signed `result` and `exit_code`; the pre-existing failed/timeout receipt
semantics deliberately remain unchanged.

If a crash leaves a directory without `receipt.json`, treat it as incomplete.
Even with a receipt, verify its signature **and** compare both stored output
hashes and sizes before relying on the bundle. The existing `work-receipt verify`
command validates the receipt, not neighboring output files. Never regenerate
missing outputs and label them as the original execution's evidence.

## Limits and privacy

- Explicit local operation only: no chat command, MCP execution tool, upload,
  payment integration, automatic delivery or new signing identity is added.
- Output and command arguments may contain secrets. Review files privately
  before sharing. The receipt also reveals its signer, repository and command.
- Each accepted stream is bounded by the existing 16 MiB receipt limit. This is
  not a hard disk quota: the command first writes to temporary streams, and the
  existing runner checks their size after it exits. Run trusted, bounded jobs.
- The selected command inherits local privileges and environment; this is not
  an execution sandbox. Use commands that wait for their workers. Detached
  processes, concurrent same-user tampering, adversarial filesystems, inherited
  ACLs and network filesystems are outside the guarantee.
- Requires local POSIX file permissions, hard links and directory fsync. Tested
  on macOS; CI tests Linux. Windows output storage is explicitly refused rather
  than claiming equivalent privacy semantics.
- The signed format does not change. A signature and matching bytes are claims
  tied together, not proof of honest execution, independent operators, upstream
  acceptance, TCLK compatibility or an entitlement to payment.

Any separate evidence inspector must compare these files against independently
chosen expectations. Bundle creation itself does not establish that those
expectations were met or that an independent verifier participated.
