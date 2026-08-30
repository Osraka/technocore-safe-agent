# Conservative LaunchAgent Rendering

## Purpose

`technocore-safe-agent launchd render` produces one macOS LaunchAgent plist for
the bounded live responder. Rendering is intentionally separate from installing
or loading a job: the command writes XML to stdout and never calls `launchctl`,
reads Keychain, contacts Technocore, or changes a runtime file.

The renderer runs the same offline checks as `health` before producing output.
It requires the identity, active config, cursor and nonce state, capability
policy, delivery journal state, audit chain, and process lock to be safe.

## Render and review

Use the installed virtual environment's absolute entry point. Config, state,
journal, audit, and lock paths default beside the selected identity:

```console
technocore-safe-agent launchd render \
  --label com.technocore.safe-agent \
  --identity "$HOME/Library/Application Support/Technocore/Osraka/public-identity.json" \
  --capability-policy "$HOME/Library/Application Support/Technocore/Osraka/safe-agent-capabilities.json" \
  --executable /absolute/path/to/.venv/bin/technocore-safe-agent
```

The renderer itself does not write the plist. A cautious manual staging sequence
avoids truncating a previously reviewed job when a new preflight fails:

```console
umask 077
candidate="$(mktemp "$HOME/Library/LaunchAgents/com.technocore.safe-agent.XXXXXX")"
technocore-safe-agent launchd render \
  --identity "$HOME/Library/Application Support/Technocore/Osraka/public-identity.json" \
  --capability-policy "$HOME/Library/Application Support/Technocore/Osraka/safe-agent-capabilities.json" \
  --executable /absolute/path/to/.venv/bin/technocore-safe-agent > "$candidate"
plutil -lint "$candidate"
```

Inspect the candidate before moving it to its final `.plist` name. Loading,
unloading, replacing, or deleting a LaunchAgent remains an explicit operator
action and is outside this command. Do not load the candidate while another
agent process holds the configured lock.

## Generated policy

The plist uses:

- `Program` and `ProgramArguments` with no shell interpolation.
- `run --start-at saved --send` with explicit local artifact paths.
- The required capability policy; it never enables `--allow-any-signed`.
- `RunAtLoad=true` and `KeepAlive={ Crashed=true }`.
- `Umask=077`, separate stdout/stderr paths, and background process type.
- A 30-second launch throttle and 20-second exit timeout.
- No `EnvironmentVariables`, room, base URL, DID, peer identity, or Keychain
  metadata.

The room and server remain bound to the validated active config. The private
seed remains in Keychain and is read only by the live process after launch.

## State table

| Preflight/process event | Render or supervisor result | Operator action |
| --- | --- | --- |
| Health `ready` | XML is rendered | Review and validate the candidate |
| Health `running` | XML is rendered, but a process already owns the lock | Do not load a second job |
| Health `unhealthy` (2) | No XML is rendered | Repair the reported local artifact |
| Health `recovery_required` (3) | No XML is rendered | Complete explicit `recover-delivery` workflow |
| Process exits normally (0) | Job remains stopped | Inspect why processing ended before restarting |
| Process exits deliberately with 2 or 3 | Job remains stopped | Resolve validation or delivery state |
| Process terminates from a crash signal | Launchd may restart it after throttling | Inspect private logs and run `health` |
| Planned stop | Unload the job before terminating it | Prevent crash-only restart during maintenance |

Crash-only restart is deliberate. Using `KeepAlive.SuccessfulExit=false` would
also restart known fail-closed exits and could turn an unresolved delivery
journal into a noisy restart loop.

## Filesystem boundary

Every generated path must be absolute. The executable must be a regular,
owner-executable file owned by the current user and not writable by group or
others. Each log's immediate directory must be a real owner-only directory.
Existing logs must be regular, owner-writable, owner-only files. A log path may
not resolve to the executable or any identity, config, state, policy, delivery,
audit, or lock artifact.

These checks are point-in-time validation, not protection against later changes
made by the same operating-system account. The log may contain bounded local
events and errors; keep it private and apply a separate operator-controlled
rotation policy if long-running use produces significant output.

## Audit checkpoint boundary

`--expected-audit-head` can require a trusted checkpoint during rendering. The
checkpoint is intentionally not embedded into the generated process arguments
or plist. Preserve and re-check the external checkpoint separately before a
later load when rollback detection matters.
