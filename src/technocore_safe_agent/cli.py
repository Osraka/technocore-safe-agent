"""Command-line entrypoint for the safe Technocore responder."""

from __future__ import annotations

import argparse
import json
import sys
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from technocore_safe_agent import __version__
from technocore_safe_agent.agent import SafeResponder, UncertainWriteError
from technocore_safe_agent.audit import AuditError, SignedAuditLog
from technocore_safe_agent.capabilities import (
    CapabilityError,
    CapabilityPolicyFile,
    CapabilityRateLimiter,
)
from technocore_safe_agent.config import AgentConfig, ConfigError
from technocore_safe_agent.controller import (
    CONTROLLER_COMMANDS,
    DEFAULT_CONTROLLER_ACCOUNT,
    DEFAULT_CONTROLLER_IDENTITY_PATH,
    DEFAULT_CONTROLLER_SERVICE,
    CONTROLLER_RATE_LIMIT,
    ControllerError,
    MacOSKeychainSeedWriter,
    create_controller_identity,
    grant_controller_to_empty_policy,
    load_controller_identity,
    send_controller_command,
)
from technocore_safe_agent.crypto import (
    IdentityError,
    ProtocolValueError,
    validate_did,
    validate_room,
)
from technocore_safe_agent.delivery import DeliveryError, DeliveryJournal
from technocore_safe_agent.delivery_recovery import recover_delivery
from technocore_safe_agent.health import HealthPaths, inspect_operational_health
from technocore_safe_agent.identity import (
    DEFAULT_AGENT_NAME,
    DEFAULT_IDENTITY_PATH,
    IdentityRecord,
    MacOSKeychainSeedProvider,
    load_verified_private_key,
)
from technocore_safe_agent.launchd import (
    LaunchAgentError,
    LaunchAgentSpec,
    render_launch_agent,
)
from technocore_safe_agent.policy import CommandPolicy
from technocore_safe_agent.process_lock import AgentProcessLock, ProcessLockError
from technocore_safe_agent.provision import provision_mailbox, recover_pending_mailbox
from technocore_safe_agent.protocol import (
    ResponseError,
    TechnocoreClient,
    TransportError,
)
from technocore_safe_agent.receipt import (
    ContributionReceiptService,
    GitHubPublicClient,
    GitHubReceiptError,
    verify_signed_receipt,
)
from technocore_safe_agent.state import AgentState, StateError
from technocore_safe_agent.work_receipt import (
    WorkReceiptError,
    countersign_work_receipt,
    create_work_receipt,
    render_work_receipt,
    verify_work_receipt,
)


def _shared_identity_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--identity",
        type=Path,
        default=DEFAULT_IDENTITY_PATH,
        help="public identity JSON; private key remains in macOS Keychain",
    )


def _controller_identity_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--identity",
        type=Path,
        default=DEFAULT_CONTROLLER_IDENTITY_PATH,
        help="public controller identity; private key remains in macOS Keychain",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="technocore-safe-agent",
        description="Run a deterministic, keychain-backed Technocore responder.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser(
        "doctor", help="verify public identity and Keychain custody"
    )
    _shared_identity_option(doctor)

    health = commands.add_parser(
        "health", help="inspect managed-agent readiness without Keychain or network"
    )
    _shared_identity_option(health)
    health.add_argument("--config", type=Path, help="active agent config path")
    health.add_argument("--state", type=Path, help="persistent state path")
    health.add_argument(
        "--capability-policy",
        type=Path,
        required=True,
        help="mode-0600 capability policy used by the managed agent",
    )
    health.add_argument("--journal", type=Path, help="delivery journal path")
    health.add_argument("--lock", type=Path, help="live process lock path")
    health.add_argument("--audit-log", type=Path, help="signed audit log path")
    health.add_argument(
        "--expected-audit-head",
        help="optional trusted SHA-256 audit checkpoint",
    )
    health.add_argument(
        "--expect-running",
        action="store_true",
        help="return unhealthy unless the live process lock is held",
    )

    controller = commands.add_parser(
        "controller", help="manage one least-privilege Keychain-backed controller"
    )
    controller_commands = controller.add_subparsers(
        dest="controller_command", required=True
    )
    controller_create = controller_commands.add_parser(
        "create", help="create a separate controller DID in macOS Keychain"
    )
    _controller_identity_option(controller_create)
    controller_create.add_argument("--service", default=DEFAULT_CONTROLLER_SERVICE)
    controller_create.add_argument("--account", default=DEFAULT_CONTROLLER_ACCOUNT)

    controller_grant = controller_commands.add_parser(
        "grant",
        help="replace an empty capability policy with the fixed controller grant",
    )
    _controller_identity_option(controller_grant)
    controller_grant.add_argument("--capability-policy", type=Path, required=True)

    controller_send = controller_commands.add_parser(
        "send", help="send one exact idempotent controller command"
    )
    _controller_identity_option(controller_send)
    controller_send.add_argument("controller_text", choices=CONTROLLER_COMMANDS)
    controller_send.add_argument("--config", type=Path, help="active agent config")
    controller_send.add_argument("--state", type=Path, help="controller nonce state")
    controller_send.add_argument("--lock", type=Path, help="controller process lock")
    controller_send.add_argument("--timeout", type=float, default=20.0)

    launchd = commands.add_parser(
        "launchd", help="render a conservative macOS LaunchAgent without installing it"
    )
    launchd_commands = launchd.add_subparsers(dest="launchd_command", required=True)
    launchd_render = launchd_commands.add_parser(
        "render", help="print a validated LaunchAgent plist to stdout"
    )
    _shared_identity_option(launchd_render)
    launchd_render.add_argument("--config", type=Path, help="active agent config path")
    launchd_render.add_argument("--state", type=Path, help="persistent state path")
    launchd_render.add_argument(
        "--capability-policy",
        type=Path,
        required=True,
        help="mode-0600 capability policy used by the managed agent",
    )
    launchd_render.add_argument("--journal", type=Path, help="delivery journal path")
    launchd_render.add_argument("--lock", type=Path, help="live process lock path")
    launchd_render.add_argument("--audit-log", type=Path, help="signed audit log path")
    launchd_render.add_argument(
        "--expected-audit-head",
        help="optional trusted SHA-256 audit checkpoint for preflight",
    )
    launchd_render.add_argument(
        "--label", default="com.technocore.safe-agent", help="LaunchAgent label"
    )
    launchd_render.add_argument(
        "--executable",
        type=Path,
        required=True,
        help="absolute technocore-safe-agent entry point",
    )
    launchd_render.add_argument(
        "--stdout-path", type=Path, help="private stdout log path"
    )
    launchd_render.add_argument(
        "--stderr-path", type=Path, help="private stderr log path"
    )

    provision = commands.add_parser(
        "provision", help="create one unlisted signed mailbox and local config"
    )
    _shared_identity_option(provision)
    provision.add_argument("--name", default=DEFAULT_AGENT_NAME)
    provision.add_argument("--base-url", default="https://technocore.chat")
    provision.add_argument("--timeout", type=float, default=20.0)
    provision.add_argument("--config", type=Path)
    provision.add_argument("--state", type=Path)

    recover = commands.add_parser(
        "recover",
        help="inspect a pending mailbox and optionally retry its one signed write",
    )
    _shared_identity_option(recover)
    recover.add_argument("--base-url", default="https://technocore.chat")
    recover.add_argument("--timeout", type=float, default=20.0)
    recover.add_argument("--config", type=Path)
    recover.add_argument("--state", type=Path)
    recover.add_argument(
        "--retry",
        action="store_true",
        help="retry once only after the room inspection found no matching write",
    )

    recover_delivery_parser = commands.add_parser(
        "recover-delivery",
        help="inspect and explicitly resolve one in-flight signed reply",
    )
    _shared_identity_option(recover_delivery_parser)
    recover_delivery_parser.add_argument(
        "--room", help="room override; defaults to the active agent config"
    )
    recover_delivery_parser.add_argument(
        "--config", type=Path, help="active agent config path"
    )
    recover_delivery_parser.add_argument("--state", type=Path)
    recover_delivery_parser.add_argument("--journal", type=Path)
    recover_delivery_parser.add_argument("--lock", type=Path)
    recover_delivery_parser.add_argument(
        "--base-url", help="server override; defaults to the active config"
    )
    recover_delivery_parser.add_argument("--timeout", type=float, default=20.0)
    recover_delivery_parser.add_argument(
        "--apply",
        action="store_true",
        help="persist a proven acknowledgement and clear the journal",
    )
    recover_delivery_parser.add_argument(
        "--confirm-retry",
        action="store_true",
        help="resend the exact envelope once only after complete history proves absence",
    )

    receipt = commands.add_parser(
        "receipt", help="issue a signed receipt for one public GitHub pull request"
    )
    _shared_identity_option(receipt)
    receipt.add_argument("pull_request", help="canonical public GitHub PR URL")
    receipt.add_argument("--timeout", type=float, default=15.0)

    verify_receipt = commands.add_parser(
        "verify-receipt", help="verify a saved contribution receipt without Keychain"
    )
    verify_receipt.add_argument("path", type=Path, help="receipt JSON file")

    work_receipt = commands.add_parser(
        "work-receipt",
        help="create and independently verify an offline work receipt",
    )
    work_receipt_commands = work_receipt.add_subparsers(
        dest="work_receipt_command", required=True
    )
    work_receipt_create = work_receipt_commands.add_parser(
        "create", help="run one command in a clean checkout and sign its result"
    )
    _shared_identity_option(work_receipt_create)
    work_receipt_create.add_argument(
        "--repository", type=Path, default=Path("."), help="clean Git checkout"
    )
    work_receipt_create.add_argument("--timeout", type=float, default=300.0)
    work_receipt_create.add_argument(
        "work_command",
        nargs=argparse.REMAINDER,
        help="command argv after --; no shell interpretation is performed",
    )

    work_receipt_verify = work_receipt_commands.add_parser(
        "verify", help="verify a work receipt and all countersignatures offline"
    )
    work_receipt_verify.add_argument("path", type=Path, help="work receipt JSON file")

    work_receipt_countersign = work_receipt_commands.add_parser(
        "countersign",
        help="rerun a receipt at the same commit and sign an exact match",
    )
    _controller_identity_option(work_receipt_countersign)
    work_receipt_countersign.add_argument(
        "--repository", type=Path, default=Path("."), help="clean Git checkout"
    )
    work_receipt_countersign.add_argument(
        "path", type=Path, help="work receipt JSON file"
    )

    audit = commands.add_parser("audit", help="inspect the signed local audit log")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    audit_verify = audit_commands.add_parser(
        "verify", help="verify every audit signature and hash-chain link offline"
    )
    audit_verify.add_argument("path", type=Path, help="audit JSONL file")
    audit_verify.add_argument(
        "--expected-head",
        help="optional trusted SHA-256 checkpoint that also detects tail rollback",
    )

    run = commands.add_parser(
        "run", help="poll one room and apply the safe command policy"
    )
    _shared_identity_option(run)
    run.add_argument("--room", help="room override; defaults to the provisioned config")
    run.add_argument("--config", type=Path, help="provisioned agent config path")
    run.add_argument(
        "--base-url", help="server override; defaults to config or Technocore"
    )
    run.add_argument("--timeout", type=float, default=20.0)
    run.add_argument(
        "--github-timeout",
        type=float,
        default=15.0,
        help="timeout for each fixed public GitHub API read",
    )
    run.add_argument("--wait", type=float, default=10.0)
    run.add_argument("--limit", type=int, default=50)
    run.add_argument("--once", action="store_true", help="perform one read and exit")
    run.add_argument(
        "--start-at",
        choices=("latest", "saved", "zero"),
        default="latest",
        help="initial cursor policy when this room has no saved state",
    )
    run.add_argument(
        "--state",
        type=Path,
        help="state path; defaults beside the public identity file",
    )
    run.add_argument(
        "--journal",
        type=Path,
        help="in-flight delivery journal; defaults beside the public identity",
    )
    run.add_argument(
        "--lock",
        type=Path,
        help="live process lock; defaults beside the public identity",
    )
    run.add_argument(
        "--audit-log",
        type=Path,
        help="signed decision log; defaults beside the public identity",
    )
    senders = run.add_mutually_exclusive_group()
    senders.add_argument(
        "--allow-did",
        action="append",
        default=[],
        metavar="DID",
        help="signed DID allowed to invoke exact built-in commands; repeatable",
    )
    senders.add_argument(
        "--allow-any-signed",
        action="store_true",
        help="allow any signed DID; appropriate only for intentionally public bots",
    )
    senders.add_argument(
        "--capability-policy",
        type=Path,
        help="mode-0600 per-DID command, repository, and rolling-rate policy",
    )
    run.add_argument(
        "--send",
        action="store_true",
        help="publish signed replies and persist state; default is dry-run",
    )
    return parser


def _print_event(event: dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=True, separators=(",", ":")), flush=True)


def _load_identity(path: Path) -> tuple[IdentityRecord, Any]:
    record = IdentityRecord.load(path)
    provider = MacOSKeychainSeedProvider(
        record.keychain_service, record.keychain_account
    )
    private_key = load_verified_private_key(record, provider)
    return record, private_key


def _doctor(args: argparse.Namespace) -> int:
    record, _ = _load_identity(args.identity)
    _print_event(
        {
            "status": "ok",
            "did": record.did,
            "fingerprint": record.fingerprint,
            "custody": "macos-keychain",
            "service": record.keychain_service,
            "account": record.keychain_account,
            "private_key_exported": False,
        }
    )
    return 0


def _health(args: argparse.Namespace) -> int:
    identity_path = args.identity.expanduser().absolute()
    config_path = _health_path(args.config, identity_path, "safe-agent-config.json")
    state_path = _health_path(args.state, identity_path, "safe-agent-state.json")
    report = inspect_operational_health(
        HealthPaths(
            identity=identity_path,
            config=config_path,
            state=state_path,
            capability_policy=args.capability_policy,
            journal=_health_path(
                args.journal, identity_path, "safe-agent-delivery.json"
            ),
            audit=_health_path(args.audit_log, identity_path, "safe-agent-audit.jsonl"),
            lock=_health_path(args.lock, identity_path, "safe-agent.lock"),
        ),
        expected_audit_head=args.expected_audit_head,
        expect_running=args.expect_running,
    )
    _print_event(report.to_event())
    return report.exit_code


def _health_path(selected: Path | None, identity_path: Path, default_name: str) -> Path:
    if selected is not None:
        return selected.expanduser().absolute()
    return identity_path.with_name(default_name)


def _controller(args: argparse.Namespace) -> int:
    identity_path = args.identity.expanduser().absolute()
    if args.controller_command == "create":
        record = create_controller_identity(
            identity_path,
            MacOSKeychainSeedWriter(args.service, args.account),
        )
        _print_event(
            {
                "status": "created",
                "did": record.did,
                "fingerprint": record.fingerprint,
                "private_key_exported": False,
            }
        )
        return 0
    if args.controller_command == "grant":
        grant_controller_to_empty_policy(
            identity_path,
            args.capability_policy.expanduser().absolute(),
        )
        _print_event(
            {
                "status": "granted",
                "commands": list(CONTROLLER_COMMANDS),
                "max_requests_per_hour": CONTROLLER_RATE_LIMIT,
                "pr_enabled": False,
            }
        )
        return 0
    if args.controller_command != "send":
        raise ControllerError("unsupported controller command")

    record = load_controller_identity(identity_path)
    provider = MacOSKeychainSeedProvider(
        record.keychain_service,
        record.keychain_account,
    )
    private_key = load_verified_private_key(record, provider)
    config_path = _health_path(args.config, identity_path, "safe-agent-config.json")
    state_path = _health_path(args.state, identity_path, "controller-state.json")
    lock_path = _health_path(args.lock, identity_path, "controller.lock")
    config = AgentConfig.load(config_path)
    with AgentProcessLock(lock_path):
        event = send_controller_command(
            did=record.did,
            private_key=private_key,
            config=config,
            state_path=state_path,
            command=args.controller_text,
            client=TechnocoreClient(base_url=config.base_url, timeout=args.timeout),
        )
    _print_event(event)
    return 0


def _launchd(args: argparse.Namespace) -> int:
    if args.launchd_command != "render":
        raise LaunchAgentError("unsupported launchd command")
    identity_path = args.identity.expanduser().absolute()
    health_paths = HealthPaths(
        identity=identity_path,
        config=_health_path(args.config, identity_path, "safe-agent-config.json"),
        state=_health_path(args.state, identity_path, "safe-agent-state.json"),
        capability_policy=args.capability_policy.expanduser().absolute(),
        journal=_health_path(args.journal, identity_path, "safe-agent-delivery.json"),
        audit=_health_path(args.audit_log, identity_path, "safe-agent-audit.jsonl"),
        lock=_health_path(args.lock, identity_path, "safe-agent.lock"),
    )
    rendered = render_launch_agent(
        LaunchAgentSpec(
            label=args.label,
            executable=args.executable.expanduser().absolute(),
            health_paths=health_paths,
            stdout_path=_health_path(
                args.stdout_path, identity_path, "safe-agent.stdout.log"
            ),
            stderr_path=_health_path(
                args.stderr_path, identity_path, "safe-agent.stderr.log"
            ),
            expected_audit_head=args.expected_audit_head,
        )
    )
    print(rendered, end="", flush=True)
    return 0


def _paths_beside_identity(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    identity_path = args.identity.expanduser().resolve()
    config_path = (
        args.config.expanduser().resolve()
        if getattr(args, "config", None)
        else identity_path.with_name("safe-agent-config.json")
    )
    state_path = (
        args.state.expanduser().resolve()
        if getattr(args, "state", None)
        else identity_path.with_name("safe-agent-state.json")
    )
    return identity_path, config_path, state_path


def _provision(args: argparse.Namespace) -> int:
    record, private_key = _load_identity(args.identity)
    _, config_path, state_path = _paths_beside_identity(args)
    client = TechnocoreClient(base_url=args.base_url, timeout=args.timeout)
    _print_event(
        provision_mailbox(
            name=args.name,
            record=record,
            private_key=private_key,
            client=client,
            config_path=config_path,
            state_path=state_path,
        )
    )
    return 0


def _recover(args: argparse.Namespace) -> int:
    record, private_key = _load_identity(args.identity)
    _, config_path, state_path = _paths_beside_identity(args)
    client = TechnocoreClient(base_url=args.base_url, timeout=args.timeout)
    _print_event(
        recover_pending_mailbox(
            record=record,
            private_key=private_key,
            client=client,
            config_path=config_path,
            state_path=state_path,
            retry=args.retry,
        )
    )
    return 0


def _recover_delivery(args: argparse.Namespace) -> int:
    identity_path, config_path, default_state_path = _paths_beside_identity(args)
    record = IdentityRecord.load(identity_path)
    config: AgentConfig | None = None
    if config_path.exists():
        config = AgentConfig.load(config_path)
        if config.did != record.did or config.fingerprint != record.fingerprint:
            raise ConfigError(
                "agent config does not belong to the selected public identity"
            )
        if config.status != "active":
            raise ConfigError("agent config must be active for delivery recovery")

    if args.room:
        room = validate_room(args.room)
    elif config is not None:
        room = config.room
    else:
        raise ConfigError(
            "no active config exists; pass --room or select the provisioned config"
        )
    base_url = args.base_url or (
        config.base_url if config is not None else "https://technocore.chat"
    )
    state_path = args.state.expanduser().resolve() if args.state else default_state_path
    journal_path = _path_beside_identity(
        args.journal, identity_path, "safe-agent-delivery.json"
    )
    lock_path = _path_beside_identity(args.lock, identity_path, "safe-agent.lock")
    with AgentProcessLock(lock_path):
        state = AgentState.load(state_path)
        event = recover_delivery(
            room=room,
            did=record.did,
            client=TechnocoreClient(base_url=base_url, timeout=args.timeout),
            state=state,
            state_path=state_path,
            journal=DeliveryJournal(journal_path),
            apply=args.apply,
            confirm_retry=args.confirm_retry,
        )
    _print_event(event)
    return 0


def _receipt(args: argparse.Namespace) -> int:
    record, private_key = _load_identity(args.identity)
    service = ContributionReceiptService(
        issuer_did=record.did,
        private_key=private_key,
        client=GitHubPublicClient(timeout=args.timeout),
    )
    print(service.issue(args.pull_request), flush=True)
    return 0


def _verify_receipt(args: argparse.Namespace) -> int:
    resolved = args.path.expanduser().resolve()
    try:
        raw = resolved.read_text(encoding="utf-8")
    except OSError as error:
        raise GitHubReceiptError(
            f"cannot read receipt file {resolved}: {error}",
            code="receipt_read_error",
        ) from error
    payload = verify_signed_receipt(raw)
    wrapper = json.loads(raw)
    _print_event(
        {
            "status": "valid",
            "schema": payload["schema"],
            "issuer": payload["issuer"],
            "repository": payload["repository"],
            "pull_number": payload["pull_number"],
            "payload_sha256": wrapper["payload_sha256"],
        }
    )
    return 0


def _read_text_artifact(path: Path, label: str, *, maximum_bytes: int) -> str:
    resolved = path.expanduser().resolve()
    try:
        if resolved.stat().st_size > maximum_bytes:
            raise WorkReceiptError(f"{label} exceeds the artifact size limit")
        return resolved.read_text(encoding="utf-8")
    except OSError as error:
        raise WorkReceiptError(f"cannot read {label} {resolved}: {error}") from error
    except UnicodeDecodeError as error:
        raise WorkReceiptError(f"{label} must be UTF-8 JSON") from error


def _work_receipt(args: argparse.Namespace) -> int:
    if args.work_receipt_command == "create":
        command = list(args.work_command)
        if command[:1] == ["--"]:
            command = command[1:]
        record, private_key = _load_identity(args.identity)
        receipt = create_work_receipt(
            args.repository,
            command,
            issuer_did=record.did,
            private_key=private_key,
            timeout=args.timeout,
        )
        print(render_work_receipt(receipt), flush=True)
        return 0
    if args.work_receipt_command == "verify":
        raw = _read_text_artifact(args.path, "work receipt", maximum_bytes=128 * 1024)
        summary = verify_work_receipt(raw)
        _print_event(
            {
                "status": "valid",
                "schema": summary.payload["schema"],
                "repository": summary.payload["repository"],
                "commit": summary.payload["commit"],
                "result": summary.payload["result"],
                "countersignatures": summary.countersignatures,
            }
        )
        return 0
    if args.work_receipt_command == "countersign":
        raw = _read_text_artifact(args.path, "work receipt", maximum_bytes=128 * 1024)
        record, private_key = _load_identity(args.identity)
        updated = countersign_work_receipt(
            raw,
            args.repository,
            verifier_did=record.did,
            private_key=private_key,
        )
        print(render_work_receipt(updated), flush=True)
        return 0
    raise WorkReceiptError("unsupported work receipt command")


def _audit(args: argparse.Namespace) -> int:
    if args.audit_command != "verify":
        raise AuditError("unsupported audit command")
    summary = SignedAuditLog(args.path).verify(expected_head=args.expected_head)
    _print_event(
        {
            "status": "valid",
            "entries": summary.entries,
            "issuer": summary.issuer,
            "head_sha256": summary.head_sha256,
            "expected_head_matched": args.expected_head is not None,
        }
    )
    return 0


def _run(args: argparse.Namespace) -> int:
    record, private_key = _load_identity(args.identity)
    identity_path, config_path, default_state_path = _paths_beside_identity(args)
    lock_path = _path_beside_identity(args.lock, identity_path, "safe-agent.lock")
    lock = AgentProcessLock(lock_path) if args.send else nullcontext()
    with lock:
        return _run_with_identity(
            args,
            record,
            private_key,
            identity_path,
            config_path,
            default_state_path,
        )


def _run_with_identity(
    args: argparse.Namespace,
    record: IdentityRecord,
    private_key: Any,
    identity_path: Path,
    config_path: Path,
    default_state_path: Path,
) -> int:
    config = _load_active_config(record, config_path)
    room, base_url = _resolve_runtime_target(args, config)
    state_path = args.state.expanduser().resolve() if args.state else default_state_path
    state = AgentState.load(state_path)
    policy = _command_policy(args, record.did, state, state_path)
    delivery_journal, audit_log = _live_artifacts(args, identity_path, record.did)
    client = TechnocoreClient(base_url=base_url, timeout=args.timeout)
    responder = SafeResponder(
        room=room,
        did=record.did,
        private_key=private_key,
        client=client,
        policy=policy,
        state=state,
        state_path=state_path,
        receipt_service=ContributionReceiptService(
            issuer_did=record.did,
            private_key=private_key,
            client=GitHubPublicClient(timeout=args.github_timeout),
        ),
        delivery_journal=delivery_journal,
        audit_log=audit_log,
        send=args.send,
    )

    if _initialize_cursor(args, responder, state, room):
        return 0
    return _poll(args, responder, state, client, room)


def _load_active_config(
    record: IdentityRecord, config_path: Path
) -> AgentConfig | None:
    config: AgentConfig | None = None
    if config_path.exists():
        config = AgentConfig.load(config_path)
        if config.did != record.did or config.fingerprint != record.fingerprint:
            raise ConfigError(
                "agent config does not belong to the selected public identity"
            )
        if config.status != "active":
            raise ConfigError(
                "agent config is pending; inspect provisioning before running"
            )
    return config


def _resolve_runtime_target(
    args: argparse.Namespace, config: AgentConfig | None
) -> tuple[str, str]:
    if args.room:
        room = validate_room(args.room)
    elif config is not None:
        room = config.room
    else:
        raise ConfigError(
            "no provisioned config exists; pass --room or run provision first"
        )
    base_url = args.base_url or (
        config.base_url if config is not None else "https://technocore.chat"
    )
    return room, base_url


def _command_policy(
    args: argparse.Namespace,
    own_did: str,
    state: AgentState,
    state_path: Path,
) -> CommandPolicy:
    if args.capability_policy is not None:
        capabilities = CapabilityPolicyFile(args.capability_policy)
        capabilities.load()
        return CommandPolicy(
            own_did=own_did,
            capabilities=capabilities,
            rate_limiter=CapabilityRateLimiter(
                state=state,
                state_path=state_path,
                consume=args.send,
            ),
        )

    allowed = frozenset(validate_did(did) for did in args.allow_did)
    if args.send and not allowed and not args.allow_any_signed:
        raise ProtocolValueError(
            "--send requires --capability-policy, at least one --allow-did, "
            "or the explicit --allow-any-signed flag"
        )
    return CommandPolicy(
        own_did=own_did,
        allowed_dids=allowed,
        allow_any_signed=args.allow_any_signed,
    )


def _live_artifacts(
    args: argparse.Namespace, identity_path: Path, did: str
) -> tuple[DeliveryJournal | None, SignedAuditLog | None]:
    if not args.send:
        return None, None
    journal = DeliveryJournal(
        _path_beside_identity(args.journal, identity_path, "safe-agent-delivery.json")
    )
    journal.require_empty()
    audit_path = _path_beside_identity(
        args.audit_log, identity_path, "safe-agent-audit.jsonl"
    )
    audit = SignedAuditLog(audit_path)
    if audit_path.exists() and audit.verify().issuer not in {None, did}:
        raise AuditError("audit log belongs to a different agent DID")
    return journal, audit


def _initialize_cursor(
    args: argparse.Namespace,
    responder: SafeResponder,
    state: AgentState,
    room: str,
) -> bool:
    if room not in state.cursors:
        if args.start_at == "saved":
            raise StateError(
                "no saved cursor exists for this room; choose --start-at latest or --start-at zero"
            )
        if args.start_at == "latest":
            _print_event(responder.bootstrap_latest())
            if args.once:
                return True
    return False


def _poll(
    args: argparse.Namespace,
    responder: SafeResponder,
    state: AgentState,
    client: TechnocoreClient,
    room: str,
) -> int:
    cache_buster = 1
    backoff = 1.0
    while True:
        try:
            snapshot = client.read_room(
                room,
                since=state.cursor_for(room),
                wait=0 if args.once else args.wait,
                limit=args.limit,
                cache_buster=cache_buster,
            )
            for event in responder.process_snapshot(snapshot):
                _print_event(event)
            backoff = 1.0
        except TransportError as error:
            if args.once:
                raise
            delay = error.retry_after if error.retry_after is not None else backoff
            delay = min(max(delay, 0.5), 30.0)
            _print_event(
                {
                    "event": "read_retry",
                    "room": room,
                    "delay_seconds": delay,
                    "http_status": error.status,
                }
            )
            time.sleep(delay)
            backoff = min(backoff * 2, 30.0)
        if args.once:
            return 0
        cache_buster += 1


def _path_beside_identity(
    selected: Path | None, identity_path: Path, default_name: str
) -> Path:
    if selected is not None:
        return selected.expanduser().resolve()
    return identity_path.with_name(default_name)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        handler = {
            "doctor": _doctor,
            "health": _health,
            "controller": _controller,
            "launchd": _launchd,
            "provision": _provision,
            "recover": _recover,
            "recover-delivery": _recover_delivery,
            "receipt": _receipt,
            "verify-receipt": _verify_receipt,
            "work-receipt": _work_receipt,
            "audit": _audit,
            "run": _run,
        }[args.command]
        return handler(args)
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
        return 130
    except UncertainWriteError as error:
        print(f"write halted: {error}", file=sys.stderr)
        return 3
    except (
        AuditError,
        CapabilityError,
        ConfigError,
        ControllerError,
        DeliveryError,
        IdentityError,
        LaunchAgentError,
        GitHubReceiptError,
        ProtocolValueError,
        ProcessLockError,
        ResponseError,
        StateError,
        TransportError,
        WorkReceiptError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
