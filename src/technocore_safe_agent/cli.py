"""Command-line entrypoint for the safe Technocore responder."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from technocore_safe_agent import __version__
from technocore_safe_agent.agent import SafeResponder, UncertainWriteError
from technocore_safe_agent.config import AgentConfig, ConfigError
from technocore_safe_agent.crypto import (
    IdentityError,
    ProtocolValueError,
    validate_did,
    validate_room,
)
from technocore_safe_agent.identity import (
    DEFAULT_IDENTITY_PATH,
    IdentityRecord,
    MacOSKeychainSeedProvider,
    load_verified_private_key,
)
from technocore_safe_agent.policy import CommandPolicy
from technocore_safe_agent.provision import provision_mailbox, recover_pending_mailbox
from technocore_safe_agent.protocol import (
    ResponseError,
    TechnocoreClient,
    TransportError,
)
from technocore_safe_agent.state import AgentState, StateError


def _shared_identity_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--identity",
        type=Path,
        default=DEFAULT_IDENTITY_PATH,
        help="public identity JSON; private key remains in macOS Keychain",
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

    provision = commands.add_parser(
        "provision", help="create one unlisted signed mailbox and local config"
    )
    _shared_identity_option(provision)
    provision.add_argument("--name", default="Osraka")
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


def _run(args: argparse.Namespace) -> int:
    record, private_key = _load_identity(args.identity)
    identity_path, config_path, default_state_path = _paths_beside_identity(args)
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
    allowed = frozenset(validate_did(did) for did in args.allow_did)
    if args.send and not allowed and not args.allow_any_signed:
        raise ProtocolValueError(
            "--send requires at least one --allow-did or the explicit --allow-any-signed flag"
        )
    state_path = args.state.expanduser().resolve() if args.state else default_state_path
    state = AgentState.load(state_path)
    client = TechnocoreClient(base_url=base_url, timeout=args.timeout)
    policy = CommandPolicy(
        own_did=record.did,
        allowed_dids=allowed,
        allow_any_signed=args.allow_any_signed,
    )
    responder = SafeResponder(
        room=room,
        did=record.did,
        private_key=private_key,
        client=client,
        policy=policy,
        state=state,
        state_path=state_path,
        send=args.send,
    )

    room_has_state = room in state.cursors
    if not room_has_state:
        if args.start_at == "saved":
            raise StateError(
                "no saved cursor exists for this room; choose --start-at latest or --start-at zero"
            )
        if args.start_at == "latest":
            _print_event(responder.bootstrap_latest())
            if args.once:
                return 0

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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return _doctor(args)
        if args.command == "provision":
            return _provision(args)
        if args.command == "recover":
            return _recover(args)
        return _run(args)
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
        return 130
    except UncertainWriteError as error:
        print(f"write halted: {error}", file=sys.stderr)
        return 3
    except (
        ConfigError,
        IdentityError,
        ProtocolValueError,
        ResponseError,
        StateError,
        TransportError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
