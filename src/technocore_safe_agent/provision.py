"""One-time creation of an unlisted, signed Technocore mailbox."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.agent import UncertainWriteError
from technocore_safe_agent.config import AgentConfig, ConfigError
from technocore_safe_agent.crypto import sign_room_message
from technocore_safe_agent.identity import IdentityRecord
from technocore_safe_agent.protocol import (
    ResponseError,
    TechnocoreClient,
    TransportError,
)
from technocore_safe_agent.state import AgentState, StateError


def provision_mailbox(
    *,
    name: str,
    record: IdentityRecord,
    private_key: Ed25519PrivateKey,
    client: TechnocoreClient,
    config_path: Path,
    state_path: Path,
    room: str | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(name, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", name) is None
    ):
        raise ConfigError(
            "agent name must contain 1-48 letters, digits, underscores, or hyphens"
        )
    selected_room = room or f"mb-p-{secrets.token_hex(12)}"
    nonce = str(time.time_ns())
    created_at = datetime.now(UTC).isoformat()
    pending = AgentConfig(
        schema="technocore-safe-agent-config-v1",
        name=name,
        did=record.did,
        fingerprint=record.fingerprint,
        room=selected_room,
        base_url=client.base_url,
        status="pending",
        created_at=created_at,
        provision_nonce=nonce,
    )
    pending.validate()
    pending.save_new(config_path)

    text = _online_text(name, record.did)
    swept, signature = sign_room_message(private_key, selected_room, nonce, text)
    try:
        posted = client.send_signed_message(
            room=selected_room,
            did=record.did,
            signature=signature,
            nonce=nonce,
            text=swept,
        )
    except (TransportError, ResponseError) as error:
        raise UncertainWriteError(
            f"mailbox provisioning has an uncertain result; inspect room {selected_room!r} "
            f"and keep the pending config at {config_path}; cause: {error}"
        ) from error
    _activate(pending, posted.seq, config_path, state_path)
    return {
        "event": "mailbox_provisioned",
        "name": name,
        "did": record.did,
        "room": selected_room,
        "sequence": posted.seq,
        "config": str(config_path.expanduser().resolve()),
        "state": str(state_path.expanduser().resolve()),
        "public_profile_published": False,
    }


def recover_pending_mailbox(
    *,
    record: IdentityRecord,
    private_key: Ed25519PrivateKey,
    client: TechnocoreClient,
    config_path: Path,
    state_path: Path,
    retry: bool,
) -> dict[str, Any]:
    pending = AgentConfig.load(config_path)
    if pending.did != record.did or pending.fingerprint != record.fingerprint:
        raise ConfigError("pending config does not belong to the selected identity")
    if pending.status != "pending":
        raise ConfigError("agent config is not pending")
    expected_text = _online_text(pending.name, pending.did)
    snapshot = client.read_room(
        pending.room, since=0, wait=0, limit=200, cache_buster=0
    )
    matching = next(
        (
            message
            for message in snapshot.messages
            if message.sender == pending.did
            and message.nonce == pending.provision_nonce
            and message.text == expected_text
        ),
        None,
    )
    if matching is not None:
        _activate(pending, matching.seq, config_path, state_path)
        return {
            "event": "mailbox_recovered_from_acknowledged_write",
            "room": pending.room,
            "sequence": matching.seq,
            "retried": False,
        }
    complete_history = snapshot.last_seq == 0 or (
        bool(snapshot.messages)
        and snapshot.first_seq == 1
        and snapshot.messages[-1].seq == snapshot.last_seq
    )
    if not complete_history:
        return {
            "event": "mailbox_history_incomplete",
            "room": pending.room,
            "retry_required": False,
            "reason": "cannot prove that the original write is absent",
        }
    if not retry:
        return {
            "event": "mailbox_write_not_found",
            "room": pending.room,
            "retry_required": True,
        }

    swept, signature = sign_room_message(
        private_key,
        pending.room,
        pending.provision_nonce,
        expected_text,
    )
    try:
        posted = client.send_signed_message(
            room=pending.room,
            did=pending.did,
            signature=signature,
            nonce=pending.provision_nonce,
            text=swept,
        )
    except (TransportError, ResponseError) as error:
        raise UncertainWriteError(
            f"manual mailbox retry has an uncertain result; inspect room {pending.room!r}; "
            f"cause: {error}"
        ) from error
    _activate(pending, posted.seq, config_path, state_path)
    return {
        "event": "mailbox_recovered_after_manual_retry",
        "room": pending.room,
        "sequence": posted.seq,
        "retried": True,
    }


def _online_text(name: str, did: str) -> str:
    return (
        f"safe-responder-online-v1 agent:{name} did:{did} "
        "commands:/ping,/status,/about,/help policy:signed-commands-only no-tools"
    )


def _activate(
    pending: AgentConfig,
    sequence: int,
    config_path: Path,
    state_path: Path,
) -> None:
    active = replace(pending, status="active", provisioned_seq=sequence)
    active.save_replacement(config_path)
    state = AgentState.load(state_path)
    state.advance_cursor(pending.room, sequence)
    state.nonces[pending.room] = int(pending.provision_nonce)
    try:
        state.save(state_path)
    except StateError as error:
        raise UncertainWriteError(
            "mailbox is active but its cursor state could not be persisted; "
            f"repair {state_path} before starting the responder"
        ) from error
