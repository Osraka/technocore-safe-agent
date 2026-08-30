"""Explicit recovery for one ambiguous signed room delivery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from technocore_safe_agent.agent import UncertainWriteError
from technocore_safe_agent.crypto import validate_did, validate_room
from technocore_safe_agent.delivery import (
    DeliveryError,
    DeliveryJournal,
    DeliveryRecord,
)
from technocore_safe_agent.protocol import (
    ResponseError,
    RoomSnapshot,
    TechnocoreClient,
    TransportError,
)
from technocore_safe_agent.state import AgentState, StateError


def recover_delivery(
    *,
    room: str,
    did: str,
    client: TechnocoreClient,
    state: AgentState,
    state_path: Path,
    journal: DeliveryJournal,
    apply: bool,
    confirm_retry: bool,
) -> dict[str, Any]:
    """Inspect first; mutate or resend only behind explicit recovery flags."""

    valid_room = validate_room(room)
    valid_did = validate_did(did)
    if confirm_retry and not apply:
        raise DeliveryError("--confirm-retry requires --apply")

    record = journal.load()
    if record is None:
        return {"event": "no_pending_delivery", "room": valid_room}
    record.verify_for_room(valid_room)
    if record.did != valid_did:
        raise DeliveryError("delivery journal belongs to a different identity")

    if record.status == "acknowledged":
        return _recover_acknowledged(
            room=valid_room,
            record=record,
            state=state,
            state_path=state_path,
            journal=journal,
            apply=apply,
        )

    snapshot = client.read_room(
        valid_room,
        since=record.input_sequence,
        wait=0,
        limit=200,
        cache_buster=0,
    )
    return _recover_pending(
        room=valid_room,
        record=record,
        snapshot=snapshot,
        client=client,
        state=state,
        state_path=state_path,
        journal=journal,
        apply=apply,
        confirm_retry=confirm_retry,
    )


def _recover_acknowledged(
    *,
    room: str,
    record: DeliveryRecord,
    state: AgentState,
    state_path: Path,
    journal: DeliveryJournal,
    apply: bool,
) -> dict[str, Any]:
    if not apply:
        return {
            "event": "delivery_acknowledged",
            "room": room,
            "input_seq": record.input_sequence,
            "reply_seq": record.reply_sequence,
            "apply_required": True,
        }
    assert record.reply_sequence is not None
    _finalize_recovery(
        room=room,
        record=record,
        reply_sequence=record.reply_sequence,
        state=state,
        state_path=state_path,
        journal=journal,
        failure_message="acknowledged delivery state could not be finalized",
    )
    return {
        "event": "delivery_recovered",
        "room": room,
        "input_seq": record.input_sequence,
        "reply_seq": record.reply_sequence,
        "retried": False,
        "evidence": "verified_acknowledgement",
    }


def _recover_pending(
    *,
    room: str,
    record: DeliveryRecord,
    snapshot: RoomSnapshot,
    client: TechnocoreClient,
    state: AgentState,
    state_path: Path,
    journal: DeliveryJournal,
    apply: bool,
    confirm_retry: bool,
) -> dict[str, Any]:
    complete = _is_complete_history(snapshot, record.input_sequence)
    matches = tuple(message for message in snapshot.messages if record.matches(message))

    if not complete:
        return {
            "event": "delivery_history_incomplete",
            "room": room,
            "input_seq": record.input_sequence,
            "matches_observed": len(matches),
            "retry_available": False,
            "reason": "cannot prove the delivery count or absence",
        }
    if len(matches) > 1:
        return {
            "event": "duplicate_delivery_records",
            "room": room,
            "input_seq": record.input_sequence,
            "reply_sequences": [message.seq for message in matches],
            "retry_available": False,
        }
    if len(matches) == 1:
        match = matches[0]
        if not apply:
            return {
                "event": "delivery_found",
                "room": room,
                "input_seq": record.input_sequence,
                "reply_seq": match.seq,
                "apply_required": True,
            }
        _finalize_recovery(
            room=room,
            record=record,
            reply_sequence=match.seq,
            state=state,
            state_path=state_path,
            journal=journal,
            failure_message="found delivery state could not be finalized",
        )
        return {
            "event": "delivery_recovered",
            "room": room,
            "input_seq": record.input_sequence,
            "reply_seq": match.seq,
            "retried": False,
            "evidence": "room_history",
        }

    if not (apply and confirm_retry):
        return {
            "event": "delivery_not_found",
            "room": room,
            "input_seq": record.input_sequence,
            "retry_available": True,
            "required_flags": ["--apply", "--confirm-retry"],
        }

    posted = _retry_exact_envelope(client, room, record)
    _finalize_recovery(
        room=room,
        record=record,
        reply_sequence=posted.seq,
        state=state,
        state_path=state_path,
        journal=journal,
        failure_message="retried delivery state could not be finalized",
    )
    return {
        "event": "delivery_retried",
        "room": room,
        "input_seq": record.input_sequence,
        "reply_seq": posted.seq,
        "retried": True,
    }


def _finalize_recovery(
    *,
    room: str,
    record: DeliveryRecord,
    reply_sequence: int,
    state: AgentState,
    state_path: Path,
    journal: DeliveryJournal,
    failure_message: str,
) -> None:
    try:
        journal.acknowledge(reply_sequence)
        _persist_recovered_state(
            room=room,
            record=record,
            state=state,
            state_path=state_path,
        )
        journal.clear()
    except (DeliveryError, StateError) as error:
        raise UncertainWriteError(
            f"{failure_message}; run recover-delivery again without retrying"
        ) from error


def _retry_exact_envelope(client: TechnocoreClient, room: str, record: DeliveryRecord):
    try:
        return client.send_signed_message(
            room=room,
            did=record.did,
            signature=record.signature,
            nonce=record.nonce,
            text=record.text,
        )
    except (TransportError, ResponseError) as error:
        raise UncertainWriteError(
            "delivery retry did not return a verifiable acknowledgement; "
            "do not retry again before inspecting the room"
        ) from error


def _persist_recovered_state(
    *,
    room: str,
    record: DeliveryRecord,
    state: AgentState,
    state_path: Path,
) -> None:
    state.observe_nonce(room, record.nonce)
    state.advance_cursor(room, max(state.cursor_for(room), record.input_sequence))
    state.save(state_path)


def _is_complete_history(snapshot: RoomSnapshot, input_sequence: int) -> bool:
    if snapshot.last_seq == input_sequence and not snapshot.messages:
        return True
    if not snapshot.messages or snapshot.last_seq < input_sequence:
        return False
    expected = list(range(input_sequence + 1, snapshot.last_seq + 1))
    observed = [message.seq for message in snapshot.messages]
    return snapshot.first_seq == input_sequence + 1 and observed == expected
