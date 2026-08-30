"""Polling and reply orchestration with explicit delivery semantics."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.audit import AuditError, SignedAuditLog
from technocore_safe_agent.crypto import fingerprint_of_did, sign_room_message
from technocore_safe_agent.delivery import (
    DeliveryError,
    DeliveryJournal,
    DeliveryRecord,
)
from technocore_safe_agent.policy import CommandPolicy
from technocore_safe_agent.protocol import (
    ResponseError,
    RoomMessage,
    RoomSnapshot,
    TechnocoreClient,
    TransportError,
)
from technocore_safe_agent.receipt import (
    GitHubReceiptError,
    ReceiptIssuer,
)
from technocore_safe_agent.state import AgentState, StateError


class UncertainWriteError(RuntimeError):
    """A signed POST may have landed, so retrying automatically is unsafe."""


@dataclass
class SafeResponder:
    room: str
    did: str
    private_key: Ed25519PrivateKey
    client: TechnocoreClient
    policy: CommandPolicy
    state: AgentState
    state_path: Path
    receipt_service: ReceiptIssuer | None = None
    delivery_journal: DeliveryJournal | None = None
    audit_log: SignedAuditLog | None = None
    send: bool = False

    def bootstrap_latest(self) -> dict[str, Any]:
        """Start after the current tail so historical messages cannot trigger replies."""

        snapshot = self.client.read_room(
            self.room, since=0, wait=0, limit=1, cache_buster=0
        )
        self.state.advance_cursor(self.room, snapshot.last_seq)
        if self.send:
            self.state.save(self.state_path)
        return {
            "event": "bootstrapped",
            "room": self.room,
            "cursor": snapshot.last_seq,
            "mode": "send" if self.send else "dry-run",
        }

    def process_snapshot(self, snapshot: RoomSnapshot) -> list[dict[str, Any]]:
        if snapshot.room != self.room:
            raise ResponseError("agent received a snapshot for a different room")
        events: list[dict[str, Any]] = []
        cursor = self.state.cursor_for(self.room)
        if snapshot.first_seq > 0 and snapshot.first_seq > cursor + 1:
            events.append(
                {
                    "event": "retention_gap",
                    "room": self.room,
                    "cursor": cursor,
                    "first_available": snapshot.first_seq,
                }
            )

        handled = False
        for message in snapshot.messages:
            if message.seq <= cursor:
                continue
            handled = True
            event = self._event_for_message(message)
            self._persist_processed_message(message, event)
            cursor = message.seq
            events.append(event)

        # A retention/expiry gap can leave no readable records even though the tail moved.
        if not handled and snapshot.last_seq > cursor:
            self.state.advance_cursor(self.room, snapshot.last_seq)
            if self.send:
                self.state.save(self.state_path)
            events.append(
                {
                    "event": "cursor_advanced_over_unavailable_messages",
                    "room": self.room,
                    "from": cursor,
                    "to": snapshot.last_seq,
                }
            )
        return events

    def _event_for_message(self, message: RoomMessage) -> dict[str, Any]:
        decision = self.policy.decide(message)
        event: dict[str, Any] = {
            "event": decision.action,
            "decision": decision.action,
            "room": self.room,
            "seq": message.seq,
            "sender": message.sender,
            "reason": decision.reason,
        }
        if decision.action == "reply" and decision.reply is not None:
            return self._reply_event(event, message.seq, message.text, decision.reply)
        if decision.action == "receipt" and decision.target is not None:
            return self._receipt_event(event, message.seq, decision.target)
        return event

    def _reply_event(
        self,
        event: dict[str, Any],
        input_sequence: int,
        command: str,
        reply: str,
    ) -> dict[str, Any]:
        if not self.send:
            event.update(
                {"event": "would_reply", "reply_command": command, "reply": reply}
            )
            return event
        posted = self._send_text(reply, input_sequence)
        event.update(
            {"event": "sent", "reply_seq": posted.seq, "reply_command": command}
        )
        return event

    def _receipt_event(
        self, event: dict[str, Any], input_sequence: int, pull_request: str
    ) -> dict[str, Any]:
        if not self.send:
            event.update(
                {
                    "event": "would_issue_receipt",
                    "pull_request": pull_request,
                    "network_requested": False,
                }
            )
            return event
        if self.receipt_service is None:
            raise ResponseError(
                "receipt command reached an agent without a receipt service"
            )
        try:
            receipt = self.receipt_service.issue(pull_request)
        except GitHubReceiptError as error:
            event.update(
                {
                    "event": "receipt_failed",
                    "pull_request": pull_request,
                    "error_code": error.code,
                    "http_status": error.status,
                    "retry_after": error.retry_after,
                }
            )
            return event
        posted = self._send_text(receipt, input_sequence)
        event.update(
            {
                "event": "sent_receipt",
                "reply_seq": posted.seq,
                "pull_request": pull_request,
                "receipt_sha256": hashlib.sha256(receipt.encode("utf-8")).hexdigest(),
            }
        )
        return event

    def _persist_processed_message(
        self, message: RoomMessage, event: dict[str, Any]
    ) -> None:
        if self.send and self.audit_log is not None:
            self._append_audit_record(message, event)
        self.state.advance_cursor(self.room, message.seq)
        if not self.send:
            return
        try:
            self.state.save(self.state_path)
        except StateError as error:
            if event["event"] in {"sent", "sent_receipt"}:
                raise UncertainWriteError(
                    "reply was acknowledged but its cursor could not be persisted; "
                    "inspect the room and repair the state file before restarting"
                ) from error
            raise

        if event["event"] in {"sent", "sent_receipt"} and self.delivery_journal:
            try:
                self.delivery_journal.clear()
            except DeliveryError as error:
                raise UncertainWriteError(
                    "reply and cursor were persisted but the delivery journal could not "
                    "be cleared; run recover-delivery before restarting"
                ) from error

    def _append_audit_record(self, message: RoomMessage, event: dict[str, Any]) -> None:
        audit_log = self.audit_log
        if audit_log is None:
            raise AuditError("audit log is not configured")
        sender_fingerprint = (
            fingerprint_of_did(message.sender) if message.is_signed else None
        )
        audit_log.append(
            issuer_did=self.did,
            private_key=self.private_key,
            observed_at=datetime.now(UTC),
            input_sequence=message.seq,
            sender_fingerprint=sender_fingerprint,
            sender_authenticated=message.is_signed,
            policy_decision=event["decision"],
            policy_reason=event["reason"],
            outcome=event["event"],
            receipt_sha256=event.get("receipt_sha256"),
            response_sequence=event.get("reply_seq"),
        )

    def _send_text(self, text: str, input_sequence: int) -> RoomMessage:
        if self.delivery_journal is not None:
            self.delivery_journal.require_empty()
        nonce = self.state.next_nonce(self.room, time.time_ns())
        swept, signature = sign_room_message(
            self.private_key,
            self.room,
            nonce,
            text,
        )
        if self.delivery_journal is not None:
            self.delivery_journal.prepare(
                DeliveryRecord.create(
                    room=self.room,
                    input_sequence=input_sequence,
                    did=self.did,
                    nonce=nonce,
                    text=swept,
                    signature=signature,
                )
            )
        try:
            posted = self.client.send_signed_message(
                room=self.room,
                did=self.did,
                signature=signature,
                nonce=nonce,
                text=swept,
            )
        except (TransportError, ResponseError) as error:
            raise UncertainWriteError(
                "signed write did not return a verifiable acknowledgement; "
                "inspect the room before restarting so the command is not answered twice"
            ) from error
        if self.delivery_journal is not None:
            try:
                self.delivery_journal.acknowledge(posted.seq)
            except DeliveryError as error:
                raise UncertainWriteError(
                    "reply was acknowledged but its delivery evidence could not be "
                    "persisted; run recover-delivery before restarting"
                ) from error
        return posted
