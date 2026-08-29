"""Polling and reply orchestration with explicit delivery semantics."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.crypto import sign_room_message
from technocore_safe_agent.policy import CommandPolicy
from technocore_safe_agent.protocol import (
    ResponseError,
    RoomSnapshot,
    TechnocoreClient,
    TransportError,
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
            decision = self.policy.decide(message)
            event: dict[str, Any] = {
                "event": decision.action,
                "room": self.room,
                "seq": message.seq,
                "sender": message.sender,
                "reason": decision.reason,
            }
            if decision.action == "reply" and decision.reply is not None:
                if self.send:
                    nonce = self.state.next_nonce(self.room, time.time_ns())
                    swept, signature = sign_room_message(
                        self.private_key,
                        self.room,
                        nonce,
                        decision.reply,
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
                    event.update(
                        {
                            "event": "sent",
                            "reply_seq": posted.seq,
                            "reply_command": message.text,
                        }
                    )
                else:
                    event.update(
                        {
                            "event": "would_reply",
                            "reply_command": message.text,
                            "reply": decision.reply,
                        }
                    )
            self.state.advance_cursor(self.room, message.seq)
            cursor = message.seq
            if self.send:
                try:
                    self.state.save(self.state_path)
                except StateError as error:
                    if event["event"] == "sent":
                        raise UncertainWriteError(
                            "reply was acknowledged but its cursor could not be persisted; "
                            "inspect the room and repair the state file before restarting"
                        ) from error
                    raise
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
