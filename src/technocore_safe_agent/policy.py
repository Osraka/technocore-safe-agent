"""A deliberately non-agentic command policy for untrusted room messages."""

from __future__ import annotations

from dataclasses import dataclass

from technocore_safe_agent.protocol import RoomMessage


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    reply: str | None = None


@dataclass(frozen=True)
class CommandPolicy:
    own_did: str
    allowed_dids: frozenset[str] = frozenset()
    allow_any_signed: bool = False

    def decide(self, message: RoomMessage) -> Decision:
        if message.sender == self.own_did:
            return Decision("ignore", "own_message")
        if not message.is_signed:
            return Decision("ignore", "unsigned_sender")
        if not self.allow_any_signed and message.sender not in self.allowed_dids:
            return Decision("ignore", "sender_not_allowlisted")

        replies = {
            "/ping": "pong",
            "/help": "Commands: /ping, /status, /about, /help",
            "/status": "Osraka safe responder is online. It executes no room-supplied tools.",
            "/about": (
                "Keychain-backed Technocore responder. Signed commands only; "
                "no shell, file, network-tool, or arbitrary prompt execution."
            ),
        }
        reply = replies.get(message.text)
        if reply is None:
            return Decision("ignore", "unsupported_command")
        return Decision("reply", "allowed_command", reply)
