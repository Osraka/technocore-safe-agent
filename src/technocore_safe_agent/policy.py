"""A deliberately non-agentic command policy for untrusted room messages."""

from __future__ import annotations

from dataclasses import dataclass

from technocore_safe_agent.protocol import RoomMessage
from technocore_safe_agent.receipt import (
    GitHubReceiptError,
    parse_github_pull_request_url,
)


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str
    reply: str | None = None
    target: str | None = None


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
            "/help": "Commands: /ping, /status, /about, /help, /pr <public GitHub PR URL>",
            "/status": (
                "Osraka safe responder is online. It reads public GitHub PR metadata "
                "only and executes no room-supplied tools."
            ),
            "/about": (
                "Keychain-backed Technocore responder. Signed commands only; "
                "fixed GitHub PR reads only; no shell, file, general URL, "
                "or arbitrary prompt execution."
            ),
        }
        reply = replies.get(message.text)
        if reply is not None:
            return Decision("reply", "allowed_command", reply)
        if message.text == "/pr" or message.text.startswith("/pr "):
            raw_url = message.text.removeprefix("/pr ")
            try:
                reference = parse_github_pull_request_url(raw_url)
            except GitHubReceiptError:
                return Decision("ignore", "invalid_pull_request_url")
            return Decision(
                "receipt", "allowed_public_pull_request", target=reference.url
            )
        return Decision("ignore", "unsupported_command")
