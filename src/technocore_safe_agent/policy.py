"""A deliberately non-agentic command policy for untrusted room messages."""

from __future__ import annotations

from dataclasses import dataclass

from technocore_safe_agent.capabilities import (
    CapabilityError,
    CapabilityGrant,
    CapabilityPolicyFile,
    CapabilityRateLimiter,
)
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
class ParsedCommand:
    name: str
    decision: Decision
    repository: str | None = None


@dataclass(frozen=True)
class CommandPolicy:
    own_did: str
    allowed_dids: frozenset[str] = frozenset()
    allow_any_signed: bool = False
    capabilities: CapabilityPolicyFile | None = None
    rate_limiter: CapabilityRateLimiter | None = None

    def __post_init__(self) -> None:
        if self.capabilities is not None and (
            self.allowed_dids or self.allow_any_signed
        ):
            raise CapabilityError(
                "capability policy cannot be combined with legacy sender flags"
            )
        if (self.capabilities is None) != (self.rate_limiter is None):
            raise CapabilityError(
                "capability policy and its rate limiter must be configured together"
            )

    def decide(self, message: RoomMessage) -> Decision:
        denial, grant = self._authorize_sender(message)
        if denial is not None:
            return denial
        return self._decide_authorized_command(message, grant)

    def _authorize_sender(
        self, message: RoomMessage
    ) -> tuple[Decision | None, CapabilityGrant | None]:
        if message.sender == self.own_did:
            return Decision("ignore", "own_message"), None
        if not message.is_signed:
            return Decision("ignore", "unsigned_sender"), None

        grant = self._grant_for(message.sender)
        if self.capabilities is None:
            if not self.allow_any_signed and message.sender not in self.allowed_dids:
                return Decision("ignore", "sender_not_allowlisted"), None
        elif grant is None:
            return Decision("ignore", "principal_not_granted"), None
        elif not grant.enabled:
            return Decision("ignore", "principal_revoked"), None
        return None, grant

    def _decide_authorized_command(
        self, message: RoomMessage, grant: CapabilityGrant | None
    ) -> Decision:
        command_name = _command_name(message.text)
        if command_name is None:
            return Decision("ignore", "unsupported_command")
        if grant is not None and command_name not in grant.commands:
            return Decision("ignore", "command_not_granted")

        parsed = _parse_command(command_name, message.text)
        if parsed.decision.action == "ignore":
            return parsed.decision
        if (
            grant is not None
            and parsed.repository is not None
            and not grant.allows_repository(parsed.repository)
        ):
            return Decision("ignore", "repository_not_granted")
        if grant is not None:
            limiter = self.rate_limiter
            if limiter is None:
                raise CapabilityError("capability rate limiter is not configured")
            if not limiter.allow(message.sender, grant.max_requests_per_hour):
                return Decision("ignore", "rate_limited")
        return parsed.decision

    def _grant_for(self, did: str) -> CapabilityGrant | None:
        if self.capabilities is None:
            return None
        return self.capabilities.load().grant_for(did)


REPLIES = {
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


def _command_name(text: str) -> str | None:
    if text in REPLIES:
        return text
    if text == "/pr" or text.startswith("/pr "):
        return "/pr"
    return None


def _parse_command(name: str, text: str) -> ParsedCommand:
    reply = REPLIES.get(name)
    if reply is not None:
        return ParsedCommand(name, Decision("reply", "allowed_command", reply))

    raw_url = text.removeprefix("/pr ")
    try:
        reference = parse_github_pull_request_url(raw_url)
    except GitHubReceiptError:
        return ParsedCommand(name, Decision("ignore", "invalid_pull_request_url"))
    return ParsedCommand(
        name,
        Decision("receipt", "allowed_public_pull_request", target=reference.url),
        repository=reference.full_name,
    )
