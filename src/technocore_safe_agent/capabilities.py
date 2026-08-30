"""Strict, reloadable capabilities for signed Technocore principals."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from technocore_safe_agent.crypto import ProtocolValueError, validate_did
from technocore_safe_agent.state import AgentState

CAPABILITY_SCHEMA = "technocore-safe-agent-capabilities-v1"
MAX_POLICY_BYTES = 64 * 1024
MAX_PRINCIPALS = 128
MAX_REQUESTS_PER_HOUR = 1_000
WINDOW_SECONDS = 3_600
SUPPORTED_COMMANDS = frozenset({"/ping", "/status", "/about", "/help", "/pr"})
POLICY_KEYS = frozenset({"schema", "principals"})
GRANT_KEYS = frozenset({"enabled", "commands", "repositories", "max_requests_per_hour"})
OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")


class CapabilityError(RuntimeError):
    """A capability file is unsafe, malformed, or internally inconsistent."""


@dataclass(frozen=True)
class CapabilityGrant:
    enabled: bool
    commands: frozenset[str]
    repositories: tuple[str, ...]
    max_requests_per_hour: int

    def allows_repository(self, full_name: str) -> bool:
        candidate = full_name.casefold()
        for scope in self.repositories:
            if scope.endswith("/*"):
                if candidate.startswith(scope[:-1]) and candidate.count("/") == 1:
                    return True
            elif candidate == scope:
                return True
        return False


@dataclass(frozen=True)
class CapabilityPolicy:
    principals: dict[str, CapabilityGrant]

    def grant_for(self, did: str) -> CapabilityGrant | None:
        return self.principals.get(did)


class CapabilityPolicyFile:
    """Load a bounded mode-0600 policy afresh for each authorization decision."""

    def __init__(self, path: Path):
        self.path = path.expanduser().absolute()

    def load(self) -> CapabilityPolicy:
        descriptor: int | None = None
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise CapabilityError("capability policy must be a regular file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise CapabilityError(
                    "capability policy permissions must not allow group or other access"
                )
            if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                raise CapabilityError(
                    "capability policy must be owned by the current user"
                )
            payload = _decode_json(_read_bounded(descriptor))
        except OSError as error:
            raise CapabilityError(
                f"cannot access capability policy {self.path}: {error}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return _parse_policy(payload)


@dataclass
class CapabilityRateLimiter:
    """Conservatively reserve persistent per-DID capacity before side effects."""

    state: AgentState
    state_path: Path
    consume: bool
    clock: Callable[[], float] = field(default=time.time, repr=False)

    def allow(self, did: str, limit: int) -> bool:
        try:
            valid_did = validate_did(did)
        except ProtocolValueError as error:
            raise CapabilityError("rate-limit principal DID is invalid") from error
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_REQUESTS_PER_HOUR
        ):
            raise CapabilityError("rate limit is outside the supported range")
        raw_now = self.clock()
        if (
            isinstance(raw_now, bool)
            or not isinstance(raw_now, (int, float))
            or not math.isfinite(raw_now)
            or raw_now < 0
        ):
            raise CapabilityError("rate-limit clock returned an invalid timestamp")
        now = int(raw_now)
        if self.state.capability_request_count(valid_did, now, WINDOW_SECONDS) >= limit:
            return False
        if self.consume:
            self.state.reserve_capability_request(valid_did, now, WINDOW_SECONDS)
            self.state.save(self.state_path)
        return True


def _parse_policy(payload: Any) -> CapabilityPolicy:
    if not isinstance(payload, dict) or set(payload) != POLICY_KEYS:
        raise CapabilityError("capability policy has unexpected top-level fields")
    if payload.get("schema") != CAPABILITY_SCHEMA:
        raise CapabilityError("capability policy has an unsupported schema")
    raw_principals = payload.get("principals")
    if not isinstance(raw_principals, dict):
        raise CapabilityError("capability policy principals must be an object")
    if len(raw_principals) > MAX_PRINCIPALS:
        raise CapabilityError("capability policy contains too many principals")

    principals: dict[str, CapabilityGrant] = {}
    for raw_did, raw_grant in raw_principals.items():
        try:
            did = validate_did(raw_did)
        except ProtocolValueError as error:
            raise CapabilityError(
                "capability policy contains an invalid DID"
            ) from error
        principals[did] = _parse_grant(raw_grant)
    return CapabilityPolicy(principals=principals)


def _parse_grant(payload: Any) -> CapabilityGrant:
    if not isinstance(payload, dict) or set(payload) != GRANT_KEYS:
        raise CapabilityError("capability grant has unexpected fields")
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        raise CapabilityError("capability grant enabled flag must be boolean")
    commands = _commands(payload.get("commands"))
    repositories = _repository_scopes(payload.get("repositories"))
    if enabled and not commands:
        raise CapabilityError("enabled capability grant must contain a command")
    if "/pr" in commands and enabled and not repositories:
        raise CapabilityError("an enabled /pr grant requires a repository scope")
    if "/pr" not in commands and repositories:
        raise CapabilityError("repository scopes require the /pr command")
    rate = payload.get("max_requests_per_hour")
    if (
        isinstance(rate, bool)
        or not isinstance(rate, int)
        or not 1 <= rate <= MAX_REQUESTS_PER_HOUR
    ):
        raise CapabilityError(
            f"max_requests_per_hour must be between 1 and {MAX_REQUESTS_PER_HOUR}"
        )
    return CapabilityGrant(
        enabled=enabled,
        commands=frozenset(commands),
        repositories=repositories,
        max_requests_per_hour=rate,
    )


def _commands(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CapabilityError("capability commands must be an array")
    checked: list[str] = []
    for command in value:
        if not isinstance(command, str) or command not in SUPPORTED_COMMANDS:
            raise CapabilityError("capability grant contains an unsupported command")
        if command in checked:
            raise CapabilityError("capability grant contains a duplicate command")
        checked.append(command)
    return tuple(checked)


def _repository_scopes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CapabilityError("capability repositories must be an array")
    checked: list[str] = []
    for raw_scope in value:
        scope = _repository_scope(raw_scope)
        if scope in checked:
            raise CapabilityError("capability grant contains a duplicate repository")
        checked.append(scope)
    return tuple(checked)


def _repository_scope(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip() or value.count("/") != 1:
        raise CapabilityError("capability repository scope is invalid")
    owner, repository = value.split("/", 1)
    if OWNER_PATTERN.fullmatch(owner) is None:
        raise CapabilityError("capability repository owner is invalid")
    if repository != "*" and (
        REPOSITORY_PATTERN.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
    ):
        raise CapabilityError("capability repository name is invalid")
    return f"{owner}/{repository}".casefold()


def _decode_json(raw: bytes) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        for key, value in pairs:
            if key in decoded:
                raise CapabilityError("capability policy contains a duplicate JSON key")
            decoded[key] = value
        return decoded

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CapabilityError("capability policy is not valid JSON") from error


def _read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    observed = 0
    try:
        while True:
            chunk = os.read(descriptor, min(16 * 1024, MAX_POLICY_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAX_POLICY_BYTES:
                raise CapabilityError("capability policy exceeds the 64 KiB limit")
    except OSError as error:
        raise CapabilityError(f"cannot read capability policy: {error}") from error
    return b"".join(chunks)
