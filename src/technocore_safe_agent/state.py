"""Crash-safe cursor and nonce persistence."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from technocore_safe_agent.crypto import ProtocolValueError, validate_did


class StateError(RuntimeError):
    """Persistent agent state is missing or malformed."""


@dataclass
class AgentState:
    cursors: dict[str, int] = field(default_factory=dict)
    nonces: dict[str, int] = field(default_factory=dict)
    capability_requests: dict[str, list[int]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "AgentState":
        resolved = path.expanduser().resolve()
        if not resolved.exists():
            return cls()
        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise StateError(f"cannot read state file {resolved}: {error}") from error
        if (
            not isinstance(payload, dict)
            or payload.get("schema") != "technocore-safe-agent-state-v1"
        ):
            raise StateError("state file has an unsupported schema")
        cursors = _nonnegative_int_map(payload.get("cursors"), "cursors")
        nonces = _nonnegative_int_map(payload.get("nonces"), "nonces")
        capability_requests = _capability_request_map(
            payload.get("capability_requests", {})
        )
        return cls(
            cursors=cursors,
            nonces=nonces,
            capability_requests=capability_requests,
        )

    def cursor_for(self, room: str) -> int:
        return self.cursors.get(room, 0)

    def advance_cursor(self, room: str, sequence: int) -> None:
        _require_nonnegative_int(sequence, "sequence")
        if sequence < self.cursor_for(room):
            raise StateError("refusing to move a room cursor backwards")
        self.cursors[room] = sequence

    def next_nonce(self, room: str, clock_value: int) -> int:
        _require_nonnegative_int(clock_value, "clock nonce")
        selected = max(clock_value, self.nonces.get(room, 0) + 1)
        if selected > 9_999_999_999_999_999_999:
            raise StateError("nonce exceeds the Technocore 19-digit limit")
        self.nonces[room] = selected
        return selected

    def observe_nonce(self, room: str, nonce: int) -> None:
        """Record a recovered nonce without ever moving its high-water mark back."""

        _require_nonnegative_int(nonce, "observed nonce")
        self.nonces[room] = max(self.nonces.get(room, 0), nonce)

    def capability_request_count(self, did: str, now: int, window_seconds: int) -> int:
        _require_nonnegative_int(now, "capability timestamp")
        _require_positive_int(window_seconds, "capability window")
        existing = self.capability_requests.get(did, [])
        effective_now = max(now, existing[-1] if existing else now)
        cutoff = effective_now - window_seconds
        return sum(timestamp > cutoff for timestamp in existing)

    def reserve_capability_request(
        self, did: str, now: int, window_seconds: int
    ) -> None:
        if not isinstance(did, str) or not did:
            raise StateError("capability principal must be a non-empty string")
        _require_nonnegative_int(now, "capability timestamp")
        _require_positive_int(window_seconds, "capability window")
        self._prune_capability_requests(now, window_seconds)
        existing = self.capability_requests.setdefault(did, [])
        effective_now = max(now, existing[-1] if existing else now)
        cutoff = effective_now - window_seconds
        existing[:] = [timestamp for timestamp in existing if timestamp > cutoff]
        existing.append(effective_now)

    def _prune_capability_requests(self, now: int, window_seconds: int) -> None:
        cutoff = now - window_seconds
        retained: dict[str, list[int]] = {}
        for did, timestamps in self.capability_requests.items():
            current = [timestamp for timestamp in timestamps if timestamp > cutoff]
            if current:
                retained[did] = current
        self.capability_requests = retained

    def save(self, path: Path) -> None:
        resolved = path.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "schema": "technocore-safe-agent-state-v1",
            "cursors": dict(sorted(self.cursors.items())),
            "nonces": dict(sorted(self.nonces.items())),
        }
        if self.capability_requests:
            payload["capability_requests"] = {
                did: timestamps
                for did, timestamps in sorted(self.capability_requests.items())
            }
        descriptor: int | None = None
        temporary_name: str | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{resolved.name}.",
                suffix=".tmp",
                dir=resolved.parent,
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = None
                json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, resolved)
            temporary_name = None
            os.chmod(resolved, 0o600)
        except OSError as error:
            raise StateError(f"cannot write state file {resolved}: {error}") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass


def _require_nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StateError(f"{label} must be a non-negative integer")
    return value


def _require_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise StateError(f"{label} must be a positive integer")
    return value


def _nonnegative_int_map(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise StateError(f"state {label} must be an object")
    checked: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise StateError(f"state {label} contains an invalid room")
        checked[key] = _require_nonnegative_int(item, f"state {label}[{key!r}]")
    return checked


def _capability_request_map(value: Any) -> dict[str, list[int]]:
    if not isinstance(value, dict) or len(value) > 128:
        raise StateError("state capability_requests must be a bounded object")
    checked: dict[str, list[int]] = {}
    for did, raw_timestamps in value.items():
        try:
            valid_did = validate_did(did)
        except ProtocolValueError as error:
            raise StateError(
                "state capability_requests contains an invalid principal"
            ) from error
        if not isinstance(raw_timestamps, list) or len(raw_timestamps) > 1_000:
            raise StateError("state capability request history is invalid or oversized")
        timestamps = [
            _require_nonnegative_int(item, "capability request timestamp")
            for item in raw_timestamps
        ]
        if timestamps != sorted(timestamps):
            raise StateError("state capability request history is not ordered")
        checked[valid_did] = timestamps
    return checked
