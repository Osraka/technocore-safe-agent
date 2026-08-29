"""Crash-safe cursor and nonce persistence."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class StateError(RuntimeError):
    """Persistent agent state is missing or malformed."""


@dataclass
class AgentState:
    cursors: dict[str, int] = field(default_factory=dict)
    nonces: dict[str, int] = field(default_factory=dict)

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
        return cls(cursors=cursors, nonces=nonces)

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

    def save(self, path: Path) -> None:
        resolved = path.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "schema": "technocore-safe-agent-state-v1",
            "cursors": dict(sorted(self.cursors.items())),
            "nonces": dict(sorted(self.nonces.items())),
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


def _nonnegative_int_map(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise StateError(f"state {label} must be an object")
    checked: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise StateError(f"state {label} contains an invalid room")
        checked[key] = _require_nonnegative_int(item, f"state {label}[{key!r}]")
    return checked
