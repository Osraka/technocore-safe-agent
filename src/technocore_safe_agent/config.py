"""Non-secret local configuration for one provisioned responder mailbox."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from technocore_safe_agent.crypto import (
    fingerprint_of_did,
    validate_did,
    validate_nonce,
    validate_room,
)
from technocore_safe_agent.protocol import validate_base_url


class ConfigError(RuntimeError):
    """The local agent configuration is missing, unsafe, or malformed."""


@dataclass(frozen=True)
class AgentConfig:
    schema: str
    name: str
    did: str
    fingerprint: str
    room: str
    base_url: str
    status: str
    created_at: str
    provision_nonce: str
    provisioned_seq: int | None = None

    @classmethod
    def load(cls, path: Path) -> "AgentConfig":
        resolved = path.expanduser().resolve()
        try:
            payload = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ConfigError(
                f"cannot read agent config {resolved}: {error}"
            ) from error
        if not isinstance(payload, dict):
            raise ConfigError("agent config must contain a JSON object")
        try:
            config = cls(**payload)
        except TypeError as error:
            raise ConfigError(
                "agent config fields do not match the supported schema"
            ) from error
        config.validate()
        return config

    def validate(self) -> None:
        if self.schema != "technocore-safe-agent-config-v1":
            raise ConfigError("agent config has an unsupported schema")
        if (
            not isinstance(self.name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", self.name) is None
        ):
            raise ConfigError("agent config has an invalid name")
        validate_did(self.did)
        validate_room(self.room)
        validate_base_url(self.base_url)
        if self.status not in {"pending", "active"}:
            raise ConfigError("agent config has an invalid status")
        if self.fingerprint != fingerprint_of_did(self.did):
            raise ConfigError("agent config fingerprint does not match its DID")
        if not isinstance(self.created_at, str) or not self.created_at:
            raise ConfigError("agent config is missing created_at")
        try:
            validate_nonce(self.provision_nonce)
        except ValueError as error:
            raise ConfigError("agent config has an invalid provision nonce") from error
        if self.provisioned_seq is not None and (
            isinstance(self.provisioned_seq, bool)
            or not isinstance(self.provisioned_seq, int)
            or self.provisioned_seq <= 0
        ):
            raise ConfigError("agent config has an invalid provisioned sequence")
        if self.status == "active" and self.provisioned_seq is None:
            raise ConfigError("active agent config is missing the provisioned sequence")

    def save_new(self, path: Path) -> None:
        resolved = path.expanduser().resolve()
        if resolved.exists():
            raise ConfigError(
                f"refusing to overwrite existing agent config: {resolved}"
            )
        _atomic_json_write(resolved, asdict(self), replace=False)

    def save_replacement(self, path: Path) -> None:
        resolved = path.expanduser().resolve()
        if not resolved.exists():
            raise ConfigError(f"cannot activate missing agent config: {resolved}")
        _atomic_json_write(resolved, asdict(self), replace=True)


def _atomic_json_write(path: Path, payload: dict[str, Any], *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if not replace and path.exists():
            raise ConfigError(f"refusing to overwrite existing agent config: {path}")
        os.replace(temporary_name, path)
        temporary_name = None
        os.chmod(path, 0o600)
    except OSError as error:
        raise ConfigError(f"cannot write agent config {path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
