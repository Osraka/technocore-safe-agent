"""Crash-safe evidence for one in-flight signed room delivery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from technocore_safe_agent.crypto import (
    ProtocolValueError,
    sweep_text,
    validate_did,
    validate_nonce,
    validate_room,
    verify_detached_signature,
)
from technocore_safe_agent.protocol import RoomMessage

DELIVERY_SCHEMA = "technocore-safe-agent-delivery-v1"
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}\Z")


class DeliveryError(RuntimeError):
    """The in-flight delivery journal is unsafe or malformed."""


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DeliveryError(f"delivery {label} must be a positive integer")
    return value


@dataclass(frozen=True)
class DeliveryRecord:
    """The exact signed envelope needed to resolve an ambiguous write."""

    status: str
    room_sha256: str
    input_sequence: int
    did: str
    nonce: int
    text: str
    text_sha256: str
    signature: str
    reply_sequence: int | None = None

    @classmethod
    def create(
        cls,
        *,
        room: str,
        input_sequence: int,
        did: str,
        nonce: int,
        text: str,
        signature: str,
    ) -> "DeliveryRecord":
        valid_room = validate_room(room)
        record = cls(
            status="pending",
            room_sha256=_sha256(valid_room),
            input_sequence=_positive_int(input_sequence, "input_sequence"),
            did=validate_did(did),
            nonce=_nonce_as_int(nonce),
            text=_exact_swept_text(text),
            text_sha256=_sha256(text),
            signature=_signature(signature),
        )
        record.verify_for_room(valid_room)
        return record

    @classmethod
    def from_payload(cls, payload: Any) -> "DeliveryRecord":
        if not isinstance(payload, dict) or payload.get("schema") != DELIVERY_SCHEMA:
            raise DeliveryError("delivery journal has an unsupported schema")
        expected = {
            "schema",
            "status",
            "room_sha256",
            "input_sequence",
            "did",
            "nonce",
            "text",
            "text_sha256",
            "signature",
            "reply_sequence",
        }
        if set(payload) != expected:
            raise DeliveryError("delivery journal contains unexpected fields")

        status = payload.get("status")
        if status not in {"pending", "acknowledged"}:
            raise DeliveryError("delivery status must be pending or acknowledged")
        room_digest = payload.get("room_sha256")
        text_digest = payload.get("text_sha256")
        if (
            not isinstance(room_digest, str)
            or SHA256_PATTERN.fullmatch(room_digest) is None
        ):
            raise DeliveryError("delivery room digest is invalid")
        if (
            not isinstance(text_digest, str)
            or SHA256_PATTERN.fullmatch(text_digest) is None
        ):
            raise DeliveryError("delivery text digest is invalid")

        text = _exact_swept_text(payload.get("text"))
        if _sha256(text) != text_digest:
            raise DeliveryError("delivery text digest does not match its payload")

        reply_sequence = payload.get("reply_sequence")
        if status == "pending":
            if reply_sequence is not None:
                raise DeliveryError("pending delivery must not have a reply sequence")
        else:
            reply_sequence = _positive_int(reply_sequence, "reply_sequence")

        record = cls(
            status=status,
            room_sha256=room_digest,
            input_sequence=_positive_int(
                payload.get("input_sequence"), "input_sequence"
            ),
            did=_did(payload.get("did")),
            nonce=_nonce_as_int(payload.get("nonce")),
            text=text,
            text_sha256=text_digest,
            signature=_signature(payload.get("signature")),
            reply_sequence=reply_sequence,
        )
        if (
            record.reply_sequence is not None
            and record.reply_sequence <= record.input_sequence
        ):
            raise DeliveryError("reply sequence must follow the triggering input")
        return record

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": DELIVERY_SCHEMA,
            "status": self.status,
            "room_sha256": self.room_sha256,
            "input_sequence": self.input_sequence,
            "did": self.did,
            "nonce": self.nonce,
            "text": self.text,
            "text_sha256": self.text_sha256,
            "signature": self.signature,
            "reply_sequence": self.reply_sequence,
        }

    def verify_for_room(self, room: str) -> None:
        valid_room = validate_room(room)
        if _sha256(valid_room) != self.room_sha256:
            raise DeliveryError("delivery journal belongs to a different room")
        canonical = f"{valid_room}|{self.nonce}|{self.text}".encode("utf-8")
        if not verify_detached_signature(self.did, canonical, self.signature):
            raise DeliveryError("delivery signature is invalid for this room")

    def acknowledge(self, reply_sequence: int) -> "DeliveryRecord":
        sequence = _positive_int(reply_sequence, "reply_sequence")
        if sequence <= self.input_sequence:
            raise DeliveryError("reply sequence must follow the triggering input")
        if self.status == "acknowledged":
            if self.reply_sequence != sequence:
                raise DeliveryError("delivery already has a different acknowledgement")
            return self
        return replace(self, status="acknowledged", reply_sequence=sequence)

    def matches(self, message: RoomMessage) -> bool:
        return (
            message.sender == self.did
            and message.nonce == str(self.nonce)
            and message.text == self.text
        )


class DeliveryJournal:
    """Persist one delivery envelope before its network request starts."""

    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()

    def load(self) -> DeliveryRecord | None:
        if not self.path.exists():
            return None
        try:
            mode = stat.S_IMODE(self.path.stat().st_mode)
            if mode & 0o077:
                raise DeliveryError(
                    "delivery journal permissions must not allow group or other access"
                )
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DeliveryError(
                f"cannot read delivery journal {self.path}: {error}"
            ) from error
        return DeliveryRecord.from_payload(payload)

    def require_empty(self) -> None:
        if self.load() is not None:
            raise DeliveryError(
                "a pending delivery requires recover-delivery before live sending"
            )

    def prepare(self, record: DeliveryRecord) -> None:
        if self.path.exists():
            raise DeliveryError(
                "a pending delivery already exists; run recover-delivery first"
            )
        self._write(record)

    def acknowledge(self, reply_sequence: int) -> DeliveryRecord:
        record = self.load()
        if record is None:
            raise DeliveryError("cannot acknowledge a missing delivery journal")
        acknowledged = record.acknowledge(reply_sequence)
        self._write(acknowledged)
        return acknowledged

    def clear(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return
        except OSError as error:
            raise DeliveryError(
                f"cannot clear delivery journal {self.path}: {error}"
            ) from error
        _fsync_directory(self.path.parent)

    def _write(self, record: DeliveryRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor: int | None = None
        temporary_name: str | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
            )
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = None
                json.dump(
                    record.to_payload(),
                    stream,
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, self.path)
            temporary_name = None
            os.chmod(self.path, 0o600)
            _fsync_directory(self.path.parent)
        except OSError as error:
            raise DeliveryError(
                f"cannot write delivery journal {self.path}: {error}"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass


def _did(value: Any) -> str:
    try:
        return validate_did(value)
    except ProtocolValueError as error:
        raise DeliveryError("delivery DID is invalid") from error


def _nonce_as_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DeliveryError("delivery nonce must be a non-negative integer")
    try:
        rendered = validate_nonce(value)
    except ProtocolValueError as error:
        raise DeliveryError("delivery nonce is invalid") from error
    return int(rendered)


def _exact_swept_text(value: Any) -> str:
    try:
        swept = sweep_text(value)
    except ProtocolValueError as error:
        raise DeliveryError("delivery text is invalid") from error
    if swept != value:
        raise DeliveryError("delivery text is not in canonical swept form")
    return swept


def _signature(value: Any) -> str:
    if not isinstance(value, str) or SIGNATURE_PATTERN.fullmatch(value) is None:
        raise DeliveryError("delivery signature is invalid")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError as error:
        raise DeliveryError(
            f"cannot sync delivery directory {path}: {error}"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
