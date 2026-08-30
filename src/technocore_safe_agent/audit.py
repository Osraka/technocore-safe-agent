"""Strict, DID-signed audit records for sanitized agent decisions."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.crypto import (
    ProtocolValueError,
    did_from_private_key,
    sign_detached,
    validate_did,
    verify_detached_signature,
)

AUDIT_SCHEMA = "technocore-safe-agent-audit-v1"
GENESIS_HASH = "0" * 64
MAX_AUDIT_BYTES = 16 * 1024 * 1024
MAX_AUDIT_LINE_BYTES = 16 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{85}[AQgw]\Z")
FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{16}\Z")
TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
POLICY_DECISIONS = frozenset({"ignore", "reply", "receipt"})
OUTCOMES = frozenset({"ignore", "sent", "receipt_failed", "sent_receipt"})
PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "audit_sequence",
        "issuer",
        "observed_at",
        "input_sequence",
        "sender_fingerprint",
        "sender_authenticated",
        "policy_decision",
        "policy_reason",
        "outcome",
        "receipt_sha256",
        "response_sequence",
        "previous_entry_sha256",
    }
)
WRAPPER_KEYS = frozenset({"payload", "payload_sha256", "signature"})


class AuditError(RuntimeError):
    """An audit record cannot be trusted, persisted, or verified."""


@dataclass(frozen=True)
class AuditSummary:
    entries: int
    issuer: str | None
    head_sha256: str


class SignedAuditLog:
    """Append and verify a bounded JSONL chain without storing message content."""

    def __init__(self, path: Path):
        # Keep the final path component unresolved so O_NOFOLLOW can reject a swap.
        self.path = path.expanduser().absolute()

    def append(
        self,
        *,
        issuer_did: str,
        private_key: Ed25519PrivateKey,
        observed_at: datetime,
        input_sequence: int,
        sender_fingerprint: str | None,
        sender_authenticated: bool,
        policy_decision: str,
        policy_reason: str,
        outcome: str,
        receipt_sha256: str | None,
        response_sequence: int | None,
    ) -> str:
        valid_issuer = _did(issuer_did)
        if did_from_private_key(private_key) != valid_issuer:
            raise AuditError("audit signing key does not match its issuer DID")

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise AuditError(
                f"cannot create audit directory {self.path.parent}: {error}"
            ) from error
        with self._locked_descriptor(write=True) as descriptor:
            raw = _read_bounded(descriptor)
            summary = _verify_bytes(raw)
            if summary.issuer is not None and summary.issuer != valid_issuer:
                raise AuditError("audit log already belongs to a different issuer")

            payload: dict[str, Any] = {
                "schema": AUDIT_SCHEMA,
                "audit_sequence": summary.entries + 1,
                "issuer": valid_issuer,
                "observed_at": _format_timestamp(observed_at),
                "input_sequence": input_sequence,
                "sender_fingerprint": sender_fingerprint,
                "sender_authenticated": sender_authenticated,
                "policy_decision": policy_decision,
                "policy_reason": policy_reason,
                "outcome": outcome,
                "receipt_sha256": receipt_sha256,
                "response_sequence": response_sequence,
                "previous_entry_sha256": summary.head_sha256,
            }
            _validate_payload(payload)
            canonical_payload = _canonical_json(payload)
            wrapper = {
                "payload": payload,
                "payload_sha256": hashlib.sha256(canonical_payload).hexdigest(),
                "signature": sign_detached(private_key, canonical_payload),
            }
            rendered = _canonical_json(wrapper) + b"\n"
            if len(rendered) > MAX_AUDIT_LINE_BYTES:
                raise AuditError("audit entry exceeds the 16 KiB line limit")
            if len(raw) + len(rendered) > MAX_AUDIT_BYTES:
                raise AuditError("audit log exceeds the 16 MiB safety limit")
            _write_all(descriptor, rendered)
            os.fsync(descriptor)

        _fsync_directory(self.path.parent)
        return _entry_hash(wrapper)

    def verify(self, *, expected_head: str | None = None) -> AuditSummary:
        if not self.path.exists():
            raise AuditError(f"audit log does not exist: {self.path}")
        with self._locked_descriptor(write=False) as descriptor:
            summary = _verify_bytes(_read_bounded(descriptor))
        if expected_head is not None:
            _sha256(expected_head, "expected audit head")
            if summary.head_sha256 != expected_head:
                raise AuditError("audit head does not match the expected checkpoint")
        return summary

    @contextmanager
    def _locked_descriptor(self, *, write: bool) -> Iterator[int]:
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT if write else os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(self.path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AuditError("audit path must be a regular file")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise AuditError(
                    "audit log permissions must not allow group or other access"
                )
            fcntl.flock(
                descriptor,
                fcntl.LOCK_EX if write else fcntl.LOCK_SH,
            )
            yield descriptor
        except OSError as error:
            raise AuditError(f"cannot access audit log {self.path}: {error}") from error
        finally:
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)


def _verify_bytes(raw: bytes) -> AuditSummary:
    if not raw:
        return AuditSummary(entries=0, issuer=None, head_sha256=GENESIS_HASH)
    if not raw.endswith(b"\n"):
        raise AuditError("audit log ends with a partial JSONL record")

    previous_hash = GENESIS_HASH
    issuer: str | None = None
    lines = raw.splitlines()
    for expected_sequence, line in enumerate(lines, start=1):
        issuer, previous_hash = _verify_line(
            line,
            expected_sequence=expected_sequence,
            expected_previous_hash=previous_hash,
            expected_issuer=issuer,
        )
    return AuditSummary(entries=len(lines), issuer=issuer, head_sha256=previous_hash)


def _verify_line(
    line: bytes,
    *,
    expected_sequence: int,
    expected_previous_hash: str,
    expected_issuer: str | None,
) -> tuple[str, str]:
    if not line or len(line) > MAX_AUDIT_LINE_BYTES:
        raise AuditError("audit log contains an empty or oversized record")
    wrapper = _decode_json(line)
    if not isinstance(wrapper, dict) or set(wrapper) != WRAPPER_KEYS:
        raise AuditError("audit record wrapper has unexpected fields")
    payload = wrapper.get("payload")
    if not isinstance(payload, dict):
        raise AuditError("audit record payload must be an object")
    _validate_payload(payload)
    if payload["audit_sequence"] != expected_sequence:
        raise AuditError("audit sequence is not contiguous")
    if payload["previous_entry_sha256"] != expected_previous_hash:
        raise AuditError("audit previous-entry hash does not match")
    issuer = payload["issuer"]
    if expected_issuer is not None and issuer != expected_issuer:
        raise AuditError("audit issuer changes inside one log")
    _verify_wrapper_signature(wrapper, payload)
    return issuer, _entry_hash(wrapper)


def _verify_wrapper_signature(wrapper: dict[str, Any], payload: dict[str, Any]) -> None:
    canonical_payload = _canonical_json(payload)
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    if wrapper.get("payload_sha256") != payload_hash:
        raise AuditError("audit payload hash does not match")
    signature = wrapper.get("signature")
    if not isinstance(signature, str) or SIGNATURE_PATTERN.fullmatch(signature) is None:
        raise AuditError("audit signature is not canonical base64url")
    if not verify_detached_signature(payload["issuer"], canonical_payload, signature):
        raise AuditError("audit signature does not match its issuer")


def _validate_payload(payload: dict[str, Any]) -> None:
    if set(payload) != PAYLOAD_KEYS or payload.get("schema") != AUDIT_SCHEMA:
        raise AuditError("audit payload has unexpected fields or schema")
    _positive_int(payload.get("audit_sequence"), "audit sequence")
    _positive_int(payload.get("input_sequence"), "input sequence")
    _did(payload.get("issuer"))
    _timestamp(payload.get("observed_at"))
    _sha256(payload.get("previous_entry_sha256"), "previous-entry hash")

    _validate_sender(payload)
    _validate_decision(payload)


def _validate_sender(payload: dict[str, Any]) -> None:
    authenticated = payload.get("sender_authenticated")
    fingerprint = payload.get("sender_fingerprint")
    if not isinstance(authenticated, bool):
        raise AuditError("sender_authenticated must be boolean")
    if authenticated:
        if (
            not isinstance(fingerprint, str)
            or FINGERPRINT_PATTERN.fullmatch(fingerprint) is None
        ):
            raise AuditError("authenticated sender fingerprint is invalid")
    elif fingerprint is not None:
        raise AuditError("unauthenticated sender must not have a DID fingerprint")


def _validate_decision(payload: dict[str, Any]) -> None:
    decision = payload.get("policy_decision")
    reason = payload.get("policy_reason")
    outcome = payload.get("outcome")
    if decision not in POLICY_DECISIONS:
        raise AuditError("audit policy decision is invalid")
    if not isinstance(reason, str) or TOKEN_PATTERN.fullmatch(reason) is None:
        raise AuditError("audit policy reason is invalid")
    if outcome not in OUTCOMES:
        raise AuditError("audit outcome is invalid")

    receipt_hash = payload.get("receipt_sha256")
    response_sequence = payload.get("response_sequence")
    if receipt_hash is not None:
        _sha256(receipt_hash, "receipt hash")
    if response_sequence is not None:
        _positive_int(response_sequence, "response sequence")
    _validate_outcome(
        decision,
        outcome,
        receipt_hash=receipt_hash,
        response_sequence=response_sequence,
    )


def _validate_outcome(
    decision: str,
    outcome: str,
    *,
    receipt_hash: str | None,
    response_sequence: int | None,
) -> None:
    valid = (
        (
            decision == "ignore"
            and outcome == "ignore"
            and receipt_hash is None
            and response_sequence is None
        )
        or (
            decision == "reply"
            and outcome == "sent"
            and receipt_hash is None
            and response_sequence is not None
        )
        or (
            decision == "receipt"
            and outcome == "receipt_failed"
            and receipt_hash is None
            and response_sequence is None
        )
        or (
            decision == "receipt"
            and outcome == "sent_receipt"
            and receipt_hash is not None
            and response_sequence is not None
        )
    )
    if not valid:
        raise AuditError("audit decision and outcome fields are inconsistent")


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _entry_hash(wrapper: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(wrapper)).hexdigest()


def _format_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AuditError("audit clock must return a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp(value: Any) -> str:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise AuditError("audit timestamp is invalid")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise AuditError("audit timestamp is invalid") from error
    return value


def _did(value: Any) -> str:
    try:
        return validate_did(value)
    except ProtocolValueError as error:
        raise AuditError("audit issuer DID is invalid") from error


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise AuditError(f"{label} is invalid")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AuditError(f"{label} must be a positive integer")
    return value


def _decode_json(raw: bytes) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        for key, value in pairs:
            if key in decoded:
                raise AuditError("audit record contains a duplicate JSON key")
            decoded[key] = value
        return decoded

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError("audit record is not valid JSON") from error


def _read_bounded(descriptor: int) -> bytes:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_AUDIT_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > MAX_AUDIT_BYTES:
                raise AuditError("audit log exceeds the 16 MiB safety limit")
        return b"".join(chunks)
    except OSError as error:
        raise AuditError(f"cannot read audit log: {error}") from error


def _write_all(descriptor: int, rendered: bytes) -> None:
    remaining = memoryview(rendered)
    try:
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise AuditError("audit append made no progress")
            remaining = remaining[written:]
    except OSError as error:
        raise AuditError(f"cannot append audit record: {error}") from error


def _fsync_directory(path: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError as error:
        raise AuditError(f"cannot sync audit directory {path}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
