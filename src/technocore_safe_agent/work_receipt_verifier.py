"""Offline work-receipt validation, without checkout or command execution."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from technocore_safe_agent.crypto import (
    ProtocolValueError,
    validate_did,
    verify_detached_signature,
)

WORK_RECEIPT_SCHEMA = "work-receipt-v1"


WORK_RECEIPT_ENVELOPE_SCHEMA = "work-receipt-envelope-v1"


WORK_COUNTERSIGNATURE_SCHEMA = "work-receipt-countersignature-v1"


MAX_COMMAND_ARGUMENTS = 64


MAX_COMMAND_ARGUMENT_BYTES = 4096


MAX_COMMAND_BYTES = 16 * 1024


MAX_OUTPUT_BYTES = 16 * 1024 * 1024


MAX_RECEIPT_BYTES = 128 * 1024


MAX_COUNTERSIGNATURES = 16


SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


GIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")


REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")


TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


WORK_PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "issuer",
        "repository",
        "commit",
        "command",
        "timeout_ms",
        "result",
        "exit_code",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
        "started_at",
        "completed_at",
        "duration_ms",
    }
)


EXECUTION_KEYS = (
    "repository",
    "commit",
    "command",
    "timeout_ms",
    "result",
    "exit_code",
    "stdout_sha256",
    "stdout_bytes",
    "stderr_sha256",
    "stderr_bytes",
)


COUNTERSIGNATURE_PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "verifier",
        "receipt_payload_sha256",
        "execution_sha256",
        "observed_at",
    }
)


SIGNED_WRAPPER_KEYS = frozenset({"payload", "payload_sha256", "signature"})


ENVELOPE_KEYS = frozenset({"schema", "receipt", "countersignatures"})


class WorkReceiptError(RuntimeError):
    """A work receipt cannot be created or verified without overstating evidence."""


@dataclass(frozen=True)
class WorkReceiptSummary:
    payload: dict[str, Any]
    countersignatures: int
    matching_countersignatures: int


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise WorkReceiptError(f"work receipt contains an invalid {label}")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise WorkReceiptError(f"work receipt contains an invalid {label}") from error


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise WorkReceiptError(f"work receipt contains an invalid {label}")
    return value


def _require_nonnegative_int(value: Any, label: str, *, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > maximum
    ):
        raise WorkReceiptError(f"work receipt contains an invalid {label}")
    return value


def _validate_repository(value: Any) -> str:
    if not isinstance(value, str) or value.count("/") != 1:
        raise WorkReceiptError("work receipt contains an invalid repository")
    owner, repository = value.split("/", 1)
    if (
        OWNER_PATTERN.fullmatch(owner) is None
        or REPOSITORY_PATTERN.fullmatch(repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
    ):
        raise WorkReceiptError("work receipt contains an invalid repository")
    return value


def _validate_command(command: Sequence[str]) -> list[str]:
    if isinstance(command, (str, bytes)) or not isinstance(command, Sequence):
        raise WorkReceiptError("command must be an argv sequence")
    normalized = list(command)
    if not normalized or len(normalized) > MAX_COMMAND_ARGUMENTS:
        raise WorkReceiptError(
            f"command must contain 1-{MAX_COMMAND_ARGUMENTS} arguments"
        )
    total = 0
    for index, argument in enumerate(normalized):
        if not isinstance(argument, str) or "\x00" in argument:
            raise WorkReceiptError("command arguments must be safe strings")
        try:
            size = len(argument.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise WorkReceiptError("command arguments must be valid UTF-8") from error
        if size > MAX_COMMAND_ARGUMENT_BYTES or (index == 0 and size == 0):
            raise WorkReceiptError("command contains an invalid argument")
        total += size
    if total > MAX_COMMAND_BYTES:
        raise WorkReceiptError("command exceeds the work receipt size limit")
    return normalized


def _execution_claim(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: payload[key] for key in EXECUTION_KEYS}


def _execution_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(_execution_claim(payload))).hexdigest()


def render_work_receipt(receipt: Mapping[str, Any] | str) -> str:
    _, envelope = _verify_and_decode(receipt)
    rendered = json.dumps(
        envelope, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    if len(rendered.encode("utf-8")) > MAX_RECEIPT_BYTES:
        raise WorkReceiptError("work receipt exceeds the artifact size limit")
    return rendered


def verify_work_receipt(receipt: Mapping[str, Any] | str) -> WorkReceiptSummary:
    summary, _ = _verify_and_decode(receipt)
    return summary


def _decode(receipt: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(receipt, str):
        if len(receipt.encode("utf-8")) > MAX_RECEIPT_BYTES:
            raise WorkReceiptError("work receipt exceeds the artifact size limit")
        try:
            decoded = json.loads(receipt)
        except json.JSONDecodeError as error:
            raise WorkReceiptError("work receipt is not valid JSON") from error
    else:
        decoded = receipt
    if not isinstance(decoded, dict):
        raise WorkReceiptError("work receipt must contain a JSON object")
    return dict(decoded)


def _verify_and_decode(
    receipt: Mapping[str, Any] | str,
) -> tuple[WorkReceiptSummary, dict[str, Any]]:
    envelope = _decode(receipt)
    if (
        set(envelope) != ENVELOPE_KEYS
        or envelope.get("schema") != WORK_RECEIPT_ENVELOPE_SCHEMA
    ):
        raise WorkReceiptError("work receipt envelope uses an unsupported schema")
    signed_receipt = envelope.get("receipt")
    payload = _verify_signed_wrapper(signed_receipt, signer_key="issuer")
    _validate_work_payload(payload)
    countersignatures = envelope.get("countersignatures")
    if (
        not isinstance(countersignatures, list)
        or len(countersignatures) > MAX_COUNTERSIGNATURES
    ):
        raise WorkReceiptError("work receipt contains invalid countersignatures")

    verifiers: set[str] = set()
    expected_receipt_hash = signed_receipt["payload_sha256"]
    expected_execution_hash = _execution_sha256(payload)
    completed_at = _parse_timestamp(payload["completed_at"], "completion timestamp")
    for signed_counter in countersignatures:
        counter_payload = _verify_signed_wrapper(signed_counter, signer_key="verifier")
        _validate_countersignature_payload(counter_payload)
        verifier = counter_payload["verifier"]
        if verifier == payload["issuer"]:
            raise WorkReceiptError("worker cannot countersign its own receipt")
        if verifier in verifiers:
            raise WorkReceiptError("work receipt contains a duplicate countersigner")
        verifiers.add(verifier)
        if counter_payload["receipt_payload_sha256"] != expected_receipt_hash:
            raise WorkReceiptError("countersignature refers to a different receipt")
        if counter_payload["execution_sha256"] != expected_execution_hash:
            raise WorkReceiptError(
                "countersignature refers to different execution evidence"
            )
        if (
            _parse_timestamp(
                counter_payload["observed_at"], "countersignature timestamp"
            )
            < completed_at
        ):
            raise WorkReceiptError("countersignature predates the primary execution")

    return (
        WorkReceiptSummary(
            payload=dict(payload),
            countersignatures=len(countersignatures),
            matching_countersignatures=len(countersignatures),
        ),
        envelope,
    )


def _verify_signed_wrapper(value: Any, *, signer_key: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != SIGNED_WRAPPER_KEYS:
        raise WorkReceiptError("signed work receipt wrapper has unexpected fields")
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise WorkReceiptError("signed work receipt payload must be an object")
    canonical = _canonical_json(payload)
    expected_hash = hashlib.sha256(canonical).hexdigest()
    if value.get("payload_sha256") != expected_hash:
        raise WorkReceiptError("work receipt payload hash does not match")
    signer = payload.get(signer_key)
    try:
        validate_did(signer)
    except (ProtocolValueError, TypeError) as error:
        raise WorkReceiptError("signed work receipt contains an invalid DID") from error
    if not verify_detached_signature(signer, canonical, value.get("signature")):
        raise WorkReceiptError("work receipt signature does not match its signer")
    return payload


def _validate_work_payload(payload: Mapping[str, Any]) -> None:
    if (
        set(payload) != WORK_PAYLOAD_KEYS
        or payload.get("schema") != WORK_RECEIPT_SCHEMA
    ):
        raise WorkReceiptError("work receipt payload uses an unsupported schema")
    try:
        validate_did(payload.get("issuer"))
    except (ProtocolValueError, TypeError) as error:
        raise WorkReceiptError("work receipt contains an invalid issuer DID") from error
    _validate_repository(payload.get("repository"))
    if (
        not isinstance(payload.get("commit"), str)
        or GIT_SHA_PATTERN.fullmatch(payload["commit"]) is None
    ):
        raise WorkReceiptError("work receipt contains an invalid commit SHA")
    _validate_command(payload.get("command"))
    timeout_ms = _require_nonnegative_int(
        payload.get("timeout_ms"), "timeout", maximum=3_600_000
    )
    if timeout_ms == 0:
        raise WorkReceiptError("work receipt timeout must be positive")
    result = payload.get("result")
    exit_code = payload.get("exit_code")
    if result == "passed":
        if exit_code != 0:
            raise WorkReceiptError("passed work receipt must have exit code zero")
    elif result == "failed":
        if (
            isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or exit_code == 0
        ):
            raise WorkReceiptError("failed work receipt must have a nonzero exit code")
        if not -255 <= exit_code <= 255:
            raise WorkReceiptError("failed work receipt exit code is outside bounds")
    elif result == "timed_out":
        if exit_code is not None:
            raise WorkReceiptError("timed-out work receipt must not claim an exit code")
    else:
        raise WorkReceiptError("work receipt contains an invalid result")
    _require_sha256(payload.get("stdout_sha256"), "stdout hash")
    _require_sha256(payload.get("stderr_sha256"), "stderr hash")
    _require_nonnegative_int(
        payload.get("stdout_bytes"), "stdout byte count", maximum=MAX_OUTPUT_BYTES
    )
    _require_nonnegative_int(
        payload.get("stderr_bytes"), "stderr byte count", maximum=MAX_OUTPUT_BYTES
    )
    started = _parse_timestamp(payload.get("started_at"), "start timestamp")
    completed = _parse_timestamp(payload.get("completed_at"), "completion timestamp")
    if completed < started:
        raise WorkReceiptError("work receipt completes before it starts")
    _require_nonnegative_int(payload.get("duration_ms"), "duration", maximum=3_700_000)


def _validate_countersignature_payload(payload: Mapping[str, Any]) -> None:
    if (
        set(payload) != COUNTERSIGNATURE_PAYLOAD_KEYS
        or payload.get("schema") != WORK_COUNTERSIGNATURE_SCHEMA
    ):
        raise WorkReceiptError("countersignature payload uses an unsupported schema")
    try:
        validate_did(payload.get("verifier"))
    except (ProtocolValueError, TypeError) as error:
        raise WorkReceiptError(
            "countersignature contains an invalid verifier DID"
        ) from error
    _require_sha256(payload.get("receipt_payload_sha256"), "receipt reference")
    _require_sha256(payload.get("execution_sha256"), "execution reference")
    _parse_timestamp(payload.get("observed_at"), "countersignature timestamp")
