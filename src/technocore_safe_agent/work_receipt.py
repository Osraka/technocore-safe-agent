"""Offline, reproducible work receipts for clean GitHub-named checkouts."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.crypto import (
    ProtocolValueError,
    did_from_private_key,
    sign_detached,
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


@dataclass(frozen=True)
class _Checkout:
    root: Path
    repository: str
    commit: str


@dataclass(frozen=True)
class _Execution:
    result: str
    exit_code: int | None
    stdout_sha256: str
    stdout_bytes: int
    stderr_sha256: str
    stderr_bytes: int
    started_at: str
    completed_at: str
    duration_ms: int


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _format_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise WorkReceiptError("work receipt clock must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _repository_from_remote(remote: str) -> str:
    value = remote.strip()
    if value.startswith("git@github.com:"):
        path = value.removeprefix("git@github.com:")
    elif value.startswith("ssh://git@github.com/"):
        path = value.removeprefix("ssh://git@github.com/")
    else:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "github.com"
            or parsed.query
            or parsed.fragment
        ):
            raise WorkReceiptError(
                "origin must be a canonical github.com repository URL"
            )
        path = parsed.path.removeprefix("/")
    if path.endswith(".git"):
        path = path[:-4]
    if path.count("/") != 1 or path.endswith("/"):
        raise WorkReceiptError("origin must identify exactly one GitHub repository")
    return _validate_repository(path)


def _git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError as error:
        raise WorkReceiptError("git is required to inspect the checkout") from error
    except subprocess.TimeoutExpired as error:
        raise WorkReceiptError("git checkout inspection timed out") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or "git command failed"
        raise WorkReceiptError(f"cannot inspect Git checkout: {detail}") from error
    return result.stdout.strip()


def _inspect_checkout(
    repository: Path, *, expected_commit: str | None = None
) -> _Checkout:
    selected = repository.expanduser().resolve()
    root_text = _git(selected, "rev-parse", "--show-toplevel")
    root = Path(root_text).resolve()
    status = _git(root, "status", "--porcelain", "--untracked-files=all")
    if status:
        raise WorkReceiptError("work receipts require a clean checkout")
    commit = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
    if GIT_SHA_PATTERN.fullmatch(commit) is None:
        raise WorkReceiptError("git returned an invalid commit SHA")
    if expected_commit is not None and commit != expected_commit:
        raise WorkReceiptError("checkout is at a different commit than the receipt")
    remote = _git(root, "remote", "get-url", "origin")
    return _Checkout(root, _repository_from_remote(remote), commit)


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


def _timeout_milliseconds(timeout: float) -> int:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0.001 <= float(timeout) <= 3600.0
    ):
        raise WorkReceiptError("timeout must be between 0.001 and 3600 seconds")
    return max(1, round(float(timeout) * 1000))


def _hash_file(handle: Any, label: str) -> tuple[str, int]:
    handle.flush()
    handle.seek(0)
    digest = hashlib.sha256()
    size = 0
    while chunk := handle.read(64 * 1024):
        size += len(chunk)
        if size > MAX_OUTPUT_BYTES:
            raise WorkReceiptError(f"{label} exceeds the work receipt output limit")
        digest.update(chunk)
    return digest.hexdigest(), size


def _execute(
    checkout: _Checkout,
    command: Sequence[str],
    *,
    timeout_ms: int,
    clock: Callable[[], datetime],
    monotonic: Callable[[], float],
) -> _Execution:
    argv = _validate_command(command)
    started_at = _format_timestamp(clock())
    started = monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                argv,
                cwd=checkout.root,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise WorkReceiptError(f"cannot start work command: {error}") from error

        timed_out = False
        try:
            return_code = process.wait(timeout=timeout_ms / 1000)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return_code = process.wait()

        elapsed = monotonic() - started
        duration_ms = max(0, round(elapsed * 1000))
        completed_at = _format_timestamp(clock())
        stdout_sha256, stdout_bytes = _hash_file(stdout, "stdout")
        stderr_sha256, stderr_bytes = _hash_file(stderr, "stderr")

    if timed_out:
        result = "timed_out"
        exit_code: int | None = None
    else:
        result = "passed" if return_code == 0 else "failed"
        exit_code = return_code
    return _Execution(
        result=result,
        exit_code=exit_code,
        stdout_sha256=stdout_sha256,
        stdout_bytes=stdout_bytes,
        stderr_sha256=stderr_sha256,
        stderr_bytes=stderr_bytes,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
    )


def _signed_wrapper(
    payload: Mapping[str, Any], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    canonical = _canonical_json(payload)
    return {
        "payload": dict(payload),
        "payload_sha256": hashlib.sha256(canonical).hexdigest(),
        "signature": sign_detached(private_key, canonical),
    }


def _execution_claim(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: payload[key] for key in EXECUTION_KEYS}


def _execution_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(_execution_claim(payload))).hexdigest()


def create_work_receipt(
    repository: Path,
    command: Sequence[str],
    *,
    issuer_did: str,
    private_key: Ed25519PrivateKey,
    timeout: float,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    try:
        validate_did(issuer_did)
    except (ProtocolValueError, TypeError) as error:
        raise WorkReceiptError("worker DID is invalid") from error
    if did_from_private_key(private_key) != issuer_did:
        raise WorkReceiptError("work receipt signing key does not match its issuer DID")
    checkout = _inspect_checkout(repository)
    timeout_ms = _timeout_milliseconds(timeout)
    execution = _execute(
        checkout,
        command,
        timeout_ms=timeout_ms,
        clock=clock,
        monotonic=monotonic,
    )
    after = _inspect_checkout(checkout.root, expected_commit=checkout.commit)
    if after.repository != checkout.repository:
        raise WorkReceiptError("checkout origin changed while the command was running")
    payload: dict[str, Any] = {
        "schema": WORK_RECEIPT_SCHEMA,
        "issuer": issuer_did,
        "repository": checkout.repository,
        "commit": checkout.commit,
        "command": _validate_command(command),
        "timeout_ms": timeout_ms,
        "result": execution.result,
        "exit_code": execution.exit_code,
        "stdout_sha256": execution.stdout_sha256,
        "stdout_bytes": execution.stdout_bytes,
        "stderr_sha256": execution.stderr_sha256,
        "stderr_bytes": execution.stderr_bytes,
        "started_at": execution.started_at,
        "completed_at": execution.completed_at,
        "duration_ms": execution.duration_ms,
    }
    _validate_work_payload(payload)
    envelope = {
        "schema": WORK_RECEIPT_ENVELOPE_SCHEMA,
        "receipt": _signed_wrapper(payload, private_key),
        "countersignatures": [],
    }
    verify_work_receipt(envelope)
    return envelope


def countersign_work_receipt(
    receipt: Mapping[str, Any] | str,
    repository: Path,
    *,
    verifier_did: str,
    private_key: Ed25519PrivateKey,
    timeout: float | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    summary, envelope = _verify_and_decode(receipt)
    try:
        validate_did(verifier_did)
    except (ProtocolValueError, TypeError) as error:
        raise WorkReceiptError("verifier DID is invalid") from error
    if did_from_private_key(private_key) != verifier_did:
        raise WorkReceiptError(
            "work receipt signing key does not match its verifier DID"
        )
    if verifier_did == summary.payload["issuer"]:
        raise WorkReceiptError("countersignature requires a different identity")
    existing = {item["payload"]["verifier"] for item in envelope["countersignatures"]}
    if verifier_did in existing:
        raise WorkReceiptError("this verifier already countersigned the receipt")

    expected_timeout_ms = summary.payload["timeout_ms"]
    if timeout is not None and _timeout_milliseconds(timeout) != expected_timeout_ms:
        raise WorkReceiptError("countersign timeout must match the original receipt")
    checkout = _inspect_checkout(repository, expected_commit=summary.payload["commit"])
    if checkout.repository != summary.payload["repository"]:
        raise WorkReceiptError("checkout repository does not match the receipt")
    execution = _execute(
        checkout,
        summary.payload["command"],
        timeout_ms=expected_timeout_ms,
        clock=clock,
        monotonic=monotonic,
    )
    after = _inspect_checkout(checkout.root, expected_commit=checkout.commit)
    if after.repository != checkout.repository:
        raise WorkReceiptError("checkout origin changed while the command was running")
    observed = {
        **_execution_claim(summary.payload),
        "result": execution.result,
        "exit_code": execution.exit_code,
        "stdout_sha256": execution.stdout_sha256,
        "stdout_bytes": execution.stdout_bytes,
        "stderr_sha256": execution.stderr_sha256,
        "stderr_bytes": execution.stderr_bytes,
    }
    if observed != _execution_claim(summary.payload):
        raise WorkReceiptError("independent execution does not match the work receipt")

    counter_payload = {
        "schema": WORK_COUNTERSIGNATURE_SCHEMA,
        "verifier": verifier_did,
        "receipt_payload_sha256": envelope["receipt"]["payload_sha256"],
        "execution_sha256": _execution_sha256(summary.payload),
        "observed_at": _format_timestamp(clock()),
    }
    updated = {
        "schema": WORK_RECEIPT_ENVELOPE_SCHEMA,
        "receipt": envelope["receipt"],
        "countersignatures": [
            *envelope["countersignatures"],
            _signed_wrapper(counter_payload, private_key),
        ],
    }
    verify_work_receipt(updated)
    return updated


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
