"""Offline, reproducible work receipts for clean GitHub-named checkouts."""

from __future__ import annotations

import hashlib
import math
import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
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
)
from technocore_safe_agent.work_receipt_verifier import (
    WORK_RECEIPT_SCHEMA as WORK_RECEIPT_SCHEMA,
    WORK_RECEIPT_ENVELOPE_SCHEMA as WORK_RECEIPT_ENVELOPE_SCHEMA,
    WORK_COUNTERSIGNATURE_SCHEMA as WORK_COUNTERSIGNATURE_SCHEMA,
    MAX_COMMAND_ARGUMENTS as MAX_COMMAND_ARGUMENTS,
    MAX_COMMAND_ARGUMENT_BYTES as MAX_COMMAND_ARGUMENT_BYTES,
    MAX_COMMAND_BYTES as MAX_COMMAND_BYTES,
    MAX_OUTPUT_BYTES as MAX_OUTPUT_BYTES,
    MAX_RECEIPT_BYTES as MAX_RECEIPT_BYTES,
    MAX_COUNTERSIGNATURES as MAX_COUNTERSIGNATURES,
    SHA256_PATTERN as SHA256_PATTERN,
    GIT_SHA_PATTERN as GIT_SHA_PATTERN,
    OWNER_PATTERN as OWNER_PATTERN,
    REPOSITORY_PATTERN as REPOSITORY_PATTERN,
    TIMESTAMP_PATTERN as TIMESTAMP_PATTERN,
    WORK_PAYLOAD_KEYS as WORK_PAYLOAD_KEYS,
    EXECUTION_KEYS as EXECUTION_KEYS,
    COUNTERSIGNATURE_PAYLOAD_KEYS as COUNTERSIGNATURE_PAYLOAD_KEYS,
    SIGNED_WRAPPER_KEYS as SIGNED_WRAPPER_KEYS,
    ENVELOPE_KEYS as ENVELOPE_KEYS,
    WorkReceiptError as WorkReceiptError,
    WorkReceiptSummary as WorkReceiptSummary,
    _canonical_json as _canonical_json,
    _parse_timestamp as _parse_timestamp,
    _require_sha256 as _require_sha256,
    _require_nonnegative_int as _require_nonnegative_int,
    _validate_repository as _validate_repository,
    _validate_command as _validate_command,
    _execution_claim as _execution_claim,
    _execution_sha256 as _execution_sha256,
    render_work_receipt as render_work_receipt,
    verify_work_receipt as verify_work_receipt,
    _decode as _decode,
    _verify_and_decode as _verify_and_decode,
    _verify_signed_wrapper as _verify_signed_wrapper,
    _validate_work_payload as _validate_work_payload,
    _validate_countersignature_payload as _validate_countersignature_payload,
)


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


def _format_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise WorkReceiptError("work receipt clock must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    capture: Callable[[Any, Any], None] | None = None,
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
        except BaseException:
            # Do not leave the explicitly launched job running after Ctrl+C.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise

        elapsed = monotonic() - started
        duration_ms = max(0, round(elapsed * 1000))
        completed_at = _format_timestamp(clock())
        stdout_sha256, stdout_bytes = _hash_file(stdout, "stdout")
        stderr_sha256, stderr_bytes = _hash_file(stderr, "stderr")
        if capture is not None:
            capture(stdout, stderr)

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


def create_work_receipt(
    repository: Path,
    command: Sequence[str],
    *,
    issuer_did: str,
    private_key: Ed25519PrivateKey,
    timeout: float,
    output_directory: Path | None = None,
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
    storage = nullcontext()
    if output_directory is not None:
        from technocore_safe_agent.work_output import OutputBundle

        storage = OutputBundle(output_directory, checkout.root)
    with storage as bundle:
        execution = _execute(
            checkout,
            command,
            timeout_ms=timeout_ms,
            clock=clock,
            monotonic=monotonic,
            capture=bundle.capture if bundle else None,
        )
        after = _inspect_checkout(checkout.root, expected_commit=checkout.commit)
        if after.repository != checkout.repository:
            raise WorkReceiptError(
                "checkout origin changed while the command was running"
            )
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
        if bundle is not None:
            bundle.finish(envelope)
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
