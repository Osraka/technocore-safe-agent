"""Compare offline work receipts with operator-selected expectations and outputs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from technocore_safe_agent.crypto import ProtocolValueError, validate_did
from technocore_safe_agent.work_receipt import (
    GIT_SHA_PATTERN,
    MAX_COMMAND_ARGUMENTS,
    MAX_COMMAND_ARGUMENT_BYTES,
    MAX_COMMAND_BYTES,
    MAX_COUNTERSIGNATURES,
    MAX_OUTPUT_BYTES,
    MAX_RECEIPT_BYTES,
    OWNER_PATTERN,
    REPOSITORY_PATTERN,
    WorkReceiptError,
    verify_work_receipt,
)

MAX_EXPECTATION_BYTES = 32 * 1024
EXPECTATION_SCHEMA = "work-evidence-expectation-v1"
COMPARISON_FIELDS = ("repository", "commit", "command", "timeout_ms", "issuer")
CHECK_NAMES = (
    "receipt",
    *COMPARISON_FIELDS,
    "required_verifiers",
    "execution",
    "stdout",
    "stderr",
)


class EvidenceInputError(ValueError):
    """An explicit local input could not be safely read or validated."""


def _read_bounded(path: Path, maximum: int) -> bytes:
    # O_NONBLOCK prevents a regular-file/FIFO replacement race from hanging open().
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    fd = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceInputError("regular_file_required")
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise EvidenceInputError("file_changed")
        if opened.st_size > maximum:
            raise EvidenceInputError("file_too_large")
        with os.fdopen(fd, "rb") as handle:
            fd = None
            data = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
        if len(data) > maximum:
            raise EvidenceInputError("file_too_large")
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(data) != after.st_size:
            raise EvidenceInputError("file_changed")
        return data
    except (OSError, ValueError) as error:
        if isinstance(error, EvidenceInputError):
            raise
        raise EvidenceInputError("file_unreadable") from None
    finally:
        if fd is not None:
            os.close(fd)


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("nonfinite_number")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant
        )
    except (ValueError, RecursionError):
        raise EvidenceInputError("invalid_json") from None
    if not isinstance(value, dict):
        raise EvidenceInputError("object_required")
    return value


def _expectation(path: Path) -> dict[str, Any]:
    value = _strict_json(_read_bounded(path, MAX_EXPECTATION_BYTES))
    if (
        set(value) != {"schema", *COMPARISON_FIELDS, "required_verifiers"}
        or value.get("schema") != EXPECTATION_SCHEMA
    ):
        raise EvidenceInputError("invalid_expectation_schema")
    repository = value["repository"]
    parts = repository.split("/") if isinstance(repository, str) else []
    if (
        len(parts) != 2
        or not OWNER_PATTERN.fullmatch(parts[0])
        or not (REPOSITORY_PATTERN.fullmatch(parts[1]))
        or parts[1] in (".", "..")
        or parts[1].endswith(".git")
    ):
        raise EvidenceInputError("invalid_repository")
    if not isinstance(value["commit"], str) or not GIT_SHA_PATTERN.fullmatch(
        value["commit"]
    ):
        raise EvidenceInputError("invalid_commit")
    timeout = value["timeout_ms"]
    if type(timeout) is not int or not 1 <= timeout <= 3_600_000:
        raise EvidenceInputError("invalid_timeout")
    command = value["command"]
    if not isinstance(command, list) or not 1 <= len(command) <= MAX_COMMAND_ARGUMENTS:
        raise EvidenceInputError("invalid_command")
    total = 0
    for index, argument in enumerate(command):
        if not isinstance(argument, str) or "\x00" in argument:
            raise EvidenceInputError("invalid_command")
        try:
            size = len(argument.encode("utf-8"))
        except UnicodeEncodeError:
            raise EvidenceInputError("invalid_command") from None
        if size > MAX_COMMAND_ARGUMENT_BYTES or (index == 0 and size == 0):
            raise EvidenceInputError("invalid_command")
        total += size
    if total > MAX_COMMAND_BYTES:
        raise EvidenceInputError("invalid_command")
    verifiers = value["required_verifiers"]
    if not isinstance(verifiers, list) or len(verifiers) > MAX_COUNTERSIGNATURES:
        raise EvidenceInputError("invalid_verifiers")
    try:
        validate_did(value["issuer"])
        for verifier in verifiers:
            validate_did(verifier)
    except ProtocolValueError:
        raise EvidenceInputError("invalid_identity") from None
    if len(set(verifiers)) != len(verifiers) or value["issuer"] in verifiers:
        raise EvidenceInputError("invalid_verifiers")
    return value


def inspect_work_evidence(
    *,
    expectation_path: Path,
    receipt_path: Path | None = None,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> dict[str, Any]:
    """Inspect explicit files only; never run a receipt's command or resolve its repo."""
    expected = _expectation(expectation_path)
    checks = dict.fromkeys(CHECK_NAMES, "not_checked")
    report = {
        "schema": "work-evidence-report-v1",
        "status": "incomplete",
        "checks": checks,
        "agreement": "not_assessed",
        "payment": "not_assessed",
        "independent_execution": "not_established",
    }
    if receipt_path is None:
        checks["receipt"] = "not_provided"
        return report
    raw = _read_bounded(receipt_path, MAX_RECEIPT_BYTES)
    try:
        envelope = _strict_json(raw)
        summary = verify_work_receipt(envelope)
    except (EvidenceInputError, WorkReceiptError, ValueError, RecursionError):
        checks["receipt"] = "invalid"
        report["status"] = "invalid_receipt"
        return report
    checks["receipt"] = "valid"
    for field in COMPARISON_FIELDS:
        checks[field] = (
            "matched" if summary.payload[field] == expected[field] else "mismatch"
        )
    verifiers = {item["payload"]["verifier"] for item in envelope["countersignatures"]}
    checks["required_verifiers"] = (
        "not_requested"
        if not expected["required_verifiers"]
        else "matched"
        if set(expected["required_verifiers"]) <= verifiers
        else "missing"
    )
    checks["execution"] = summary.payload["result"]
    for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        if path is None:
            checks[name] = "not_provided"
            continue
        data = _read_bounded(path, MAX_OUTPUT_BYTES)
        checks[name] = (
            "matched"
            if (
                len(data) == summary.payload[f"{name}_bytes"]
                and hashlib.sha256(data).hexdigest()
                == summary.payload[f"{name}_sha256"]
            )
            else "mismatch"
        )
    if "mismatch" in checks.values() or checks["execution"] != "passed":
        report["status"] = "does_not_match"
    elif "missing" in checks.values() or "not_provided" in checks.values():
        report["status"] = "incomplete"
    else:
        report["status"] = "matches_local_expectations"
    return report


def render_evidence_markdown(report: dict[str, Any]) -> str:
    """Render a report returned by inspect_work_evidence, without raw evidence."""
    lines = [
        "# Local Work Evidence",
        "",
        f"Status: `{report['status']}`",
        "",
        "| Check | Result |",
        "| --- | --- |",
    ]
    lines.extend(f"| {name} | `{report['checks'][name]}` |" for name in CHECK_NAMES)
    lines.extend(
        [
            "",
            "Agreement: `not_assessed`. Payment: `not_assessed`.",
            "Independent execution: `not_established`.",
            "",
            "Local expectations are operator supplied, not an authenticated agreement.",
            "This check does not execute work, establish its quality, or verify payment.",
        ]
    )
    return "\n".join(lines) + "\n"
