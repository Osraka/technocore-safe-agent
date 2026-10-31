"""Optional, offline-only MCP surface for bounded verification operations."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from technocore_safe_agent import __version__
from technocore_safe_agent.audit import AuditError, SignedAuditLog
from technocore_safe_agent.receipt import GitHubReceiptError, verify_signed_receipt
from technocore_safe_agent.work_evidence import (
    EvidenceInputError,
    inspect_work_evidence as inspect_evidence_files,
)

MAX_RECEIPT_INPUT_BYTES = 4_096


class MCPDependencyError(RuntimeError):
    """The optional stable MCP SDK is unavailable."""


@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    error_code: str | None
    receipt_schema: str | None
    issuer: str | None
    repository: str | None
    pull_number: int | None
    payload_sha256: str | None


@dataclass(frozen=True)
class AuditVerification:
    valid: bool
    error_code: str | None
    entries: int | None
    issuer: str | None
    head_sha256: str | None
    expected_head_matched: bool


def verify_receipt_content(receipt_json: str) -> ReceiptVerification:
    """Verify one bounded receipt string without filesystem or network access."""

    try:
        encoded = receipt_json.encode("utf-8")
    except (AttributeError, UnicodeEncodeError):
        return _invalid_receipt("invalid_receipt")
    if len(encoded) > MAX_RECEIPT_INPUT_BYTES:
        return _invalid_receipt("receipt_too_large")
    try:
        payload = verify_signed_receipt(receipt_json)
    except GitHubReceiptError as error:
        return _invalid_receipt(error.code)
    wrapper = json.loads(receipt_json)
    return ReceiptVerification(
        valid=True,
        error_code=None,
        receipt_schema=payload["schema"],
        issuer=payload["issuer"],
        repository=payload["repository"],
        pull_number=payload["pull_number"],
        payload_sha256=wrapper["payload_sha256"],
    )


def verify_audit_path(
    audit_path: Path, *, expected_head: str | None = None
) -> AuditVerification:
    """Verify one operator-selected audit path without exposing it in results."""

    try:
        summary = SignedAuditLog(audit_path).verify(expected_head=expected_head)
    except AuditError:
        return AuditVerification(
            valid=False,
            error_code="audit_verification_failed",
            entries=None,
            issuer=None,
            head_sha256=None,
            expected_head_matched=False,
        )
    return AuditVerification(
        valid=True,
        error_code=None,
        entries=summary.entries,
        issuer=summary.issuer,
        head_sha256=summary.head_sha256,
        expected_head_matched=expected_head is not None,
    )


def build_mcp_server(
    *,
    audit_path: Path | None = None,
    work_expectation: Path | None = None,
    work_receipt: Path | None = None,
    work_stdout: Path | None = None,
    work_stderr: Path | None = None,
) -> Any:
    """Build a stdio-oriented MCP v2 server with no open-world operations."""

    if work_expectation is None and any(
        value is not None for value in (work_receipt, work_stdout, work_stderr)
    ):
        raise ValueError("work evidence inputs require an expectation")
    mcp_server, annotations_type = _mcp_types()
    if work_expectation is not None:
        from mcp.server.mcpserver.exceptions import ToolError

        class WorkEvidenceServer(mcp_server):
            async def list_tools(self) -> list[Any]:
                tools = await super().list_tools()
                for tool in tools:
                    if tool.name == "inspect_work_evidence":
                        tool.input_schema["additionalProperties"] = False
                return tools

            async def call_tool(
                self, name: str, arguments: dict[str, Any], context: Any = None
            ) -> Any:
                # The SDK otherwise ignores extra arguments to a no-argument tool.
                # Refuse them before any read instead of implying a new file was checked.
                if name == "inspect_work_evidence" and arguments:
                    raise ToolError("inspect_work_evidence accepts no arguments")
                return await super().call_tool(name, arguments, context)

        mcp_server = WorkEvidenceServer
    server = mcp_server(
        "Technocore Safe Agent Verifier",
        description="Offline verification for contribution receipts, work evidence and audit integrity.",
        instructions=(
            "Read-only and closed-world. This server does not access Keychain, "
            "the network, Technocore rooms, arbitrary files, or write operations."
        ),
        version=__version__,
    )

    @server.tool(
        name="verify_contribution_receipt",
        title="Verify contribution receipt",
        description=(
            "Verify a bounded signed receipt supplied as JSON and return only "
            "its public subject metadata. Performs no network or file access."
        ),
        annotations=_read_only_annotations(annotations_type),
        structured_output=True,
    )
    def verify_contribution_receipt(receipt_json: str) -> ReceiptVerification:
        return verify_receipt_content(receipt_json)

    if audit_path is not None:
        fixed_audit_path = audit_path.expanduser().absolute()

        @server.tool(
            name="inspect_audit_integrity",
            title="Inspect audit integrity",
            description=(
                "Verify the operator-configured signed audit log and return only "
                "its entry count, issuer, and head hash. No path argument is accepted."
            ),
            annotations=_read_only_annotations(annotations_type),
            structured_output=True,
        )
        def inspect_audit_integrity(
            expected_head: str | None = None,
        ) -> AuditVerification:
            return verify_audit_path(fixed_audit_path, expected_head=expected_head)

    if work_expectation is not None:
        fixed_work_paths = {
            name: path.expanduser().absolute() if path is not None else None
            for name, path in (
                ("expectation_path", work_expectation),
                ("receipt_path", work_receipt),
                ("stdout_path", work_stdout),
                ("stderr_path", work_stderr),
            )
        }

        @server.tool(
            name="inspect_work_evidence",
            title="Inspect configured work evidence",
            description=(
                "Compare only operator-configured local work evidence with the configured "
                "expectation. Accepts no arguments. Returns status/check tokens, not raw "
                "output or paths. Does not prove execution, acceptance or payment."
            ),
            annotations=_read_only_annotations(annotations_type),
            structured_output=True,
        )
        def inspect_work_evidence() -> dict[str, Any]:
            try:
                return inspect_evidence_files(**fixed_work_paths)
            except EvidenceInputError:
                return {"status": "input_error", "reason": "work_evidence_input_error"}

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="technocore-safe-agent-mcp",
        description="Run the offline-only Technocore verifier over MCP stdio.",
    )
    parser.add_argument(
        "--audit-log",
        type=Path,
        help="fixed audit log exposed only through summary integrity checks",
    )
    parser.add_argument(
        "--work-expectation",
        type=Path,
        help="fixed operator expectation; enables offline work evidence inspection",
    )
    for stream in ("receipt", "stdout", "stderr"):
        parser.add_argument(
            f"--work-{stream}",
            type=Path,
            help=f"fixed work {stream} file; requires --work-expectation",
        )
    args = parser.parse_args(argv)
    if args.work_expectation is None and any(
        value is not None
        for value in (args.work_receipt, args.work_stdout, args.work_stderr)
    ):
        parser.error(
            "--work-receipt, --work-stdout and --work-stderr require --work-expectation"
        )
    try:
        server = build_mcp_server(
            audit_path=args.audit_log,
            work_expectation=args.work_expectation,
            work_receipt=args.work_receipt,
            work_stdout=args.work_stdout,
            work_stderr=args.work_stderr,
        )
    except MCPDependencyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    try:
        server.run(transport="stdio")
    except KeyboardInterrupt:
        return 130
    return 0


def _invalid_receipt(error_code: str) -> ReceiptVerification:
    return ReceiptVerification(
        valid=False,
        error_code=error_code,
        receipt_schema=None,
        issuer=None,
        repository=None,
        pull_number=None,
        payload_sha256=None,
    )


def _mcp_types() -> tuple[Any, Any]:
    try:
        from mcp.server import MCPServer
        from mcp.types import ToolAnnotations
    except ImportError as error:
        raise MCPDependencyError(
            "MCP SDK v2 is required; install technocore-safe-agent[mcp]"
        ) from error
    return MCPServer, ToolAnnotations


def _read_only_annotations(annotations_type: Any) -> Any:
    return annotations_type(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
