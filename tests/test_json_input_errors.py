from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.audit import AuditError, SignedAuditLog
from technocore_safe_agent.cli import main
from technocore_safe_agent.mcp_server import verify_audit_path, verify_receipt_content
from technocore_safe_agent.receipt import GitHubReceiptError, verify_signed_receipt
from technocore_safe_agent.work_receipt_verifier import (
    WorkReceiptError,
    verify_work_receipt,
)


class JsonInputErrorTests(unittest.TestCase):
    def setUp(self) -> None:
        original_limit = sys.get_int_max_str_digits()
        self.addCleanup(sys.set_int_max_str_digits, original_limit)
        sys.set_int_max_str_digits(640)
        self.raw = '{"unexpected":' + "1" * 641 + "}"
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "input.json"
        self.path.write_text(self.raw + "\n", encoding="utf-8")
        self.path.chmod(0o600)

    def test_verifiers_wrap_integer_conversion_errors(self) -> None:
        for verify, expected_error in (
            (verify_signed_receipt, GitHubReceiptError),
            (verify_work_receipt, WorkReceiptError),
        ):
            with self.subTest(verifier=verify.__name__):
                with self.assertRaises(expected_error) as caught:
                    verify(self.raw)
                self.assertNotIn(self.raw, str(caught.exception))
        with self.assertRaises(AuditError) as caught:
            SignedAuditLog(self.path).verify()
        self.assertNotIn(self.raw, str(caught.exception))

    def test_mcp_receipt_returns_invalid_instead_of_raising(self) -> None:
        result = verify_receipt_content(self.raw)
        self.assertFalse(result.valid)
        self.assertEqual(result.error_code, "invalid_receipt")
        self.assertIsNone(result.issuer)
        self.assertIsNone(result.repository)

    def test_mcp_audit_returns_generic_failure_without_the_path(self) -> None:
        result = verify_audit_path(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.error_code, "audit_verification_failed")
        self.assertIsNone(result.issuer)
        self.assertIsNone(result.head_sha256)
        self.assertNotIn(str(self.path), json.dumps(asdict(result)))

    def test_cli_verifiers_use_controlled_error_exits(self) -> None:
        for command in (
            ["verify-receipt", str(self.path)],
            ["work-receipt", "verify", str(self.path)],
            ["audit", "verify", str(self.path)],
        ):
            with (
                self.subTest(command=command[0]),
                redirect_stdout(io.StringIO()) as output,
                redirect_stderr(io.StringIO()) as errors,
                patch("socket.socket", side_effect=AssertionError("no network")),
                patch("subprocess.Popen", side_effect=AssertionError("no execution")),
                patch(
                    "technocore_safe_agent.cli._load_identity",
                    side_effect=AssertionError("no identity"),
                ),
            ):
                self.assertEqual(main(command), 2)
                self.assertEqual(output.getvalue(), "")
                self.assertTrue(errors.getvalue().startswith("error: "))
                self.assertNotIn("Traceback", errors.getvalue())
                self.assertNotIn(self.raw, errors.getvalue())

    def test_existing_syntax_and_utf8_failures_remain_controlled(self) -> None:
        for raw in ("not-json", '{"unexpected":' + "1" * 640 + "}"):
            with self.subTest(raw=raw[:12]):
                self.assertEqual(
                    verify_receipt_content(raw).error_code, "invalid_receipt"
                )
                with self.assertRaises(WorkReceiptError):
                    verify_work_receipt(raw)
        self.path.write_bytes(b"\xff\n")
        self.assertEqual(
            verify_audit_path(self.path).error_code, "audit_verification_failed"
        )
