from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from technocore_safe_agent.crypto import private_key_from_seed, sign_detached
from technocore_safe_agent.mcp_server import build_mcp_server, main
from technocore_safe_agent.work_evidence import EvidenceInputError
from technocore_safe_agent.work_receipt import MAX_OUTPUT_BYTES

try:
    from mcp import Client
    from mcp.server import MCPServer  # noqa: F401

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@unittest.skipUnless(MCP_AVAILABLE, "MCP v2 optional dependency is not installed")
class WorkEvidenceMcpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.expectation = self.root / "expectation.json"
        self.receipt = self.root / "receipt.json"
        self.stdout = self.root / "stdout.bin"
        self.stderr = self.root / "stderr.bin"
        self.expectation.write_bytes(
            (FIXTURES / "work-evidence-v1/expectation.json").read_bytes()
        )
        self.receipt.write_bytes((FIXTURES / "work-receipt-v1/valid.json").read_bytes())
        self.stdout.write_bytes(b"fixture-ok\n")
        self.stderr.write_bytes(b"")
        self.options = {
            "work_expectation": self.expectation,
            "work_receipt": self.receipt,
            "work_stdout": self.stdout,
            "work_stderr": self.stderr,
        }

    async def inspect(self, **overrides):
        server = build_mcp_server(**{**self.options, **overrides})
        async with Client(server) as client:
            result = await client.call_tool("inspect_work_evidence", {})
        self.assertFalse(result.is_error)
        return result.structured_content

    async def test_default_tools_are_unchanged_and_new_tool_is_opt_in(self):
        default = await build_mcp_server().list_tools()
        self.assertEqual(
            [tool.name for tool in default], ["verify_contribution_receipt"]
        )
        configured = await build_mcp_server(**self.options).list_tools()
        tool = next(tool for tool in configured if tool.name == "inspect_work_evidence")
        self.assertEqual(tool.input_schema["properties"], {})
        self.assertIs(tool.input_schema["additionalProperties"], False)
        self.assertTrue(tool.annotations.read_only_hint)
        self.assertFalse(tool.annotations.destructive_hint)
        self.assertTrue(tool.annotations.idempotent_hint)
        self.assertFalse(tool.annotations.open_world_hint)

    async def test_matching_evidence_has_structured_result_and_no_payment_claim(self):
        report = await self.inspect()
        self.assertEqual(report["status"], "matches_local_expectations")
        self.assertEqual(report["checks"]["receipt"], "valid")
        self.assertEqual(report["agreement"], "not_assessed")
        self.assertEqual(report["payment"], "not_assessed")
        self.assertEqual(report["independent_execution"], "not_established")
        expected = json.loads(self.expectation.read_text())
        envelope = json.loads(self.receipt.read_text())
        for value in (
            str(self.root),
            expected["issuer"],
            expected["repository"],
            expected["commit"],
            envelope["receipt"]["signature"],
            "fixture-ok",
        ):
            self.assertNotIn(value, json.dumps(report))

    async def test_changed_commit_and_changed_output_are_not_matches(self):
        expected = json.loads(self.expectation.read_text())
        expected["commit"] = "0" * 40
        self.expectation.write_text(json.dumps(expected))
        report = await self.inspect()
        self.assertEqual(report["status"], "does_not_match")
        self.assertEqual(report["checks"]["commit"], "mismatch")
        self.stdout.write_bytes(b"different output")
        self.assertEqual((await self.inspect())["checks"]["stdout"], "mismatch")

    async def test_omitted_receipt_and_outputs_are_incomplete(self):
        for missing in ("work_receipt", "work_stdout", "work_stderr"):
            with self.subTest(missing=missing):
                self.assertEqual(
                    (await self.inspect(**{missing: None}))["status"], "incomplete"
                )

    async def test_missing_required_countersigner_is_incomplete(self):
        envelope = json.loads(self.receipt.read_text())
        envelope["countersignatures"] = []
        self.receipt.write_text(json.dumps(envelope))
        report = await self.inspect()
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["checks"]["required_verifiers"], "missing")

    async def test_invalid_receipt_does_not_open_configured_output(self):
        self.receipt.write_bytes(
            (FIXTURES / "work-receipt-v1/tampered-output.json").read_bytes()
        )
        report = await self.inspect(work_stdout=self.root / "must-not-be-opened")
        self.assertEqual(report["status"], "invalid_receipt")
        self.assertEqual(report["checks"]["stdout"], "not_checked")

    async def test_signed_failed_and_timeout_results_are_not_success(self):
        for outcome, code in (("failed", 1), ("timed_out", None)):
            with self.subTest(outcome=outcome):
                envelope = json.loads(self.receipt.read_text())
                payload = envelope["receipt"]["payload"]
                payload.update(result=outcome, exit_code=code)
                raw = json.dumps(
                    payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode()
                envelope["receipt"].update(
                    payload_sha256=hashlib.sha256(raw).hexdigest(),
                    signature=sign_detached(private_key_from_seed("11" * 32), raw),
                )
                envelope["countersignatures"] = []
                self.receipt.write_text(json.dumps(envelope))
                report = await self.inspect()
                self.assertEqual(report["checks"]["receipt"], "valid")
                self.assertEqual(report["checks"]["execution"], outcome)
                self.assertEqual(report["status"], "does_not_match")

    async def test_missing_malformed_and_nonregular_inputs_have_safe_errors(self):
        for replacement in (self.root / "missing.json", self.root):
            with self.subTest(replacement=replacement.name):
                report = await self.inspect(work_expectation=replacement)
                self.assertEqual(report["status"], "input_error")
                self.assertNotIn(str(self.root), json.dumps(report))
        self.expectation.write_text("not json")
        self.assertEqual((await self.inspect())["status"], "input_error")

    async def test_symlinked_and_oversized_output_files_are_refused(self):
        alias = self.root / "symlink-output"
        alias.symlink_to(self.stdout)
        self.assertEqual(
            (await self.inspect(work_stdout=alias))["status"], "input_error"
        )
        with self.stdout.open("wb") as stream:
            stream.truncate(MAX_OUTPUT_BYTES + 1)
        self.assertEqual((await self.inspect())["status"], "input_error")

    @unittest.skipUnless(os.name == "posix", "FIFO semantics require POSIX")
    async def test_fifo_is_refused_without_waiting_for_a_writer(self):
        fifo = self.root / "output.fifo"
        os.mkfifo(fifo)
        self.assertEqual(
            (await self.inspect(work_stdout=fifo))["status"], "input_error"
        )

    async def test_errors_never_return_underlying_exception_text(self):
        with patch(
            "technocore_safe_agent.mcp_server.inspect_evidence_files",
            side_effect=EvidenceInputError("private diagnostic must not escape"),
        ):
            report = await self.inspect()
        self.assertEqual(report["status"], "input_error")
        self.assertNotIn("private diagnostic", json.dumps(report))

    async def test_model_selected_arguments_are_rejected_before_reading(self):
        server = build_mcp_server(**self.options)
        async with Client(server) as client:
            with patch(
                "technocore_safe_agent.mcp_server.inspect_evidence_files",
                side_effect=AssertionError("must reject before any file read"),
            ):
                for key in (
                    "path",
                    "expectation",
                    "receipt",
                    "stdout",
                    "command",
                    "url",
                ):
                    with self.subTest(key=key):
                        result = await client.call_tool(
                            "inspect_work_evidence", {key: "untrusted-value"}
                        )
                        self.assertTrue(result.is_error)
                        self.assertNotIn("untrusted-value", str(result))

    async def test_each_call_rechecks_evidence_and_cannot_use_cached_success(self):
        server = build_mcp_server(**self.options)
        async with Client(server) as client:
            first = await client.call_tool("inspect_work_evidence", {})
            self.assertEqual(
                first.structured_content["status"], "matches_local_expectations"
            )
            self.stdout.write_bytes(b"changed after first check")
            second = await client.call_tool("inspect_work_evidence", {})
            self.assertEqual(second.structured_content["status"], "does_not_match")

    async def test_relative_paths_are_fixed_at_startup_not_tool_call(self):
        original = Path.cwd()
        try:
            os.chdir(self.root)
            server = build_mcp_server(
                **{name: Path(path.name) for name, path in self.options.items()}
            )
            elsewhere = self.root / "elsewhere"
            elsewhere.mkdir()
            os.chdir(elsewhere)
            async with Client(server) as client:
                result = await client.call_tool("inspect_work_evidence", {})
            self.assertEqual(
                result.structured_content["status"], "matches_local_expectations"
            )
        finally:
            os.chdir(original)

    async def test_tool_has_no_network_execution_identity_or_write_side_effects(self):
        server = build_mcp_server(**self.options)
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        async with Client(server) as client:
            with (
                patch(
                    "subprocess.Popen",
                    side_effect=AssertionError("no execution or Keychain"),
                ),
                patch("socket.socket", side_effect=AssertionError("no network")),
                patch(
                    "pathlib.Path.write_bytes", side_effect=AssertionError("no write")
                ),
                patch(
                    "pathlib.Path.write_text", side_effect=AssertionError("no write")
                ),
            ):
                result = await client.call_tool("inspect_work_evidence", {})
        self.assertFalse(result.is_error)
        self.assertEqual(
            result.structured_content["status"], "matches_local_expectations"
        )
        self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir()}, before)

    async def test_audit_and_work_tools_can_coexist_without_widening_inputs(self):
        tools = await build_mcp_server(
            audit_path=self.root / "absent-audit", **self.options
        ).list_tools()
        self.assertEqual(
            {tool.name for tool in tools},
            {
                "verify_contribution_receipt",
                "inspect_audit_integrity",
                "inspect_work_evidence",
            },
        )

    def test_library_refuses_evidence_inputs_without_expectation(self):
        for name in ("work_receipt", "work_stdout", "work_stderr"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "expectation"):
                    build_mcp_server(**{name: self.receipt})


class WorkEvidenceMcpCliTests(unittest.TestCase):
    def test_cli_passes_operator_paths_and_keeps_stdio_transport(self):
        server = Mock()
        with patch(
            "technocore_safe_agent.mcp_server.build_mcp_server", return_value=server
        ) as build:
            self.assertEqual(
                main(
                    [
                        "--work-expectation",
                        "expectation.json",
                        "--work-receipt",
                        "receipt.json",
                        "--work-stdout",
                        "stdout.bin",
                        "--work-stderr",
                        "stderr.bin",
                    ]
                ),
                0,
            )
        build.assert_called_once_with(
            audit_path=None,
            work_expectation=Path("expectation.json"),
            work_receipt=Path("receipt.json"),
            work_stdout=Path("stdout.bin"),
            work_stderr=Path("stderr.bin"),
        )
        server.run.assert_called_once_with(transport="stdio")

    def test_cli_rejects_output_configuration_without_expectation_before_start(self):
        for option in ("--work-receipt", "--work-stdout", "--work-stderr"):
            with self.subTest(option=option):
                with (
                    patch("sys.stderr", new_callable=io.StringIO) as stderr,
                    patch("technocore_safe_agent.mcp_server.build_mcp_server") as build,
                ):
                    with self.assertRaises(SystemExit) as error:
                        main([option, "unused"])
                self.assertEqual(error.exception.code, 2)
                self.assertIn("require --work-expectation", stderr.getvalue())
                build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
