from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from technocore_safe_agent.audit import SignedAuditLog
from technocore_safe_agent.crypto import did_from_private_key, private_key_from_seed
from technocore_safe_agent.mcp_server import (
    build_mcp_server,
    verify_audit_path,
    verify_receipt_content,
)
from technocore_safe_agent.receipt import (
    PullRequestEvidence,
    build_signed_receipt,
    render_signed_receipt,
)

try:
    from mcp import Client
    from mcp.server import MCPServer  # noqa: F401

    MCP_V2_AVAILABLE = True
except ImportError:
    MCP_V2_AVAILABLE = False


KEY = private_key_from_seed("09" * 32)
DID = did_from_private_key(KEY)


def _receipt() -> str:
    evidence = PullRequestEvidence(
        repository="foundry-rs/foundry",
        number=42,
        url="https://github.com/foundry-rs/foundry/pull/42",
        author="contributor",
        state="open",
        merged=False,
        draft=False,
        head_sha="a" * 40,
        base_sha="b" * 40,
        merge_commit_sha=None,
        ci="success",
        ci_data_complete=True,
        checks_observed=1,
        checks_total=1,
        statuses_observed=0,
        statuses_total=0,
        source_updated_at="2026-08-30T10:00:00Z",
    )
    return render_signed_receipt(
        build_signed_receipt(
            evidence,
            issuer_did=DID,
            private_key=KEY,
            observed_at=datetime(2026, 8, 30, 10, 5, tzinfo=UTC),
        )
    )


class McpAdapterTests(unittest.TestCase):
    def test_receipt_adapter_returns_only_bounded_verified_metadata(self) -> None:
        raw = _receipt()

        result = verify_receipt_content(raw)

        self.assertTrue(result.valid)
        self.assertIsNone(result.error_code)
        self.assertEqual(result.receipt_schema, "technocore-github-pr-receipt-v1")
        self.assertEqual(result.issuer, DID)
        self.assertEqual(result.repository, "foundry-rs/foundry")
        self.assertEqual(result.pull_number, 42)
        self.assertNotIn("contributor", json.dumps(result.__dict__))
        self.assertNotIn(raw, json.dumps(result.__dict__))

    def test_receipt_adapter_rejects_tampered_and_oversized_input(self) -> None:
        tampered = json.loads(_receipt())
        tampered["payload"]["repository"] = "base/account-sdk"

        invalid = verify_receipt_content(json.dumps(tampered))
        oversized = verify_receipt_content("x" * 4_097)

        self.assertFalse(invalid.valid)
        self.assertEqual(invalid.error_code, "invalid_receipt")
        self.assertFalse(oversized.valid)
        self.assertEqual(oversized.error_code, "receipt_too_large")

    def test_audit_adapter_uses_one_fixed_path_and_never_exposes_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-audit.jsonl"
            head = SignedAuditLog(path).append(
                issuer_did=DID,
                private_key=KEY,
                observed_at=datetime(2026, 8, 30, 10, 0, tzinfo=UTC),
                input_sequence=1,
                sender_fingerprint=None,
                sender_authenticated=False,
                policy_decision="ignore",
                policy_reason="unsigned_sender",
                outcome="ignore",
                receipt_sha256=None,
                response_sequence=None,
            )

            valid = verify_audit_path(path, expected_head=head)
            invalid = verify_audit_path(path, expected_head="f" * 64)
            missing_path = Path(directory) / "missing-audit.jsonl"
            missing = verify_audit_path(missing_path)

            self.assertTrue(valid.valid)
            self.assertEqual(valid.entries, 1)
            self.assertEqual(valid.head_sha256, head)
            self.assertTrue(valid.expected_head_matched)
            self.assertFalse(invalid.valid)
            self.assertEqual(invalid.error_code, "audit_verification_failed")
            self.assertNotIn(str(path), json.dumps(invalid.__dict__))
            self.assertFalse(missing.valid)
            self.assertEqual(missing.error_code, "audit_verification_failed")
            self.assertNotIn(str(missing_path), json.dumps(missing.__dict__))


@unittest.skipUnless(MCP_V2_AVAILABLE, "MCP v2 optional dependency is not installed")
class McpContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_audit_tool_is_absent_without_operator_selected_path(self) -> None:
        tools = await build_mcp_server().list_tools()

        self.assertEqual([tool.name for tool in tools], ["verify_contribution_receipt"])

    async def test_server_exposes_only_closed_world_read_only_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            head = SignedAuditLog(audit_path).append(
                issuer_did=DID,
                private_key=KEY,
                observed_at=datetime(2026, 8, 30, 10, 0, tzinfo=UTC),
                input_sequence=1,
                sender_fingerprint=None,
                sender_authenticated=False,
                policy_decision="ignore",
                policy_reason="unsigned_sender",
                outcome="ignore",
                receipt_sha256=None,
                response_sequence=None,
            )
            server = build_mcp_server(audit_path=audit_path)

            tools = await server.list_tools()

            self.assertEqual(
                {tool.name for tool in tools},
                {"verify_contribution_receipt", "inspect_audit_integrity"},
            )
            for tool in tools:
                self.assertTrue(tool.annotations.read_only_hint)
                self.assertFalse(tool.annotations.destructive_hint)
                self.assertTrue(tool.annotations.idempotent_hint)
                self.assertFalse(tool.annotations.open_world_hint)
                self.assertNotIn("path", tool.input_schema["properties"])

            async with Client(server) as client:
                result = await client.call_tool(
                    "inspect_audit_integrity", {"expected_head": head}
                )

            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["valid"], True)
            self.assertEqual(result.structured_content["entries"], 1)
            self.assertEqual(result.structured_content["head_sha256"], head)

    async def test_in_memory_client_receives_structured_receipt_result(self) -> None:
        server = build_mcp_server()

        async with Client(server) as client:
            result = await client.call_tool(
                "verify_contribution_receipt", {"receipt_json": _receipt()}
            )

        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["valid"], True)
        self.assertEqual(
            result.structured_content["receipt_schema"],
            "technocore-github-pr-receipt-v1",
        )
        self.assertEqual(result.structured_content["repository"], "foundry-rs/foundry")


if __name__ == "__main__":
    unittest.main()
