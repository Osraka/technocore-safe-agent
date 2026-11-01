from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sysconfig
import unittest

try:
    from mcp import Client, StdioServerParameters

    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@unittest.skipUnless(MCP_AVAILABLE, "MCP v2 optional dependency is not installed")
class WorkEvidenceStdioTests(unittest.IsolatedAsyncioTestCase):
    async def inspect(self, *, missing_stderr=False, tampered=False):
        executable = "technocore-safe-agent-mcp" + (".exe" if os.name == "nt" else "")
        command = Path(sysconfig.get_path("scripts")) / executable
        self.assertTrue(command.is_file(), "install the package with its MCP extra")
        args = [
            "--work-expectation",
            str(FIXTURES / "work-evidence-v1/expectation.json"),
            "--work-receipt",
            str(
                FIXTURES
                / "work-receipt-v1"
                / ("tampered-output.json" if tampered else "valid.json")
            ),
            "--work-stdout",
            str(FIXTURES / "work-evidence-v1/stdout.txt"),
        ]
        if not missing_stderr:
            args += ["--work-stderr", str(FIXTURES / "work-evidence-v1/stderr.txt")]
        async with asyncio.timeout(15):
            async with Client(
                StdioServerParameters(command=str(command), args=args)
            ) as client:
                result = await client.call_tool("inspect_work_evidence", {})
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["payment"], "not_assessed")
        self.assertEqual(
            result.structured_content["independent_execution"], "not_established"
        )
        return result.structured_content["status"]

    async def test_installed_stdio_entry_point_matches_fixture(self):
        self.assertEqual(await self.inspect(), "matches_local_expectations")

    async def test_installed_stdio_entry_point_reports_missing_output(self):
        self.assertEqual(await self.inspect(missing_stderr=True), "incomplete")

    async def test_installed_stdio_entry_point_rejects_tampered_receipt(self):
        self.assertEqual(await self.inspect(tampered=True), "invalid_receipt")


if __name__ == "__main__":
    unittest.main()
