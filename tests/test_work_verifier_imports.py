from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

import technocore_safe_agent


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class WorkVerifierImportTests(unittest.TestCase):
    def inspect_without_runner(self, module: str, function: str) -> None:
        script = textwrap.dedent(
            """
            import importlib
            from pathlib import Path
            import sys

            blocked = {
                "technocore_safe_agent.work_receipt",
                "technocore_safe_agent.work_output",
                "technocore_safe_agent.identity",
                "technocore_safe_agent.controller",
            }

            class NoRunnerImports:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname in blocked:
                        raise AssertionError("offline inspection imported the runner")

            sys.meta_path.insert(0, NoRunnerImports())
            module = importlib.import_module(sys.argv[1])
            inspect = getattr(module, sys.argv[2])
            root = Path(sys.argv[3])
            options = {
                "expectation_path": root / "work-evidence-v1/expectation.json",
                "receipt_path": root / "work-receipt-v1/valid.json",
                "stdout_path": root / "work-evidence-v1/stdout.txt",
                "stderr_path": root / "work-evidence-v1/stderr.txt",
            }
            assert inspect(**options)["status"] == "matches_local_expectations"
            assert inspect(**{**options, "stderr_path": None})["status"] == "incomplete"
            invalid = root / "work-receipt-v1/tampered-output.json"
            assert inspect(**{**options, "receipt_path": invalid})["status"] == "invalid_receipt"
            assert not blocked.intersection(sys.modules)
            """
        )
        environment = {
            **os.environ,
            "PYTHONPATH": str(
                Path(technocore_safe_agent.__file__).resolve().parent.parent
            ),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(
            [sys.executable, "-c", script, module, function, str(FIXTURES)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_work_evidence_does_not_import_command_runner(self):
        self.inspect_without_runner(
            "technocore_safe_agent.work_evidence", "inspect_work_evidence"
        )

    def test_mcp_work_evidence_does_not_import_command_runner(self):
        self.inspect_without_runner(
            "technocore_safe_agent.mcp_server", "inspect_evidence_files"
        )

    def test_existing_verifier_imports_remain_compatible(self):
        from technocore_safe_agent import work_receipt, work_receipt_verifier

        for name in (
            "WorkReceiptError",
            "WorkReceiptSummary",
            "verify_work_receipt",
            "render_work_receipt",
        ):
            with self.subTest(name=name):
                self.assertIs(
                    getattr(work_receipt, name), getattr(work_receipt_verifier, name)
                )


if __name__ == "__main__":
    unittest.main()
