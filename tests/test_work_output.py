from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from technocore_safe_agent.cli import main
from technocore_safe_agent.work_output import OutputBundle
from technocore_safe_agent.work_receipt import (
    WorkReceiptError,
    create_work_receipt,
    verify_work_receipt,
)
from test_work_receipt import WORKER_DID, WORKER_KEY, _make_repository


@unittest.skipUnless(os.name == "posix", "private output bundles require POSIX")
class WorkOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repository = _make_repository(self.root)
        self.output = self.root / "evidence"

    def create(self, code, **kwargs):
        return create_work_receipt(
            self.repository,
            [sys.executable, "-c", code],
            issuer_did=WORKER_DID,
            private_key=WORKER_KEY,
            timeout=kwargs.pop("timeout", 5),
            **kwargs,
        )

    def assert_bundle(self, receipt, stdout, stderr):
        payload = verify_work_receipt(receipt).payload
        self.assertEqual(
            json.loads((self.output / "receipt.json").read_text()), receipt
        )
        self.assertEqual(
            set(path.name for path in self.output.iterdir()),
            {"stdout.bin", "stderr.bin", "receipt.json"},
        )
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        for name, data in (("stdout", stdout), ("stderr", stderr)):
            path = self.output / f"{name}.bin"
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(payload[f"{name}_bytes"], len(data))
            self.assertEqual(
                payload[f"{name}_sha256"], hashlib.sha256(data).hexdigest()
            )
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_opt_in_preserves_exact_binary_output_and_receipt(self):
        receipt = self.create(
            "import os; os.write(1, b'out\\x00\\xff'); os.write(2, b'err\\r\\n')",
            output_directory=self.output,
        )
        self.assert_bundle(receipt, b"out\x00\xff", b"err\r\n")

    def test_failed_execution_preserves_evidence_without_becoming_passed(self):
        receipt = self.create(
            "import sys; print('failed'); sys.exit(7)", output_directory=self.output
        )
        self.assert_bundle(receipt, b"failed\n", b"")
        payload = verify_work_receipt(receipt).payload
        self.assertEqual(payload["result"], "failed")
        self.assertEqual(payload["exit_code"], 7)

    def test_timeout_can_preserve_empty_output(self):
        receipt = self.create(
            "import time; time.sleep(60)", timeout=0.1, output_directory=self.output
        )
        self.assert_bundle(receipt, b"", b"")
        self.assertEqual(verify_work_receipt(receipt).payload["result"], "timed_out")

    def test_default_does_not_retain_output(self):
        receipt = self.create("print('temporary only')")
        self.assertEqual(verify_work_receipt(receipt).payload["result"], "passed")
        self.assertEqual(list(self.root.iterdir()), [self.repository])

    def test_preexisting_destinations_are_never_overwritten_or_executed(self):
        with patch("technocore_safe_agent.work_receipt._execute") as execute:
            self.output.mkdir()
            for populated in (False, True):
                if populated:
                    (self.output / "keep").write_bytes(b"untouched")
                with (
                    self.subTest(populated=populated),
                    self.assertRaises(WorkReceiptError),
                ):
                    self.create("pass", output_directory=self.output)
                execute.assert_not_called()
            self.assertEqual((self.output / "keep").read_bytes(), b"untouched")
            for target in (self.output, self.root / "absent"):
                link = self.root / "link"
                link.symlink_to(target)
                with self.assertRaises(WorkReceiptError):
                    self.create("pass", output_directory=link)
                self.assertTrue(link.is_symlink())
                link.unlink()
            file = self.root / "file"
            file.write_bytes(b"untouched")
            with self.assertRaises(WorkReceiptError):
                self.create("pass", output_directory=file)
            self.assertEqual(file.read_bytes(), b"untouched")
            execute.assert_not_called()

    def test_inside_checkout_missing_parent_and_writable_parent_are_refused(self):
        with patch("technocore_safe_agent.work_receipt._execute") as execute:
            for target in (
                self.repository,
                self.repository / "evidence",
                self.root / "missing" / "evidence",
            ):
                with (
                    self.subTest(target=target.name),
                    self.assertRaises(WorkReceiptError),
                ):
                    self.create("pass", output_directory=target)
            self.root.chmod(0o777)
            try:
                with self.assertRaisesRegex(WorkReceiptError, "not writable"):
                    self.create("pass", output_directory=self.output)
            finally:
                self.root.chmod(0o700)
            execute.assert_not_called()

    def test_permissive_umask_does_not_expose_output(self):
        previous = os.umask(0)
        try:
            receipt = self.create("pass", output_directory=self.output)
            self.assert_bundle(receipt, b"", b"")
        finally:
            os.umask(previous)

    def test_output_limit_failure_removes_reserved_directory(self):
        with (
            patch("technocore_safe_agent.work_receipt.MAX_OUTPUT_BYTES", 16),
            patch("technocore_safe_agent.work_output.MAX_OUTPUT_BYTES", 16),
        ):
            for fd in (1, 2):
                with (
                    self.subTest(fd=fd),
                    self.assertRaisesRegex(WorkReceiptError, "limit"),
                ):
                    self.create(
                        f"import os; os.write({fd}, b'x' * 17)",
                        output_directory=self.output,
                    )
                self.assertFalse(self.output.exists())

    def test_storage_failures_never_leave_a_completed_receipt(self):
        for target in ("capture", "finish"):
            with (
                self.subTest(target=target),
                patch.object(
                    OutputBundle,
                    target,
                    side_effect=WorkReceiptError("injected storage failure"),
                ),
                self.assertRaises(WorkReceiptError),
            ):
                self.create("print('output')", output_directory=self.output)
            self.assertFalse(self.output.exists())
        for target in ("fsync", "link"):
            with (
                self.subTest(target=target),
                patch(
                    f"technocore_safe_agent.work_output.os.{target}",
                    side_effect=OSError("disk error"),
                ),
                self.assertRaises(WorkReceiptError),
            ):
                self.create("pass", output_directory=self.output)
            self.assertFalse(self.output.exists())

    def test_changed_captured_bytes_are_not_published(self):
        original = OutputBundle.capture

        def corrupt(bundle, stdout, stderr):
            original(bundle, stdout, stderr)
            (bundle.path / "stdout.bin").write_bytes(b"substituted output")

        with (
            patch.object(OutputBundle, "capture", corrupt),
            self.assertRaisesRegex(WorkReceiptError, "same execution"),
        ):
            self.create("print('original')", output_directory=self.output)
        self.assertFalse(self.output.exists())

    def test_changed_checkout_is_refused_and_not_rolled_back(self):
        with self.assertRaisesRegex(WorkReceiptError, "clean checkout"):
            self.create(
                "from pathlib import Path; Path('value.txt').write_text('changed')",
                output_directory=self.output,
            )
        self.assertEqual((self.repository / "value.txt").read_text(), "changed")
        self.assertFalse(self.output.exists())

    def test_signing_failure_does_not_publish_evidence(self):
        with (
            patch(
                "technocore_safe_agent.work_receipt._signed_wrapper",
                side_effect=WorkReceiptError("signing failed"),
            ),
            self.assertRaises(WorkReceiptError),
        ):
            self.create("pass", output_directory=self.output)
        self.assertFalse(self.output.exists())

    def test_command_start_failure_removes_reservation(self):
        with (
            patch(
                "technocore_safe_agent.work_receipt.subprocess.Popen",
                side_effect=FileNotFoundError("command missing"),
            ),
            patch(
                "technocore_safe_agent.work_receipt._inspect_checkout",
                return_value=SimpleNamespace(
                    root=self.repository, repository="example/project", commit="a" * 40
                ),
            ),
            self.assertRaises(WorkReceiptError),
        ):
            self.create("pass", output_directory=self.output)
        self.assertFalse(self.output.exists())

    def test_interrupted_wait_reaps_command_and_removes_reservation(self):
        process = Mock(pid=123456)
        process.wait.side_effect = [KeyboardInterrupt(), -9]
        with (
            patch(
                "technocore_safe_agent.work_receipt.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "technocore_safe_agent.work_receipt._inspect_checkout",
                return_value=SimpleNamespace(
                    root=self.repository, repository="example/project", commit="a" * 40
                ),
            ),
            patch("technocore_safe_agent.work_receipt.os.killpg") as kill,
            self.assertRaises(KeyboardInterrupt),
        ):
            self.create("pass", output_directory=self.output)
        kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)
        self.assertFalse(self.output.exists())

    def test_receipt_is_not_published_before_original_outputs(self):
        original = OutputBundle._sync_directory
        calls = []

        def inspect(bundle):
            names = {path.name for path in bundle.path.iterdir()}
            calls.append(names)
            self.assertTrue({"stdout.bin", "stderr.bin"}.issubset(names))
            original(bundle)

        with patch.object(OutputBundle, "_sync_directory", inspect):
            self.create("pass", output_directory=self.output)
        self.assertNotIn("receipt.json", calls[0])
        self.assertIn("receipt.json", calls[-1])

    def test_cli_success_and_error_do_not_contact_services_or_real_identity(self):
        args = [
            "work-receipt",
            "create",
            "--repository",
            str(self.repository),
            "--output-directory",
            str(self.output),
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
        with (
            patch(
                "technocore_safe_agent.cli._load_identity",
                return_value=(SimpleNamespace(did=WORKER_DID), WORKER_KEY),
            ),
            patch("socket.socket", side_effect=AssertionError("no network")),
        ):
            with patch("sys.stdout", io.StringIO()) as stdout:
                self.assertEqual(main(args), 0)
            self.assert_bundle(json.loads(stdout.getvalue()), b"", b"")
            with (
                patch("sys.stdout", io.StringIO()) as stdout,
                patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(main(args), 2)
            self.assertEqual(stdout.getvalue(), "")
