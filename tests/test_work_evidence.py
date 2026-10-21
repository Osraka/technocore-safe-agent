from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from technocore_safe_agent.cli import main
from technocore_safe_agent.crypto import (
    did_from_private_key,
    private_key_from_seed,
    sign_detached,
)
from technocore_safe_agent.work_evidence import (
    EvidenceInputError,
    inspect_work_evidence,
    render_evidence_markdown,
)
from technocore_safe_agent.work_receipt import MAX_OUTPUT_BYTES, create_work_receipt

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/work-receipt-v1"


class WorkEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.envelope = json.loads((FIXTURES / "valid.json").read_text())
        payload = self.envelope["receipt"]["payload"]
        self.expected = {
            "schema": "work-evidence-expectation-v1",
            **{
                k: copy.deepcopy(payload[k])
                for k in ("repository", "commit", "command", "timeout_ms", "issuer")
            },
            "required_verifiers": [
                self.envelope["countersignatures"][0]["payload"]["verifier"]
            ],
        }
        self.expectation = self.root / "expectation.json"
        self.receipt = self.root / "receipt.json"
        self.stdout = self.root / "stdout.bin"
        self.stderr = self.root / "stderr.bin"
        self.stdout.write_bytes(b"fixture-ok\n")
        self.stderr.write_bytes(b"")
        self.save()

    def save(self) -> None:
        self.expectation.write_text(json.dumps(self.expected))
        self.receipt.write_text(json.dumps(self.envelope))

    def inspect(self, **overrides):
        kwargs = dict(
            expectation_path=self.expectation,
            receipt_path=self.receipt,
            stdout_path=self.stdout,
            stderr_path=self.stderr,
        )
        kwargs.update(overrides)
        return inspect_work_evidence(**kwargs)

    def test_complete_fixture_matches_without_claiming_payment_or_independence(self):
        report = self.inspect()
        self.assertEqual(report["status"], "matches_local_expectations")
        self.assertEqual(report["checks"]["receipt"], "valid")
        self.assertEqual(report["checks"]["execution"], "passed")
        self.assertEqual(report["checks"]["required_verifiers"], "matched")
        self.assertEqual(report["agreement"], "not_assessed")
        self.assertEqual(report["payment"], "not_assessed")
        self.assertEqual(report["independent_execution"], "not_established")

    def test_documented_fixture_matches(self):
        example = FIXTURES.parent / "work-evidence-v1"
        report = inspect_work_evidence(
            expectation_path=example / "expectation.json",
            receipt_path=FIXTURES / "valid.json",
            stdout_path=example / "stdout.txt",
            stderr_path=example / "stderr.txt",
        )
        self.assertEqual(report["status"], "matches_local_expectations")

    @unittest.skipUnless(os.name == "posix", "private output bundles require POSIX")
    def test_original_output_bundle_matches_local_expectations(self):
        repository = self.root / "project"
        repository.mkdir()

        def git(*args):
            return subprocess.run(
                ["git", "-C", str(repository), *args],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        git("init", "--quiet")
        git("config", "user.name", "Evidence Test")
        git("config", "user.email", "evidence@example.invalid")
        git("remote", "add", "origin", "https://github.com/example/project.git")
        (repository / "value.txt").write_text("stable\n", encoding="utf-8")
        git("add", "value.txt")
        git("commit", "--quiet", "-m", "initial")

        command = [sys.executable, "-c", "print('bundle-ok')"]
        bundle = self.root / "bundle"
        receipt = create_work_receipt(
            repository,
            command,
            issuer_did=did_from_private_key(private_key_from_seed("11" * 32)),
            private_key=private_key_from_seed("11" * 32),
            timeout=5,
            output_directory=bundle,
        )
        payload = receipt["receipt"]["payload"]
        self.expected = {
            "schema": "work-evidence-expectation-v1",
            **{
                field: payload[field]
                for field in ("repository", "commit", "command", "timeout_ms", "issuer")
            },
            "required_verifiers": [],
        }
        self.expectation.write_text(json.dumps(self.expected))

        report = self.inspect(
            receipt_path=bundle / "receipt.json",
            stdout_path=bundle / "stdout.bin",
            stderr_path=bundle / "stderr.bin",
        )
        self.assertEqual(report["status"], "matches_local_expectations")
        self.assertEqual((bundle / "stdout.bin").read_bytes(), b"bundle-ok\n")
        self.assertEqual(report["checks"]["required_verifiers"], "not_requested")

        (bundle / "stdout.bin").write_bytes(b"altered\n")
        report = self.inspect(
            receipt_path=bundle / "receipt.json",
            stdout_path=bundle / "stdout.bin",
            stderr_path=bundle / "stderr.bin",
        )
        self.assertEqual(report["status"], "does_not_match")
        self.assertEqual(report["checks"]["stdout"], "mismatch")

    def test_missing_receipt_and_outputs_are_not_success(self):
        report = self.inspect(receipt_path=None)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["checks"]["receipt"], "not_provided")
        for name in ("stdout_path", "stderr_path"):
            with self.subTest(name=name):
                report = self.inspect(**{name: None})
                self.assertEqual(report["status"], "incomplete")

    def test_each_expectation_is_checked_not_just_signature(self):
        original = copy.deepcopy(self.expected)
        changes = {
            "repository": "different/repository",
            "commit": "a" * 40,
            "command": ["python3", "-c", "print('different')"],
            "timeout_ms": 5001,
            "issuer": self.expected["required_verifiers"][0],
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.expected = {**original, field: value, "required_verifiers": []}
                self.save()
                report = self.inspect()
                self.assertEqual(report["checks"]["receipt"], "valid")
                self.assertEqual(report["checks"][field], "mismatch")
                self.assertEqual(report["status"], "does_not_match")

    def test_tampered_receipt_is_invalid_and_no_outputs_are_opened(self):
        self.envelope["receipt"]["payload"]["stdout_sha256"] = "0" * 64
        self.save()
        report = self.inspect(stdout_path=self.root / "must-not-be-read")
        self.assertEqual(report["status"], "invalid_receipt")
        self.assertEqual(report["checks"]["stdout"], "not_checked")

    def test_output_changes_and_truncation_do_not_match(self):
        for data in (b"", b"fixture-ok", b"fixture-ok\nextra", b"other-data\n"):
            with self.subTest(data=data):
                self.stdout.write_bytes(data)
                report = self.inspect()
                self.assertEqual(report["checks"]["stdout"], "mismatch")
                self.assertEqual(report["status"], "does_not_match")
        self.stdout.write_bytes(b"fixture-ok\n")
        self.stderr.write_bytes(b"unexpected stderr")
        self.assertEqual(self.inspect()["checks"]["stderr"], "mismatch")

    def test_valid_failed_and_timeout_receipts_never_report_success(self):
        for outcome, exit_code in (("failed", 1), ("timed_out", None)):
            with self.subTest(outcome=outcome):
                payload = self.envelope["receipt"]["payload"]
                payload.update(result=outcome, exit_code=exit_code)
                raw = json.dumps(
                    payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode()
                self.envelope["receipt"].update(
                    payload_sha256=hashlib.sha256(raw).hexdigest(),
                    signature=sign_detached(private_key_from_seed("11" * 32), raw),
                )
                self.envelope["countersignatures"] = []
                self.expected["required_verifiers"] = []
                self.save()
                report = self.inspect()
                self.assertEqual(report["checks"]["receipt"], "valid")
                self.assertEqual(report["checks"]["execution"], outcome)
                self.assertEqual(report["status"], "does_not_match")

    def test_missing_required_verifier_is_incomplete(self):
        self.envelope["countersignatures"] = []
        self.save()
        report = self.inspect()
        self.assertEqual(report["checks"]["required_verifiers"], "missing")
        self.assertEqual(report["status"], "incomplete")

    def test_invalid_counter_signature_rejects_whole_receipt(self):
        self.envelope["countersignatures"][0]["payload"]["execution_sha256"] = "0" * 64
        self.save()
        self.assertEqual(self.inspect()["status"], "invalid_receipt")

    def test_valid_unrequested_verifier_does_not_satisfy_required_key(self):
        self.expected["required_verifiers"] = [
            did_from_private_key(private_key_from_seed("33" * 32))
        ]
        self.save()
        report = self.inspect()
        self.assertEqual(report["checks"]["receipt"], "valid")
        self.assertEqual(report["checks"]["required_verifiers"], "missing")
        self.assertEqual(report["status"], "incomplete")

    def test_empty_required_verifiers_is_explicitly_not_requested(self):
        self.expected["required_verifiers"] = []
        self.save()
        self.assertEqual(
            self.inspect()["checks"]["required_verifiers"], "not_requested"
        )

    def test_invalid_expectation_field_types_and_bounds(self):
        original = copy.deepcopy(self.expected)
        cases = {
            "repository": [
                None,
                [],
                "https://example.com/repo",
                "owner/..",
                "owner/repo.git",
            ],
            "commit": [False, "a" * 39, "A" * 40],
            "timeout_ms": [False, 0, -1, 1.5, 3_600_001],
            "command": [
                None,
                "sh",
                [],
                [""],
                [False],
                ["x\x00"],
                ["\ud800"],
                ["x" * 4097],
                ["x"] * 65,
                ["x" * 4096] * 5,
            ],
            "issuer": [[], None, "not-a-key"],
            "required_verifiers": [
                None,
                "not-a-list",
                [{}],
                original["required_verifiers"] * 2,
                original["required_verifiers"] * 17,
            ],
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.expected = {**original, field: value}
                    self.save()
                    with self.assertRaises(EvidenceInputError):
                        self.inspect()

    def test_bad_receipt_json_is_invalid_not_an_exception(self):
        for raw in (
            b"[]",
            b"null",
            b"\xff",
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b'{"x":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}",
        ):
            with self.subTest(raw=raw[:20]):
                self.receipt.write_bytes(raw)
                self.assertEqual(self.inspect()["status"], "invalid_receipt")

    def test_mismatch_takes_precedence_over_missing_output(self):
        self.expected["commit"] = "a" * 40
        self.save()
        self.assertEqual(self.inspect(stderr_path=None)["status"], "does_not_match")

    def test_unreadable_inputs_and_file_replacement_are_rejected(self):
        for path in (self.root, self.root / "missing"):
            with self.subTest(path=path):
                with self.assertRaises(EvidenceInputError):
                    self.inspect(stdout_path=path)
        real_open = os.open

        def replacing_open(path, flags):
            if path == self.stdout:
                alternate = self.root / "replacement"
                alternate.write_bytes(b"fixture-ok\n")
                alternate.replace(self.stdout)
            return real_open(path, flags)

        with patch(
            "technocore_safe_agent.work_evidence.os.open", side_effect=replacing_open
        ):
            with self.assertRaisesRegex(EvidenceInputError, "file_changed"):
                self.inspect()

    def test_cli_markdown_and_missing_evidence(self):
        with redirect_stdout(io.StringIO()) as output:
            code = main(
                [
                    "work-evidence",
                    "--expectation",
                    str(self.expectation),
                    "--format",
                    "markdown",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("Status: `incomplete`", output.getvalue())
        self.assertIn("Payment: `not_assessed`", output.getvalue())

    def test_duplicate_keys_invalid_utf8_and_unknown_fields_are_refused(self):
        cases = [
            b'{"schema":"one","schema":"two"}',
            b"\xff",
            json.dumps({**self.expected, "artifact_path": "/not-followed"}).encode(),
            json.dumps({**self.expected, "timeout_ms": True}).encode(),
            json.dumps(
                {**self.expected, "required_verifiers": [self.expected["issuer"]]}
            ).encode(),
        ]
        for raw in cases:
            with self.subTest(raw=raw[:25]):
                self.expectation.write_bytes(raw)
                with self.assertRaises(EvidenceInputError):
                    self.inspect()

    def test_duplicate_receipt_keys_are_invalid(self):
        raw = self.receipt.read_text()
        self.receipt.write_text('{"schema":"hidden",' + raw[1:])
        self.assertEqual(self.inspect()["status"], "invalid_receipt")

    def test_oversized_files_and_symlinks_are_refused(self):
        self.expectation.write_bytes(b" " * (32 * 1024 + 1))
        with self.assertRaises(EvidenceInputError):
            self.inspect()
        self.save()
        with self.stdout.open("wb") as handle:
            handle.truncate(MAX_OUTPUT_BYTES + 1)
        with self.assertRaises(EvidenceInputError):
            self.inspect()
        self.stdout.unlink()
        self.stdout.symlink_to(self.stderr)
        with self.assertRaises(EvidenceInputError):
            self.inspect()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_fifo_is_refused_without_blocking(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(EvidenceInputError):
            self.inspect(stdout_path=fifo)

    def test_report_omits_identities_commands_hashes_paths_and_output(self):
        report = self.inspect()
        text = json.dumps(report) + render_evidence_markdown(report)
        for private in (
            self.expected["issuer"],
            str(self.root),
            "fixture-ok",
            self.expected["commit"],
            self.expected["repository"],
            self.envelope["receipt"]["signature"],
        ):
            self.assertNotIn(private, text)

    def test_cli_is_readonly_and_has_distinct_exit_codes(self):
        argv = [
            "work-evidence",
            "--expectation",
            str(self.expectation),
            "--receipt",
            str(self.receipt),
            "--stdout",
            str(self.stdout),
            "--stderr",
            str(self.stderr),
        ]
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        with (
            patch("subprocess.Popen", side_effect=AssertionError("no execution")),
            patch("socket.socket", side_effect=AssertionError("no network")),
            patch(
                "technocore_safe_agent.cli._load_identity",
                side_effect=AssertionError("no identity"),
            ),
        ):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(argv), 0)
            self.assertEqual(
                json.loads(output.getvalue())["status"], "matches_local_expectations"
            )
            self.assertEqual(
                {p.name: p.read_bytes() for p in self.root.iterdir()}, before
            )
            self.stdout.write_bytes(b"changed")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(argv), 1)
            self.expectation.write_text("bad json")
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(argv), 2)
            self.assertNotIn(str(self.root), output.getvalue())
        self.assertEqual(self.receipt.read_bytes(), before[self.receipt.name])
        self.assertEqual(self.stderr.read_bytes(), before[self.stderr.name])
