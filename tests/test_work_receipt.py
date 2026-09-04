from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.crypto import (
    did_from_private_key,
    private_key_from_seed,
    sign_detached,
)
from technocore_safe_agent.work_receipt import (
    WorkReceiptError,
    countersign_work_receipt,
    create_work_receipt,
    render_work_receipt,
    verify_work_receipt,
)


WORKER_KEY = private_key_from_seed("11" * 32)
VERIFIER_KEY = private_key_from_seed("22" * 32)
WORKER_DID = did_from_private_key(WORKER_KEY)
VERIFIER_DID = did_from_private_key(VERIFIER_KEY)


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _make_repository(root: Path) -> Path:
    repository = root / "project"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Work Receipt Test")
    _git(repository, "config", "user.email", "work-receipt@example.invalid")
    _git(
        repository,
        "remote",
        "add",
        "origin",
        "https://github.com/example/project.git",
    )
    (repository / "value.txt").write_text("stable\n", encoding="utf-8")
    _git(repository, "add", "value.txt")
    _git(repository, "commit", "--quiet", "-m", "initial")
    return repository


def _stable_command(text: str = "stable") -> list[str]:
    return [sys.executable, "-c", f"print({text!r})"]


class WorkReceiptTests(unittest.TestCase):
    def test_create_and_verify_passed_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            receipt = create_work_receipt(
                repository,
                _stable_command(),
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )

            summary = verify_work_receipt(render_work_receipt(receipt))

            self.assertEqual(summary.payload["schema"], "work-receipt-v1")
            self.assertEqual(summary.payload["repository"], "example/project")
            self.assertEqual(
                summary.payload["commit"], _git(repository, "rev-parse", "HEAD")
            )
            self.assertEqual(summary.payload["command"], _stable_command())
            self.assertEqual(summary.payload["result"], "passed")
            self.assertEqual(summary.payload["exit_code"], 0)
            self.assertEqual(summary.countersignatures, 0)

    def test_tampered_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            receipt = create_work_receipt(
                repository,
                _stable_command(),
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )
            tampered = copy.deepcopy(receipt)
            tampered["receipt"]["payload"]["result"] = "failed"

            with self.assertRaisesRegex(WorkReceiptError, "payload hash"):
                verify_work_receipt(tampered)

    def test_failed_test_is_signed_as_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            receipt = create_work_receipt(
                repository,
                [sys.executable, "-c", "import sys; print('failed'); sys.exit(7)"],
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )

            payload = verify_work_receipt(receipt).payload

            self.assertEqual(payload["result"], "failed")
            self.assertEqual(payload["exit_code"], 7)
            self.assertGreater(payload["stdout_bytes"], 0)

    def test_timeout_is_signed_without_an_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            receipt = create_work_receipt(
                repository,
                [sys.executable, "-c", "import time; time.sleep(5)"],
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=0.05,
            )

            payload = verify_work_receipt(receipt).payload

            self.assertEqual(payload["result"], "timed_out")
            self.assertIsNone(payload["exit_code"])

    def test_second_identity_can_countersign_an_exact_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            command = _stable_command()
            receipt = create_work_receipt(
                repository,
                command,
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )

            countersigned = countersign_work_receipt(
                receipt,
                repository,
                verifier_did=VERIFIER_DID,
                private_key=VERIFIER_KEY,
                timeout=5,
            )
            summary = verify_work_receipt(countersigned)

            self.assertEqual(summary.countersignatures, 1)
            self.assertEqual(summary.matching_countersignatures, 1)

    def test_failed_test_can_be_countersigned_when_exactly_reproduced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            command = [sys.executable, "-c", "import sys; sys.exit(9)"]
            receipt = create_work_receipt(
                repository,
                command,
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )

            countersigned = countersign_work_receipt(
                receipt,
                repository,
                verifier_did=VERIFIER_DID,
                private_key=VERIFIER_KEY,
                timeout=5,
            )

            self.assertEqual(verify_work_receipt(countersigned).countersignatures, 1)

    def test_worker_cannot_countersign_its_own_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            receipt = create_work_receipt(
                repository,
                _stable_command(),
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )

            with self.assertRaisesRegex(WorkReceiptError, "different identity"):
                countersign_work_receipt(
                    receipt,
                    repository,
                    verifier_did=WORKER_DID,
                    private_key=WORKER_KEY,
                    timeout=5,
                )

    def test_countersign_rejects_a_different_commit_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            receipt = create_work_receipt(
                repository,
                _stable_command(),
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )
            (repository / "value.txt").write_text("changed\n", encoding="utf-8")
            _git(repository, "add", "value.txt")
            _git(repository, "commit", "--quiet", "-m", "change")

            with self.assertRaisesRegex(WorkReceiptError, "different commit"):
                countersign_work_receipt(
                    receipt,
                    repository,
                    verifier_did=VERIFIER_DID,
                    private_key=VERIFIER_KEY,
                    timeout=5,
                )

    def test_countersign_rejects_different_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            command = [
                sys.executable,
                "-c",
                "import os; print(os.environ['WORK_RECEIPT_TEST_VALUE'])",
            ]
            with patch.dict(os.environ, {"WORK_RECEIPT_TEST_VALUE": "first"}):
                receipt = create_work_receipt(
                    repository,
                    command,
                    issuer_did=WORKER_DID,
                    private_key=WORKER_KEY,
                    timeout=5,
                )

            with (
                patch.dict(os.environ, {"WORK_RECEIPT_TEST_VALUE": "second"}),
                self.assertRaisesRegex(WorkReceiptError, "does not match"),
            ):
                countersign_work_receipt(
                    receipt,
                    repository,
                    verifier_did=VERIFIER_DID,
                    private_key=VERIFIER_KEY,
                    timeout=5,
                )

    def test_create_rejects_a_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            (repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")

            with self.assertRaisesRegex(WorkReceiptError, "clean checkout"):
                create_work_receipt(
                    repository,
                    _stable_command(),
                    issuer_did=WORKER_DID,
                    private_key=WORKER_KEY,
                    timeout=5,
                )

    def test_create_rejects_a_command_that_changes_the_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            command = [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('value.txt').write_text('changed')",
            ]

            with self.assertRaisesRegex(WorkReceiptError, "clean checkout"):
                create_work_receipt(
                    repository,
                    command,
                    issuer_did=WORKER_DID,
                    private_key=WORKER_KEY,
                    timeout=5,
                )

    def test_create_rejects_a_non_github_origin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            _git(repository, "remote", "set-url", "origin", str(repository))

            with self.assertRaisesRegex(WorkReceiptError, "canonical github.com"):
                create_work_receipt(
                    repository,
                    _stable_command(),
                    issuer_did=WORKER_DID,
                    private_key=WORKER_KEY,
                    timeout=5,
                )

    def test_countersignature_cannot_predate_primary_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = _make_repository(Path(directory))
            receipt = create_work_receipt(
                repository,
                _stable_command(),
                issuer_did=WORKER_DID,
                private_key=WORKER_KEY,
                timeout=5,
            )
            countersigned = countersign_work_receipt(
                receipt,
                repository,
                verifier_did=VERIFIER_DID,
                private_key=VERIFIER_KEY,
                timeout=5,
            )
            signed_counter = countersigned["countersignatures"][0]
            counter_payload = signed_counter["payload"]
            counter_payload["observed_at"] = "2000-01-01T00:00:00Z"
            canonical = json.dumps(
                counter_payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            signed_counter["payload_sha256"] = hashlib.sha256(canonical).hexdigest()
            signed_counter["signature"] = sign_detached(VERIFIER_KEY, canonical)

            with self.assertRaisesRegex(WorkReceiptError, "predates"):
                verify_work_receipt(countersigned)


if __name__ == "__main__":
    unittest.main()
