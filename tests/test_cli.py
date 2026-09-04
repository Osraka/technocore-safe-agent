from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.audit import SignedAuditLog
from technocore_safe_agent.cli import build_parser, main
from technocore_safe_agent.controller import (
    DEFAULT_CONTROLLER_ACCOUNT,
    DEFAULT_CONTROLLER_IDENTITY_PATH,
    DEFAULT_CONTROLLER_SERVICE,
)
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
)
from technocore_safe_agent.identity import (
    DEFAULT_AGENT_NAME,
    DEFAULT_IDENTITY_PATH,
    DEFAULT_RUNTIME_DIRECTORY,
    IdentityRecord,
)
from technocore_safe_agent.receipt import (
    PullRequestEvidence,
    build_signed_receipt,
    render_signed_receipt,
)


SEED = "04" * 32
VERIFIER_SEED = "05" * 32


def _work_repository(root: Path) -> Path:
    repository = root / "project"
    repository.mkdir()
    commands = (
        ("init", "--quiet"),
        ("config", "user.name", "CLI Test"),
        ("config", "user.email", "cli-test@example.invalid"),
        (
            "remote",
            "add",
            "origin",
            "https://github.com/example/project.git",
        ),
    )
    for command in commands:
        subprocess.run(
            ["git", "-C", str(repository), *command],
            check=True,
            capture_output=True,
        )
    (repository / "value.txt").write_text("stable\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(repository), "add", "value.txt"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "--quiet", "-m", "initial"],
        check=True,
        capture_output=True,
    )
    return repository


def _identity(seed: str) -> tuple[IdentityRecord, object]:
    key = private_key_from_seed(seed)
    did = did_from_private_key(key)
    return (
        IdentityRecord(did, fingerprint_of_did(did), "test-service", "test-account"),
        key,
    )


def _receipt() -> dict[str, object]:
    key = private_key_from_seed(SEED)
    evidence = PullRequestEvidence(
        repository="example/project",
        number=42,
        url="https://github.com/example/project/pull/42",
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
        source_updated_at="2026-08-29T12:30:00Z",
    )
    return build_signed_receipt(
        evidence,
        issuer_did=did_from_private_key(key),
        private_key=key,
        observed_at=datetime(2026, 8, 29, 15, 0, tzinfo=UTC),
    )


class CliTests(unittest.TestCase):
    def test_work_receipt_parser_preserves_command_argv(self) -> None:
        args = build_parser().parse_args(
            [
                "work-receipt",
                "create",
                "--repository",
                ".",
                "--timeout",
                "5",
                "--",
                "python",
                "-c",
                "print('ok')",
            ]
        )
        self.assertEqual(args.work_receipt_command, "create")
        self.assertEqual(args.work_command, ["--", "python", "-c", "print('ok')"])

    def test_work_receipt_cli_create_verify_and_countersign(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = _work_repository(root)
            command = [sys.executable, "-c", "print('stable')"]
            worker = _identity(SEED)
            verifier = _identity(VERIFIER_SEED)

            created_stdout = io.StringIO()
            with (
                patch("technocore_safe_agent.cli._load_identity", return_value=worker),
                redirect_stdout(created_stdout),
            ):
                result = main(
                    [
                        "work-receipt",
                        "create",
                        "--repository",
                        str(repository),
                        "--timeout",
                        "5",
                        "--",
                        *command,
                    ]
                )
            self.assertEqual(result, 0)
            receipt_path = root / "receipt.json"
            receipt_path.write_text(created_stdout.getvalue(), encoding="utf-8")

            verified_stdout = io.StringIO()
            with (
                patch("technocore_safe_agent.cli._load_identity") as load_identity,
                redirect_stdout(verified_stdout),
            ):
                result = main(["work-receipt", "verify", str(receipt_path)])
            self.assertEqual(result, 0)
            load_identity.assert_not_called()
            self.assertEqual(
                json.loads(verified_stdout.getvalue())["countersignatures"], 0
            )

            countersigned_stdout = io.StringIO()
            with (
                patch(
                    "technocore_safe_agent.cli._load_identity", return_value=verifier
                ),
                redirect_stdout(countersigned_stdout),
            ):
                result = main(
                    [
                        "work-receipt",
                        "countersign",
                        "--repository",
                        str(repository),
                        str(receipt_path),
                    ]
                )
            self.assertEqual(result, 0)
            countersigned_path = root / "countersigned.json"
            countersigned_path.write_text(
                countersigned_stdout.getvalue(), encoding="utf-8"
            )

            final_stdout = io.StringIO()
            with redirect_stdout(final_stdout):
                result = main(["work-receipt", "verify", str(countersigned_path)])
            self.assertEqual(result, 0)
            self.assertEqual(
                json.loads(final_stdout.getvalue())["countersignatures"], 1
            )

    def test_public_defaults_are_generic_and_share_one_runtime_directory(self) -> None:
        doctor = build_parser().parse_args(["doctor"])
        provision = build_parser().parse_args(["provision"])
        controller = build_parser().parse_args(["controller", "create"])

        self.assertEqual(DEFAULT_AGENT_NAME, "SafeAgent")
        self.assertEqual(doctor.identity, DEFAULT_IDENTITY_PATH)
        self.assertEqual(provision.name, DEFAULT_AGENT_NAME)
        self.assertEqual(controller.identity, DEFAULT_CONTROLLER_IDENTITY_PATH)
        self.assertEqual(DEFAULT_IDENTITY_PATH.parent, DEFAULT_RUNTIME_DIRECTORY)
        self.assertEqual(
            DEFAULT_CONTROLLER_IDENTITY_PATH.parent, DEFAULT_RUNTIME_DIRECTORY
        )
        self.assertEqual(DEFAULT_CONTROLLER_SERVICE, "technocore.safe-agent.controller")
        self.assertEqual(DEFAULT_CONTROLLER_ACCOUNT, "safe-agent-controller")
        self.assertEqual(DEFAULT_RUNTIME_DIRECTORY.name, DEFAULT_AGENT_NAME)

    def test_controller_parser_accepts_only_the_closed_command_set(self) -> None:
        args = build_parser().parse_args(["controller", "send", "/status"])
        self.assertEqual(args.command, "controller")
        self.assertEqual(args.controller_command, "send")
        self.assertEqual(args.controller_text, "/status")

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(["controller", "send", "/pr"])

    def test_run_parser_accepts_capability_policy_as_a_sender_mode(self) -> None:
        args = build_parser().parse_args(
            ["run", "--capability-policy", "capabilities.json"]
        )
        self.assertEqual(args.capability_policy, Path("capabilities.json"))
        self.assertEqual(args.allow_did, [])
        self.assertFalse(args.allow_any_signed)

        with self.assertRaises(SystemExit):
            build_parser().parse_args(
                [
                    "run",
                    "--capability-policy",
                    "capabilities.json",
                    "--allow-did",
                    did_from_private_key(private_key_from_seed(SEED)),
                ]
            )

    def test_audit_verify_parser_requires_only_the_log_path(self) -> None:
        args = build_parser().parse_args(["audit", "verify", "audit.jsonl"])
        self.assertEqual(args.command, "audit")
        self.assertEqual(args.audit_command, "verify")
        self.assertEqual(args.path, Path("audit.jsonl"))
        self.assertIsNone(args.expected_head)

    def test_audit_verify_is_offline_and_accepts_a_trusted_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            key = private_key_from_seed(SEED)
            did = did_from_private_key(key)
            head = SignedAuditLog(path).append(
                issuer_did=did,
                private_key=key,
                observed_at=datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
                input_sequence=2,
                sender_fingerprint=None,
                sender_authenticated=False,
                policy_decision="ignore",
                policy_reason="unsigned_sender",
                outcome="ignore",
                receipt_sha256=None,
                response_sequence=None,
            )
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                result = main(["audit", "verify", str(path), "--expected-head", head])

            event = json.loads(stdout.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(event["status"], "valid")
            self.assertEqual(event["entries"], 1)
            self.assertEqual(event["issuer"], did)
            self.assertTrue(event["expected_head_matched"])

    def test_recover_delivery_defaults_to_inspection_without_retry(self) -> None:
        args = build_parser().parse_args(["recover-delivery"])
        self.assertEqual(args.command, "recover-delivery")
        self.assertFalse(args.apply)
        self.assertFalse(args.confirm_retry)

    def test_recover_delivery_without_journal_does_not_access_keychain_or_network(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            did = did_from_private_key(private_key_from_seed(SEED))
            identity = root / "identity.json"
            identity.write_text(
                json.dumps(
                    {
                        "did": did,
                        "fingerprint": fingerprint_of_did(did),
                        "custody": {
                            "backend": "macos-keychain",
                            "service": "must-not-be-read",
                            "account": "must-not-be-read",
                        },
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = main(
                    [
                        "recover-delivery",
                        "--identity",
                        str(identity),
                        "--room",
                        "test-room",
                        "--state",
                        str(root / "state.json"),
                        "--journal",
                        str(root / "delivery.json"),
                        "--lock",
                        str(root / "agent.lock"),
                    ]
                )

            self.assertEqual(result, 0)
            self.assertEqual(
                json.loads(stdout.getvalue())["event"], "no_pending_delivery"
            )

    def test_verify_receipt_does_not_require_keychain_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(render_signed_receipt(_receipt()), encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = main(["verify-receipt", str(path)])
            event = json.loads(stdout.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(event["status"], "valid")
            self.assertEqual(event["repository"], "example/project")

    def test_verify_receipt_returns_an_error_for_tampered_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            receipt = _receipt()
            payload = receipt["payload"]
            self.assertIsInstance(payload, dict)
            assert isinstance(payload, dict)
            payload["ci"] = "failure"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(["verify-receipt", str(path)])
            self.assertEqual(result, 2)
            self.assertIn("payload hash does not match", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
