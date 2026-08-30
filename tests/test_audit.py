from __future__ import annotations

import json
import stat
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from technocore_safe_agent.audit import AuditError, SignedAuditLog
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
)


KEY = private_key_from_seed("06" * 32)
DID = did_from_private_key(KEY)
PEER = did_from_private_key(private_key_from_seed("07" * 32))
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def _append(
    log: SignedAuditLog,
    *,
    input_sequence: int,
    decision: str = "reply",
    outcome: str = "sent",
    response_sequence: int | None = 10,
    receipt_sha256: str | None = None,
) -> str:
    return log.append(
        issuer_did=DID,
        private_key=KEY,
        observed_at=NOW,
        input_sequence=input_sequence,
        sender_fingerprint=fingerprint_of_did(PEER),
        sender_authenticated=True,
        policy_decision=decision,
        policy_reason="allowed_command",
        outcome=outcome,
        receipt_sha256=receipt_sha256,
        response_sequence=response_sequence,
    )


class AuditTests(unittest.TestCase):
    def test_appends_signed_private_hash_chain_without_sensitive_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = SignedAuditLog(path)

            first_head = _append(log, input_sequence=2)
            final_head = _append(
                log,
                input_sequence=4,
                decision="receipt",
                outcome="sent_receipt",
                response_sequence=5,
                receipt_sha256="a" * 64,
            )

            summary = log.verify(expected_head=final_head)
            raw = path.read_text(encoding="utf-8")
            self.assertEqual(summary.entries, 2)
            self.assertEqual(summary.issuer, DID)
            self.assertEqual(summary.head_sha256, final_head)
            self.assertNotEqual(first_head, final_head)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(PEER, raw)
            self.assertNotIn("secret-room", raw)
            self.assertNotIn("/pr https://github.com/example/project/pull/1", raw)

    def test_detects_tampering_reordering_and_missing_middle_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "audit.jsonl"
            log = SignedAuditLog(path)
            _append(log, input_sequence=2)
            _append(log, input_sequence=4)
            _append(log, input_sequence=6)
            original = path.read_text(encoding="utf-8").splitlines()

            tampered = json.loads(original[1])
            tampered["payload"]["outcome"] = "ignore"
            path.write_text(
                "\n".join([original[0], json.dumps(tampered), original[2]]) + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(AuditError, "hash|inconsistent"):
                log.verify()

            path.write_text(
                "\n".join([original[1], original[0], original[2]]) + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(AuditError, "sequence|previous"):
                log.verify()

            path.write_text(
                "\n".join([original[0], original[2]]) + "\n", encoding="utf-8"
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(AuditError, "sequence|previous"):
                log.verify()

    def test_rejects_wrong_expected_head_partial_line_and_unsafe_permissions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = SignedAuditLog(path)
            _append(log, input_sequence=2)

            with self.assertRaisesRegex(AuditError, "head"):
                log.verify(expected_head="f" * 64)

            path.write_text(
                path.read_text(encoding="utf-8").rstrip("\n"), encoding="utf-8"
            )
            with self.assertRaisesRegex(AuditError, "partial"):
                log.verify()

            path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            path.chmod(0o640)
            with self.assertRaisesRegex(AuditError, "permissions"):
                log.verify()

    def test_expected_head_detects_an_otherwise_valid_tail_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = SignedAuditLog(path)
            prefix_head = _append(log, input_sequence=2)
            trusted_head = _append(log, input_sequence=4)
            first_line = path.read_text(encoding="utf-8").splitlines()[0]
            path.write_text(first_line + "\n", encoding="utf-8")
            path.chmod(0o600)

            self.assertEqual(log.verify().head_sha256, prefix_head)
            with self.assertRaisesRegex(AuditError, "head"):
                log.verify(expected_head=trusted_head)

    def test_rejects_signing_key_that_does_not_match_issuer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = SignedAuditLog(Path(directory) / "audit.jsonl")
            with self.assertRaisesRegex(AuditError, "issuer"):
                log.append(
                    issuer_did=DID,
                    private_key=private_key_from_seed("08" * 32),
                    observed_at=NOW,
                    input_sequence=2,
                    sender_fingerprint=None,
                    sender_authenticated=False,
                    policy_decision="ignore",
                    policy_reason="unsigned_sender",
                    outcome="ignore",
                    receipt_sha256=None,
                    response_sequence=None,
                )

    def test_rejects_appending_with_a_different_valid_issuer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = SignedAuditLog(Path(directory) / "audit.jsonl")
            _append(log, input_sequence=2)
            other_key = private_key_from_seed("08" * 32)

            with self.assertRaisesRegex(AuditError, "different issuer"):
                log.append(
                    issuer_did=did_from_private_key(other_key),
                    private_key=other_key,
                    observed_at=NOW,
                    input_sequence=4,
                    sender_fingerprint=None,
                    sender_authenticated=False,
                    policy_decision="ignore",
                    policy_reason="unsigned_sender",
                    outcome="ignore",
                    receipt_sha256=None,
                    response_sequence=None,
                )

    def test_rejects_noncanonical_signature_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = SignedAuditLog(path)
            _append(log, input_sequence=2)
            wrapper = json.loads(path.read_text(encoding="utf-8"))
            wrapper["signature"] = wrapper["signature"][:-1] + "B"
            path.write_text(json.dumps(wrapper) + "\n", encoding="utf-8")
            path.chmod(0o600)

            with self.assertRaisesRegex(AuditError, "canonical"):
                log.verify()

    def test_refuses_a_symlinked_audit_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.write_text("", encoding="utf-8")
            target.chmod(0o600)
            link = root / "audit.jsonl"
            link.symlink_to(target)

            with self.assertRaisesRegex(AuditError, "access"):
                _append(SignedAuditLog(link), input_sequence=2)
            self.assertEqual(target.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
