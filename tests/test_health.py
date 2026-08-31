from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.audit import SignedAuditLog
from technocore_safe_agent.cli import main
from technocore_safe_agent.config import AgentConfig
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
    sign_room_message,
)
from technocore_safe_agent.delivery import DeliveryJournal, DeliveryRecord
from technocore_safe_agent.health import HealthPaths, inspect_operational_health
from technocore_safe_agent.process_lock import AgentProcessLock
from technocore_safe_agent.state import AgentState


KEY = private_key_from_seed("0a" * 32)
DID = did_from_private_key(KEY)
PEER_DID = did_from_private_key(private_key_from_seed("0b" * 32))
ROOM = "mb-p-health-fixture"


class HealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.paths = HealthPaths(
            identity=root / "public-identity.json",
            config=root / "safe-agent-config.json",
            state=root / "safe-agent-state.json",
            capability_policy=root / "safe-agent-capabilities.json",
            journal=root / "safe-agent-delivery.json",
            audit=root / "safe-agent-audit.jsonl",
            lock=root / "safe-agent.lock",
        )
        self.paths.identity.write_text(
            json.dumps(
                {
                    "did": DID,
                    "fingerprint": fingerprint_of_did(DID),
                    "custody": {
                        "backend": "macos-keychain",
                        "service": "must-not-be-read",
                        "account": "must-not-be-read",
                    },
                }
            ),
            encoding="utf-8",
        )
        AgentConfig(
            schema="technocore-safe-agent-config-v1",
            name="SafeAgent",
            did=DID,
            fingerprint=fingerprint_of_did(DID),
            room=ROOM,
            base_url="https://technocore.chat",
            status="active",
            created_at="2026-08-30T00:00:00+00:00",
            provision_nonce="10",
            provisioned_seq=3,
        ).save_new(self.paths.config)
        state = AgentState(cursors={ROOM: 3}, nonces={ROOM: 10})
        state.save(self.paths.state)
        self.paths.capability_policy.write_text(
            json.dumps(
                {
                    "schema": "technocore-safe-agent-capabilities-v1",
                    "principals": {
                        PEER_DID: {
                            "enabled": True,
                            "commands": ["/status"],
                            "repositories": [],
                            "max_requests_per_hour": 2,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.paths.capability_policy.chmod(0o600)

    def test_ready_report_is_offline_bounded_and_contains_no_identifiers(self) -> None:
        report = inspect_operational_health(self.paths)

        self.assertEqual(report.status, "ready")
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(
            report.checks,
            {
                "identity": "valid",
                "config": "active",
                "state": "valid",
                "capability_policy": "valid",
                "delivery": "clear",
                "audit": "not_created",
                "process": "stopped",
            },
        )
        self.assertEqual(report.problems, ())
        self.assertFalse(report.private_key_checked)
        self.assertFalse(report.network_checked)
        rendered = json.dumps(report.to_event())
        self.assertNotIn(str(self.paths.identity.parent), rendered)
        self.assertNotIn(ROOM, rendered)
        self.assertNotIn(DID, rendered)
        self.assertNotIn(PEER_DID, rendered)

    def test_missing_or_rolled_back_state_fails_closed(self) -> None:
        self.paths.state.unlink()

        missing = inspect_operational_health(self.paths)

        self.assertEqual(missing.status, "unhealthy")
        self.assertEqual(missing.exit_code, 2)
        self.assertIn("state_missing", missing.problems)

        AgentState(cursors={ROOM: 2}, nonces={ROOM: 10}).save(self.paths.state)

        rolled_back = inspect_operational_health(self.paths)

        self.assertEqual(rolled_back.status, "unhealthy")
        self.assertIn("state_cursor_behind_config", rolled_back.problems)

        AgentState(cursors={ROOM: 3}, nonces={ROOM: 9}).save(self.paths.state)

        nonce_rolled_back = inspect_operational_health(self.paths)

        self.assertEqual(nonce_rolled_back.status, "unhealthy")
        self.assertIn("state_nonce_behind_config", nonce_rolled_back.problems)

    def test_malformed_identity_and_config_become_bounded_health_failures(self) -> None:
        identity_payload = json.loads(self.paths.identity.read_text(encoding="utf-8"))
        identity_payload["did"] = "did:key:invalid"
        self.paths.identity.write_text(json.dumps(identity_payload), encoding="utf-8")

        invalid_identity = inspect_operational_health(self.paths)

        self.assertEqual(invalid_identity.status, "unhealthy")
        self.assertIn("identity_invalid", invalid_identity.problems)

        identity_payload["did"] = DID
        self.paths.identity.write_text(json.dumps(identity_payload), encoding="utf-8")
        config_payload = json.loads(self.paths.config.read_text(encoding="utf-8"))
        config_payload["base_url"] = "file:///tmp/not-a-server"
        self.paths.config.write_text(json.dumps(config_payload), encoding="utf-8")

        invalid_config = inspect_operational_health(self.paths)

        self.assertEqual(invalid_config.status, "unhealthy")
        self.assertIn("config_invalid", invalid_config.problems)

    def test_pending_delivery_requires_recovery_without_exposing_content(self) -> None:
        text, signature = sign_room_message(KEY, ROOM, "11", "private reply")
        DeliveryJournal(self.paths.journal).prepare(
            DeliveryRecord.create(
                room=ROOM,
                input_sequence=4,
                did=DID,
                nonce=11,
                text=text,
                signature=signature,
            )
        )

        report = inspect_operational_health(self.paths)

        self.assertEqual(report.status, "recovery_required")
        self.assertEqual(report.exit_code, 3)
        self.assertEqual(report.checks["delivery"], "pending")
        self.assertEqual(report.problems, ("delivery_recovery_required",))
        self.assertNotIn("private reply", json.dumps(report.to_event()))

        with AgentProcessLock(self.paths.lock):
            in_flight = inspect_operational_health(self.paths, expect_running=True)

        self.assertEqual(in_flight.status, "running")
        self.assertEqual(in_flight.checks["delivery"], "pending")
        self.assertNotIn("delivery_recovery_required", in_flight.problems)

    def test_policy_can_pause_safely_but_unsafe_permissions_fail(self) -> None:
        self.paths.capability_policy.write_text(
            json.dumps(
                {
                    "schema": "technocore-safe-agent-capabilities-v1",
                    "principals": {},
                }
            ),
            encoding="utf-8",
        )

        paused = inspect_operational_health(self.paths)

        self.assertEqual(paused.status, "ready")
        self.assertEqual(paused.checks["capability_policy"], "valid_no_enabled_grants")

        self.paths.capability_policy.chmod(0o644)

        unsafe = inspect_operational_health(self.paths)

        self.assertEqual(unsafe.status, "unhealthy")
        self.assertIn("capability_policy_invalid", unsafe.problems)

    def test_broken_runtime_symlinks_are_invalid_not_absent(self) -> None:
        cases = (
            (self.paths.journal, "delivery", "delivery_invalid"),
            (self.paths.audit, "audit", "audit_invalid"),
            (self.paths.lock, "process", "process_lock_invalid"),
        )
        for path, check, problem in cases:
            with self.subTest(check=check):
                path.symlink_to(path.with_name("missing-target"))

                report = inspect_operational_health(self.paths)

                self.assertEqual(report.status, "unhealthy")
                self.assertEqual(report.checks[check], "invalid")
                self.assertIn(problem, report.problems)
                path.unlink()

    def test_audit_checkpoint_and_process_expectation_are_enforced(self) -> None:
        head = SignedAuditLog(self.paths.audit).append(
            issuer_did=DID,
            private_key=KEY,
            observed_at=datetime(2026, 8, 30, 12, 0, tzinfo=UTC),
            input_sequence=4,
            sender_fingerprint=None,
            sender_authenticated=False,
            policy_decision="ignore",
            policy_reason="unsigned_sender",
            outcome="ignore",
            receipt_sha256=None,
            response_sequence=None,
        )

        valid = inspect_operational_health(self.paths, expected_audit_head=head)
        wrong_head = inspect_operational_health(
            self.paths, expected_audit_head="f" * 64
        )

        self.assertEqual(valid.checks["audit"], "valid_checkpoint")
        self.assertEqual(valid.status, "ready")
        self.assertEqual(wrong_head.status, "unhealthy")
        self.assertIn("audit_invalid", wrong_head.problems)

        with AgentProcessLock(self.paths.lock):
            running = inspect_operational_health(self.paths, expect_running=True)

        stopped = inspect_operational_health(self.paths, expect_running=True)

        self.assertEqual(running.status, "running")
        self.assertEqual(running.checks["process"], "running")
        self.assertEqual(stopped.status, "unhealthy")
        self.assertIn("process_not_running", stopped.problems)

    def test_cli_health_never_reads_keychain_or_network(self) -> None:
        stdout = io.StringIO()
        with (
            patch(
                "technocore_safe_agent.identity.MacOSKeychainSeedProvider.load_seed",
                side_effect=AssertionError("Keychain must not be read"),
            ),
            patch(
                "technocore_safe_agent.protocol.urlopen",
                side_effect=AssertionError("network must not be accessed"),
            ),
            redirect_stdout(stdout),
        ):
            result = main(
                [
                    "health",
                    "--identity",
                    str(self.paths.identity),
                    "--capability-policy",
                    str(self.paths.capability_policy),
                ]
            )

        event = json.loads(stdout.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(event["status"], "ready")
        self.assertFalse(event["private_key_checked"])
        self.assertFalse(event["network_checked"])


if __name__ == "__main__":
    unittest.main()
