from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.agent import SafeResponder, UncertainWriteError
from technocore_safe_agent.audit import AuditError, SignedAuditLog
from technocore_safe_agent.capabilities import (
    CapabilityPolicyFile,
    CapabilityRateLimiter,
)
from technocore_safe_agent.crypto import did_from_private_key, private_key_from_seed
from technocore_safe_agent.delivery import DeliveryJournal
from technocore_safe_agent.policy import CommandPolicy
from technocore_safe_agent.protocol import RoomMessage, RoomSnapshot, TransportError
from technocore_safe_agent.receipt import GitHubReceiptError
from technocore_safe_agent.state import AgentState
from technocore_safe_agent.state import StateError


SEED = "01" * 32
PEER = "did:key:z6MkgYtEcT6LycB7YPDvGVYnCn66CbAH7BH3p88MZAyrSPwJ"


class FakeClient:
    def __init__(self, *, fail_write: bool = False) -> None:
        self.fail_write = fail_write
        self.posts: list[dict[str, object]] = []
        self.snapshot = RoomSnapshot("room", 1, 4, ())

    def read_room(self, *args: object, **kwargs: object) -> RoomSnapshot:
        return self.snapshot

    def send_signed_message(self, **kwargs: object) -> RoomMessage:
        self.posts.append(kwargs)
        if self.fail_write:
            raise TransportError("connection dropped")
        return RoomMessage(
            10, str(kwargs["did"]), str(kwargs["text"]), str(kwargs["nonce"])
        )


class FakeReceiptService:
    def __init__(self, *, failure: bool = False) -> None:
        self.failure = failure
        self.calls: list[str] = []

    def issue(self, url: str) -> str:
        self.calls.append(url)
        if self.failure:
            raise GitHubReceiptError(
                "lookup failed", code="github_http_503", status=503
            )
        return '{"signed":"receipt"}'


class AgentTests(unittest.TestCase):
    def _responder(
        self,
        directory: Path,
        *,
        send: bool,
        client: FakeClient,
        receipt_service: FakeReceiptService | None = None,
    ) -> SafeResponder:
        private_key = private_key_from_seed(SEED)
        did = did_from_private_key(private_key)
        return SafeResponder(
            room="room",
            did=did,
            private_key=private_key,
            client=client,  # type: ignore[arg-type]
            policy=CommandPolicy(own_did=did, allowed_dids=frozenset({PEER})),
            state=AgentState(),
            state_path=directory / "state.json",
            receipt_service=receipt_service,
            send=send,
        )

    def test_dry_run_reports_reply_without_writing_or_persisting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            responder = self._responder(root, send=False, client=client)
            events = responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),))
            )
            self.assertEqual(events[0]["event"], "would_reply")
            self.assertEqual(client.posts, [])
            self.assertFalse((root / "state.json").exists())

    def test_send_persists_only_after_a_verified_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            responder = self._responder(root, send=True, client=client)
            events = responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),))
            )
            self.assertEqual(events[0]["event"], "sent")
            self.assertEqual(len(client.posts), 1)
            self.assertEqual(AgentState.load(root / "state.json").cursor_for("room"), 1)

    def test_uncertain_write_halts_without_advancing_the_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responder = self._responder(
                root, send=True, client=FakeClient(fail_write=True)
            )
            with self.assertRaises(UncertainWriteError):
                responder.process_snapshot(
                    RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),))
                )
            self.assertEqual(responder.state.cursor_for("room"), 0)
            self.assertFalse((root / "state.json").exists())

    def test_acknowledged_write_with_failed_state_save_halts_as_uncertain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            responder = self._responder(root, send=True, client=client)
            with patch.object(
                responder.state, "save", side_effect=StateError("disk full")
            ):
                with self.assertRaisesRegex(UncertainWriteError, "acknowledged"):
                    responder.process_snapshot(
                        RoomSnapshot(
                            "room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),)
                        )
                    )
            self.assertEqual(len(client.posts), 1)
            self.assertFalse((root / "state.json").exists())

    def test_bootstrap_uses_current_tail_and_does_not_process_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            responder = self._responder(root, send=False, client=client)
            event = responder.bootstrap_latest()
            self.assertEqual(event["cursor"], 4)
            self.assertEqual(responder.state.cursor_for("room"), 4)

    def test_receipt_dry_run_never_contacts_github_or_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            receipts = FakeReceiptService()
            responder = self._responder(
                root,
                send=False,
                client=client,
                receipt_service=receipts,
            )
            command = "/pr https://github.com/example/project/pull/42"
            events = responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, command, "1"),))
            )
            self.assertEqual(events[0]["event"], "would_issue_receipt")
            self.assertFalse(events[0]["network_requested"])
            self.assertEqual(receipts.calls, [])
            self.assertEqual(client.posts, [])
            self.assertFalse((root / "state.json").exists())

    def test_live_receipt_is_looked_up_once_then_sent_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            receipts = FakeReceiptService()
            responder = self._responder(
                root,
                send=True,
                client=client,
                receipt_service=receipts,
            )
            url = "https://github.com/example/project/pull/42"
            events = responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, f"/pr {url}", "1"),))
            )
            self.assertEqual(events[0]["event"], "sent_receipt")
            self.assertEqual(receipts.calls, [url])
            self.assertEqual(client.posts[0]["text"], '{"signed":"receipt"}')
            self.assertEqual(AgentState.load(root / "state.json").cursor_for("room"), 1)

    def test_failed_receipt_lookup_is_not_retried_or_sent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            receipts = FakeReceiptService(failure=True)
            responder = self._responder(
                root,
                send=True,
                client=client,
                receipt_service=receipts,
            )
            url = "https://github.com/example/project/pull/42"
            events = responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, f"/pr {url}", "1"),))
            )
            self.assertEqual(events[0]["event"], "receipt_failed")
            self.assertEqual(events[0]["error_code"], "github_http_503")
            self.assertEqual(receipts.calls, [url])
            self.assertEqual(client.posts, [])
            self.assertEqual(AgentState.load(root / "state.json").cursor_for("room"), 1)

    def test_delivery_journal_is_cleared_only_after_ack_and_cursor_persist(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            responder = self._responder(root, send=True, client=client)
            responder.delivery_journal = DeliveryJournal(root / "delivery.json")

            events = responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),))
            )

            self.assertEqual(events[0]["event"], "sent")
            self.assertFalse((root / "delivery.json").exists())
            self.assertEqual(AgentState.load(root / "state.json").cursor_for("room"), 1)

    def test_uncertain_write_leaves_pending_delivery_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responder = self._responder(
                root, send=True, client=FakeClient(fail_write=True)
            )
            journal = DeliveryJournal(root / "delivery.json")
            responder.delivery_journal = journal

            with self.assertRaises(UncertainWriteError):
                responder.process_snapshot(
                    RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),))
                )

            pending = journal.load()
            self.assertIsNotNone(pending)
            self.assertEqual(pending.status, "pending")
            self.assertEqual(pending.input_sequence, 1)
            self.assertEqual(pending.text, "pong")
            self.assertEqual(responder.state.cursor_for("room"), 0)

    def test_state_save_failure_leaves_acknowledged_delivery_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responder = self._responder(root, send=True, client=FakeClient())
            journal = DeliveryJournal(root / "delivery.json")
            responder.delivery_journal = journal

            with patch.object(
                responder.state, "save", side_effect=StateError("disk full")
            ):
                with self.assertRaisesRegex(UncertainWriteError, "acknowledged"):
                    responder.process_snapshot(
                        RoomSnapshot(
                            "room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),)
                        )
                    )

            acknowledged = journal.load()
            self.assertIsNotNone(acknowledged)
            self.assertEqual(acknowledged.status, "acknowledged")
            self.assertEqual(acknowledged.reply_sequence, 10)

    def test_live_decision_writes_only_sanitized_signed_audit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responder = self._responder(root, send=True, client=FakeClient())
            responder.audit_log = SignedAuditLog(root / "audit.jsonl")

            events = responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),))
            )

            summary = responder.audit_log.verify()
            raw = (root / "audit.jsonl").read_text(encoding="utf-8")
            self.assertEqual(events[0]["event"], "sent")
            self.assertEqual(summary.entries, 1)
            self.assertNotIn("room", raw)
            self.assertNotIn(PEER, raw)
            self.assertNotIn("/ping", raw)
            self.assertNotIn("pong", raw)
            payload = json.loads(raw)["payload"]
            self.assertEqual(payload["policy_decision"], "reply")
            self.assertEqual(payload["outcome"], "sent")
            self.assertEqual(payload["response_sequence"], 10)

    def test_live_receipt_audit_binds_exact_rendered_receipt_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responder = self._responder(
                root,
                send=True,
                client=FakeClient(),
                receipt_service=FakeReceiptService(),
            )
            responder.audit_log = SignedAuditLog(root / "audit.jsonl")
            url = "https://github.com/example/project/pull/42"

            responder.process_snapshot(
                RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, f"/pr {url}", "1"),))
            )

            payload = json.loads((root / "audit.jsonl").read_text())["payload"]
            self.assertEqual(payload["policy_decision"], "receipt")
            self.assertEqual(payload["outcome"], "sent_receipt")
            self.assertEqual(
                payload["receipt_sha256"],
                hashlib.sha256(b'{"signed":"receipt"}').hexdigest(),
            )

    def test_audit_failure_preserves_acknowledged_delivery_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = FakeClient()
            responder = self._responder(root, send=True, client=client)
            journal = DeliveryJournal(root / "delivery.json")
            responder.delivery_journal = journal
            audit_path = root / "audit.jsonl"
            audit_path.write_text("", encoding="utf-8")
            audit_path.chmod(0o640)
            responder.audit_log = SignedAuditLog(audit_path)

            with self.assertRaisesRegex(AuditError, "permissions"):
                responder.process_snapshot(
                    RoomSnapshot("room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),))
                )

            pending = journal.load()
            self.assertEqual(len(client.posts), 1)
            self.assertIsNotNone(pending)
            self.assertEqual(pending.status, "acknowledged")
            self.assertEqual(responder.state.cursor_for("room"), 0)
            self.assertFalse((root / "state.json").exists())

    def test_failed_receipt_lookup_consumes_capability_before_external_work(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "capabilities.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "schema": "technocore-safe-agent-capabilities-v1",
                        "principals": {
                            PEER: {
                                "enabled": True,
                                "commands": ["/pr"],
                                "repositories": ["example/project"],
                                "max_requests_per_hour": 1,
                            }
                        },
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            policy_path.chmod(0o600)
            service = FakeReceiptService(failure=True)
            responder = self._responder(
                root,
                send=True,
                client=FakeClient(),
                receipt_service=service,
            )
            responder.policy = CommandPolicy(
                own_did=responder.did,
                capabilities=CapabilityPolicyFile(policy_path),
                rate_limiter=CapabilityRateLimiter(
                    state=responder.state,
                    state_path=responder.state_path,
                    consume=True,
                    clock=lambda: 10_000,
                ),
            )
            command = "/pr https://github.com/example/project/pull/42"

            events = responder.process_snapshot(
                RoomSnapshot(
                    "room",
                    1,
                    2,
                    (
                        RoomMessage(1, PEER, command, "1"),
                        RoomMessage(2, PEER, command, "2"),
                    ),
                )
            )

            self.assertEqual(events[0]["event"], "receipt_failed")
            self.assertEqual(events[1]["reason"], "rate_limited")
            self.assertEqual(
                service.calls, ["https://github.com/example/project/pull/42"]
            )

    def test_rate_limit_persistence_failure_prevents_the_reply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "capabilities.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "schema": "technocore-safe-agent-capabilities-v1",
                        "principals": {
                            PEER: {
                                "enabled": True,
                                "commands": ["/ping"],
                                "repositories": [],
                                "max_requests_per_hour": 1,
                            }
                        },
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            policy_path.chmod(0o600)
            client = FakeClient()
            responder = self._responder(root, send=True, client=client)
            responder.policy = CommandPolicy(
                own_did=responder.did,
                capabilities=CapabilityPolicyFile(policy_path),
                rate_limiter=CapabilityRateLimiter(
                    state=responder.state,
                    state_path=responder.state_path,
                    consume=True,
                    clock=lambda: 10_000,
                ),
            )

            with patch.object(
                responder.state, "save", side_effect=StateError("disk full")
            ):
                with self.assertRaisesRegex(StateError, "disk full"):
                    responder.process_snapshot(
                        RoomSnapshot(
                            "room", 1, 1, (RoomMessage(1, PEER, "/ping", "1"),)
                        )
                    )

            self.assertEqual(client.posts, [])
            self.assertEqual(responder.state.cursor_for("room"), 0)


if __name__ == "__main__":
    unittest.main()
