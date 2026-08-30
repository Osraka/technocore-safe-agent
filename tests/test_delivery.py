from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from technocore_safe_agent.crypto import (
    did_from_private_key,
    private_key_from_seed,
    sign_room_message,
)
from technocore_safe_agent.delivery import (
    DeliveryError,
    DeliveryJournal,
    DeliveryRecord,
)
from technocore_safe_agent.delivery_recovery import recover_delivery
from technocore_safe_agent.protocol import RoomMessage, RoomSnapshot
from technocore_safe_agent.state import AgentState


ROOM = "mb-p-0123456789abcdef01234567"
KEY = private_key_from_seed("05" * 32)
DID = did_from_private_key(KEY)


def _record() -> DeliveryRecord:
    text, signature = sign_room_message(KEY, ROOM, 101, "pong")
    return DeliveryRecord.create(
        room=ROOM,
        input_sequence=8,
        did=DID,
        nonce=101,
        text=text,
        signature=signature,
    )


class RecoveryClient:
    base_url = "https://technocore.chat"

    def __init__(self, snapshot: RoomSnapshot, *, reply_sequence: int = 9) -> None:
        self.snapshot = snapshot
        self.reply_sequence = reply_sequence
        self.posts: list[dict[str, object]] = []
        self.reads = 0

    def read_room(self, *args: object, **kwargs: object) -> RoomSnapshot:
        self.reads += 1
        return self.snapshot

    def send_signed_message(self, **kwargs: object) -> RoomMessage:
        self.posts.append(kwargs)
        return RoomMessage(
            self.reply_sequence,
            str(kwargs["did"]),
            str(kwargs["text"]),
            str(kwargs["nonce"]),
        )


class DeliveryTests(unittest.TestCase):
    def test_journal_round_trips_private_verified_record_and_acknowledgement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "delivery.json"
            journal = DeliveryJournal(path)
            journal.prepare(_record())

            loaded = journal.load()
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.status, "pending")
            loaded.verify_for_room(ROOM)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            acknowledged = journal.acknowledge(9)
            self.assertEqual(
                (acknowledged.status, acknowledged.reply_sequence), ("acknowledged", 9)
            )
            self.assertEqual(journal.load(), acknowledged)

            journal.clear()
            self.assertIsNone(journal.load())

    def test_journal_rejects_overwrite_and_tampered_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "delivery.json"
            journal = DeliveryJournal(path)
            journal.prepare(_record())
            with self.assertRaisesRegex(DeliveryError, "pending delivery"):
                journal.prepare(_record())

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["text"] = "different"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(DeliveryError, "digest"):
                journal.load()

    def test_journal_refuses_group_readable_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "delivery.json"
            journal = DeliveryJournal(path)
            journal.prepare(_record())
            path.chmod(0o640)

            with self.assertRaisesRegex(DeliveryError, "permissions"):
                journal.load()

    def test_acknowledged_delivery_recovers_without_network_read_or_resend(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = DeliveryJournal(root / "delivery.json")
            journal.prepare(_record())
            journal.acknowledge(9)
            state_path = root / "state.json"
            state = AgentState(cursors={ROOM: 7}, nonces={ROOM: 50})
            state.save(state_path)
            client = RecoveryClient(RoomSnapshot(ROOM, 0, 0, ()))

            inspection = recover_delivery(
                room=ROOM,
                did=DID,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=journal,
                apply=False,
                confirm_retry=False,
            )
            self.assertEqual(inspection["event"], "delivery_acknowledged")
            self.assertEqual(client.reads, 0)

            applied = recover_delivery(
                room=ROOM,
                did=DID,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=journal,
                apply=True,
                confirm_retry=False,
            )
            self.assertEqual(applied["event"], "delivery_recovered")
            self.assertEqual(client.reads, 0)
            self.assertEqual(client.posts, [])
            self.assertIsNone(journal.load())

    def test_recovery_finds_delivery_without_mutating_in_inspection_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = DeliveryJournal(root / "delivery.json")
            journal.prepare(_record())
            state_path = root / "state.json"
            state = AgentState(cursors={ROOM: 7}, nonces={ROOM: 50})
            state.save(state_path)
            found = RoomMessage(9, DID, "pong", "101")
            client = RecoveryClient(RoomSnapshot(ROOM, 9, 9, (found,)))

            event = recover_delivery(
                room=ROOM,
                did=DID,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=journal,
                apply=False,
                confirm_retry=False,
            )

            self.assertEqual(event["event"], "delivery_found")
            self.assertEqual(client.posts, [])
            self.assertIsNotNone(journal.load())
            self.assertEqual(AgentState.load(state_path).cursor_for(ROOM), 7)

    def test_recovery_applies_found_delivery_without_resending(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = DeliveryJournal(root / "delivery.json")
            journal.prepare(_record())
            state_path = root / "state.json"
            state = AgentState(cursors={ROOM: 7}, nonces={ROOM: 50})
            state.save(state_path)
            found = RoomMessage(9, DID, "pong", "101")
            client = RecoveryClient(RoomSnapshot(ROOM, 9, 9, (found,)))

            event = recover_delivery(
                room=ROOM,
                did=DID,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=journal,
                apply=True,
                confirm_retry=False,
            )

            recovered = AgentState.load(state_path)
            self.assertEqual(event["event"], "delivery_recovered")
            self.assertEqual(recovered.cursor_for(ROOM), 8)
            self.assertEqual(recovered.nonces[ROOM], 101)
            self.assertEqual(client.posts, [])
            self.assertIsNone(journal.load())

    def test_absent_delivery_requires_explicit_retry_and_reuses_signed_envelope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = DeliveryJournal(root / "delivery.json")
            record = _record()
            journal.prepare(record)
            state_path = root / "state.json"
            state = AgentState(cursors={ROOM: 7}, nonces={ROOM: 50})
            state.save(state_path)
            client = RecoveryClient(RoomSnapshot(ROOM, 0, 8, ()))

            inspection = recover_delivery(
                room=ROOM,
                did=DID,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=journal,
                apply=False,
                confirm_retry=False,
            )
            self.assertEqual(inspection["event"], "delivery_not_found")
            self.assertTrue(inspection["retry_available"])
            self.assertEqual(client.posts, [])

            recovered = recover_delivery(
                room=ROOM,
                did=DID,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=journal,
                apply=True,
                confirm_retry=True,
            )
            self.assertEqual(recovered["event"], "delivery_retried")
            self.assertEqual(len(client.posts), 1)
            self.assertEqual(client.posts[0]["nonce"], record.nonce)
            self.assertEqual(client.posts[0]["signature"], record.signature)
            self.assertEqual(client.posts[0]["text"], record.text)
            self.assertEqual(AgentState.load(state_path).cursor_for(ROOM), 8)
            self.assertIsNone(journal.load())

    def test_recovery_refuses_retry_for_history_gap_or_duplicate_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            state = AgentState(cursors={ROOM: 7}, nonces={ROOM: 50})
            state.save(state_path)

            gap_journal = DeliveryJournal(root / "gap.json")
            gap_journal.prepare(_record())
            other = RoomMessage(12, DID, "other", "12")
            gap_client = RecoveryClient(RoomSnapshot(ROOM, 12, 12, (other,)))
            gap = recover_delivery(
                room=ROOM,
                did=DID,
                client=gap_client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=gap_journal,
                apply=True,
                confirm_retry=True,
            )
            self.assertEqual(gap["event"], "delivery_history_incomplete")
            self.assertEqual(gap_client.posts, [])

            duplicate_journal = DeliveryJournal(root / "duplicate.json")
            duplicate_journal.prepare(_record())
            matches = (
                RoomMessage(9, DID, "pong", "101"),
                RoomMessage(10, DID, "pong", "101"),
            )
            duplicate_client = RecoveryClient(RoomSnapshot(ROOM, 9, 10, matches))
            duplicate = recover_delivery(
                room=ROOM,
                did=DID,
                client=duplicate_client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                journal=duplicate_journal,
                apply=True,
                confirm_retry=True,
            )
            self.assertEqual(duplicate["event"], "duplicate_delivery_records")
            self.assertEqual(duplicate_client.posts, [])


if __name__ == "__main__":
    unittest.main()
