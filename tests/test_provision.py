from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from technocore_safe_agent.agent import UncertainWriteError
from technocore_safe_agent.config import AgentConfig
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
)
from technocore_safe_agent.identity import IdentityRecord
from technocore_safe_agent.protocol import RoomMessage, RoomSnapshot, TransportError
from technocore_safe_agent.provision import provision_mailbox, recover_pending_mailbox
from technocore_safe_agent.state import AgentState


SEED = "03" * 32
ROOM = "mb-p-0123456789abcdef01234567"


class ProvisionClient:
    base_url = "https://technocore.chat"

    def __init__(
        self, fail: bool = False, snapshot: RoomSnapshot | None = None
    ) -> None:
        self.fail = fail
        self.posts: list[dict[str, object]] = []
        self.snapshot = snapshot or RoomSnapshot(ROOM, 0, 0, ())

    def read_room(self, *args: object, **kwargs: object) -> RoomSnapshot:
        return self.snapshot

    def send_signed_message(self, **kwargs: object) -> RoomMessage:
        self.posts.append(kwargs)
        if self.fail:
            raise TransportError("connection dropped")
        return RoomMessage(
            seq=12,
            sender=str(kwargs["did"]),
            text=str(kwargs["text"]),
            nonce=str(kwargs["nonce"]),
        )


class ProvisionTests(unittest.TestCase):
    def _identity(self) -> tuple[IdentityRecord, object]:
        key = private_key_from_seed(SEED)
        did = did_from_private_key(key)
        return (
            IdentityRecord(
                did=did,
                fingerprint=fingerprint_of_did(did),
                keychain_service="test.service",
                keychain_account="test",
            ),
            key,
        )

    def test_success_activates_config_and_initializes_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            state_path = root / "state.json"
            record, key = self._identity()
            client = ProvisionClient()
            event = provision_mailbox(
                name="SafeAgent",
                record=record,
                private_key=key,  # type: ignore[arg-type]
                client=client,  # type: ignore[arg-type]
                config_path=config_path,
                state_path=state_path,
                room=ROOM,
            )
            config = AgentConfig.load(config_path)
            state = AgentState.load(state_path)
            self.assertEqual((config.status, config.provisioned_seq), ("active", 12))
            self.assertEqual(state.cursor_for(ROOM), 12)
            self.assertEqual(event["public_profile_published"], False)
            self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
            self.assertEqual(len(client.posts), 1)

    def test_uncertain_network_result_leaves_recoverable_pending_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            state_path = root / "state.json"
            record, key = self._identity()
            with self.assertRaisesRegex(UncertainWriteError, "uncertain result"):
                provision_mailbox(
                    name="SafeAgent",
                    record=record,
                    private_key=key,  # type: ignore[arg-type]
                    client=ProvisionClient(fail=True),  # type: ignore[arg-type]
                    config_path=config_path,
                    state_path=state_path,
                    room=ROOM,
                )
            self.assertEqual(AgentConfig.load(config_path).status, "pending")
            self.assertFalse(state_path.exists())

            inspection = recover_pending_mailbox(
                record=record,
                private_key=key,  # type: ignore[arg-type]
                client=ProvisionClient(),  # type: ignore[arg-type]
                config_path=config_path,
                state_path=state_path,
                retry=False,
            )
            self.assertEqual(inspection["event"], "mailbox_write_not_found")

            retry_client = ProvisionClient()
            recovered = recover_pending_mailbox(
                record=record,
                private_key=key,  # type: ignore[arg-type]
                client=retry_client,  # type: ignore[arg-type]
                config_path=config_path,
                state_path=state_path,
                retry=True,
            )
            self.assertEqual(recovered["event"], "mailbox_recovered_after_manual_retry")
            self.assertEqual(AgentConfig.load(config_path).status, "active")
            self.assertEqual(len(retry_client.posts), 1)

    def test_recovery_activates_a_write_found_during_inspection_without_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            state_path = root / "state.json"
            record, key = self._identity()
            with self.assertRaises(UncertainWriteError):
                provision_mailbox(
                    name="SafeAgent",
                    record=record,
                    private_key=key,  # type: ignore[arg-type]
                    client=ProvisionClient(fail=True),  # type: ignore[arg-type]
                    config_path=config_path,
                    state_path=state_path,
                    room=ROOM,
                )
            pending = AgentConfig.load(config_path)
            text = (
                f"safe-responder-online-v1 agent:SafeAgent did:{record.did} "
                "commands:/ping,/status,/about,/help policy:signed-commands-only no-tools"
            )
            found = RoomMessage(7, record.did, text, pending.provision_nonce)
            client = ProvisionClient(snapshot=RoomSnapshot(ROOM, 7, 7, (found,)))
            event = recover_pending_mailbox(
                record=record,
                private_key=key,  # type: ignore[arg-type]
                client=client,  # type: ignore[arg-type]
                config_path=config_path,
                state_path=state_path,
                retry=False,
            )
            self.assertEqual(
                event["event"], "mailbox_recovered_from_acknowledged_write"
            )
            self.assertEqual(client.posts, [])
            self.assertEqual(AgentState.load(state_path).cursor_for(ROOM), 7)

    def test_recovery_refuses_retry_when_room_history_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            state_path = root / "state.json"
            record, key = self._identity()
            with self.assertRaises(UncertainWriteError):
                provision_mailbox(
                    name="SafeAgent",
                    record=record,
                    private_key=key,  # type: ignore[arg-type]
                    client=ProvisionClient(fail=True),  # type: ignore[arg-type]
                    config_path=config_path,
                    state_path=state_path,
                    room=ROOM,
                )

            other = RoomMessage(9, record.did, "other message", "9")
            client = ProvisionClient(snapshot=RoomSnapshot(ROOM, 9, 9, (other,)))
            event = recover_pending_mailbox(
                record=record,
                private_key=key,  # type: ignore[arg-type]
                client=client,  # type: ignore[arg-type]
                config_path=config_path,
                state_path=state_path,
                retry=True,
            )

            self.assertEqual(event["event"], "mailbox_history_incomplete")
            self.assertEqual(event["retry_required"], False)
            self.assertEqual(client.posts, [])
            self.assertEqual(AgentConfig.load(config_path).status, "pending")


if __name__ == "__main__":
    unittest.main()
