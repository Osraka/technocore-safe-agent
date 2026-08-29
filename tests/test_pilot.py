from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from technocore_safe_agent.config import AgentConfig
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
)
from technocore_safe_agent.identity import IdentityRecord
from technocore_safe_agent.pilot import execute_live_pilot
from technocore_safe_agent.protocol import RoomMessage, RoomSnapshot, TransportError
from technocore_safe_agent.state import AgentState


ROOM = "mb-p-0123456789abcdef01234567"


class InMemoryPilotClient:
    base_url = "https://technocore.chat"

    def __init__(self) -> None:
        self.messages: list[RoomMessage] = [
            RoomMessage(1, "bootstrap", "safe-responder-online-v1")
        ]

    def read_room(self, room: str, *, since: int, **_: object) -> RoomSnapshot:
        messages = tuple(message for message in self.messages if message.seq > since)
        first_seq = messages[0].seq if messages else 0
        return RoomSnapshot(room, first_seq, self.messages[-1].seq, messages)

    def send_signed_message(self, **kwargs: object) -> RoomMessage:
        message = RoomMessage(
            len(self.messages) + 1,
            str(kwargs["did"]),
            str(kwargs["text"]),
            str(kwargs["nonce"]),
        )
        self.messages.append(message)
        return message

    def send_unsigned(self, room: str, nick: str, text: str) -> RoomMessage:
        message = RoomMessage(len(self.messages) + 1, nick, text)
        self.messages.append(message)
        return message


class PilotTests(unittest.TestCase):
    def _run_pilot(
        self, *, reject_unsigned: bool
    ) -> tuple[dict[str, object], InMemoryPilotClient, str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            agent_key = private_key_from_seed("01" * 32)
            agent_did = did_from_private_key(agent_key)
            record = IdentityRecord(
                did=agent_did,
                fingerprint=fingerprint_of_did(agent_did),
                keychain_service="test.service",
                keychain_account="test",
            )
            config = AgentConfig(
                schema="technocore-safe-agent-config-v1",
                name="Osraka",
                did=agent_did,
                fingerprint=record.fingerprint,
                room=ROOM,
                base_url="https://technocore.chat",
                status="active",
                created_at="2026-08-29T00:00:00+00:00",
                provision_nonce="1",
                provisioned_seq=1,
            )
            state = AgentState(cursors={ROOM: 1}, nonces={ROOM: 1})
            client = InMemoryPilotClient()
            peer_seeds = iter(("02" * 32, "03" * 32))

            def send_unsigned(
                selected: InMemoryPilotClient,
                room: str,
                nick: str,
                text: str,
            ) -> RoomMessage:
                if reject_unsigned:
                    raise TransportError("mailboxes require signed writes", status=403)
                return selected.send_unsigned(room, nick, text)

            report = execute_live_pilot(
                record=record,
                private_key=agent_key,
                config=config,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                unsigned_sender=send_unsigned,  # type: ignore[arg-type]
                peer_key_factory=lambda: private_key_from_seed(next(peer_seeds)),
            )

            self.assertTrue(state_path.exists())
            return report, client, agent_did

    def test_runs_all_scenarios_without_persisting_ephemeral_keys(self) -> None:
        report, client, agent_did = self._run_pilot(reject_unsigned=False)

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["ephemeral_keys_persisted"], False)
        scenarios = report["scenarios"]
        self.assertEqual(
            scenarios["allowlisted_signed_exact_command"]["result"],
            "replied_once",
        )
        self.assertEqual(scenarios["unallowlisted_signed_command"]["result"], "ignored")
        self.assertEqual(
            scenarios["unsigned_command"]["result"], "delivered_but_ignored"
        )
        self.assertEqual(scenarios["extended_prompt_like_command"]["result"], "ignored")
        agent_messages = [
            message for message in client.messages if message.sender == agent_did
        ]
        self.assertEqual([message.text for message in agent_messages], ["pong"])

    def test_accepts_mailbox_unsigned_rejection_as_a_stronger_boundary(self) -> None:
        report, client, _ = self._run_pilot(reject_unsigned=True)

        scenarios = report["scenarios"]
        self.assertEqual(
            scenarios["unsigned_command"],
            {"result": "rejected_at_transport", "http_status": 403},
        )
        self.assertFalse(
            any(message.sender.startswith("pilot-u-") for message in client.messages)
        )

    def test_script_requires_explicit_live_confirmation(self) -> None:
        from scripts.run_live_pilot import main

        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
