from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.config import AgentConfig
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
)
from technocore_safe_agent.identity import IdentityRecord
from technocore_safe_agent.pilot import (
    PilotError,
    execute_live_pilot,
    execute_live_receipt_pilot,
)
from technocore_safe_agent.protocol import RoomMessage, RoomSnapshot, TransportError
from technocore_safe_agent.receipt import (
    GitHubReceiptError,
    PullRequestEvidence,
    build_signed_receipt,
    render_signed_receipt,
    verify_signed_receipt,
)
from technocore_safe_agent.state import AgentState


ROOM = "mb-p-0123456789abcdef01234567"
PR_URL = "https://github.com/foundry-rs/foundry/pull/15797"
HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40


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


class StaticReceiptService:
    def __init__(
        self, *, private_key: Ed25519PrivateKey, did: str, failure: bool = False
    ) -> None:
        self.private_key = private_key
        self.did = did
        self.failure = failure
        self.calls: list[str] = []

    def issue(self, url: str) -> str:
        self.calls.append(url)
        if self.failure:
            raise GitHubReceiptError(
                "lookup failed", code="github_http_503", status=503
            )
        evidence = PullRequestEvidence(
            repository="foundry-rs/foundry",
            number=15797,
            url=PR_URL,
            author="Osraka",
            state="open",
            merged=False,
            draft=False,
            head_sha=HEAD_SHA,
            base_sha=BASE_SHA,
            merge_commit_sha=None,
            ci="no_signals",
            ci_data_complete=True,
            checks_observed=0,
            checks_total=0,
            statuses_observed=0,
            statuses_total=0,
            source_updated_at="2026-08-29T12:00:00Z",
        )
        return render_signed_receipt(
            build_signed_receipt(
                evidence,
                issuer_did=self.did,
                private_key=self.private_key,
                observed_at=datetime(2026, 8, 29, 15, 0, tzinfo=UTC),
            )
        )


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

    def test_live_receipt_pilot_writes_one_command_and_one_verified_receipt(
        self,
    ) -> None:
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
            receipts = StaticReceiptService(private_key=agent_key, did=agent_did)

            report = execute_live_receipt_pilot(
                record=record,
                private_key=agent_key,
                config=config,
                client=client,  # type: ignore[arg-type]
                state=state,
                state_path=state_path,
                pull_request=PR_URL,
                receipt_service=receipts,
                peer_key_factory=lambda: private_key_from_seed("04" * 32),
            )

            self.assertEqual(receipts.calls, [PR_URL])
            self.assertEqual(len(client.messages), 3)
            self.assertEqual(client.messages[1].text, f"/pr {PR_URL}")
            payload = verify_signed_receipt(client.messages[2].text)
            self.assertEqual(payload["issuer"], agent_did)
            self.assertEqual(payload["head_sha"], HEAD_SHA)
            self.assertEqual(report["acknowledged_signed_writes"], 2)
            self.assertEqual(report["final_cursor"], client.messages[2].seq)
            self.assertEqual(
                AgentState.load(state_path).cursor_for(ROOM), client.messages[2].seq
            )
            self.assertEqual(report["ephemeral_key_persisted"], False)
            self.assertEqual(report["public_profile_published"], False)

    def test_live_receipt_pilot_does_not_retry_a_failed_lookup(self) -> None:
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
            receipts = StaticReceiptService(
                private_key=agent_key, did=agent_did, failure=True
            )

            with self.assertRaisesRegex(PilotError, "github_http_503"):
                execute_live_receipt_pilot(
                    record=record,
                    private_key=agent_key,
                    config=config,
                    client=client,  # type: ignore[arg-type]
                    state=state,
                    state_path=state_path,
                    pull_request=PR_URL,
                    receipt_service=receipts,
                    peer_key_factory=lambda: private_key_from_seed("04" * 32),
                )

            self.assertEqual(receipts.calls, [PR_URL])
            self.assertEqual(
                [message.text for message in client.messages[1:]], [f"/pr {PR_URL}"]
            )
            self.assertEqual(AgentState.load(state_path).cursor_for(ROOM), 2)

    def test_receipt_pilot_script_requires_explicit_live_confirmation(self) -> None:
        from scripts.run_live_receipt_pilot import main

        self.assertEqual(main(["--pull-request", PR_URL]), 2)


if __name__ == "__main__":
    unittest.main()
