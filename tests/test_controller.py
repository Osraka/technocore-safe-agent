from __future__ import annotations

import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.capabilities import CapabilityPolicyFile
from technocore_safe_agent.config import AgentConfig
from technocore_safe_agent.controller import (
    CONTROLLER_COMMANDS,
    ControllerError,
    MacOSKeychainSeedWriter,
    create_controller_identity,
    grant_controller_to_empty_policy,
    send_controller_command,
)
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
    verify_detached_signature,
)
from technocore_safe_agent.identity import IdentityRecord
from technocore_safe_agent.protocol import RoomMessage, TransportError
from technocore_safe_agent.state import AgentState
import technocore_safe_agent.controller as controller_module


CONTROLLER_SEED = "0e" * 32
AGENT_SEED = "0f" * 32


@dataclass
class RecordingSeedStore:
    service: str = "technocore.test.controller"
    account: str = "test-controller"
    stored: list[str] = field(default_factory=list)
    deleted: int = 0

    def store_seed(self, seed: str) -> None:
        self.stored.append(seed)

    def delete_seed(self) -> None:
        self.deleted += 1


@dataclass
class RecordingClient:
    base_url: str
    state_path: Path
    calls: list[dict[str, object]] = field(default_factory=list)

    def send_signed_message(self, **kwargs: object) -> RoomMessage:
        persisted = AgentState.load(self.state_path)
        room = str(kwargs["room"])
        nonce = int(str(kwargs["nonce"]))
        if persisted.nonces.get(room) != nonce:
            raise AssertionError("controller nonce was not durable before network")
        self.calls.append(kwargs)
        return RoomMessage(
            seq=17,
            sender=str(kwargs["did"]),
            text=str(kwargs["text"]),
            nonce=str(kwargs["nonce"]),
        )


class ControllerTests(unittest.TestCase):
    def test_keychain_writer_keeps_seed_out_of_argv_and_delegates_to_pty(
        self,
    ) -> None:
        writer = MacOSKeychainSeedWriter(
            service="technocore.test.controller",
            account="test-controller",
        )

        with patch(
            "technocore_safe_agent.controller._run_hidden_keychain_prompt"
        ) as prompt:
            writer.store_seed(CONTROLLER_SEED)

        arguments, supplied_seed = prompt.call_args.args
        self.assertEqual(arguments[-1], "-w")
        self.assertNotIn(CONTROLLER_SEED, arguments)
        self.assertNotIn(CONTROLLER_SEED, " ".join(arguments))
        self.assertEqual(supplied_seed, CONTROLLER_SEED)
        self.assertEqual(
            prompt.call_args.kwargs["timeout"],
            controller_module.KEYCHAIN_PROMPT_TIMEOUT_SECONDS,
        )

    def test_hidden_keychain_prompt_answers_both_prompts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "fake_security.py"
            script.write_text(
                """import sys

sys.stdout.write("password data for new item: ")
sys.stdout.flush()
first = sys.stdin.readline()
sys.stdout.write("\\r\\nretype password for new item: ")
sys.stdout.flush()
second = sys.stdin.readline()
raise SystemExit(0 if first == second and len(first.strip()) == 64 else 9)
""",
                encoding="utf-8",
            )

            controller_module._run_hidden_keychain_prompt(
                [sys.executable, str(script)],
                CONTROLLER_SEED,
                timeout=2,
            )

    def test_hidden_keychain_prompt_times_out_without_echoing_seed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "slow_security.py"
            script.write_text(
                """import sys
import time

sys.stdout.write("password data for new item: ")
sys.stdout.flush()
sys.stdin.readline()
time.sleep(10)
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ControllerError, "timed out") as raised:
                controller_module._run_hidden_keychain_prompt(
                    [sys.executable, str(script)],
                    CONTROLLER_SEED,
                    timeout=0.05,
                )

        self.assertNotIn(CONTROLLER_SEED, str(raised.exception))

    def test_hidden_keychain_prompt_rejects_nonzero_exit_without_seed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "failing_security.py"
            script.write_text(
                """import sys

for prompt in (
    "password data for new item: ",
    "retype password for new item: ",
):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    sys.stdin.readline()
raise SystemExit(7)
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ControllerError, "cannot create") as raised:
                controller_module._run_hidden_keychain_prompt(
                    [sys.executable, str(script)],
                    CONTROLLER_SEED,
                    timeout=2,
                )

        self.assertNotIn(CONTROLLER_SEED, str(raised.exception))

    def test_keychain_writer_never_echoes_seed_on_failure(self) -> None:
        writer = MacOSKeychainSeedWriter("service", "account")

        with (
            patch(
                "technocore_safe_agent.controller._run_hidden_keychain_prompt",
                side_effect=ControllerError("cannot create Keychain item"),
            ),
            self.assertRaises(ControllerError) as raised,
        ):
            writer.store_seed(CONTROLLER_SEED)

        self.assertNotIn(CONTROLLER_SEED, str(raised.exception))

    def test_keychain_writer_deletes_only_the_exact_item(self) -> None:
        writer = MacOSKeychainSeedWriter("service", "account")

        with patch("technocore_safe_agent.controller.subprocess.run") as run:
            writer.delete_seed()

        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/security",
                "delete-generic-password",
                "-a",
                "account",
                "-s",
                "service",
            ],
        )
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertNotIn("input", run.call_args.kwargs)

    def test_keychain_writer_ignores_only_item_not_found_on_delete(self) -> None:
        writer = MacOSKeychainSeedWriter("service", "account")
        missing = subprocess.CalledProcessError(44, ["security"])
        denied = subprocess.CalledProcessError(1, ["security"])

        with patch(
            "technocore_safe_agent.controller.subprocess.run",
            side_effect=missing,
        ):
            writer.delete_seed()
        with (
            patch(
                "technocore_safe_agent.controller.subprocess.run",
                side_effect=denied,
            ),
            self.assertRaisesRegex(ControllerError, "cannot delete"),
        ):
            writer.delete_seed()

    def test_keychain_writer_rejects_unsafe_item_selectors(self) -> None:
        with self.assertRaisesRegex(ControllerError, "service is invalid"):
            MacOSKeychainSeedWriter("service\nother", "account")
        with self.assertRaisesRegex(ControllerError, "account is invalid"):
            MacOSKeychainSeedWriter("service", "")

    def test_create_writes_only_public_identity_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "controller-identity.json"
            store = RecordingSeedStore()

            record = create_controller_identity(
                path,
                store,
                seed_factory=lambda: CONTROLLER_SEED,
                created_at="2026-08-30T00:00:00+00:00",
            )

            payload = path.read_text(encoding="utf-8")
            self.assertEqual(store.stored, [CONTROLLER_SEED])
            self.assertNotIn(CONTROLLER_SEED, payload)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(IdentityRecord.load(path), record)
            self.assertEqual(
                record.did,
                did_from_private_key(private_key_from_seed(CONTROLLER_SEED)),
            )

            with self.assertRaisesRegex(ControllerError, "overwrite"):
                create_controller_identity(path, store)
            self.assertEqual(store.stored, [CONTROLLER_SEED])

    def test_create_removes_keychain_item_if_public_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "controller-identity.json"
            store = RecordingSeedStore()

            with (
                patch(
                    "technocore_safe_agent.controller._write_new_private_json",
                    side_effect=ControllerError("simulated public write failure"),
                ),
                self.assertRaisesRegex(ControllerError, "public write failure"),
            ):
                create_controller_identity(
                    path,
                    store,
                    seed_factory=lambda: CONTROLLER_SEED,
                )

            self.assertEqual(store.stored, [CONTROLLER_SEED])
            self.assertEqual(store.deleted, 1)
            self.assertFalse(path.exists())

    def test_create_surfaces_keychain_cleanup_failure(self) -> None:
        class CleanupFailureStore(RecordingSeedStore):
            def delete_seed(self) -> None:
                raise ControllerError("simulated cleanup failure")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "controller-identity.json"

            with (
                patch(
                    "technocore_safe_agent.controller._write_new_private_json",
                    side_effect=ControllerError("simulated public write failure"),
                ),
                self.assertRaisesRegex(ControllerError, "cleanup also failed"),
            ):
                create_controller_identity(
                    path,
                    CleanupFailureStore(),
                    seed_factory=lambda: CONTROLLER_SEED,
                )

            self.assertFalse(path.exists())

    def test_grant_only_replaces_an_empty_policy_with_fixed_read_only_scope(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            identity_path = root / "controller-identity.json"
            policy_path = root / "capabilities.json"
            create_controller_identity(
                identity_path,
                RecordingSeedStore(),
                seed_factory=lambda: CONTROLLER_SEED,
                created_at="2026-08-30T00:00:00+00:00",
            )
            policy_path.write_text(
                '{"schema":"technocore-safe-agent-capabilities-v1","principals":{}}\n',
                encoding="utf-8",
            )
            policy_path.chmod(0o600)

            grant_controller_to_empty_policy(identity_path, policy_path)

            record = IdentityRecord.load(identity_path)
            grant = CapabilityPolicyFile(policy_path).load().grant_for(record.did)
            if grant is None:
                self.fail("controller grant was not written")
            self.assertTrue(grant.enabled)
            self.assertEqual(grant.commands, frozenset(CONTROLLER_COMMANDS))
            self.assertEqual(grant.repositories, ())
            self.assertEqual(grant.max_requests_per_hour, 10)
            self.assertEqual(stat.S_IMODE(policy_path.stat().st_mode), 0o600)

            with self.assertRaisesRegex(ControllerError, "empty policy"):
                grant_controller_to_empty_policy(identity_path, policy_path)

            root.chmod(0o755)
            with self.assertRaisesRegex(ControllerError, "owner-only"):
                grant_controller_to_empty_policy(identity_path, policy_path)

    def test_send_persists_nonce_first_and_accepts_only_read_only_commands(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            state_path = root / "controller-state.json"
            controller_key = private_key_from_seed(CONTROLLER_SEED)
            controller_did = did_from_private_key(controller_key)
            agent_did = did_from_private_key(private_key_from_seed(AGENT_SEED))
            config = AgentConfig(
                schema="technocore-safe-agent-config-v1",
                name="SafeAgent",
                did=agent_did,
                fingerprint=fingerprint_of_did(agent_did),
                room="mb-p-controller-test",
                base_url="https://technocore.chat",
                status="active",
                created_at="2026-08-30T00:00:00+00:00",
                provision_nonce="1",
                provisioned_seq=1,
            )
            client = RecordingClient(config.base_url, state_path)

            event = send_controller_command(
                did=controller_did,
                private_key=controller_key,
                config=config,
                state_path=state_path,
                command="/status",
                client=client,
                clock_ns=lambda: 123,
            )

            self.assertEqual(event, {"status": "acknowledged", "command": "/status"})
            self.assertEqual(len(client.calls), 1)
            request = client.calls[0]
            canonical = f"{config.room}|{request['nonce']}|{request['text']}".encode()
            self.assertTrue(
                verify_detached_signature(
                    controller_did,
                    canonical,
                    str(request["signature"]),
                )
            )
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)

            with self.assertRaisesRegex(ControllerError, "read-only command"):
                send_controller_command(
                    did=controller_did,
                    private_key=controller_key,
                    config=config,
                    state_path=state_path,
                    command="/pr https://github.com/example/repo/pull/1",
                    client=client,
                )
            self.assertEqual(len(client.calls), 1)

            with self.assertRaisesRegex(ControllerError, "does not match"):
                send_controller_command(
                    did=controller_did,
                    private_key=private_key_from_seed(AGENT_SEED),
                    config=config,
                    state_path=state_path,
                    command="/ping",
                    client=client,
                )
            self.assertEqual(len(client.calls), 1)
            self.assertEqual(AgentState.load(state_path).nonces[config.room], 123)

    def test_failed_transport_consumes_nonce_and_is_never_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "controller-state.json"
            key = private_key_from_seed(CONTROLLER_SEED)
            did = did_from_private_key(key)
            agent_did = did_from_private_key(private_key_from_seed(AGENT_SEED))
            config = AgentConfig(
                schema="technocore-safe-agent-config-v1",
                name="SafeAgent",
                did=agent_did,
                fingerprint=fingerprint_of_did(agent_did),
                room="mb-p-controller-test",
                base_url="https://technocore.chat",
                status="active",
                created_at="2026-08-30T00:00:00+00:00",
                provision_nonce="1",
                provisioned_seq=1,
            )
            calls = 0

            class FailingClient:
                base_url = config.base_url

                def send_signed_message(self, **kwargs: object) -> RoomMessage:
                    nonlocal calls
                    calls += 1
                    raise TransportError("ambiguous write")

            with self.assertRaises(TransportError):
                send_controller_command(
                    did=did,
                    private_key=key,
                    config=config,
                    state_path=state_path,
                    command="/ping",
                    client=FailingClient(),
                    clock_ns=lambda: 456,
                )

            self.assertEqual(calls, 1)
            self.assertEqual(AgentState.load(state_path).nonces[config.room], 456)


if __name__ == "__main__":
    unittest.main()
