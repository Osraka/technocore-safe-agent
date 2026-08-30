from __future__ import annotations

import ctypes
import stat
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
    MacOSKeychainSeedStore,
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
    def test_framework_add_receives_exact_seed_and_wipes_input_buffer(self) -> None:
        class RecordingFramework:
            added: tuple[bytes, bytes, bytes] | None = None

            def SecKeychainAddGenericPassword(
                self,
                keychain: object,
                service_length: int,
                service: bytes,
                account_length: int,
                account: bytes,
                password_length: int,
                password: ctypes.c_void_p,
                item_ref: object,
            ) -> int:
                self.added = (
                    service[:service_length],
                    account[:account_length],
                    ctypes.string_at(password, password_length),
                )
                return 0

        framework = RecordingFramework()
        with (
            patch(
                "technocore_safe_agent.controller._load_security_framework",
                return_value=framework,
            ),
            patch(
                "technocore_safe_agent.controller.ctypes.memset",
                wraps=ctypes.memset,
            ) as wipe,
        ):
            controller_module._add_generic_password(
                "technocore.test.controller",
                "test-controller",
                CONTROLLER_SEED,
            )

        self.assertEqual(
            framework.added,
            (
                b"technocore.test.controller",
                b"test-controller",
                CONTROLLER_SEED.encode("ascii"),
            ),
        )
        self.assertEqual(wipe.call_count, 1)
        self.assertEqual(wipe.call_args.args[1:], (0, 64))

    def test_framework_read_releases_returned_keychain_buffer(self) -> None:
        class RecordingFramework:
            def __init__(self) -> None:
                self.buffer = ctypes.create_string_buffer(
                    CONTROLLER_SEED.encode("ascii")
                )
                self.freed_pointer: int | None = None

            def SecKeychainFindGenericPassword(
                self,
                keychain: object,
                service_length: int,
                service: bytes,
                account_length: int,
                account: bytes,
                password_length: object,
                password_data: object,
                item_ref: object,
            ) -> int:
                ctypes.cast(
                    password_length,
                    ctypes.POINTER(ctypes.c_uint32),
                ).contents.value = len(CONTROLLER_SEED)
                ctypes.cast(
                    password_data,
                    ctypes.POINTER(ctypes.c_void_p),
                ).contents.value = ctypes.addressof(self.buffer)
                return 0

            def SecKeychainItemFreeContent(
                self,
                attributes: object,
                password_data: ctypes.c_void_p,
            ) -> int:
                self.freed_pointer = password_data.value
                return 0

        framework = RecordingFramework()
        with patch(
            "technocore_safe_agent.controller._load_security_framework",
            return_value=framework,
        ):
            loaded = controller_module._read_generic_password(
                "technocore.test.controller",
                "test-controller",
            )

        self.assertEqual(loaded, CONTROLLER_SEED)
        self.assertEqual(framework.freed_pointer, ctypes.addressof(framework.buffer))

    def test_keychain_store_uses_framework_helpers(self) -> None:
        store = MacOSKeychainSeedStore(
            service="technocore.test.controller",
            account="test-controller",
        )

        with (
            patch("technocore_safe_agent.controller._add_generic_password") as add,
            patch(
                "technocore_safe_agent.controller._read_generic_password",
                return_value=CONTROLLER_SEED,
            ) as read,
        ):
            store.store_seed(CONTROLLER_SEED)
            loaded = store.load_seed()

        add.assert_called_once_with(
            "technocore.test.controller",
            "test-controller",
            CONTROLLER_SEED,
        )
        read.assert_called_once_with(
            "technocore.test.controller",
            "test-controller",
        )
        self.assertEqual(loaded, CONTROLLER_SEED)

    def test_keychain_store_never_echoes_seed_on_failure(self) -> None:
        store = MacOSKeychainSeedStore("service", "account")

        with (
            patch(
                "technocore_safe_agent.controller._add_generic_password",
                side_effect=ControllerError("cannot create Keychain item"),
            ),
            self.assertRaises(ControllerError) as raised,
        ):
            store.store_seed(CONTROLLER_SEED)

        self.assertNotIn(CONTROLLER_SEED, str(raised.exception))

    def test_keychain_store_rejects_unsafe_item_selectors(self) -> None:
        with self.assertRaisesRegex(ControllerError, "service is invalid"):
            MacOSKeychainSeedStore("service\nother", "account")
        with self.assertRaisesRegex(ControllerError, "account is invalid"):
            MacOSKeychainSeedStore("service", "")

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
                name="Osraka",
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
                name="Osraka",
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
