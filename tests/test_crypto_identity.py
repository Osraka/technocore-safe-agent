from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.crypto import (
    IdentityError,
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
    public_key_from_did,
    sign_detached,
    sign_room_message,
    sweep_text,
    verify_detached_signature,
)
from technocore_safe_agent.identity import (
    IdentityRecord,
    MacOSKeychainSeedProvider,
    StaticSeedProvider,
    load_verified_private_key,
)


SEED = "01" * 32


class CryptoIdentityTests(unittest.TestCase):
    def _record_file(self, directory: Path, seed: str = SEED) -> tuple[Path, str]:
        did = did_from_private_key(private_key_from_seed(seed))
        path = directory / "public-identity.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "technocore-public-identity-v1",
                    "did": did,
                    "fingerprint": fingerprint_of_did(did),
                    "custody": {
                        "backend": "macos-keychain",
                        "service": "test.technocore.identity",
                        "account": "test-agent",
                    },
                }
            ),
            encoding="utf-8",
        )
        return path, did

    def test_loads_public_record_and_matches_private_seed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, did = self._record_file(Path(directory))
            record = IdentityRecord.load(path)
            key = load_verified_private_key(record, StaticSeedProvider(SEED))
            self.assertEqual(did_from_private_key(key), did)

    def test_rejects_a_keychain_seed_for_a_different_did(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self._record_file(Path(directory))
            record = IdentityRecord.load(path)
            with self.assertRaisesRegex(IdentityError, "does not match"):
                load_verified_private_key(record, StaticSeedProvider("02" * 32))

    def test_keychain_provider_never_places_the_secret_in_argv(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=SEED + "\n", stderr=""
        )
        with patch(
            "technocore_safe_agent.identity.subprocess.run", return_value=completed
        ) as run:
            provider = MacOSKeychainSeedProvider("service", "account")
            self.assertEqual(provider.load_seed(), SEED)
        argv = run.call_args.args[0]
        self.assertNotIn(SEED, argv)
        self.assertEqual(argv[-4:], ["-s", "service", "-a", "account"])

    def test_signing_uses_the_server_sweep_and_canonical_nonce(self) -> None:
        key = private_key_from_seed(SEED)
        swept, signature = sign_room_message(key, "room", 7, " hello\u200b\nworld ")
        self.assertEqual(swept, "hello  world")
        self.assertEqual(len(signature), 86)
        self.assertEqual(sweep_text("\u200b\ntext"), "text")

    def test_detached_signatures_verify_against_the_did_public_key(self) -> None:
        key = private_key_from_seed(SEED)
        did = did_from_private_key(key)
        payload = b"canonical receipt payload"
        signature = sign_detached(key, payload)

        self.assertEqual(
            public_key_from_did(did).public_bytes_raw(),
            key.public_key().public_bytes_raw(),
        )
        self.assertTrue(verify_detached_signature(did, payload, signature))
        self.assertFalse(verify_detached_signature(did, payload + b"!", signature))
        self.assertFalse(verify_detached_signature(did, payload, "not-a-signature"))


if __name__ == "__main__":
    unittest.main()
