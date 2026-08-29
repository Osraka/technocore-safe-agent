from __future__ import annotations

import unittest
from dataclasses import replace

from technocore_safe_agent.config import AgentConfig, ConfigError
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
)


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        did = did_from_private_key(private_key_from_seed("01" * 32))
        self.config = AgentConfig(
            schema="technocore-safe-agent-config-v1",
            name="Osraka",
            did=did,
            fingerprint=fingerprint_of_did(did),
            room="mb-p-test",
            base_url="https://technocore.chat",
            status="active",
            created_at="2026-08-29T00:00:00+00:00",
            provision_nonce="1",
            provisioned_seq=1,
        )

    def test_accepts_a_consistent_config(self) -> None:
        self.config.validate()

    def test_rejects_name_characters_not_allowed_during_provisioning(self) -> None:
        with self.assertRaisesRegex(ConfigError, "invalid name"):
            replace(self.config, name="unsafe name").validate()

    def test_rejects_a_fingerprint_that_does_not_match_the_did(self) -> None:
        with self.assertRaisesRegex(ConfigError, "does not match"):
            replace(self.config, fingerprint="0" * 16).validate()


if __name__ == "__main__":
    unittest.main()
