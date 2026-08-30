from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from technocore_safe_agent.capabilities import (
    CapabilityError,
    CapabilityPolicyFile,
    CapabilityRateLimiter,
)
from technocore_safe_agent.state import AgentState


PEER = "did:key:z6MkgYtEcT6LycB7YPDvGVYnCn66CbAH7BH3p88MZAyrSPwJ"


def _policy_payload(*, enabled: bool = True) -> dict[str, object]:
    return {
        "schema": "technocore-safe-agent-capabilities-v1",
        "principals": {
            PEER: {
                "enabled": enabled,
                "commands": ["/pr", "/status"],
                "repositories": ["Foundry-RS/*", "alloy-rs/alloy"],
                "max_requests_per_hour": 3,
            }
        },
    }


def _write_policy(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


class CapabilityPolicyFileTests(unittest.TestCase):
    def test_loads_strict_policy_and_canonicalizes_repository_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capabilities.json"
            _write_policy(path, _policy_payload())

            grant = CapabilityPolicyFile(path).load().grant_for(PEER)

            self.assertIsNotNone(grant)
            assert grant is not None
            self.assertTrue(grant.enabled)
            self.assertEqual(grant.commands, frozenset({"/pr", "/status"}))
            self.assertEqual(grant.repositories, ("foundry-rs/*", "alloy-rs/alloy"))
            self.assertTrue(grant.allows_repository("FOUNDRY-RS/Foundry"))
            self.assertTrue(grant.allows_repository("alloy-rs/alloy"))
            self.assertFalse(grant.allows_repository("base/account-sdk"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_reload_observes_an_immediate_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capabilities.json"
            source = CapabilityPolicyFile(path)
            _write_policy(path, _policy_payload(enabled=True))
            self.assertTrue(source.load().grant_for(PEER).enabled)  # type: ignore[union-attr]

            _write_policy(path, _policy_payload(enabled=False))

            self.assertFalse(source.load().grant_for(PEER).enabled)  # type: ignore[union-attr]

    def test_rejects_unsafe_or_ambiguous_policy_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "capabilities.json"
            _write_policy(path, _policy_payload())
            path.chmod(0o640)
            with self.assertRaisesRegex(CapabilityError, "permissions"):
                CapabilityPolicyFile(path).load()

            target = root / "target.json"
            _write_policy(target, _policy_payload())
            link = root / "linked.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(CapabilityError, "access"):
                CapabilityPolicyFile(link).load()

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema":"technocore-safe-agent-capabilities-v1",'
                '"schema":"technocore-safe-agent-capabilities-v1",'
                '"principals":{}}\n',
                encoding="utf-8",
            )
            duplicate.chmod(0o600)
            with self.assertRaisesRegex(CapabilityError, "duplicate"):
                CapabilityPolicyFile(duplicate).load()

            ambiguous = root / "ambiguous.json"
            payload = _policy_payload()
            principal = payload["principals"][PEER]  # type: ignore[index]
            principal["repositories"] = ["foundry-rs/*", "FOUNDRY-RS/*"]
            _write_policy(ambiguous, payload)
            with self.assertRaisesRegex(CapabilityError, "duplicate"):
                CapabilityPolicyFile(ambiguous).load()

            invalid_glob = root / "invalid-glob.json"
            payload = _policy_payload()
            principal = payload["principals"][PEER]  # type: ignore[index]
            principal["repositories"] = ["*/foundry"]
            _write_policy(invalid_glob, payload)
            with self.assertRaisesRegex(CapabilityError, "repository"):
                CapabilityPolicyFile(invalid_glob).load()


class CapabilityRateLimiterTests(unittest.TestCase):
    def test_limit_is_persistent_and_uses_a_rolling_hour(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = [10_000]
            limiter = CapabilityRateLimiter(
                state=AgentState(),
                state_path=path,
                consume=True,
                clock=lambda: now[0],
            )

            self.assertTrue(limiter.allow(PEER, 2))
            self.assertTrue(limiter.allow(PEER, 2))
            self.assertFalse(limiter.allow(PEER, 2))

            restarted = CapabilityRateLimiter(
                state=AgentState.load(path),
                state_path=path,
                consume=True,
                clock=lambda: now[0],
            )
            self.assertFalse(restarted.allow(PEER, 2))
            now[0] += 3_600
            self.assertTrue(restarted.allow(PEER, 2))

    def test_dry_run_checks_but_does_not_consume_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            limiter = CapabilityRateLimiter(
                state=AgentState(),
                state_path=path,
                consume=False,
                clock=lambda: 10_000,
            )

            self.assertTrue(limiter.allow(PEER, 1))
            self.assertTrue(limiter.allow(PEER, 1))
            self.assertFalse(path.exists())

    def test_wall_clock_rollback_does_not_restore_capacity_early(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            now = [10_000]
            state = AgentState()
            limiter = CapabilityRateLimiter(
                state=state,
                state_path=path,
                consume=True,
                clock=lambda: now[0],
            )

            self.assertTrue(limiter.allow(PEER, 2))
            now[0] = 9_000
            self.assertTrue(limiter.allow(PEER, 2))
            self.assertFalse(limiter.allow(PEER, 2))
            self.assertEqual(state.capability_requests[PEER], [10_000, 10_000])


if __name__ == "__main__":
    unittest.main()
