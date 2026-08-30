from __future__ import annotations

import io
import json
import plistlib
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent.cli import main
from technocore_safe_agent.config import AgentConfig
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
)
from technocore_safe_agent.health import HealthPaths
from technocore_safe_agent.launchd import (
    LaunchAgentError,
    LaunchAgentSpec,
    render_launch_agent,
)
from technocore_safe_agent.state import AgentState


DID = did_from_private_key(private_key_from_seed("0c" * 32))
PEER_DID = did_from_private_key(private_key_from_seed("0d" * 32))
ROOM = "mb-p-launchd-fixture"


class LaunchAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.executable = root / "bin" / "technocore-safe-agent"
        self.executable.parent.mkdir()
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o755)
        self.paths = HealthPaths(
            identity=root / "public-identity.json",
            config=root / "safe-agent-config.json",
            state=root / "safe-agent-state.json",
            capability_policy=root / "safe-agent-capabilities.json",
            journal=root / "safe-agent-delivery.json",
            audit=root / "safe-agent-audit.jsonl",
            lock=root / "safe-agent.lock",
        )
        self.paths.identity.write_text(
            json.dumps(
                {
                    "did": DID,
                    "fingerprint": fingerprint_of_did(DID),
                    "custody": {
                        "backend": "macos-keychain",
                        "service": "must-not-be-read",
                        "account": "must-not-be-read",
                    },
                }
            ),
            encoding="utf-8",
        )
        AgentConfig(
            schema="technocore-safe-agent-config-v1",
            name="Osraka",
            did=DID,
            fingerprint=fingerprint_of_did(DID),
            room=ROOM,
            base_url="https://technocore.chat",
            status="active",
            created_at="2026-08-30T00:00:00+00:00",
            provision_nonce="10",
            provisioned_seq=3,
        ).save_new(self.paths.config)
        AgentState(cursors={ROOM: 3}, nonces={ROOM: 10}).save(self.paths.state)
        self.paths.capability_policy.write_text(
            json.dumps(
                {
                    "schema": "technocore-safe-agent-capabilities-v1",
                    "principals": {
                        PEER_DID: {
                            "enabled": True,
                            "commands": ["/status"],
                            "repositories": [],
                            "max_requests_per_hour": 2,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        self.paths.capability_policy.chmod(0o600)
        self.spec = LaunchAgentSpec(
            label="com.technocore.safe-agent.test",
            executable=self.executable,
            health_paths=self.paths,
            stdout_path=root / "safe-agent.stdout.log",
            stderr_path=root / "safe-agent.stderr.log",
        )

    def test_renderer_uses_direct_arguments_and_crash_only_restart(self) -> None:
        rendered = render_launch_agent(self.spec)
        payload = plistlib.loads(rendered.encode("utf-8"))

        self.assertEqual(payload["Label"], self.spec.label)
        self.assertEqual(payload["Program"], str(self.executable))
        self.assertEqual(payload["ProgramArguments"][0], str(self.executable))
        self.assertEqual(payload["ProgramArguments"][1], "run")
        self.assertEqual(payload["KeepAlive"], {"Crashed": True})
        self.assertTrue(payload["RunAtLoad"])
        self.assertEqual(payload["Umask"], "077")
        self.assertEqual(payload["ProcessType"], "Background")
        self.assertEqual(payload["LimitLoadToSessionType"], "Aqua")
        self.assertEqual(payload["ThrottleInterval"], 30)
        arguments = payload["ProgramArguments"]
        self.assertIn("--start-at", arguments)
        self.assertIn("saved", arguments)
        self.assertIn("--send", arguments)
        self.assertNotIn("--room", arguments)
        self.assertNotIn("--base-url", arguments)
        self.assertNotIn("--allow-any-signed", arguments)
        self.assertNotIn("EnvironmentVariables", payload)
        self.assertNotIn(DID, rendered)
        self.assertNotIn(PEER_DID, rendered)
        self.assertNotIn(ROOM, rendered)
        self.assertNotIn("must-not-be-read", rendered)
        self.assertFalse(self.spec.stdout_path.exists())
        self.assertFalse(self.spec.stderr_path.exists())

    def test_renderer_refuses_failed_health_and_unsafe_runtime_paths(self) -> None:
        self.paths.state.unlink()
        with self.assertRaisesRegex(LaunchAgentError, "health preflight failed"):
            render_launch_agent(self.spec)

        AgentState(cursors={ROOM: 3}, nonces={ROOM: 10}).save(self.paths.state)
        target = self.executable.with_name("real-agent")
        self.executable.rename(target)
        self.executable.symlink_to(target)
        with self.assertRaisesRegex(LaunchAgentError, "executable"):
            render_launch_agent(self.spec)

    def test_renderer_refuses_unsafe_label_and_log_directory(self) -> None:
        invalid_label = LaunchAgentSpec(
            label="unsafe label",
            executable=self.executable,
            health_paths=self.paths,
            stdout_path=self.spec.stdout_path,
            stderr_path=self.spec.stderr_path,
        )
        with self.assertRaisesRegex(LaunchAgentError, "label"):
            render_launch_agent(invalid_label)

        self.spec.stdout_path.parent.chmod(0o755)
        with self.assertRaisesRegex(LaunchAgentError, "log directory"):
            render_launch_agent(self.spec)

    def test_renderer_refuses_logs_that_overwrite_runtime_artifacts(self) -> None:
        colliding_spec = LaunchAgentSpec(
            label=self.spec.label,
            executable=self.executable,
            health_paths=self.paths,
            stdout_path=self.paths.capability_policy,
            stderr_path=self.spec.stderr_path,
        )

        with self.assertRaisesRegex(LaunchAgentError, "runtime artifact"):
            render_launch_agent(colliding_spec)

    def test_cli_renders_only_and_never_reads_keychain_or_network(self) -> None:
        stdout = io.StringIO()
        with (
            patch(
                "technocore_safe_agent.identity.MacOSKeychainSeedProvider.load_seed",
                side_effect=AssertionError("Keychain must not be read"),
            ),
            patch(
                "technocore_safe_agent.protocol.urlopen",
                side_effect=AssertionError("network must not be accessed"),
            ),
            redirect_stdout(stdout),
        ):
            result = main(
                [
                    "launchd",
                    "render",
                    "--label",
                    self.spec.label,
                    "--executable",
                    str(self.executable),
                    "--identity",
                    str(self.paths.identity),
                    "--capability-policy",
                    str(self.paths.capability_policy),
                    "--stdout-path",
                    str(self.spec.stdout_path),
                    "--stderr-path",
                    str(self.spec.stderr_path),
                ]
            )

        payload = plistlib.loads(stdout.getvalue().encode("utf-8"))
        self.assertEqual(result, 0)
        self.assertEqual(payload["Label"], self.spec.label)
        self.assertFalse(any(self.paths.identity.parent.glob("*.plist")))


if __name__ == "__main__":
    unittest.main()
