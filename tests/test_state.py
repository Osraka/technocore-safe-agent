from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from technocore_safe_agent.state import AgentState, StateError


class StateTests(unittest.TestCase):
    def test_round_trips_cursor_and_monotonic_nonce_with_private_permissions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.state.json"
            state = AgentState()
            state.advance_cursor("room", 9)
            self.assertEqual(state.next_nonce("room", 100), 100)
            self.assertEqual(state.next_nonce("room", 50), 101)
            state.save(path)

            loaded = AgentState.load(path)
            self.assertEqual(loaded.cursor_for("room"), 9)
            self.assertEqual(loaded.nonces["room"], 101)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_observes_recovered_nonce_without_regressing(self) -> None:
        state = AgentState(nonces={"room": 100})
        state.observe_nonce("room", 90)
        self.assertEqual(state.nonces["room"], 100)
        state.observe_nonce("room", 101)
        self.assertEqual(state.nonces["room"], 101)

    def test_refuses_cursor_regression_and_corrupt_state(self) -> None:
        state = AgentState(cursors={"room": 8})
        with self.assertRaisesRegex(StateError, "backwards"):
            state.advance_cursor("room", 7)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
            with self.assertRaisesRegex(StateError, "unsupported schema"):
                AgentState.load(path)


if __name__ == "__main__":
    unittest.main()
