from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from technocore_safe_agent.process_lock import AgentProcessLock, ProcessLockError


class ProcessLockTests(unittest.TestCase):
    def test_rejects_second_live_process_and_allows_reacquire_after_release(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.lock"
            with AgentProcessLock(path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaisesRegex(ProcessLockError, "already running"):
                    with AgentProcessLock(path):
                        self.fail("second process lock unexpectedly succeeded")

            with AgentProcessLock(path):
                self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
