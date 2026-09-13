from __future__ import annotations

import io
import json
import unittest
from argparse import Namespace
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request

from technocore_safe_agent.agent import UncertainWriteError
from technocore_safe_agent.cli import _poll, main
from technocore_safe_agent.protocol import TechnocoreClient, TransportError
from technocore_safe_agent.state import AgentState


class StopPolling(Exception):
    pass


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []
        self.interrupt = False
        self.oversleep = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.interrupt:
            raise KeyboardInterrupt
        self.now += seconds + self.oversleep


class PollRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.attempts: list[float] = []
        self.actions: list[tuple[int, str | None]] = []
        self.responder = Mock()
        self.responder.process_snapshot.return_value = ()
        self.state = AgentState()
        self.state.advance_cursor("fixture", 7)
        self.args = Namespace(once=False, wait=10, limit=50)
        self.client = TechnocoreClient("http://127.0.0.1")
        self.enterContext(patch("technocore_safe_agent.cli.time", self.clock))
        self.events = self.enterContext(patch("technocore_safe_agent.cli._print_event"))
        self.enterContext(
            patch("technocore_safe_agent.protocol.urlopen", side_effect=self._response)
        )

    def _response(self, request: Request, **kwargs: object) -> io.BytesIO:
        self.attempts.append(self.clock.monotonic())
        if not self.actions:
            raise StopPolling
        status, header = self.actions.pop(0)
        if status != 200:
            raise HTTPError(
                request.full_url,
                status,
                "synthetic refusal",
                {} if header is None else {"Retry-After": header},
                io.BytesIO(b"synthetic refusal"),
            )
        return io.BytesIO(
            json.dumps(
                {
                    "room": "fixture",
                    "last_seq": 7,
                    "first_seq": None,
                    "messages": [],
                }
            ).encode()
        )

    def _run_poll(self) -> int:
        return _poll(self.args, self.responder, self.state, self.client, "fixture")

    def _observe(self) -> None:
        with self.assertRaises(StopPolling):
            self._run_poll()

    def test_numeric_retry_after_does_not_poll_early(self) -> None:
        for status in (429, 503):
            for header, expected in (
                ("0", 0.5),
                ("0.1", 0.5),
                ("1", 1),
                ("30", 30),
                ("31", 31),
                ("60", 60),
                ("90", 90),
            ):
                with self.subTest(status=status, header=header):
                    self.attempts.clear()
                    self.clock.sleeps.clear()
                    self.actions = [(status, header)]
                    self._observe()
                    self.assertEqual(self.attempts[1] - self.attempts[0], expected)
                    event = self.events.call_args.args[0]
                    self.assertEqual(event["delay_seconds"], expected)
                    self.assertEqual(event["http_status"], status)
                    self.assertTrue(all(0 < delay <= 30 for delay in self.clock.sleeps))
                    self.assertEqual(self.state.cursor_for("fixture"), 7)
        self.responder.process_snapshot.assert_not_called()

    def test_absent_or_invalid_header_preserves_initial_backoff(self) -> None:
        for header in (None, "", "invalid", "-1", "NaN", "inf"):
            with self.subTest(header=header):
                self.attempts.clear()
                self.actions = [(429, header)]
                self._observe()
                self.assertEqual(self.attempts[1] - self.attempts[0], 1)

    def test_fallback_stays_capped_and_resets_after_success(self) -> None:
        self.actions = [(503, None)] * 7 + [(200, None), (503, None)]
        self._observe()
        gaps = [right - left for left, right in zip(self.attempts, self.attempts[1:])]
        self.assertEqual(gaps, [1, 2, 4, 8, 16, 30, 30, 0, 1])
        self.responder.process_snapshot.assert_called_once()

    def test_long_retry_is_interruptible_before_another_read(self) -> None:
        self.actions = [(429, "60")]
        self.clock.interrupt = True
        with self.assertRaises(KeyboardInterrupt):
            self._run_poll()
        self.assertEqual(self.clock.sleeps, [30])
        self.assertEqual(len(self.attempts), 1)
        self.assertEqual(self.state.cursor_for("fixture"), 7)

    def test_extremely_large_retry_uses_bounded_sleep(self) -> None:
        self.actions = [(429, "1e300")]
        self.clock.interrupt = True
        with self.assertRaises(KeyboardInterrupt):
            self._run_poll()
        self.assertEqual(self.clock.sleeps, [30])
        self.assertEqual(self.events.call_args.args[0]["delay_seconds"], 1e300)
        self.assertEqual(len(self.attempts), 1)

    def test_remaining_wait_accounts_for_elapsed_monotonic_time(self) -> None:
        self.actions = [(429, "60")]
        self.clock.oversleep = 5
        self._observe()
        self.assertEqual(self.clock.sleeps, [30, 25])
        self.assertEqual(self.attempts[1] - self.attempts[0], 65)

    def test_once_propagates_error_without_sleep(self) -> None:
        self.args.once = True
        self.actions = [(429, "60")]
        with self.assertRaises(TransportError) as caught:
            self._run_poll()
        self.assertEqual(caught.exception.retry_after, 60)
        self.assertEqual(self.clock.sleeps, [])
        self.events.assert_not_called()
        self.assertEqual(len(self.attempts), 1)

    def test_unreadable_http_error_body_preserves_poll_cooldown_and_cursor(
        self,
    ) -> None:
        body = io.BytesIO()
        error = HTTPError(
            "http://127.0.0.1/fixture", 503, "unavailable", {"Retry-After": "60"}, body
        )
        try:
            with (
                patch.object(body, "read", side_effect=OSError("interrupted")),
                patch(
                    "technocore_safe_agent.protocol.urlopen",
                    side_effect=[error, StopPolling()],
                ) as open_request,
            ):
                self._observe()
            self.assertEqual(open_request.call_count, 2)
            self.assertEqual(self.clock.sleeps, [30, 30])
            self.assertEqual(self.state.cursor_for("fixture"), 7)
            self.assertEqual(self.events.call_args.args[0]["http_status"], 503)
            self.assertTrue(body.closed)
            self.responder.process_snapshot.assert_not_called()
        finally:
            error.close()

    def test_ambiguous_write_is_not_retried(self) -> None:
        self.actions = [(200, None)]
        self.responder.process_snapshot.side_effect = UncertainWriteError("fixture")
        with self.assertRaises(UncertainWriteError):
            self._run_poll()
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual(len(self.attempts), 1)
        self.events.assert_not_called()
        self.assertEqual(self.state.cursor_for("fixture"), 7)

    def test_cli_retains_interrupt_exit_code(self) -> None:
        self.actions = [(429, "60")]
        self.clock.interrupt = True
        with (
            patch(
                "technocore_safe_agent.cli._run", side_effect=lambda _: self._run_poll()
            ),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            self.assertEqual(main(["run"]), 130)
        self.assertEqual(stderr.getvalue().strip(), "stopped")
        self.assertEqual(len(self.attempts), 1)


if __name__ == "__main__":
    unittest.main()
