from __future__ import annotations

import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from technocore_safe_agent.protocol import TechnocoreClient, TransportError


class HTTPErrorCleanupTests(unittest.TestCase):
    def test_closes_error_response_and_preserves_transport_details(self) -> None:
        for status in (400, 403, 409, 429, 500, 503):
            with self.subTest(status=status):
                body = io.BytesIO(b"request refused")
                error = HTTPError(
                    "http://127.0.0.1/fixture",
                    status,
                    "refused",
                    {"Retry-After": "2"},
                    body,
                )
                try:
                    with patch(
                        "technocore_safe_agent.protocol.urlopen", side_effect=error
                    ):
                        with self.assertRaises(TransportError) as caught:
                            TechnocoreClient("http://127.0.0.1").read_room(
                                "fixture",
                                since=0,
                                wait=0,
                            )
                    self.assertTrue(body.closed)
                    self.assertEqual(caught.exception.status, status)
                    self.assertEqual(caught.exception.retry_after, 2)
                    self.assertIn("request refused", str(caught.exception))
                    self.assertIs(caught.exception.__cause__, error)
                finally:
                    error.close()

    def test_closes_error_response_when_reading_its_body_fails(self) -> None:
        class BrokenBody(io.BytesIO):
            def read(self, size: int = -1) -> bytes:
                raise OSError("error body interrupted")

        body = BrokenBody()
        error = HTTPError("http://127.0.0.1/fixture", 503, "unavailable", {}, body)
        try:
            with patch("technocore_safe_agent.protocol.urlopen", side_effect=error):
                with self.assertRaisesRegex(OSError, "error body interrupted"):
                    TechnocoreClient("http://127.0.0.1").read_room(
                        "fixture",
                        since=0,
                        wait=0,
                    )
            self.assertTrue(body.closed)
        finally:
            error.close()
