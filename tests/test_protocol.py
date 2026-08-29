from __future__ import annotations

import json
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from technocore_safe_agent.protocol import TechnocoreClient, verified_tls_context
from technocore_safe_agent.crypto import ProtocolValueError


DID = "did:key:z6MkmjY8Bmy9CnWW1JPfQWA9tK7KT7C9CAeWQKZmYtXyS2uH"


class FixtureHandler(BaseHTTPRequestHandler):
    seen_get_query: dict[str, list[str]] | None = None
    seen_post: dict[str, str] | None = None

    def log_message(self, format: str, *args: object) -> None:
        return

    def _reply(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if "/say-signed/" in parsed.path:
            parts = parsed.path.split("/")
            body = {
                "did": unquote(parts[4]),
                "sig": unquote(parts[5]),
                "nonce": unquote(parts[6]),
                "text": unquote(parts[7]),
            }
            type(self).seen_post = body
            posted = {
                "seq": 2,
                "from": body["did"],
                "nonce": body["nonce"],
                "text": body["text"],
            }
            self._reply(
                {
                    "room": "test-room",
                    "count": 2,
                    "first_seq": 1,
                    "last_seq": 2,
                    "messages": [
                        {"seq": 1, "from": DID, "nonce": 4, "text": "/ping"},
                        posted,
                    ],
                    "posted": posted,
                }
            )
            return
        type(self).seen_get_query = parse_qs(parsed.query)
        self._reply(
            {
                "room": "test-room",
                "count": 1,
                "first_seq": 1,
                "last_seq": 1,
                "messages": [{"seq": 1, "from": DID, "nonce": 4, "text": "/ping"}],
            }
        )


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.client = TechnocoreClient(base_url=f"http://{host}:{port}", timeout=2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_reads_with_cursor_wait_limit_and_cache_buster(self) -> None:
        snapshot = self.client.read_room(
            "test-room", since=0, wait=0, limit=7, cache_buster=3
        )
        self.assertEqual(snapshot.messages[0].text, "/ping")
        self.assertEqual(
            FixtureHandler.seen_get_query,
            {
                "format": ["json"],
                "since": ["0"],
                "wait": ["0.0"],
                "limit": ["7"],
                "n": ["3"],
            },
        )

    def test_tls_context_keeps_certificate_and_hostname_verification_enabled(
        self,
    ) -> None:
        context = verified_tls_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_empty_room_accepts_null_first_sequence_from_real_server_shape(
        self,
    ) -> None:
        from technocore_safe_agent.protocol import _parse_snapshot

        snapshot = _parse_snapshot(
            {
                "room": "empty-room",
                "count": 0,
                "first_seq": None,
                "last_seq": 0,
                "messages": [],
            },
            "empty-room",
        )
        self.assertEqual((snapshot.first_seq, snapshot.last_seq), (0, 0))

    def test_empty_since_window_accepts_null_first_sequence_with_nonzero_tail(
        self,
    ) -> None:
        from technocore_safe_agent.protocol import _parse_snapshot

        snapshot = _parse_snapshot(
            {
                "room": "caught-up-room",
                "count": 0,
                "first_seq": None,
                "last_seq": 7,
                "messages": [],
            },
            "caught-up-room",
        )
        self.assertEqual(
            (snapshot.first_seq, snapshot.last_seq, snapshot.messages), (0, 7, ())
        )

    def test_sends_signed_get_and_validates_the_server_acknowledgement(self) -> None:
        posted = self.client.send_signed_message(
            room="test-room",
            did=DID,
            signature="A" * 86,
            nonce=5,
            text="pong",
        )
        self.assertEqual((posted.seq, posted.text, posted.nonce), (2, "pong", "5"))
        self.assertEqual(FixtureHandler.seen_post["did"], DID)

    def test_rejects_noncanonical_signature_before_network(self) -> None:
        with self.assertRaisesRegex(ProtocolValueError, "canonical"):
            self.client.send_signed_message(
                room="test-room",
                did=DID,
                signature="A" * 85 + "B",
                nonce=5,
                text="pong",
            )


if __name__ == "__main__":
    unittest.main()
