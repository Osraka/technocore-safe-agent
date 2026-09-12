"""Actual Safe Agent behavior against the pinned Technocore server.

Adapted from the local compatibility audit. Never accepts a remote service URL.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import time
import unittest
from urllib.request import ProxyHandler, build_opener

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from technocore_safe_agent.agent import SafeResponder, UncertainWriteError
from technocore_safe_agent.audit import SignedAuditLog
from technocore_safe_agent.crypto import did_from_private_key, sign_room_message
from technocore_safe_agent.delivery import DeliveryJournal
from technocore_safe_agent.delivery_recovery import recover_delivery
from technocore_safe_agent.policy import CommandPolicy
from technocore_safe_agent.protocol import TechnocoreClient, TransportError
from technocore_safe_agent.state import AgentState

from fixture import server as local_server

CHECKOUT: Path | None = None
PYTHON: Path | None = None


def server(**settings):
    if CHECKOUT is None or PYTHON is None:
        raise RuntimeError("use tests/interop/run.py to configure the pinned server")
    return local_server(CHECKOUT, PYTHON, **settings)


def post(client, key, room, nonce, text):
    swept, signature = sign_room_message(key, room, nonce, text)
    return client.send_signed_message(
        room=room,
        did=did_from_private_key(key),
        signature=signature,
        nonce=nonce,
        text=swept,
    )


def responder(client, root, peer, *, room="pilot", send=False):
    key = Ed25519PrivateKey.generate()
    did = did_from_private_key(key)
    return SafeResponder(
        room=room,
        did=did,
        private_key=key,
        client=client,
        policy=CommandPolicy(own_did=did, allowed_dids=frozenset({peer})),
        state=AgentState(),
        state_path=root / "state.json",
        send=send,
        delivery_journal=DeliveryJournal(root / "journal.json"),
        audit_log=SignedAuditLog(root / "audit.jsonl"),
    )


class LocalCompatibility(unittest.TestCase):
    def test_signed_ack_unicode_roundtrip_and_replay(self):
        with server() as (client, _):
            key = Ed25519PrivateKey.generate()
            ack = post(client, key, "pilot", 1, "line\nUnicode: \u00e9 / ? %")
            snapshot = client.read_room("pilot", since=0, wait=0)
            self.assertEqual(snapshot.messages, (ack,))
            with self.assertRaises(TransportError) as error:
                post(client, key, "pilot", 1, "line\nUnicode: \u00e9 / ? %")
            self.assertIn(error.exception.status, (400, 403, 409))
            self.assertEqual(client.read_room("pilot", since=0, wait=0).last_seq, 1)

    def test_forged_signature_leaves_no_message(self):
        with server() as (client, _):
            key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
            text, signature = sign_room_message(other, "pilot", 1, "probe")
            with self.assertRaises(TransportError) as error:
                client.send_signed_message(
                    room="pilot",
                    did=did_from_private_key(key),
                    signature=signature,
                    nonce=1,
                    text=text,
                )
            self.assertEqual(error.exception.status, 403)
            self.assertEqual(client.read_room("pilot", since=0, wait=0).last_seq, 0)

    def test_reply_ack_clears_journal_and_verifies_audit(self):
        with server() as (client, root):
            peer = Ed25519PrivateKey.generate()
            agent = responder(client, root, did_from_private_key(peer), send=True)
            post(client, peer, "pilot", 1, "/ping")
            events = agent.process_snapshot(client.read_room("pilot", since=0, wait=0))
            self.assertEqual([event["event"] for event in events], ["sent"])
            self.assertEqual(agent.state.cursor_for("pilot"), 1)
            self.assertIsNone(agent.delivery_journal.load())
            self.assertEqual(agent.audit_log.verify().entries, 1)
            self.assertEqual(client.read_room("pilot", since=0, wait=0).last_seq, 2)
            # Reading our own reply must not create a response loop.
            agent.process_snapshot(client.read_room("pilot", since=1, wait=0))
            self.assertEqual(client.read_room("pilot", since=0, wait=0).last_seq, 2)
            self.assertEqual(agent.audit_log.verify().entries, 2)

    def test_post_commit_ack_loss_halts_and_readonly_recovery_finds_delivery(self):
        class LoseAck(TechnocoreClient):
            def send_signed_message(self, **kwargs):
                super().send_signed_message(**kwargs)
                raise TransportError("injected loss AFTER real server acknowledgement")

        with server() as (client, root):
            peer = Ed25519PrivateKey.generate()
            agent = responder(
                LoseAck(client.base_url), root, did_from_private_key(peer), send=True
            )
            post(client, peer, "pilot", 1, "/ping")
            with self.assertRaises(UncertainWriteError):
                agent.process_snapshot(client.read_room("pilot", since=0, wait=0))
            self.assertEqual(agent.state.cursor_for("pilot"), 0)
            before = (root / "journal.json").read_bytes()
            result = recover_delivery(
                room="pilot",
                did=agent.did,
                client=client,
                state=agent.state,
                state_path=agent.state_path,
                journal=agent.delivery_journal,
                apply=False,
                confirm_retry=False,
            )
            self.assertEqual(result["event"], "delivery_found")
            self.assertEqual((root / "journal.json").read_bytes(), before)
            self.assertEqual(client.read_room("pilot", since=0, wait=0).last_seq, 2)

    def test_bootstrap_tail_limit_gap_and_empty_longpoll(self):
        with server() as (client, root):
            peer = Ed25519PrivateKey.generate()
            for nonce in range(1, 5):
                post(client, peer, "pilot", nonce, f"message {nonce}")
            agent = responder(client, root, did_from_private_key(peer))
            self.assertEqual(agent.bootstrap_latest()["cursor"], 4)
            first = client.read_room("pilot", since=0, wait=0, limit=2)
            # store.read_messages returns the newest N, not the next N page.
            self.assertEqual([m.seq for m in first.messages], [3, 4])
            fresh = responder(client, root, did_from_private_key(peer))
            events = fresh.process_snapshot(first)
            self.assertEqual(events[0]["event"], "retention_gap")
            self.assertEqual(fresh.state.cursor_for("pilot"), 4)
            self.assertEqual(
                client.read_room("pilot", since=1, wait=0).messages[0].seq, 2
            )
            empty = client.read_room("pilot", since=4, wait=0.2)
            self.assertEqual(empty.messages, ())
            self.assertEqual(empty.last_seq, 4)

    def test_expired_empty_history_preserves_cursor_and_new_message_sequence(self):
        with server(CHAT_EPHEMERAL_TTL_SECONDS="1") as (client, root):
            peer = Ed25519PrivateKey.generate()
            post(client, peer, "e-pilot", 1, "expires")
            agent = responder(client, root, did_from_private_key(peer), room="e-pilot")
            agent.state.advance_cursor("e-pilot", 1)
            deadline = time.monotonic() + 5
            while True:
                snapshot = client.read_room("e-pilot", since=0, wait=0)
                if not snapshot.messages:
                    break
                if time.monotonic() >= deadline:
                    self.fail("ephemeral record did not expire within 5 seconds")
                time.sleep(0.1)
            # Empty read's last_seq echoes since (or zero), not the disk high-water mark.
            self.assertEqual(snapshot.last_seq, 0)
            events = agent.process_snapshot(snapshot)
            self.assertEqual(events, [])
            self.assertEqual(agent.state.cursor_for("e-pilot"), 1)
            self.assertEqual(client.read_room("e-pilot", since=1, wait=0).last_seq, 1)
            self.assertEqual(post(client, peer, "e-pilot", 2, "/status").seq, 2)
            # A fresh consumer sees a missing prefix, not an invented contiguous history.
            fresh = responder(client, root, did_from_private_key(peer), room="e-pilot")
            events = fresh.process_snapshot(
                client.read_room("e-pilot", since=0, wait=0)
            )
            self.assertIn("retention_gap", [e["event"] for e in events])

    def test_read_budget_footer_and_429_preserve_json_contract(self):
        with server(CHAT_RATE_READ="8") as (client, _):
            opener = build_opener(ProxyHandler({}))
            cache_policies = []
            for index in range(8):
                # Alternate real client and raw inspection of the identical JSON endpoint.
                if index % 2 == 0:
                    self.assertEqual(
                        client.read_room("pilot", since=0, wait=0).last_seq, 0
                    )
                else:
                    with opener.open(
                        client.base_url + "/r/pilot?format=json&wait=0", timeout=3
                    ) as response:
                        payload = json.load(response)
                        # respond() omits prose footers from JSON even in the warning band.
                        self.assertNotIn("note", payload)
                        cache_policies.append(response.headers.get("Cache-Control"))
            self.assertTrue(any("public" in policy for policy in cache_policies))
            self.assertIn("no-store", cache_policies)
            with self.assertRaises(TransportError) as error:
                client.read_room("pilot", since=0, wait=0)
            self.assertEqual(error.exception.status, 429)
            self.assertGreater(error.exception.retry_after, 0)

    def test_plaintext_budget_warning_is_separate_from_json(self):
        with server(CHAT_RATE_READ="4") as (client, _):
            opener = build_opener(ProxyHandler({}))
            bodies = []
            for _ in range(4):
                with opener.open(client.base_url + "/r/pilot", timeout=3) as response:
                    bodies.append(response.read().decode())
            self.assertNotIn("# budget:", bodies[0])
            self.assertIn("# budget:", bodies[-1])


class DelegationInspection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CHECKOUT is None:
            raise RuntimeError(
                "use tests/interop/run.py to configure the pinned server"
            )
        spec = importlib.util.spec_from_file_location(
            "upstream_sign", CHECKOUT / "scripts/sign.py"
        )
        cls.sign = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.sign)

    def setUp(self):
        self.root_key, self.agent_key = (
            Ed25519PrivateKey.generate(),
            Ed25519PrivateKey.generate(),
        )
        self.root_did = self.sign.did_of(self.root_key)
        self.agent_did = self.sign.did_of(self.agent_key)

    def record(self, scope="r:pilot", *, nonce="1", expires=None):
        expires = str(int(time.time()) + 3600) if expires is None else expires
        value = self.sign.delegation(
            self.root_did, self.agent_did, scope, expires, nonce
        )
        sig = self.sign.signature(self.root_key, value)
        return f"delegate: {self.agent_did} {scope} {expires} {nonce} {sig}"

    def check(self, body, root=None):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            count = self.sign.check_note(root or self.root_did, body)
        return count, [
            line.split()[0] for line in output.getvalue().splitlines() if line
        ]

    def test_signature_and_expiry_use_upstream_checker(self):
        body = self.record()
        self.assertEqual(self.check(body), (1, ["OK"]))
        other = self.sign.did_of(Ed25519PrivateKey.generate())
        self.assertEqual(self.check(body, other), (0, ["FORGED"]))
        self.assertEqual(self.check(self.record(expires="1")), (0, ["EXPIRED"]))

    def test_narrowing_and_large_nonce_use_upstream_resolution(self):
        old = self.record("*", nonce="9999999999999999998")
        new = self.record("r:pilot", nonce="9999999999999999999")
        self.assertEqual(self.check(old + " " + new), (1, ["SUPERSEDED", "OK"]))

    def test_valid_delegation_does_not_grant_local_permission(self):
        self.assertEqual(self.check(self.record())[0], 1)
        from technocore_safe_agent.protocol import RoomMessage

        policy = CommandPolicy(own_did=self.root_did)
        decision = policy.decide(RoomMessage(1, self.agent_did, "/ping", "1"))
        self.assertEqual(decision.reason, "sender_not_allowlisted")

    def test_cached_delegation_survives_note_deletion_until_expiry(self):
        cached = self.record()
        self.assertEqual(self.check("")[0], 0)
        self.assertEqual(self.check(cached)[0], 1)
