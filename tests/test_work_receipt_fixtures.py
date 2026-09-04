from __future__ import annotations

import json
import unittest
from pathlib import Path

from technocore_safe_agent.crypto import did_from_private_key, private_key_from_seed
from technocore_safe_agent.work_receipt import WorkReceiptError, verify_work_receipt


FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "work-receipt-v1"
RELEASE_COMMIT = "104062644fd4ac33037246f49c4c0dafa63391b2"
WORKER_DID = did_from_private_key(private_key_from_seed("11" * 32))
VERIFIER_DID = did_from_private_key(private_key_from_seed("22" * 32))


class WorkReceiptFixtureTests(unittest.TestCase):
    def test_valid_fixture_verifies_with_expected_public_claims(self) -> None:
        fixture = (FIXTURE_DIRECTORY / "valid.json").read_text(encoding="utf-8")
        envelope = json.loads(fixture)

        summary = verify_work_receipt(fixture)

        self.assertEqual(summary.payload["issuer"], WORKER_DID)
        self.assertEqual(summary.payload["repository"], "Osraka/technocore-safe-agent")
        self.assertEqual(summary.payload["commit"], RELEASE_COMMIT)
        self.assertEqual(
            summary.payload["command"],
            ["python3", "-c", "print('fixture-ok')"],
        )
        self.assertEqual(summary.payload["result"], "passed")
        self.assertEqual(summary.payload["exit_code"], 0)
        self.assertEqual(summary.countersignatures, 1)
        self.assertEqual(summary.matching_countersignatures, 1)
        self.assertEqual(
            envelope["countersignatures"][0]["payload"]["verifier"],
            VERIFIER_DID,
        )
        self.assertNotIn("/Users/", fixture)
        self.assertNotIn("Library/Application Support", fixture)

    def test_tampered_output_fixture_is_rejected(self) -> None:
        fixture = (FIXTURE_DIRECTORY / "tampered-output.json").read_text(
            encoding="utf-8"
        )

        with self.assertRaisesRegex(WorkReceiptError, "payload hash"):
            verify_work_receipt(fixture)


if __name__ == "__main__":
    unittest.main()
