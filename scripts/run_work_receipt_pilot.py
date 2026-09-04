#!/usr/bin/env python3
"""Run one explicit two-identity work-receipt pilot in a clean local clone."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.crypto import did_from_private_key
from technocore_safe_agent.work_receipt import (
    countersign_work_receipt,
    create_work_receipt,
    render_work_receipt,
    verify_work_receipt,
)


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def _write_private_new(path: Path, content: str) -> None:
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.write("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a bounded two-identity work-receipt pilot."
    )
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--execute-work-receipt-pilot",
        action="store_true",
        help="required acknowledgement that the local test will run twice",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.execute_work_receipt_pilot:
        print(
            "refusing to run without --execute-work-receipt-pilot",
            file=sys.stderr,
        )
        return 2

    source = args.repository.expanduser().resolve()
    if _git(source, "status", "--porcelain", "--untracked-files=all"):
        print("source checkout must be clean", file=sys.stderr)
        return 2
    origin = _git(source, "remote", "get-url", "origin")

    with tempfile.TemporaryDirectory(prefix="work-receipt-pilot-") as directory:
        checkout = Path(directory) / "checkout"
        subprocess.run(
            ["git", "clone", "--quiet", "--no-hardlinks", str(source), str(checkout)],
            check=True,
            timeout=60,
        )
        _git(checkout, "remote", "set-url", "origin", origin)

        worker_key = Ed25519PrivateKey.generate()
        verifier_key = Ed25519PrivateKey.generate()
        worker_did = did_from_private_key(worker_key)
        verifier_did = did_from_private_key(verifier_key)
        command = [
            "python3",
            "-c",
            (
                "import io,sys,unittest;"
                "sys.path.insert(0,'src');"
                "suite=unittest.defaultTestLoader.loadTestsFromName("
                "'tests.test_crypto_identity.CryptoIdentityTests."
                "test_detached_signatures_verify_against_the_did_public_key');"
                "result=unittest.TextTestRunner(stream=io.StringIO(),verbosity=0).run(suite);"
                "raise SystemExit(0 if result.wasSuccessful() else 1)"
            ),
        ]
        receipt = create_work_receipt(
            checkout,
            command,
            issuer_did=worker_did,
            private_key=worker_key,
            timeout=30,
        )
        countersigned = countersign_work_receipt(
            receipt,
            checkout,
            verifier_did=verifier_did,
            private_key=verifier_key,
            timeout=30,
        )
        summary = verify_work_receipt(countersigned)
        rendered = render_work_receipt(countersigned)
        if args.output is not None:
            _write_private_new(args.output, rendered)

    print(
        json.dumps(
            {
                "status": "passed",
                "schema": summary.payload["schema"],
                "result": summary.payload["result"],
                "independent_signers": 2,
                "countersignatures": summary.countersignatures,
                "artifact_written": args.output is not None,
                "artifact_published": False,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
