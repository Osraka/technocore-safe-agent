"""Explicit real-server gate. Missing prerequisites and skipped tests are failures."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import fixture  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-checkout", required=True, type=Path)
    parser.add_argument("--server-python", required=True, type=Path)
    args = parser.parse_args()
    checkout = args.server_checkout.resolve()
    # Resolving a venv interpreter symlink would bypass that venv's dependencies.
    python = args.server_python.absolute()
    try:
        fixture.preflight(checkout, python)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"interop setup: {error}\n")

    import checks

    checks.CHECKOUT, checks.PYTHON = checkout, python
    suite = unittest.defaultTestLoader.loadTestsFromModule(checks)
    expected = suite.countTestCases()
    if expected < 12:
        parser.exit(
            2,
            "interop setup: expected at least 12 checks; refusing incomplete discovery\n",
        )
    # Both urllib clients must bypass inherited proxies for the loopback fixture.
    clean = {
        key: value
        for key, value in os.environ.items()
        if not key.lower().endswith("_proxy")
    }
    with patch.dict(os.environ, clean, clear=True):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    return int(
        not result.wasSuccessful()
        or bool(result.skipped)
        or result.testsRun != expected
    )


if __name__ == "__main__":
    raise SystemExit(main())
