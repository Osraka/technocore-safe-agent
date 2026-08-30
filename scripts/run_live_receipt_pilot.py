#!/usr/bin/env python3
"""Run one explicit Technocore PR-receipt pilot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from technocore_safe_agent.agent import UncertainWriteError
from technocore_safe_agent.config import ConfigError
from technocore_safe_agent.crypto import IdentityError, ProtocolValueError
from technocore_safe_agent.identity import DEFAULT_IDENTITY_PATH
from technocore_safe_agent.pilot import (
    PilotError,
    run_live_receipt_pilot_from_identity,
)
from technocore_safe_agent.protocol import ResponseError, TransportError
from technocore_safe_agent.receipt import GitHubReceiptError
from technocore_safe_agent.state import StateError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write one signed /pr command and one signed receipt reply."
    )
    parser.add_argument("--identity", type=Path, default=DEFAULT_IDENTITY_PATH)
    parser.add_argument(
        "--pull-request",
        required=True,
        help="exact public https://github.com/OWNER/REPO/pull/NUMBER URL",
    )
    parser.add_argument(
        "--execute-live-receipt-pilot",
        action="store_true",
        help="acknowledge that exactly two signed records may be written",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.execute_live_receipt_pilot:
        print(
            "refusing to write: pass --execute-live-receipt-pilot after reviewing "
            "the one-command, one-receipt scope",
            file=sys.stderr,
        )
        return 2
    try:
        report = run_live_receipt_pilot_from_identity(args.identity, args.pull_request)
    except UncertainWriteError as error:
        print(f"write halted: {error}", file=sys.stderr)
        return 3
    except (
        ConfigError,
        GitHubReceiptError,
        IdentityError,
        PilotError,
        ProtocolValueError,
        ResponseError,
        StateError,
        TransportError,
    ) as error:
        print(f"pilot failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
