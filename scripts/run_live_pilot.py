#!/usr/bin/env python3
"""Run the explicit, bounded Technocore live-pilot scenarios."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from technocore_safe_agent.agent import UncertainWriteError
from technocore_safe_agent.config import ConfigError
from technocore_safe_agent.crypto import IdentityError, ProtocolValueError
from technocore_safe_agent.identity import DEFAULT_IDENTITY_PATH
from technocore_safe_agent.pilot import PilotError, run_live_pilot_from_identity
from technocore_safe_agent.protocol import ResponseError, TransportError
from technocore_safe_agent.state import StateError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run bounded live safety checks with ephemeral peer DIDs."
    )
    parser.add_argument("--identity", type=Path, default=DEFAULT_IDENTITY_PATH)
    parser.add_argument(
        "--execute-live-pilot",
        action="store_true",
        help="acknowledge that five test records will be written to the configured mailbox",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.execute_live_pilot:
        print(
            "refusing to write: pass --execute-live-pilot after reviewing the test scope",
            file=sys.stderr,
        )
        return 2
    try:
        report = run_live_pilot_from_identity(args.identity)
    except UncertainWriteError as error:
        print(f"write halted: {error}", file=sys.stderr)
        return 3
    except (
        ConfigError,
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
