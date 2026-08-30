"""Render a conservative macOS LaunchAgent without installing it."""

from __future__ import annotations

import os
import plistlib
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from technocore_safe_agent.health import HealthPaths, inspect_operational_health

LABEL_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,126}[A-Za-z0-9])?\Z")


class LaunchAgentError(RuntimeError):
    """A LaunchAgent cannot be rendered without weakening local safety."""


@dataclass(frozen=True)
class LaunchAgentSpec:
    label: str
    executable: Path
    health_paths: HealthPaths
    stdout_path: Path
    stderr_path: Path
    expected_audit_head: str | None = None


def render_launch_agent(spec: LaunchAgentSpec) -> str:
    """Return one validated XML plist without writing or loading it."""

    _validate_spec(spec)
    health = inspect_operational_health(
        spec.health_paths,
        expected_audit_head=spec.expected_audit_head,
    )
    if health.exit_code != 0:
        raise LaunchAgentError(f"health preflight failed with status {health.status}")

    paths = spec.health_paths
    arguments = [
        str(spec.executable),
        "run",
        "--identity",
        str(paths.identity),
        "--config",
        str(paths.config),
        "--state",
        str(paths.state),
        "--journal",
        str(paths.journal),
        "--lock",
        str(paths.lock),
        "--audit-log",
        str(paths.audit),
        "--capability-policy",
        str(paths.capability_policy),
        "--start-at",
        "saved",
        "--send",
    ]
    payload = {
        "Label": spec.label,
        "Program": str(spec.executable),
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        "KeepAlive": {"Crashed": True},
        "ThrottleInterval": 30,
        "ExitTimeOut": 20,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "LimitLoadToSessionType": "Aqua",
        "Umask": "077",
        "StandardOutPath": str(spec.stdout_path),
        "StandardErrorPath": str(spec.stderr_path),
    }
    return plistlib.dumps(
        payload,
        fmt=plistlib.FMT_XML,
        sort_keys=False,
    ).decode("utf-8")


def _validate_spec(spec: LaunchAgentSpec) -> None:
    if (
        not isinstance(spec.label, str)
        or LABEL_PATTERN.fullmatch(spec.label) is None
        or "." not in spec.label
        or ".." in spec.label
    ):
        raise LaunchAgentError("LaunchAgent label must be a reverse-DNS token")
    _require_absolute_paths(spec)
    _validate_executable(spec.executable)
    _validate_log_destinations(spec)
    _validate_log_path(spec.stdout_path)
    _validate_log_path(spec.stderr_path)


def _require_absolute_paths(spec: LaunchAgentSpec) -> None:
    paths = (
        spec.executable,
        spec.health_paths.identity,
        spec.health_paths.config,
        spec.health_paths.state,
        spec.health_paths.capability_policy,
        spec.health_paths.journal,
        spec.health_paths.audit,
        spec.health_paths.lock,
        spec.stdout_path,
        spec.stderr_path,
    )
    if any(not path.is_absolute() for path in paths):
        raise LaunchAgentError("all LaunchAgent paths must be absolute")


def _validate_log_destinations(spec: LaunchAgentSpec) -> None:
    paths = spec.health_paths
    artifacts = (
        spec.executable,
        paths.identity,
        paths.config,
        paths.state,
        paths.capability_policy,
        paths.journal,
        paths.audit,
        paths.lock,
    )
    try:
        stdout = spec.stdout_path.resolve(strict=False)
        stderr = spec.stderr_path.resolve(strict=False)
        protected = {path.resolve(strict=False) for path in artifacts}
    except (OSError, RuntimeError) as error:
        raise LaunchAgentError("LaunchAgent paths cannot be resolved safely") from error
    if stdout == stderr:
        raise LaunchAgentError("stdout and stderr log paths must be different")
    if stdout in protected or stderr in protected:
        raise LaunchAgentError("LaunchAgent logs must not overwrite a runtime artifact")


def _validate_executable(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LaunchAgentError("LaunchAgent executable cannot be inspected") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise LaunchAgentError("LaunchAgent executable must be a regular file")
    if not metadata.st_mode & stat.S_IXUSR:
        raise LaunchAgentError("LaunchAgent executable is not owner-executable")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise LaunchAgentError(
            "LaunchAgent executable must not be group/other writable"
        )
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise LaunchAgentError("LaunchAgent executable must be owned by this user")


def _validate_log_path(path: Path) -> None:
    _validate_log_directory(path.parent)
    _validate_existing_log(path)


def _validate_log_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LaunchAgentError(
            "LaunchAgent log directory cannot be inspected"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise LaunchAgentError("LaunchAgent log directory must be a real directory")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise LaunchAgentError("LaunchAgent log directory must be owner-only")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise LaunchAgentError("LaunchAgent log directory must be owned by this user")


def _validate_existing_log(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise LaunchAgentError("LaunchAgent log path cannot be inspected") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise LaunchAgentError("LaunchAgent log path must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise LaunchAgentError("LaunchAgent log permissions must be owner-only")
    if not metadata.st_mode & stat.S_IWUSR:
        raise LaunchAgentError("LaunchAgent log must be owner-writable")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise LaunchAgentError("LaunchAgent log must be owned by this user")
