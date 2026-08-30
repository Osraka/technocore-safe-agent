"""Offline operational health checks for one managed responder instance."""

from __future__ import annotations

import fcntl
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from technocore_safe_agent.audit import AuditError, SignedAuditLog
from technocore_safe_agent.capabilities import CapabilityError, CapabilityPolicyFile
from technocore_safe_agent.config import AgentConfig, ConfigError
from technocore_safe_agent.crypto import IdentityError, ProtocolValueError
from technocore_safe_agent.delivery import (
    DeliveryError,
    DeliveryJournal,
    DeliveryRecord,
)
from technocore_safe_agent.identity import IdentityRecord
from technocore_safe_agent.state import AgentState, StateError


@dataclass(frozen=True)
class HealthPaths:
    identity: Path
    config: Path
    state: Path
    capability_policy: Path
    journal: Path
    audit: Path
    lock: Path


@dataclass(frozen=True)
class HealthReport:
    status: str
    exit_code: int
    checks: dict[str, str]
    problems: tuple[str, ...]
    private_key_checked: bool = False
    network_checked: bool = False

    def to_event(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "checks": self.checks,
            "problems": list(self.problems),
            "private_key_checked": self.private_key_checked,
            "network_checked": self.network_checked,
        }


class HealthError(RuntimeError):
    """An operational artifact cannot be inspected safely."""


def inspect_operational_health(
    paths: HealthPaths,
    *,
    expected_audit_head: str | None = None,
    expect_running: bool = False,
) -> HealthReport:
    """Inspect local readiness without Keychain, network, or file mutation."""

    checks: dict[str, str] = {}
    problems: list[str] = []
    identity = _identity_check(paths.identity, checks, problems)
    config = _config_check(paths.config, identity, checks, problems)
    _state_check(paths.state, config, checks, problems)
    _capability_check(paths.capability_policy, checks, problems)
    delivery = _delivery_check(paths.journal, identity, config, checks, problems)
    _audit_check(
        paths.audit,
        identity,
        expected_audit_head=expected_audit_head,
        checks=checks,
        problems=problems,
    )
    process = _process_check(paths.lock, checks, problems)

    if expect_running and process == "stopped":
        problems.append("process_not_running")
    if delivery is not None and process == "stopped":
        problems.append("delivery_recovery_required")

    non_recovery_problems = [
        problem for problem in problems if problem != "delivery_recovery_required"
    ]
    if non_recovery_problems:
        status, exit_code = "unhealthy", 2
    elif "delivery_recovery_required" in problems:
        status, exit_code = "recovery_required", 3
    elif process == "running":
        status, exit_code = "running", 0
    else:
        status, exit_code = "ready", 0
    return HealthReport(
        status=status,
        exit_code=exit_code,
        checks=checks,
        problems=tuple(problems),
    )


def _identity_check(
    path: Path, checks: dict[str, str], problems: list[str]
) -> IdentityRecord | None:
    try:
        identity = IdentityRecord.load(path)
    except (IdentityError, ProtocolValueError, OSError):
        checks["identity"] = "invalid"
        problems.append("identity_invalid")
        return None
    checks["identity"] = "valid"
    return identity


def _config_check(
    path: Path,
    identity: IdentityRecord | None,
    checks: dict[str, str],
    problems: list[str],
) -> AgentConfig | None:
    try:
        present = _path_present(path)
    except HealthError:
        checks["config"] = "invalid"
        problems.append("config_invalid")
        return None
    if not present:
        checks["config"] = "missing"
        problems.append("config_missing")
        return None
    try:
        _require_private_regular_file(path, "config")
        config = AgentConfig.load(path)
    except (ConfigError, HealthError, ProtocolValueError):
        checks["config"] = "invalid"
        problems.append("config_invalid")
        return None
    if config.status != "active":
        checks["config"] = config.status
        problems.append("config_not_active")
        return None
    if identity is None or (
        config.did != identity.did or config.fingerprint != identity.fingerprint
    ):
        checks["config"] = "identity_mismatch"
        problems.append("config_identity_mismatch")
        return None
    checks["config"] = "active"
    return config


def _state_check(
    path: Path,
    config: AgentConfig | None,
    checks: dict[str, str],
    problems: list[str],
) -> None:
    try:
        present = _path_present(path)
    except HealthError:
        checks["state"] = "invalid"
        problems.append("state_invalid")
        return
    if not present:
        checks["state"] = "missing"
        problems.append("state_missing")
        return
    try:
        _require_private_regular_file(path, "state")
        state = AgentState.load(path)
    except (HealthError, StateError):
        checks["state"] = "invalid"
        problems.append("state_invalid")
        return
    if config is None:
        checks["state"] = "valid_unbound"
        return

    room_cursor = state.cursors.get(config.room)
    room_nonce = state.nonces.get(config.room)
    state_problems: list[str] = []
    if room_cursor is None:
        state_problems.append("state_cursor_missing")
    elif config.provisioned_seq is not None and room_cursor < config.provisioned_seq:
        state_problems.append("state_cursor_behind_config")
    if room_nonce is None:
        state_problems.append("state_nonce_missing")
    elif room_nonce < int(config.provision_nonce):
        state_problems.append("state_nonce_behind_config")
    if state_problems:
        checks["state"] = "invalid"
        problems.extend(state_problems)
    else:
        checks["state"] = "valid"


def _capability_check(path: Path, checks: dict[str, str], problems: list[str]) -> None:
    try:
        policy = CapabilityPolicyFile(path).load()
    except CapabilityError:
        checks["capability_policy"] = "invalid"
        problems.append("capability_policy_invalid")
        return
    if any(grant.enabled for grant in policy.principals.values()):
        checks["capability_policy"] = "valid"
    else:
        checks["capability_policy"] = "valid_no_enabled_grants"


def _delivery_check(
    path: Path,
    identity: IdentityRecord | None,
    config: AgentConfig | None,
    checks: dict[str, str],
    problems: list[str],
) -> DeliveryRecord | None:
    try:
        present = _path_present(path)
    except HealthError:
        checks["delivery"] = "invalid"
        problems.append("delivery_invalid")
        return None
    if not present:
        checks["delivery"] = "clear"
        return None
    try:
        _require_private_regular_file(path, "delivery journal")
        record = DeliveryJournal(path).load()
        if record is None:
            checks["delivery"] = "clear"
            return None
        if identity is None or config is None or record.did != identity.did:
            raise DeliveryError("delivery journal is not bound to this agent")
        record.verify_for_room(config.room)
    except (DeliveryError, HealthError):
        checks["delivery"] = "invalid"
        problems.append("delivery_invalid")
        return None
    checks["delivery"] = record.status
    return record


def _audit_check(
    path: Path,
    identity: IdentityRecord | None,
    *,
    expected_audit_head: str | None,
    checks: dict[str, str],
    problems: list[str],
) -> None:
    try:
        present = _path_present(path)
    except HealthError:
        checks["audit"] = "invalid"
        problems.append("audit_invalid")
        return
    if not present:
        if expected_audit_head is None:
            checks["audit"] = "not_created"
        else:
            checks["audit"] = "missing"
            problems.append("audit_missing")
        return
    try:
        _require_private_regular_file(path, "audit")
        summary = SignedAuditLog(path).verify(expected_head=expected_audit_head)
        if identity is None or summary.issuer not in {None, identity.did}:
            raise AuditError("audit issuer does not match this agent")
    except (AuditError, HealthError):
        checks["audit"] = "invalid"
        problems.append("audit_invalid")
        return
    checks["audit"] = "valid_checkpoint" if expected_audit_head is not None else "valid"


def _process_check(path: Path, checks: dict[str, str], problems: list[str]) -> str:
    try:
        status = _process_lock_status(path)
    except HealthError:
        checks["process"] = "invalid"
        problems.append("process_lock_invalid")
        return "invalid"
    checks["process"] = status
    return status


def _process_lock_status(path: Path) -> str:
    selected = path.expanduser().absolute()
    if not _path_present(selected):
        return "stopped"
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    acquired = False
    try:
        descriptor = os.open(selected, flags)
        _require_private_regular_metadata(os.fstat(descriptor), "process lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            return "stopped"
        except BlockingIOError:
            return "running"
    except OSError as error:
        raise HealthError("process lock cannot be inspected") from error
    finally:
        if descriptor is not None:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _require_private_regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.expanduser().absolute().lstat()
    except OSError as error:
        raise HealthError(f"{label} cannot be inspected") from error
    _require_private_regular_metadata(metadata, label)


def _path_present(path: Path) -> bool:
    try:
        path.expanduser().absolute().lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise HealthError("runtime path cannot be inspected") from error
    return True


def _require_private_regular_metadata(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise HealthError(f"{label} must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise HealthError(f"{label} permissions are unsafe")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise HealthError(f"{label} must be owned by the current user")
