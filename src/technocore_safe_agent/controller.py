"""Keychain-backed, least-privilege control-plane helpers."""

from __future__ import annotations

import errno
import json
import os
import pty
import secrets
import select
import signal
import stat
import subprocess
import tempfile
import termios
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_safe_agent.capabilities import (
    CAPABILITY_SCHEMA,
    CapabilityPolicyFile,
)
from technocore_safe_agent.config import AgentConfig
from technocore_safe_agent.crypto import (
    did_from_private_key,
    fingerprint_of_did,
    private_key_from_seed,
    sign_room_message,
    validate_did,
)
from technocore_safe_agent.identity import DEFAULT_RUNTIME_DIRECTORY, IdentityRecord
from technocore_safe_agent.protocol import RoomMessage
from technocore_safe_agent.state import AgentState

DEFAULT_CONTROLLER_IDENTITY_PATH = (
    DEFAULT_RUNTIME_DIRECTORY / "controller-identity.json"
)
DEFAULT_CONTROLLER_SERVICE = "technocore.safe-agent.controller"
DEFAULT_CONTROLLER_ACCOUNT = "safe-agent-controller"
CONTROLLER_COMMANDS = ("/ping", "/status", "/about", "/help")
CONTROLLER_RATE_LIMIT = 10
KEYCHAIN_PASSWORD_PROMPTS = (
    b"password data for new item:",
    b"retype password for new item:",
)
KEYCHAIN_PROMPT_TIMEOUT_SECONDS = 15.0
KEYCHAIN_PROMPT_BUFFER_BYTES = 512
KEYCHAIN_ITEM_NOT_FOUND_EXIT_CODE = 44


class ControllerError(RuntimeError):
    """A controller operation would weaken its local safety boundary."""


class SeedStore(Protocol):
    service: str
    account: str

    def store_seed(self, seed: str) -> None:
        """Store one exact seed without logging it."""

    def delete_seed(self) -> None:
        """Delete only the item owned by this store."""


class ControllerClient(Protocol):
    base_url: str

    def send_signed_message(self, **kwargs: object) -> RoomMessage:
        """Publish one signed command and return its verified acknowledgement."""


@dataclass(frozen=True)
class MacOSKeychainSeedWriter:
    service: str
    account: str
    security_binary: ClassVar[str] = "/usr/bin/security"

    def __post_init__(self) -> None:
        _validate_keychain_selector(self.service, "service")
        _validate_keychain_selector(self.account, "account")

    def store_seed(self, seed: str) -> None:
        private_key_from_seed(seed)
        arguments = [
            self.security_binary,
            "add-generic-password",
            "-a",
            self.account,
            "-s",
            self.service,
            "-l",
            "Technocore Safe Agent Controller",
            "-w",
        ]
        _run_hidden_keychain_prompt(
            arguments,
            seed,
            timeout=KEYCHAIN_PROMPT_TIMEOUT_SECONDS,
        )

    def delete_seed(self) -> None:
        arguments = [
            self.security_binary,
            "delete-generic-password",
            "-a",
            self.account,
            "-s",
            self.service,
        ]
        try:
            subprocess.run(  # noqa: S603
                arguments,
                check=True,
                capture_output=True,
                text=True,
                timeout=KEYCHAIN_PROMPT_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as error:
            raise ControllerError("macOS security command is not available") from error
        except subprocess.CalledProcessError as error:
            if error.returncode == KEYCHAIN_ITEM_NOT_FOUND_EXIT_CODE:
                return
            raise ControllerError(
                "cannot delete the controller Keychain item"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise ControllerError("controller Keychain cleanup timed out") from error


def create_controller_identity(
    path: Path,
    seed_store: SeedStore,
    *,
    seed_factory: Callable[[], str] = lambda: secrets.token_hex(32),
    created_at: str | None = None,
) -> IdentityRecord:
    """Create one public controller record backed by a new Keychain seed."""

    resolved = path.expanduser().absolute()
    _require_private_directory(resolved.parent)
    if _path_exists(resolved):
        raise ControllerError("refusing to overwrite an existing controller identity")

    seed = seed_factory()
    private_key = private_key_from_seed(seed)
    did = did_from_private_key(private_key)
    payload = {
        "schema": "technocore-local-identity-v1",
        "created_at": created_at or datetime.now(UTC).isoformat(),
        "did": did,
        "fingerprint": fingerprint_of_did(did),
        "custody": {
            "backend": "macos-keychain",
            "service": seed_store.service,
            "account": seed_store.account,
        },
    }

    seed_store.store_seed(seed)
    try:
        _write_new_private_json(resolved, payload)
        record = load_controller_identity(resolved)
        if (
            record.did != did
            or record.keychain_service != seed_store.service
            or record.keychain_account != seed_store.account
        ):
            raise ControllerError("created controller identity failed verification")
    except Exception:
        _unlink_if_present(resolved)
        try:
            seed_store.delete_seed()
        except Exception as cleanup_error:
            raise ControllerError(
                "controller creation failed and Keychain cleanup also failed"
            ) from cleanup_error
        raise
    return record


def load_controller_identity(path: Path) -> IdentityRecord:
    resolved = path.expanduser().absolute()
    _require_private_regular_file(resolved, "controller identity")
    return IdentityRecord.load(resolved)


def grant_controller_to_empty_policy(
    controller_identity: Path,
    capability_policy: Path,
) -> None:
    """Replace an empty validated policy with one fixed read-only controller grant."""

    record = load_controller_identity(controller_identity)
    policy_path = capability_policy.expanduser().absolute()
    _require_private_directory(policy_path.parent)
    policy = CapabilityPolicyFile(policy_path).load()
    if policy.principals:
        raise ControllerError("controller grant requires an empty policy")
    payload = {
        "schema": CAPABILITY_SCHEMA,
        "principals": {
            record.did: {
                "enabled": True,
                "commands": list(CONTROLLER_COMMANDS),
                "repositories": [],
                "max_requests_per_hour": CONTROLLER_RATE_LIMIT,
            }
        },
    }
    _replace_private_json(policy_path, payload)
    grant = CapabilityPolicyFile(policy_path).load().grant_for(record.did)
    if (
        grant is None
        or not grant.enabled
        or grant.commands != frozenset(CONTROLLER_COMMANDS)
        or grant.repositories
        or grant.max_requests_per_hour != CONTROLLER_RATE_LIMIT
    ):
        raise ControllerError("controller policy failed post-write validation")


def send_controller_command(
    *,
    did: str,
    private_key: Ed25519PrivateKey,
    config: AgentConfig,
    state_path: Path,
    command: str,
    client: ControllerClient,
    clock_ns: Callable[[], int] = time.time_ns,
) -> dict[str, str]:
    """Send one exact idempotent command after durably reserving its nonce."""

    valid_did = validate_did(did)
    if command not in CONTROLLER_COMMANDS:
        raise ControllerError("controller accepts only an exact read-only command")
    config.validate()
    if config.status != "active":
        raise ControllerError("controller requires an active agent config")
    if client.base_url != config.base_url:
        raise ControllerError("controller client does not match the agent config")
    if did_from_private_key(private_key) != valid_did:
        raise ControllerError("controller key does not match its public DID")

    resolved_state = state_path.expanduser().absolute()
    _require_private_directory(resolved_state.parent)
    if _path_exists(resolved_state):
        _require_private_regular_file(resolved_state, "controller state")
    state = AgentState.load(resolved_state)
    nonce = state.next_nonce(config.room, clock_ns())
    state.save(resolved_state)
    text, signature = sign_room_message(private_key, config.room, nonce, command)
    client.send_signed_message(
        room=config.room,
        did=valid_did,
        signature=signature,
        nonce=nonce,
        text=text,
    )
    return {"status": "acknowledged", "command": command}


def _validate_keychain_selector(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ControllerError(f"controller Keychain {label} is invalid")


def _run_hidden_keychain_prompt(
    arguments: list[str],
    secret: str,
    *,
    timeout: float,
) -> None:
    """Answer the fixed ``security -w`` prompts without exposing the secret."""

    master_fd: int | None = None
    session: _KeychainPromptSession | None = None
    secret_line = bytearray(secret, "ascii")
    secret_line.append(0x0A)
    try:
        child_pid, master_fd = _spawn_keychain_prompt(arguments)
        session = _KeychainPromptSession(
            child_pid=child_pid,
            master_fd=master_fd,
            secret_line=secret_line,
            deadline=time.monotonic() + timeout,
        )
        session.run()
    except BaseException:
        if session is not None and session.wait_status is None:
            _terminate_child(session.child_pid)
        raise
    finally:
        _wipe_bytearray(secret_line)
        if session is not None:
            _wipe_bytearray(session.prompt_buffer)
        if master_fd is not None:
            os.close(master_fd)


@dataclass
class _KeychainPromptSession:
    child_pid: int
    master_fd: int
    secret_line: bytearray
    deadline: float
    prompt_index: int = 0
    wait_status: int | None = None
    prompt_buffer: bytearray = field(default_factory=bytearray)

    def run(self) -> None:
        while self.wait_status is None:
            self._step()
        if os.waitstatus_to_exitcode(self.wait_status) != 0 or self.prompt_index != len(
            KEYCHAIN_PASSWORD_PROMPTS
        ):
            raise ControllerError("cannot create the controller Keychain item")

    def _step(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ControllerError("controller Keychain prompt timed out")
        if _keychain_prompt_ready(self.master_fd, remaining):
            self._respond_to_prompt(_read_keychain_prompt(self.master_fd))
        waited_pid, candidate = _poll_child(self.child_pid)
        if waited_pid == self.child_pid:
            self.wait_status = candidate

    def _respond_to_prompt(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.prompt_buffer.extend(chunk)
        if len(self.prompt_buffer) > KEYCHAIN_PROMPT_BUFFER_BYTES:
            del self.prompt_buffer[:-KEYCHAIN_PROMPT_BUFFER_BYTES]
        if self.prompt_index >= len(KEYCHAIN_PASSWORD_PROMPTS):
            return
        if KEYCHAIN_PASSWORD_PROMPTS[self.prompt_index] not in self.prompt_buffer:
            return
        _disable_terminal_echo(self.master_fd)
        _write_all(self.master_fd, self.secret_line)
        self.prompt_index += 1
        _wipe_bytearray(self.prompt_buffer)


def _spawn_keychain_prompt(arguments: list[str]) -> tuple[int, int]:
    try:
        child_pid, master_fd = pty.fork()
    except OSError as error:
        raise ControllerError("cannot create a private Keychain prompt") from error
    if child_pid == 0:
        try:
            os.execv(arguments[0], arguments)  # noqa: S606
        except OSError:
            os._exit(127)
    return child_pid, master_fd


def _keychain_prompt_ready(master_fd: int, remaining: float) -> bool:
    try:
        readable, _, _ = select.select([master_fd], [], [], min(0.1, remaining))
    except OSError as error:
        raise ControllerError("controller Keychain prompt failed") from error
    return bool(readable)


def _poll_child(child_pid: int) -> tuple[int, int]:
    try:
        return os.waitpid(child_pid, os.WNOHANG)
    except OSError as error:
        raise ControllerError("cannot monitor the Keychain prompt") from error


def _read_keychain_prompt(master_fd: int) -> bytes:
    try:
        return os.read(master_fd, 1_024)
    except OSError as error:
        if error.errno == errno.EIO:
            return b""
        raise ControllerError("cannot read the Keychain prompt") from error


def _disable_terminal_echo(master_fd: int) -> None:
    try:
        attributes = termios.tcgetattr(master_fd)
        attributes[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(master_fd, termios.TCSANOW, attributes)
    except termios.error as error:
        raise ControllerError("cannot disable Keychain prompt echo") from error


def _write_all(master_fd: int, payload: bytearray) -> None:
    remaining = memoryview(payload)
    try:
        while remaining:
            written = os.write(master_fd, remaining)
            if written <= 0:
                raise ControllerError("cannot answer the Keychain prompt")
            remaining = remaining[written:]
    except OSError as error:
        raise ControllerError("cannot answer the Keychain prompt") from error
    finally:
        remaining.release()


def _wipe_bytearray(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    value.clear()


def _terminate_child(child_pid: int) -> None:
    try:
        os.kill(child_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(child_pid, 0)
    except ChildProcessError:
        pass


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ControllerError("controller path cannot be inspected safely") from error
    return True


def _require_private_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ControllerError("controller directory cannot be inspected") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ControllerError("controller directory must be a real directory")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ControllerError("controller directory must be owner-only")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise ControllerError("controller directory must be owned by this user")


def _require_private_regular_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ControllerError(f"{label} cannot be inspected") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ControllerError(f"{label} must be a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ControllerError(f"{label} permissions must be owner-only")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise ControllerError(f"{label} must be owned by this user")


def _write_new_private_json(path: Path, payload: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        _unlink_if_present(path)
        raise ControllerError("cannot write the controller identity") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _replace_private_json(path: Path, payload: dict[str, Any]) -> None:
    descriptor: int | None = None
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
        os.chmod(path, 0o600)
    except OSError as error:
        raise ControllerError("cannot update the capability policy") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            _unlink_if_present(Path(temporary_name))


def _unlink_if_present(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return
