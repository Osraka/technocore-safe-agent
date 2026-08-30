"""Keychain-backed, least-privilege control-plane helpers."""

from __future__ import annotations

import ctypes
import json
import os
import secrets
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

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
from technocore_safe_agent.identity import IdentityRecord
from technocore_safe_agent.protocol import RoomMessage
from technocore_safe_agent.state import AgentState

DEFAULT_CONTROLLER_IDENTITY_PATH = Path(
    "~/Library/Application Support/Technocore/Osraka/controller-identity.json"
).expanduser()
DEFAULT_CONTROLLER_SERVICE = "technocore.osraka.controller"
DEFAULT_CONTROLLER_ACCOUNT = "Osraka-controller"
CONTROLLER_COMMANDS = ("/ping", "/status", "/about", "/help")
CONTROLLER_RATE_LIMIT = 10
SECURITY_FRAMEWORK_PATH = "/System/Library/Frameworks/Security.framework/Security"
COREFOUNDATION_FRAMEWORK_PATH = (
    "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
)
ERR_SEC_SUCCESS = 0
ERR_SEC_ITEM_NOT_FOUND = -25300
MAX_KEYCHAIN_SECRET_BYTES = 4_096


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
class MacOSKeychainSeedStore:
    service: str
    account: str

    def __post_init__(self) -> None:
        _validate_keychain_selector(self.service, "service")
        _validate_keychain_selector(self.account, "account")

    def store_seed(self, seed: str) -> None:
        private_key_from_seed(seed)
        _add_generic_password(self.service, self.account, seed)

    def load_seed(self) -> str:
        return _read_generic_password(self.service, self.account)

    def delete_seed(self) -> None:
        _delete_generic_password(self.service, self.account)


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


def _load_security_framework() -> Any:
    try:
        library = ctypes.CDLL(SECURITY_FRAMEWORK_PATH)
    except OSError as error:
        raise ControllerError("macOS Security.framework is not available") from error

    library.SecKeychainAddGenericPassword.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.SecKeychainAddGenericPassword.restype = ctypes.c_int32
    library.SecKeychainFindGenericPassword.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.SecKeychainFindGenericPassword.restype = ctypes.c_int32
    library.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    library.SecKeychainItemFreeContent.restype = ctypes.c_int32
    library.SecKeychainItemDelete.argtypes = [ctypes.c_void_p]
    library.SecKeychainItemDelete.restype = ctypes.c_int32
    return library


def _load_corefoundation_framework() -> Any:
    try:
        library = ctypes.CDLL(COREFOUNDATION_FRAMEWORK_PATH)
    except OSError as error:
        raise ControllerError("macOS CoreFoundation is not available") from error
    library.CFRelease.argtypes = [ctypes.c_void_p]
    library.CFRelease.restype = None
    return library


def _add_generic_password(service: str, account: str, secret: str) -> None:
    library = _load_security_framework()
    service_bytes = service.encode("utf-8")
    account_bytes = account.encode("utf-8")
    secret_bytes = bytearray(secret, "ascii")
    secret_buffer = (ctypes.c_ubyte * len(secret_bytes)).from_buffer(secret_bytes)
    try:
        status = library.SecKeychainAddGenericPassword(
            None,
            len(service_bytes),
            service_bytes,
            len(account_bytes),
            account_bytes,
            len(secret_bytes),
            ctypes.cast(secret_buffer, ctypes.c_void_p),
            None,
        )
    finally:
        ctypes.memset(ctypes.addressof(secret_buffer), 0, len(secret_bytes))
    if status != ERR_SEC_SUCCESS:
        raise ControllerError("cannot create the controller Keychain item")


def _read_generic_password(service: str, account: str) -> str:
    library = _load_security_framework()
    service_bytes = service.encode("utf-8")
    account_bytes = account.encode("utf-8")
    password_length = ctypes.c_uint32()
    password_data = ctypes.c_void_p()
    status = library.SecKeychainFindGenericPassword(
        None,
        len(service_bytes),
        service_bytes,
        len(account_bytes),
        account_bytes,
        ctypes.byref(password_length),
        ctypes.byref(password_data),
        None,
    )
    if status != ERR_SEC_SUCCESS:
        raise ControllerError("cannot read the controller Keychain item")

    invalid_buffer = password_length.value > MAX_KEYCHAIN_SECRET_BYTES or (
        password_length.value > 0 and password_data.value is None
    )
    try:
        raw = (
            b""
            if invalid_buffer or password_data.value is None
            else ctypes.string_at(password_data.value, password_length.value)
        )
    finally:
        if password_data.value is not None:
            free_status = library.SecKeychainItemFreeContent(None, password_data)
            if free_status != ERR_SEC_SUCCESS:
                raise ControllerError("cannot release controller Keychain memory")
    if invalid_buffer:
        raise ControllerError("controller Keychain item has an invalid size")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ControllerError("controller Keychain item is not ASCII") from error


def _delete_generic_password(service: str, account: str) -> None:
    library = _load_security_framework()
    service_bytes = service.encode("utf-8")
    account_bytes = account.encode("utf-8")
    item_ref = ctypes.c_void_p()
    status = library.SecKeychainFindGenericPassword(
        None,
        len(service_bytes),
        service_bytes,
        len(account_bytes),
        account_bytes,
        None,
        None,
        ctypes.byref(item_ref),
    )
    if status == ERR_SEC_ITEM_NOT_FOUND:
        return
    if status != ERR_SEC_SUCCESS or item_ref.value is None:
        raise ControllerError("cannot locate the controller Keychain item")
    try:
        if library.SecKeychainItemDelete(item_ref) != ERR_SEC_SUCCESS:
            raise ControllerError("cannot delete the controller Keychain item")
    finally:
        _load_corefoundation_framework().CFRelease(item_ref)


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
