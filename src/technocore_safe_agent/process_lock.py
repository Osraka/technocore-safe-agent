"""Single-process guard for live mailbox state mutations."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from types import TracebackType


class ProcessLockError(RuntimeError):
    """Another live agent or recovery process owns the state lock."""


class AgentProcessLock:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self._descriptor: int | None = None

    def acquire(self) -> None:
        if self._descriptor is not None:
            raise ProcessLockError("agent process lock is already held")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor: int | None = None
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise ProcessLockError(
                "another live agent or recovery process is already running"
            ) from error
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise ProcessLockError(
                f"cannot acquire process lock {self.path}: {error}"
            ) from error

        assert descriptor is not None
        self._descriptor = descriptor
        try:
            os.ftruncate(descriptor, 0)
            os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
            os.fsync(descriptor)
        except OSError as error:
            self.release()
            raise ProcessLockError(
                f"cannot initialize process lock {self.path}: {error}"
            ) from error

    def release(self) -> None:
        if self._descriptor is None:
            return
        descriptor = self._descriptor
        self._descriptor = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "AgentProcessLock":
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()
