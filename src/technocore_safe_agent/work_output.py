"""Opt-in private output storage for one local work-receipt execution."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from typing import Any

from technocore_safe_agent.work_receipt import (
    MAX_OUTPUT_BYTES,
    WorkReceiptError,
    _hash_file,
    render_work_receipt,
)


class OutputBundle:
    def __init__(self, destination: Path, checkout: Path) -> None:
        if os.name != "posix":
            raise WorkReceiptError("private output bundles require POSIX permissions")
        selected = destination.expanduser()
        try:
            parent = selected.parent.resolve(strict=True)
            info = parent.stat()
        except OSError as error:
            raise WorkReceiptError(
                "output parent must be an existing accessible directory"
            ) from error
        self.path = parent / selected.name
        if not selected.name or self.path.is_relative_to(checkout):
            raise WorkReceiptError("output directory must be outside the checkout")
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise WorkReceiptError(
                "output parent must be owned by you and not writable by others"
            )
        self.complete = False

    def __enter__(self) -> OutputBundle:
        try:
            # Reserve before execution, refusing every pre-existing destination,
            # including empty directories and dangling symlinks.
            self.path.mkdir(mode=0o700)
        except OSError as error:
            raise WorkReceiptError(
                "output directory must be new and writable"
            ) from error
        try:
            self.path.chmod(0o700)
        except OSError as error:
            self.path.rmdir()
            raise WorkReceiptError(
                "cannot secure output directory permissions"
            ) from error
        return self

    def __exit__(self, kind, value, traceback) -> None:
        if not self.complete:
            try:
                shutil.rmtree(self.path)
            except OSError as error:
                raise WorkReceiptError(
                    "incomplete output bundle remains; inspect the chosen directory manually"
                ) from error

    def _open_new(self, name: str):
        fd = os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchmod(fd, 0o600)
            return os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            raise

    def capture(self, stdout: Any, stderr: Any) -> None:
        try:
            for name, source in (("stdout", stdout), ("stderr", stderr)):
                source.seek(0)
                size = 0
                with self._open_new(f"{name}.bin") as target:
                    while chunk := source.read(64 * 1024):
                        size += len(chunk)
                        if size > MAX_OUTPUT_BYTES:
                            raise WorkReceiptError(
                                "captured output exceeds the receipt limit"
                            )
                        target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
        except OSError as error:
            raise WorkReceiptError("cannot preserve work output") from error

    def _sync_directory(self) -> None:
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def finish(self, receipt: dict[str, Any]) -> None:
        try:
            payload = receipt["receipt"]["payload"]
            for name in ("stdout", "stderr"):
                with (self.path / f"{name}.bin").open("rb") as handle:
                    digest, size = _hash_file(handle, name)
                if (digest, size) != (
                    payload[f"{name}_sha256"],
                    payload[f"{name}_bytes"],
                ):
                    raise WorkReceiptError(
                        "preserved output does not match the same execution"
                    )
            with self._open_new("receipt.pending") as target:
                target.write((render_work_receipt(receipt) + "\n").encode("utf-8"))
                target.flush()
                os.fsync(target.fileno())
            # Persist the output files before making the completion receipt visible.
            # link() publishes without replacing an unexpected existing receipt.
            self._sync_directory()
            os.link(self.path / "receipt.pending", self.path / "receipt.json")
            (self.path / "receipt.pending").unlink()
            self._sync_directory()
            self.complete = True
        except OSError as error:
            raise WorkReceiptError("cannot complete work output bundle") from error
