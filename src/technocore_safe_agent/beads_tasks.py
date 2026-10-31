"""Operator-invoked, bounded view of ready work in a local Beads database."""

from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
import unicodedata
from pathlib import Path
from typing import TypedDict

MAX_READY_TASKS = 10
MAX_METADATA_BYTES = 16_384
MAX_RESULT_BYTES = 65_536
MAX_STDERR_BYTES = 4_096
QUERY_TIMEOUT_SECONDS = 10
TASK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class BeadsTasksError(RuntimeError):
    """The selected queue cannot be safely listed."""


class ReadyTask(TypedDict):
    id: str
    title: str
    priority: int


def list_ready_tasks(
    beads_dir: Path, *, limit: int = MAX_READY_TASKS
) -> list[ReadyTask]:
    """Return bounded ready-task metadata; never create, claim, or close tasks."""

    if type(limit) is not int or not 1 <= limit <= MAX_READY_TASKS:
        raise BeadsTasksError("task limit must be between 1 and 10")
    if os.name != "posix":
        raise BeadsTasksError("local Beads queries require macOS or Linux")
    selected = beads_dir.expanduser()
    _check_local_database(selected)

    binary = shutil.which("bd")
    if binary is None:
        raise BeadsTasksError("Beads CLI (bd) is not installed")
    # Pass only ordinary runtime variables, not inherited GitHub or Beads credentials.
    environment = {
        name: os.environ[name]
        for name in ("HOME", "PATH", "LANG", "LC_ALL", "USER", "TMPDIR", "SYSTEMROOT")
        if name in os.environ
    }
    environment.update(
        {"BEADS_DIR": str(selected), "BD_NON_INTERACTIVE": "1", "NO_COLOR": "1"}
    )
    try:
        result = _query(
            [
                binary,
                "--readonly",
                "--sandbox",
                "ready",
                "--json",
                "--brief",
                "--limit",
                str(limit),
            ],
            cwd=selected.parent,
            env=environment,
        )
    except FileNotFoundError as error:
        raise BeadsTasksError("Beads CLI (bd) is not available") from error
    except subprocess.TimeoutExpired as error:
        raise BeadsTasksError("Beads query timed out") from error
    except (OSError, UnicodeError) as error:
        raise BeadsTasksError("Beads query failed") from error
    if result.returncode != 0:
        raise BeadsTasksError("Beads query failed")
    if len(result.stdout.encode("utf-8")) > MAX_RESULT_BYTES:
        raise BeadsTasksError("Beads result is too large")
    try:
        rows = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise BeadsTasksError("Beads returned invalid JSON") from error
    if not isinstance(rows, list) or len(rows) > limit:
        raise BeadsTasksError("Beads returned an invalid task list")
    return [_task_from_row(row) for row in rows]


def _query(
    argv: list[str], *, cwd: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
    with subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        try:
            assert process.stdout is not None and process.stderr is not None
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                for stream, maximum in (
                    (process.stdout, MAX_RESULT_BYTES),
                    (process.stderr, MAX_STDERR_BYTES),
                ):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, maximum)
                sizes = {
                    stream.fileno(): 0 for stream in (process.stdout, process.stderr)
                }
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, QUERY_TIMEOUT_SECONDS)
                    for key, _ in selector.select(remaining):
                        try:
                            chunk = os.read(
                                key.fd, min(8192, key.data - sizes[key.fd] + 1)
                            )
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        sizes[key.fd] += len(chunk)
                        if sizes[key.fd] > key.data:
                            raise BeadsTasksError("Beads result is too large")
                        if key.fileobj is process.stdout:
                            output.extend(chunk)
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            # A descendant can keep a pipe open after bd exits. Stop the owned
            # session too, rather than waiting for its inherited descriptors.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    return subprocess.CompletedProcess(argv, code, output.decode("utf-8"), "")


def _check_local_database(path: Path) -> None:
    if not path.is_absolute() or path.name != ".beads":
        raise BeadsTasksError("select an absolute local .beads directory")
    try:
        directory = path.lstat()
        metadata_path = path / "metadata.json"
        metadata_file = metadata_path.lstat()
        if not stat.S_ISDIR(directory.st_mode) or not stat.S_ISREG(
            metadata_file.st_mode
        ):
            raise BeadsTasksError("local Beads database is not available")
        if directory.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise BeadsTasksError("Beads directory must be owner-only")
        if hasattr(os, "getuid") and directory.st_uid != os.getuid():
            raise BeadsTasksError("Beads directory must belong to this user")
        with metadata_path.open("rb") as source:
            raw = source.read(MAX_METADATA_BYTES + 1)
    except OSError as error:
        raise BeadsTasksError("local Beads database is not available") from error
    if len(raw) > MAX_METADATA_BYTES:
        raise BeadsTasksError("Beads metadata is too large")
    try:
        metadata = json.loads(raw)
    except (UnicodeError, ValueError) as error:
        raise BeadsTasksError("Beads metadata is invalid") from error
    if not isinstance(metadata, dict) or (
        metadata.get("backend") != "dolt" or metadata.get("dolt_mode") != "embedded"
    ):
        raise BeadsTasksError("only local embedded Beads databases are supported")


def _task_from_row(row: object) -> ReadyTask:
    if not isinstance(row, dict):
        raise BeadsTasksError("Beads returned an invalid task")
    task_id = row.get("id")
    title = row.get("title")
    priority = row.get("priority")
    if (
        not isinstance(task_id, str)
        or TASK_ID.fullmatch(task_id) is None
        or not isinstance(title, str)
        or not 1 <= len(title) <= 200
        or not title.strip()
        or any(unicodedata.category(char) in {"Cc", "Cf"} for char in title)
        or type(priority) is not int
        or not 0 <= priority <= 4
        or row.get("status") != "open"
    ):
        raise BeadsTasksError("Beads returned an invalid task")
    return {"id": task_id, "title": title, "priority": priority}
