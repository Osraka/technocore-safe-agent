"""Disposable POSIX server fixture; no live endpoint or operator state inputs."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from typing import Iterator
from urllib.request import ProxyHandler, build_opener

from technocore_safe_agent.protocol import TechnocoreClient

PIN = Path(__file__).with_name("server-revision.txt")


def preflight(checkout: Path, python: Path) -> None:
    if os.name != "posix":
        raise ValueError("integration fixture requires POSIX socket inheritance")
    if not python.is_file():
        raise ValueError(
            "server Python is missing; install the locked server dependencies"
        )
    for name in ("src/app.py", "scripts/sign.py", "SKILL.md", "uv.lock"):
        if not (checkout / name).is_file():
            raise ValueError(f"server checkout is missing {name}")
    for args, expected in (
        (["rev-parse", "--show-toplevel"], str(checkout.resolve())),
        (["rev-parse", "HEAD"], PIN.read_text().strip()),
        (["status", "--porcelain", "--untracked-files=no"], ""),
    ):
        actual = subprocess.run(
            ["git", "-C", str(checkout), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        if actual != expected:
            raise ValueError("server must be a clean checkout of the pinned revision")


def stop(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


@contextlib.contextmanager
def server(
    checkout: Path, python: Path, *, startup_timeout: float = 15, **settings: str
) -> Iterator[tuple[TechnocoreClient, Path]]:
    allowed = {"CHAT_RATE_READ", "CHAT_EPHEMERAL_TTL_SECONDS"}
    if settings.keys() - allowed:
        raise ValueError("unsupported fixture setting")
    with tempfile.TemporaryDirectory(prefix="technocore-interop-") as directory:
        root = Path(directory)
        # Inherit the bound socket; do not race another process for a free port.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            base = f"http://127.0.0.1:{listener.getsockname()[1]}"
            env = {
                "PATH": os.defpath,
                "HOME": directory,
                "TMPDIR": directory,
                "PYTHONDONTWRITEBYTECODE": "1",
                "CHAT_ROOT": str(root / "store"),
                "CHAT_RATE_READ": "1000",
                "CHAT_RATE_WRITE": "1000",
                "CHAT_WAIT_POLL": "0.05",
                **settings,
            }
            process = subprocess.Popen(
                [
                    str(python),
                    "-B",
                    "-m",
                    "uvicorn",
                    "--app-dir",
                    str(checkout / "src"),
                    "app:app",
                    "--fd",
                    str(listener.fileno()),
                    "--no-access-log",
                    "--log-level",
                    "error",
                ],
                cwd=checkout,
                env=env,
                pass_fds=(listener.fileno(),),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + startup_timeout
                opener = build_opener(ProxyHandler({}))
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(
                            "local server exited before readiness; check dependencies"
                        )
                    try:
                        with opener.open(base + "/healthz", timeout=0.2) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("local server readiness timed out")
                    time.sleep(0.05)
                yield TechnocoreClient(base_url=base, timeout=3), root
            finally:
                stop(process)
