from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from technocore_safe_agent import beads_tasks
from technocore_safe_agent.beads_tasks import BeadsTasksError, list_ready_tasks
from technocore_safe_agent.cli import main


class BeadsTasksTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.beads_dir = Path(self.temporary.name) / ".beads"
        self.beads_dir.mkdir(mode=0o700)
        (self.beads_dir / "metadata.json").write_text(
            json.dumps({"backend": "dolt", "dolt_mode": "embedded"}),
            encoding="utf-8",
        )

    def test_ready_lists_only_bounded_task_fields_without_claiming(self) -> None:
        raw = json.dumps(
            [
                {
                    "id": "safe-123",
                    "title": "Review test failure",
                    "priority": 1,
                    "status": "open",
                    "description": "do not print this private note",
                }
            ]
        )
        with (
            patch(
                "technocore_safe_agent.beads_tasks.shutil.which", return_value="/bin/bd"
            ),
            patch(
                "technocore_safe_agent.beads_tasks._query",
                return_value=subprocess.CompletedProcess([], 0, raw, "warning"),
            ) as run,
        ):
            tasks = list_ready_tasks(self.beads_dir)

        self.assertEqual(
            tasks, [{"id": "safe-123", "title": "Review test failure", "priority": 1}]
        )
        args, kwargs = run.call_args
        self.assertEqual(
            args[0],
            [
                "/bin/bd",
                "--readonly",
                "--sandbox",
                "ready",
                "--json",
                "--brief",
                "--limit",
                "10",
            ],
        )
        self.assertEqual(kwargs["env"]["BEADS_DIR"], str(self.beads_dir))
        self.assertEqual(kwargs["cwd"], self.beads_dir.parent)
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("GH_TOKEN", kwargs["env"])

    def test_empty_queue_and_json_output_are_explicit(self) -> None:
        with patch("technocore_safe_agent.cli.list_ready_tasks", return_value=[]):
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["tasks", "ready", "--beads-dir", str(self.beads_dir)])
            self.assertEqual(code, 0)
            self.assertEqual(output.getvalue(), "No ready tasks.\n")
            output = io.StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "tasks",
                        "ready",
                        "--beads-dir",
                        str(self.beads_dir),
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(
                json.loads(output.getvalue()), {"status": "ready", "tasks": []}
            )

    def test_rejects_nonlocal_backend_before_running_bd(self) -> None:
        (self.beads_dir / "metadata.json").write_text(
            json.dumps({"backend": "http"}), encoding="utf-8"
        )
        with patch("technocore_safe_agent.beads_tasks._query") as run:
            with self.assertRaises(BeadsTasksError):
                list_ready_tasks(self.beads_dir)
        run.assert_not_called()

    def test_rejects_world_readable_or_symlinked_database(self) -> None:
        self.beads_dir.chmod(0o755)
        with self.assertRaises(BeadsTasksError):
            list_ready_tasks(self.beads_dir)
        self.beads_dir.chmod(0o700)
        link = self.beads_dir.parent / "linked" / ".beads"
        link.parent.mkdir()
        link.symlink_to(self.beads_dir, target_is_directory=True)
        with self.assertRaises(BeadsTasksError):
            list_ready_tasks(link)

    def test_rejects_symlinked_or_oversized_metadata(self) -> None:
        metadata = self.beads_dir / "metadata.json"
        target = self.beads_dir.parent / "target.json"
        metadata.rename(target)
        metadata.symlink_to(target)
        with self.assertRaises(BeadsTasksError):
            list_ready_tasks(self.beads_dir)
        metadata.unlink()
        metadata.write_bytes(b"x" * 16_385)
        with self.assertRaises(BeadsTasksError):
            list_ready_tasks(self.beads_dir)

    def test_rejects_untrusted_output_and_failed_queries(self) -> None:
        bad_outputs = [
            "not json",
            json.dumps({"tasks": []}),
            json.dumps([{"id": "x-1", "title": "bad\x1b[31m", "priority": 1}]),
            json.dumps([{"id": "x-1", "title": "ok", "priority": True}]),
            json.dumps(
                [
                    {
                        "id": f"x-{number}",
                        "title": "ok",
                        "priority": 1,
                        "status": "open",
                    }
                    for number in range(11)
                ]
            ),
            "x" * 65_537,
        ]
        with patch(
            "technocore_safe_agent.beads_tasks.shutil.which", return_value="/bin/bd"
        ):
            for raw in bad_outputs:
                with (
                    self.subTest(raw=raw),
                    patch(
                        "technocore_safe_agent.beads_tasks._query",
                        return_value=subprocess.CompletedProcess([], 0, raw, ""),
                    ),
                ):
                    with self.assertRaises(BeadsTasksError):
                        list_ready_tasks(self.beads_dir)
            with patch(
                "technocore_safe_agent.beads_tasks._query",
                return_value=subprocess.CompletedProcess([], 2, "", "private path"),
            ):
                with self.assertRaises(BeadsTasksError) as caught:
                    list_ready_tasks(self.beads_dir)
                self.assertNotIn("private path", str(caught.exception))

    def test_missing_binary_and_timeout_do_not_fall_back_to_other_tools(self) -> None:
        with patch("technocore_safe_agent.beads_tasks.shutil.which", return_value=None):
            with self.assertRaises(BeadsTasksError):
                list_ready_tasks(self.beads_dir)
        with (
            patch(
                "technocore_safe_agent.beads_tasks.shutil.which", return_value="/bin/bd"
            ),
            patch(
                "technocore_safe_agent.beads_tasks._query",
                side_effect=subprocess.TimeoutExpired(["bd"], 10),
            ),
        ):
            with self.assertRaises(BeadsTasksError):
                list_ready_tasks(self.beads_dir)

    def test_unsupported_platform_is_refused_before_starting_a_query(self) -> None:
        with (
            patch.object(beads_tasks.os, "name", "nt"),
            patch.object(beads_tasks, "_query") as query,
            self.assertRaisesRegex(BeadsTasksError, "require macOS or Linux"),
        ):
            list_ready_tasks(self.beads_dir)
        query.assert_not_called()

    def test_cli_prints_local_tasks_without_identity_or_network(self) -> None:
        output = io.StringIO()
        with (
            patch(
                "technocore_safe_agent.cli.list_ready_tasks",
                return_value=[
                    {"id": "safe-123", "title": "Review test failure", "priority": 1}
                ],
            ) as listing,
            redirect_stdout(output),
        ):
            code = main(["tasks", "ready", "--beads-dir", str(self.beads_dir)])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue(), "P1 safe-123 Review test failure\n")
        listing.assert_called_once_with(self.beads_dir, limit=10)

    def test_cli_rejects_bad_limit_and_does_not_show_private_error(self) -> None:
        error_output = io.StringIO()
        with redirect_stderr(error_output):
            with self.assertRaises(SystemExit):
                main(
                    [
                        "tasks",
                        "ready",
                        "--beads-dir",
                        str(self.beads_dir),
                        "--limit",
                        "11",
                    ]
                )
        with (
            patch(
                "technocore_safe_agent.cli.list_ready_tasks",
                side_effect=BeadsTasksError("beads query failed"),
            ),
            redirect_stderr(error_output),
        ):
            code = main(["tasks", "ready", "--beads-dir", str(self.beads_dir)])
        self.assertEqual(code, 2)
        self.assertIn("beads query failed", error_output.getvalue())


@unittest.skipUnless(os.name == "posix", "local Beads queries require POSIX pipes")
class BeadsProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / ".beads"
        self.database.mkdir(mode=0o700)
        (self.database / "metadata.json").write_text(
            json.dumps({"backend": "dolt", "dolt_mode": "embedded"})
        )
        self.binary = self.root / "bd"
        self.children: list[subprocess.Popen] = []

    def query(self, code: str):
        self.binary.write_text(f"#!{sys.executable}\n{code}\n")
        self.binary.chmod(0o700)
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            self.children.append(process)
            return process

        with (
            patch.dict(
                os.environ,
                {
                    "HOME": str(self.root),
                    "PATH": str(self.root),
                    "LANG": "C.UTF-8",
                    "GH_TOKEN": "synthetic-not-a-credential",
                },
                clear=True,
            ),
            patch.object(beads_tasks.subprocess, "Popen", side_effect=start),
        ):
            return list_ready_tasks(self.database)

    def assert_reaped(self) -> None:
        self.assertEqual(len(self.children), 1)
        process = self.children[0]
        self.assertIsNotNone(process.returncode)
        with self.assertRaises(ProcessLookupError):
            os.kill(process.pid, 0)

    def test_oversized_stdout_is_rejected_before_the_child_exits(self) -> None:
        with (
            patch.object(beads_tasks, "QUERY_TIMEOUT_SECONDS", 5),
            self.assertRaisesRegex(BeadsTasksError, "result is too large"),
        ):
            self.query(
                "import os, time\n"
                "open('pid', 'w').write(str(os.getpid()))\n"
                "os.write(1, b'x' * 65537)\n"
                "time.sleep(60)"
            )
        self.assert_reaped()

    def test_oversized_stderr_is_rejected_while_stdout_remains_open(self) -> None:
        with (
            patch.object(beads_tasks, "QUERY_TIMEOUT_SECONDS", 5),
            self.assertRaisesRegex(BeadsTasksError, "result is too large"),
        ):
            self.query(
                "import os, time\n"
                "open('pid', 'w').write(str(os.getpid()))\n"
                "os.write(1, b'[]')\n"
                "os.write(2, b'x' * 4097)\n"
                "time.sleep(60)"
            )
        self.assert_reaped()

    def test_exact_stdout_and_stderr_limits_allow_valid_json(self) -> None:
        self.assertEqual(
            self.query(
                "import sys\n"
                "sys.stdout.buffer.write(b'[]' + b' ' * 65534)\n"
                "sys.stderr.buffer.write(b'x' * 4096)"
            ),
            [],
        )

    def test_real_child_preserves_readonly_argv_and_filters_credentials(self) -> None:
        self.query(
            "import json, os, sys\n"
            "open('observed.json', 'w').write(json.dumps({\n"
            " 'argv': sys.argv[1:], 'directory': os.environ.get('BEADS_DIR'),\n"
            " 'credential_present': 'GH_TOKEN' in os.environ,\n"
            " 'session': os.getsid(0), 'pid': os.getpid()}))\n"
            "print('[]')"
        )
        observed = json.loads((self.root / "observed.json").read_text())
        self.assertEqual(
            observed["argv"],
            ["--readonly", "--sandbox", "ready", "--json", "--brief", "--limit", "10"],
        )
        self.assertEqual(observed["directory"], str(self.database))
        self.assertFalse(observed["credential_present"])
        self.assertEqual(observed["session"], observed["pid"])

    def test_multibyte_stdout_is_limited_by_bytes(self) -> None:
        with self.assertRaisesRegex(BeadsTasksError, "result is too large"):
            self.query("import sys; sys.stdout.buffer.write(b'\\xc3\\xa9' * 32769)")

    def test_invalid_utf8_and_nonzero_exit_keep_diagnostics_private(self) -> None:
        for code in (
            "import os; os.write(1, b'\\xff')",
            "import sys; sys.stderr.write('private fixture diagnostic'); sys.exit(2)",
        ):
            with self.subTest(code=code), self.assertRaises(BeadsTasksError) as caught:
                self.query(code)
            self.assertEqual(str(caught.exception), "Beads query failed")

    def test_closed_pipes_do_not_bypass_the_process_deadline(self) -> None:
        with (
            patch.object(beads_tasks, "QUERY_TIMEOUT_SECONDS", 5),
            self.assertRaisesRegex(BeadsTasksError, "query timed out"),
        ):
            self.query(
                "import os, time\n"
                "open('pid', 'w').write(str(os.getpid()))\n"
                "os.close(1); os.close(2)\n"
                "time.sleep(60)"
            )
        self.assert_reaped()

    def test_inherited_pipe_timeout_stops_the_owned_process_group(self) -> None:
        with (
            patch.object(beads_tasks, "QUERY_TIMEOUT_SECONDS", 5),
            patch.object(beads_tasks.os, "killpg", wraps=os.killpg) as kill_group,
            self.assertRaisesRegex(BeadsTasksError, "query timed out"),
        ):
            self.query(
                "import os, subprocess, sys\n"
                "open('pid', 'w').write(str(os.getpid()))\n"
                "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])"
            )
        kill_group.assert_called_once_with(self.children[0].pid, signal.SIGKILL)
        self.assert_reaped()

    def test_interruption_kills_and_reaps_the_query(self) -> None:
        with (
            patch.object(
                beads_tasks.selectors.DefaultSelector,
                "select",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.query("import time; time.sleep(60)")
        self.assert_reaped()
        self.assertEqual(self.children[0].returncode, -signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
