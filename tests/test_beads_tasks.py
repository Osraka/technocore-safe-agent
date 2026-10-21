from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

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
                "technocore_safe_agent.beads_tasks.subprocess.run",
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
        with patch("technocore_safe_agent.beads_tasks.subprocess.run") as run:
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
                        "technocore_safe_agent.beads_tasks.subprocess.run",
                        return_value=subprocess.CompletedProcess([], 0, raw, ""),
                    ),
                ):
                    with self.assertRaises(BeadsTasksError):
                        list_ready_tasks(self.beads_dir)
            with patch(
                "technocore_safe_agent.beads_tasks.subprocess.run",
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
                "technocore_safe_agent.beads_tasks.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["bd"], 10),
            ),
        ):
            with self.assertRaises(BeadsTasksError):
                list_ready_tasks(self.beads_dir)

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


if __name__ == "__main__":
    unittest.main()
