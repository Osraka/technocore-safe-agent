from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


def load(name):
    path = Path(__file__).parent / "interop" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"interop_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("fixture")
with patch.dict(sys.modules, {"fixture": fixture}):
    runner = load("run")


class FixtureTests(unittest.TestCase):
    def test_preflight_refuses_missing_setup_before_starting(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Python is missing"):
                fixture.preflight(Path(directory), Path(directory) / "missing-python")
            with self.assertRaisesRegex(ValueError, "checkout is missing"):
                fixture.preflight(Path(directory), Path(sys.executable))

    def test_preflight_requires_exact_clean_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("src/app.py", "scripts/sign.py", "SKILL.md", "uv.lock"):
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.touch()
            good = [str(root.resolve()), fixture.PIN.read_text().strip(), ""]
            for values, valid in (
                (good, True),
                ([good[0], "0" * 40, ""], False),
                ([*good[:2], " M src/app.py"], False),
                (["/different-checkout", *good[1:]], False),
            ):
                with (
                    self.subTest(values=values),
                    patch.object(
                        fixture.subprocess,
                        "run",
                        side_effect=[Mock(stdout=value) for value in values],
                    ),
                ):
                    if valid:
                        fixture.preflight(root, Path(sys.executable))
                    else:
                        with self.assertRaisesRegex(ValueError, "pinned revision"):
                            fixture.preflight(root, Path(sys.executable))

    def _setup_server(self):
        process = Mock()
        process.poll.return_value = None
        popen = self.enterContext(
            patch.object(fixture.subprocess, "Popen", return_value=process)
        )
        response = Mock()
        response.__enter__ = Mock(return_value=Mock(status=200))
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        self.enterContext(patch.object(fixture, "build_opener", return_value=opener))
        # The unit suite never needs to bind a socket or start a real server.
        listener = Mock()
        listener.__enter__ = Mock(return_value=listener)
        listener.__exit__ = Mock(return_value=False)
        listener.getsockname.return_value = ("127.0.0.1", 12345)
        listener.fileno.return_value = 77
        self.enterContext(patch.object(fixture.socket, "socket", return_value=listener))
        return process, popen, opener, listener

    def test_fixture_is_loopback_isolated_and_cleans_up_on_success(self):
        process, popen, _, listener = self._setup_server()
        with fixture.server(Path("/checkout"), Path("/python")) as (client, root):
            self.assertEqual(client.base_url, "http://127.0.0.1:12345")
            self.assertTrue(root.is_dir())
            env = popen.call_args.kwargs["env"]
            self.assertEqual(env["CHAT_ROOT"], str(root / "store"))
            self.assertEqual(env["HOME"], str(root))
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("HTTPS_PROXY", env)
            self.assertNotIn("PYTHONPATH", env)
        listener.bind.assert_called_once_with(("127.0.0.1", 0))
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)
        self.assertFalse(root.exists())

    def test_fixture_cleans_up_on_test_failure_and_interrupt(self):
        process, _, _, _ = self._setup_server()
        for error in (AssertionError("test failed"), KeyboardInterrupt()):
            process.reset_mock()
            with (
                self.subTest(error=type(error).__name__),
                self.assertRaises(type(error)),
            ):
                with fixture.server(Path("/checkout"), Path("/python")) as (_, root):
                    raise error
            process.terminate.assert_called_once()
            self.assertFalse(root.exists())

    def test_fixture_refuses_early_exit(self):
        process, _, _, _ = self._setup_server()
        process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, "before readiness"):
            with fixture.server(Path("/checkout"), Path("/python")):
                self.fail("dead process must not yield a client")

    def test_fixture_startup_timeout_stops_process(self):
        process, _, opener, _ = self._setup_server()
        opener.open.side_effect = OSError("not ready")
        with patch.object(fixture.time, "monotonic", side_effect=[0, 16]):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                with fixture.server(Path("/checkout"), Path("/python")):
                    self.fail("startup timeout must not yield a client")
        process.terminate.assert_called_once()

    def test_start_failure_removes_temporary_directory(self):
        _, popen, _, _ = self._setup_server()
        popen.side_effect = OSError("cannot start interpreter")
        with self.assertRaises(OSError):
            with fixture.server(Path("/checkout"), Path("/python")):
                self.fail("spawn failed")
        root = Path(popen.call_args.kwargs["env"]["HOME"])
        self.assertFalse(root.exists())

    def test_stop_kills_child_that_does_not_terminate(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("server", 5), 0]
        fixture.stop(process)
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_fixture_refuses_overriding_root_or_proxy(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            with fixture.server(
                Path("/checkout"), Path("/python"), CHAT_ROOT="/real-state"
            ):
                self.fail("state override accepted")

    def test_explicit_runner_refuses_missing_setup(self):
        argv = [
            "run.py",
            "--server-checkout",
            "/missing-server",
            "--server-python",
            "/missing-python",
        ]
        with patch.object(sys, "argv", argv), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                runner.main()
        self.assertEqual(error.exception.code, 2)

    def test_runner_refuses_empty_discovery_or_skips(self):
        argv = [
            "run.py",
            "--server-checkout",
            "/checkout",
            "--server-python",
            "/python",
        ]
        checks = Mock()
        for count, skipped, expected in (
            (0, [], 2),
            (12, [("case", "missing")], 1),
            (12, [], 0),
        ):
            with (
                self.subTest(count=count, skipped=skipped),
                patch.object(sys, "argv", argv),
                patch.object(fixture, "preflight"),
                patch.dict(sys.modules, {"checks": checks}),
                patch.object(
                    unittest.defaultTestLoader,
                    "loadTestsFromModule",
                    return_value=Mock(countTestCases=lambda: count),
                ),
                patch.object(unittest, "TextTestRunner") as reporter,
                patch("sys.stderr", io.StringIO()),
            ):
                reporter.return_value.run.return_value = Mock(
                    wasSuccessful=lambda: True, skipped=skipped, testsRun=count
                )
                if expected == 2:
                    with self.assertRaises(SystemExit) as error:
                        runner.main()
                    self.assertEqual(error.exception.code, 2)
                    reporter.assert_not_called()
                else:
                    self.assertEqual(runner.main(), expected)
