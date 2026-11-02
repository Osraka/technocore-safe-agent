from pathlib import Path
import tomllib
import unittest

from technocore_safe_agent import __version__


class VersionTests(unittest.TestCase):
    def test_runtime_version_matches_package_metadata(self) -> None:
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        metadata = tomllib.loads(pyproject.read_text(encoding="utf-8"))

        self.assertEqual(__version__, metadata["project"]["version"])

    def test_current_version_has_release_notes(self) -> None:
        changelog = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
        self.assertIn(f"## {__version__} - ", changelog.read_text(encoding="utf-8"))
