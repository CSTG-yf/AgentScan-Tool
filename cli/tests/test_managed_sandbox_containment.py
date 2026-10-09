"""A real backend must reject a write outside the managed workspace."""

from __future__ import annotations

import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from ai_sandbox.registry import get_report, get_sandbox_backend


@unittest.skipUnless(sys.platform in {"darwin", "linux"}, "POSIX backend test")
class ManagedSandboxContainmentTest(unittest.TestCase):
    def test_outside_write_is_denied(self) -> None:
        report = get_report()
        if report.degraded or report.name is None:
            self.skipTest("OS sandbox unavailable")
        outside = Path.home() / (".tracebastion-sandbox-test-" + uuid.uuid4().hex)
        created = False
        with tempfile.TemporaryDirectory(prefix="tracebastion-sandbox-") as workspace:
            runner = get_sandbox_backend().make_runner(workspace)
            try:
                result = runner.run(
                    ["/bin/sh", "-c", 'printf blocked > "$1"', "sh", str(outside)],
                    runner.agent_root(), timeout=10,
                )
            finally:
                close = getattr(runner, "close", None)
                if close is not None:
                    close()
                created = outside.exists()
                if created:
                    outside.unlink()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(created)

    def test_existing_git_metadata_is_read_only(self) -> None:
        report = get_report()
        if report.degraded or report.name is None:
            self.skipTest("OS sandbox unavailable")
        with tempfile.TemporaryDirectory(prefix="tracebastion-sandbox-") as workspace:
            git_dir = Path(workspace) / ".git"
            git_dir.mkdir()
            head = git_dir / "HEAD"
            head.write_text("original", encoding="utf-8")
            runner = get_sandbox_backend().make_runner(workspace)
            try:
                result = runner.run(
                    ["/bin/sh", "-c", "printf changed > .git/HEAD"],
                    runner.agent_root(), timeout=10,
                )
            finally:
                close = getattr(runner, "close", None)
                if close is not None:
                    close()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(head.read_text(encoding="utf-8"), "original")


if __name__ == "__main__":
    unittest.main()
