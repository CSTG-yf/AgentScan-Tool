"""Managed sandbox CLI keeps execution behind a verified OS backend."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_sandbox import sandbox
from defenseclaw.context import AppContext


class ManagedSandboxCLITest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = str(Path(self.temp.name).resolve())
        self.app = AppContext()
        self.app.logger = Mock()
        self.cli = CliRunner()

    def invoke(self, *args: str):
        return self.cli.invoke(sandbox, list(args), obj=self.app)

    def test_status_rejects_null_backend(self) -> None:
        report = SimpleNamespace(name="null", level="none", degraded=True, failures=[])
        with patch("ai_sandbox.registry.get_report", return_value=report):
            result = self.invoke("status")
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("managed execution is disabled", result.output)

    def test_exec_rejects_null_without_running(self) -> None:
        report = SimpleNamespace(name="null", level="none", degraded=True, failures=[])
        with patch("ai_sandbox.registry.get_report", return_value=report), \
                patch("ai_sandbox.registry.get_sandbox_backend") as backend:
            result = self.invoke("exec", "--workspace", self.workspace,
                                 "--", "echo", "ok")
        self.assertNotEqual(result.exit_code, 0)
        backend.assert_not_called()
        self.app.logger.log_action.assert_called_once()

    def test_manual_mode_denies_when_approval_is_unavailable(self) -> None:
        report = SimpleNamespace(name="sandbox-exec", level="weak", degraded=False,
                                 failures=[])
        with patch("ai_sandbox.registry.get_report", return_value=report), \
                patch("ai_sandbox.registry.get_sandbox_backend") as backend:
            result = self.invoke("exec", "--workspace", self.workspace,
                                 "--", "unknown-command")
        self.assertNotEqual(result.exit_code, 0)
        backend.assert_not_called()

    def test_success_records_start_and_exit(self) -> None:
        report = SimpleNamespace(name="sandbox-exec", level="weak", degraded=False,
                                 failures=[])
        runner = Mock()
        runner.agent_root.return_value = self.workspace
        runner.run.return_value = subprocess.CompletedProcess(["echo", "ok"], 0, "ok\n", "")
        backend = Mock()
        backend.make_runner.return_value = runner
        with patch("ai_sandbox.registry.get_report", return_value=report), \
                patch("ai_sandbox.registry.get_sandbox_backend", return_value=backend):
            result = self.invoke("exec", "--workspace", self.workspace,
                                 "--mode", "auto", "--", "echo", "ok")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("ok", result.output)
        self.assertEqual(self.app.logger.log_action.call_count, 2)


if __name__ == "__main__":
    unittest.main()
