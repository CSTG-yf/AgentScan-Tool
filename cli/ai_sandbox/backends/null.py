# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2026/09/16'
__desc__ = 'null 沙箱后端（降级模式：无隔离直执）'

"""
null 沙箱后端 — 降级模式（任意平台，NONE）

仅在 graded 策略 + 强隔离后端不可用时由 auto 链兜底选中（strict 策略下
registry 上报后启动失败，不会走到这里）。语义：

- 命令直接在本机执行（无文件系统/进程隔离），chdir 为宿主真实路径
  （shell 视角 = 宿主路径，与 sandbox-exec 同款路径语言）；
- 解释器用宿主路径（config.PYTHON_PATH 等），不再有中性挂载；
- 挂载校验仍执行敏感路径黑名单（无隔离下更要拒绝暴露敏感目录）；
- 已知退化（接受）：proc.kill() 无命名空间级联（后台进程可能残留）。
"""

import os
import subprocess
from typing import Optional

from .. import settings as config
from ..workspace import system_mounts_for
from ..base import (
    SANDBOX_LEVEL_NONE, SandboxBackend, SandboxRunner,
    agent_path_to_host, host_to_sandbox,
)


class _NullRunner(SandboxRunner):
    """null 会话级运行器：直执 + 真实根路径语言"""

    def __init__(self, workspace_dir: str,
                 extra_ro_mounts: Optional[dict[str, str]] = None,
                 system_dir: Optional[str] = None):
        self._workspace_dir = workspace_dir
        self._extra_ro_mounts = extra_ro_mounts or {}
        self._system_mounts = system_mounts_for(system_dir) if system_dir else {}

    def _tables(self):
        return self._extra_ro_mounts, self._system_mounts

    # ---- 路径语言（shell 视角 = 宿主真实路径） ----

    def agent_root(self) -> str:
        return self._workspace_dir

    def agent_path(self, shell_path: str) -> str:
        extra, sys_mounts = self._tables()
        return host_to_sandbox(shell_path, self._workspace_dir,
                               extra, sys_mounts) or shell_path

    def shell_path(self, agent_path: str) -> str:
        extra, sys_mounts = self._tables()
        return agent_path_to_host(agent_path, self._workspace_dir,
                                  extra, sys_mounts)

    def build_command(self, argv: list[str], chdir: str) -> list[str]:
        # chdir 不进 argv，由 run/spawn 以 cwd 落实（直执语义）
        return list(argv)

    def run(self, argv: list[str], chdir: str, timeout: Optional[int] = None,
            extra_env: Optional[dict] = None) -> subprocess.CompletedProcess:
        env = {**os.environ, **extra_env} if extra_env else None
        return subprocess.run(
            list(argv), cwd=chdir, capture_output=True,
            text=True, timeout=timeout or config.PYTHON_MAX_TIMEOUT_SECONDS,
            env=env)

    def spawn(self, argv: list[str], chdir: str,
              extra_env: Optional[dict] = None) -> subprocess.Popen:
        env = {**os.environ, **extra_env} if extra_env else None
        return subprocess.Popen(
            list(argv), cwd=chdir, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)

    def host_to_agent_path(self, path: str,
                           extra_ro_mounts: Optional[dict] = None,
                           system_mounts: Optional[dict] = None) -> Optional[str]:
        return host_to_sandbox(
            path, self._workspace_dir,
            extra_ro_mounts if extra_ro_mounts is not None else self._extra_ro_mounts,
            system_mounts if system_mounts is not None else self._system_mounts)

    def agent_python_bin(self) -> str:
        return config.PYTHON_PATH

    def agent_node_bin(self) -> str:
        return config.resolve_node_bin() or "node"


class NullBackend(SandboxBackend):
    """null 后端（降级模式，NONE）——probe 恒可用，auto 链的兜底候选"""

    name = "null"
    level = SANDBOX_LEVEL_NONE

    def probe(self) -> None:
        return None

    def make_runner(self, workspace_dir: str,
                    extra_ro_mounts: Optional[dict[str, str]] = None,
                    system_dir: Optional[str] = None) -> SandboxRunner:
        return _NullRunner(workspace_dir, extra_ro_mounts=extra_ro_mounts,
                           system_dir=system_dir)
