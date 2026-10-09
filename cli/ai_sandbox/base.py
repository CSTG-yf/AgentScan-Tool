# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2026/09/16'
__desc__ = 'SandboxBackend 抽象（轴 A：OS 沙箱后端）'

"""
SandboxBackend 抽象 — 轴 A（OS 沙箱后端）

双正交轴设计：
- 轴 A（本模块）：OS 沙箱后端，管隔离与宿主/沙箱路径翻译
  （bwrap / sandbox-exec / appcontainer / null 降级）；
- 轴 B（shell_profile.py）：Shell 工具链，管持久 Shell 协议与审批正则
  （bash / zsh / pwsh）。

设计约束：
- 抽象在 spawn 层而非 argv 层——AppContainer 需 CreateProcessW + 安全
  属性，无法表达为命令前缀，故 Runner 暴露 build_command/run/spawn 而
  非只给 argv 拼接；
- seccomp（--seccomp 3 + /bin/sh fd 外壳）是 bwrap 私有组件，
  封装在 BwrapRunner.build_command 内部，不进本接口；
- 后端选择由 registry.py 统一决策（显式指定 > auto 探测链，启动时一次）。
"""

import os
import subprocess
from abc import ABC, abstractmethod
from typing import Optional

from . import settings as config

# 产品路径语言根（agent 对话层恒定：提示词/cd 工具/文件工具/审计统一
# 使用 /workspace 前缀，跨平台不变；shell 内视角由 Runner.agent_root 衔接）
WORKSPACE_AGENT_ROOT = config.SANDBOX_WORKSPACE_ROOT

# 隔离强度：strong（文件系统+进程命名空间级）/ weak（策略级）/ none（直执）
SANDBOX_LEVEL_STRONG = "strong"
SANDBOX_LEVEL_WEAK = "weak"
SANDBOX_LEVEL_NONE = "none"

# ---- probe() 失败形态（"失败形态分流"：按形态决定降级/硬失败/指引排查）----
# 二进制缺失：auto 链正常降级到下一候选
PROBE_MISSING = "missing"
# 后端缺陷（如 profile 语法错、冒烟失败）：显式指定语义下硬失败并透出
# 可读原因；auto 链降级 + 醒目上报
PROBE_DEFECT = "defect"
# 父进程已沙箱（Seatbelt 等一次性 profile 不可嵌套）：报错指引"换未
# 沙箱终端运行"，不判定后端损坏（sandbox-exec 后端使用，预留）
PROBE_NESTED = "nested"


class SandboxProbeError(Exception):
    """backend.probe() 失败。form 取 PROBE_* 常量，message 面向日志/上报。"""

    def __init__(self, message: str, form: str = PROBE_MISSING):
        super().__init__(message)
        self.form = form


class SandboxRunner(ABC):
    """
    会话级沙箱运行器 — 绑定 workspace/挂载上下文，负责实际进程执行。

    由 backend.make_runner(...) 创建，一个会话一个实例；argv 为"shell 内
    视角"的命令，路径翻译与隔离外壳由具体实现负责。

    路径语言（chdir/argv 路径均为 shell 内视角；产品语言恒为 /workspace）：
    - agent_root()：shell 内的 workspace 根（bwrap="/workspace" 挂载虚拟根；
      sandbox-exec/null=宿主真实路径——无挂载命名空间，LLM 自由文本命令
      不可翻译，业界同构）；
    - agent_path()：shell 视角 → 产品语言（marker pwd 回传翻译）；
    - shell_path()：产品语言 → shell 视角（cd 前奏/argv 路径翻译）。
    bwrap 下两种语言恒等（零行为变化）。
    """

    @abstractmethod
    def agent_root(self) -> str:
        """shell 内视角的 workspace 根路径（spawn chdir / cwd 校验基准）。"""

    @abstractmethod
    def agent_path(self, shell_path: str) -> str:
        """shell 内视角路径 → 产品语言（/workspace/...）。"""

    @abstractmethod
    def shell_path(self, agent_path: str) -> str:
        """产品语言（/workspace/...）→ shell 内视角路径。"""

    @abstractmethod
    def build_command(self, argv: list[str], chdir: str) -> list[str]:
        """构造完整宿主侧 spawn argv（chdir 为 shell 内视角路径）。"""

    @abstractmethod
    def run(self, argv: list[str], chdir: str, timeout: Optional[int] = None,
            extra_env: Optional[dict] = None) -> subprocess.CompletedProcess:
        """一次性执行（capture_output + text）。timeout 缺省取产品级默认。"""

    @abstractmethod
    def spawn(self, argv: list[str], chdir: str,
              extra_env: Optional[dict] = None) -> subprocess.Popen:
        """长驻执行（stdin/stdout 管道、stderr 并入 stdout）——持久 Shell 用。"""

    @abstractmethod
    def agent_python_bin(self) -> str:
        """python 解释器的沙箱内路径（工具构造 argv 用）。"""

    @abstractmethod
    def agent_node_bin(self) -> str:
        """node 解释器的沙箱内路径（不可用时返回 "node" 由 PATH 解析）。"""

    @abstractmethod
    def host_to_agent_path(self, path: str,
                           extra_ro_mounts: Optional[dict] = None,
                           system_mounts: Optional[dict] = None) -> Optional[str]:
        """宿主绝对路径 → 沙箱 /workspace 路径；不在允许范围返回 None。

        extra_ro_mounts/system_mounts 可覆盖实例上下文（缺省用构造时传入的表）。
        """


class SandboxBackend(ABC):
    """
    OS 沙箱后端（Strategy）。实例由 registry 持有；probe
    与会话上下文无关，make_runner 按会话参数构建 Runner。
    """

    name: str = ""
    level: str = SANDBOX_LEVEL_NONE

    @abstractmethod
    def probe(self) -> None:
        """冒烟自检。不可用抛 SandboxProbeError（含失败形态分类）。"""

    @abstractmethod
    def make_runner(self, workspace_dir: str,
                    extra_ro_mounts: Optional[dict[str, str]] = None,
                    system_dir: Optional[str] = None) -> SandboxRunner:
        """构建会话级运行器（绑定 workspace 与挂载上下文）。"""


def _posix_tail(path: str, root: str) -> str:
    """取 path 相对 root 的余段并规范化为 "/" 分隔（产品语言恒定 posix 形态；
    Windows 宿主路径余段为 "\\"，posix 平台本函数为字节级恒等）"""
    return path[len(root):].replace("\\", "/")


def host_to_sandbox(path: str, workspace_dir: str,
                    extra_ro_mounts: Optional[dict[str, str]] = None,
                    system_mounts: Optional[dict[str, str]] = None) -> Optional[str]:
    """
    将宿主机绝对路径转换为产品语言 /workspace 路径（轴 A 公共纯函数）。

    - workspace_dir 及其子路径 → /workspace/...
    - extra_ro_mounts 值（如 skills 目录）及其子路径 → /workspace/<虚拟段>/...
    - system_mounts 值（系统数据段 .git/.tmp 等）及其子路径 → /workspace/<名称>/...
    - 其余返回 None（不在任何允许的宿主范围内）

    Windows 路径大小写不敏感：前缀比对经 normcase（posix 恒等）。
    """
    if not path or not os.path.isabs(path):
        return None
    p, ws = os.path.normcase(path), os.path.normcase(workspace_dir)
    if p == ws or p.startswith(ws + os.sep):
        return WORKSPACE_AGENT_ROOT + _posix_tail(path, workspace_dir)
    for virt, host_path in {**(extra_ro_mounts or {}), **(system_mounts or {})}.items():
        if not host_path:
            continue
        hp = os.path.normcase(host_path)
        if p == hp or p.startswith(hp + os.sep):
            return f"{WORKSPACE_AGENT_ROOT}/{virt}" + _posix_tail(path, host_path)
    return None


def agent_path_to_host(agent_path: str, workspace_dir: str,
                       extra_ro_mounts: Optional[dict[str, str]] = None,
                       system_mounts: Optional[dict[str, str]] = None) -> str:
    """
    产品语言 /workspace 路径 → 宿主机绝对路径（真实根后端的 shell 视角）。

    虚拟段（extra_ro_mounts/system_mounts）优先按表翻译；其余 /workspace/xxx
    直落 workspace_dir/xxx；非 /workspace 前缀原样返回（已是宿主路径）。
    """
    root = WORKSPACE_AGENT_ROOT
    if agent_path == root:
        return workspace_dir
    if not agent_path.startswith(root + "/"):
        return agent_path
    rest = agent_path[len(root) + 1:]
    for virt, host_path in {**(extra_ro_mounts or {}), **(system_mounts or {})}.items():
        if host_path and (rest == virt or rest.startswith(virt + "/")):
            inner = rest[len(virt):].lstrip("/")
            # 产品语言 "/" 分段 join（Windows os.path.join 保留入参原分隔符，
            # "x/y" 直拼会产出混合分隔路径；posix 平台行为恒等）
            return host_path if not inner else os.path.join(host_path, *inner.split("/"))
    return os.path.join(workspace_dir, *rest.split("/"))
