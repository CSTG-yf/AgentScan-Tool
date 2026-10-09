# -*- coding: utf-8 -*-
"""ai-sandbox-kit —— 可移植的 AI 代码执行安全层（沙箱 + 审批 + 路径守卫）

从 Autonomous Agent（FastAPI + LangGraph 自主智能体）项目中提取。三层能力：

1) 隔离执行（轴 A）：SandboxBackend / SandboxRunner 抽象 + 四个后端
   （Linux bwrap+seccomp / macOS sandbox-exec / Windows AppContainer / null 直执），
   平台候选链自动探测，strict/graded 两种降级策略；
2) Shell 协议（轴 B）：ShellProfile（bash / zsh / pwsh / cmd）——引号、编码、
   cwd 前奏、结束标记、启动旗标，跨平台命令执行语义统一；
3) 策略管控：命令审批规则链（deny > ask > allow）、只读白名单、路径越界守卫、
   HOME 只读 + workspace 唯一可写、.git 只读保护。

最小用法：
    from ai_sandbox import SandboxSession, ApprovalGate, resolve_path

    with SandboxSession("/tmp/ws") as s:
        print(s.shell("echo hi"))
"""

from . import settings                       # noqa: F401  （导入即加载 .env）
from .approval import (ApprovalGate, Decision, decide, langgraph_ask_handler,
                       match_dangerous, match_denied, shell_allowlisted,
                       split_shell_segments)
from .base import (PROBE_DEFECT, PROBE_MISSING, PROBE_NESTED,
                   SANDBOX_LEVEL_NONE, SANDBOX_LEVEL_STRONG, SANDBOX_LEVEL_WEAK,
                   WORKSPACE_AGENT_ROOT, SandboxBackend, SandboxProbeError,
                   SandboxRunner, agent_path_to_host, host_to_sandbox)
from .executor import (PersistentShell, SandboxSession, cap_proc_output,
                       offload_large_output, write_temp_code)
from .path_guard import guard_within, is_readonly_mount, resolve_path
from .registry import (SandboxReport, get_report, get_sandbox_backend,
                       register_backend, reset, resolve)
from .shell_profile import ShellProfile, get_shell_profile
from .workspace import (from_workspace_path, is_system_data_path,
                        system_mounts_for, to_workspace_path)

__version__ = "1.0.0"

__all__ = [
    # 执行
    "SandboxSession", "PersistentShell", "cap_proc_output",
    "offload_large_output", "write_temp_code",
    # 后端与解析
    "resolve", "get_report", "get_sandbox_backend", "register_backend", "reset",
    "SandboxReport", "SandboxBackend", "SandboxRunner", "SandboxProbeError",
    "WORKSPACE_AGENT_ROOT", "SANDBOX_LEVEL_STRONG", "SANDBOX_LEVEL_WEAK",
    "SANDBOX_LEVEL_NONE", "PROBE_MISSING", "PROBE_DEFECT", "PROBE_NESTED",
    "host_to_sandbox", "agent_path_to_host",
    # Shell 协议
    "ShellProfile", "get_shell_profile",
    # 审批策略
    "ApprovalGate", "Decision", "decide", "langgraph_ask_handler",
    "match_dangerous", "match_denied", "shell_allowlisted",
    "split_shell_segments",
    # 路径守卫
    "resolve_path", "guard_within", "is_readonly_mount",
    "to_workspace_path", "from_workspace_path", "system_mounts_for",
    "is_system_data_path",
]
