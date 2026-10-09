# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2024/7/19 09:27'
__desc__ = 'bwrap 沙箱后端（BwrapBuilder 原类保留 + Backend/Runner 薄适配）'

"""
bwrap 沙箱后端（Linux，STRONG）

- BwrapBuilder：bwrap 参数构建器（原 sandbox/bwrap.py 迁入，行为不变）；
- seccomp 过滤器生成/复用 + "/bin/sh -c 'exec 3<…' fd 外壳"是 bwrap
  私有组件，封装在 BwrapRunner 内部，不进 SandboxBackend 接口；
- BwrapBackend/BwrapRunner：对 SandboxBackend/SandboxRunner 的薄适配。
"""

import os
import shlex
import shutil
import subprocess
import tempfile
from typing import Optional

from .. import settings as config
from ..logging_compat import log
from ..workspace import SYSTEM_DATA_DIR_NAMES, system_mounts_for
from ..base import (
    PROBE_DEFECT, PROBE_MISSING, SANDBOX_LEVEL_STRONG, WORKSPACE_AGENT_ROOT,
    SandboxBackend, SandboxProbeError, SandboxRunner, host_to_sandbox,
)

__all__ = ["BwrapBuilder", "BwrapBackend", "BwrapRunner",
           "detect_python_info", "detect_node_info", "detect_git_info",
           "ensure_seccomp_filter"]

# 禁止挂载的敏感宿主路径 / 中性沙箱挂载路径统一由 config.sandbox 维护
SANDBOX_PYTHON_PREFIX = config.SANDBOX_PYTHON_PREFIX
SANDBOX_NODE_PREFIX = config.SANDBOX_NODE_PREFIX
SANDBOX_GIT_PREFIX = config.SANDBOX_GIT_PREFIX

# bwrap 冒烟测试超时（秒）
BWRAP_SMOKE_TIMEOUT = 20


# ---- 解释器/工具探测（沙箱挂载所需，自 sandbox_tools.py 迁入，行为不变）----

def detect_python_info() -> dict:
    """从 config.PYTHON_PATH 推导解释器信息（非系统路径时需挂载进沙箱）"""
    bin_path = os.path.realpath(config.PYTHON_PATH)
    bin_dir = os.path.dirname(bin_path)
    prefix = os.path.dirname(bin_dir)
    lib_dir = os.path.join(prefix, "lib")
    return {"prefix": prefix, "binDir": bin_dir, "libDir": lib_dir, "realPath": bin_path}


def detect_node_info() -> dict | None:
    """推导 node 解释器信息（非系统路径时需挂载进沙箱）

    经 config.resolve_node_bin() 解析（NODE_BIN 显式配置优先，其次系统
    PATH）；均不可用返回 None（沙箱 node 工具不可用，启动预检已告警）。
    """
    node_bin = config.resolve_node_bin()
    if not node_bin:
        return None
    bin_path = os.path.realpath(node_bin)
    bin_dir = os.path.dirname(bin_path)
    return {"prefix": os.path.dirname(bin_dir), "binDir": bin_dir, "realPath": bin_path}


def detect_git_info() -> dict | None:
    """推导 git 信息（非系统路径时需挂载进沙箱）

    经 config.resolve_git() 解析（GIT_BIN 内置优先，其次系统 PATH）；均不
    可用返回 None（沙箱内 git 不可用）。env 为内置 git 的运行时变量
    （exec-path / 模板目录），由 bwrap 侧随 prefix 重映射到中性沙箱路径。
    """
    git_bin, git_env = config.resolve_git()
    if not git_bin:
        return None
    bin_path = os.path.realpath(git_bin)
    bin_dir = os.path.dirname(bin_path)
    return {"prefix": os.path.dirname(bin_dir), "binDir": bin_dir,
            "realPath": bin_path, "env": git_env}


# ---- seccomp 过滤器（bwrap 私有组件）----

def ensure_seccomp_filter() -> str | None:
    """
    生成/复用共享 seccomp 过滤器（SESSION_DIR/.shared/seccomp.bpf）。

    失败返回 None（fail-open，文件系统隔离仍生效）。
    """
    filter_path = config.SECCOMP_FILTER_PATH
    if os.path.exists(filter_path) and os.path.getsize(filter_path) > 0:
        return filter_path
    try:
        from ..seccomp import SeccompFilter
        os.makedirs(os.path.dirname(filter_path), exist_ok=True)
        return SeccompFilter.write_filter(filter_path)
    except Exception as e:
        log.warning("seccomp 过滤器生成失败", extra={"error": str(e)})
        return None


class BwrapBuilder:
    """bwrap 沙箱参数构建器"""

    @staticmethod
    def is_system_path(path: str) -> bool:
        """判断路径是否为系统路径（已在系统目录挂载中覆盖，不需额外挂载）"""
        system_prefixes = ["/usr", "/bin", "/sbin", "/lib", "/lib64"]
        for prefix in system_prefixes:
            if path == prefix or path.startswith(prefix + "/"):
                return True
        return False

    @staticmethod
    def build_bwrap_args(
        workspace_dir: str,
        python_info: Optional[dict] = None,
        node_info: Optional[dict] = None,
        git_info: Optional[dict] = None,
        extra_ro_mounts: Optional[dict[str, str]] = None,
        system_dir: Optional[str] = None,
    ) -> list[str]:
        """
        构建 bwrap 参数列表。

        参数:
            workspace_dir: 用户工作空间目录（宿主绝对路径，挂载为 /workspace）
            python_info: Python 解释器信息 {prefix, binDir, libDir, realPath}
            node_info: Node.js 解释器信息 {prefix, binDir, libDir, realPath}
            git_info: git 信息 {prefix, binDir, realPath, env}（env 为内置 git
                的运行时变量，随 prefix 重映射到中性沙箱路径）
            extra_ro_mounts: 额外只读挂载 {虚拟段名: 宿主绝对路径}，
                宿主路径挂载为沙箱内 /workspace/<虚拟段名>（如 skills 目录）
            system_dir: 工作空间系统数据目录（.git/.tmp 等物理落点），
                以虚拟段挂回 /workspace/<名称>，保持沙箱内契约不变：
                .git 只读（防 rm -rf 破坏版本历史），其余可写

        返回:
            bwrap 参数列表（不含 bwrap 命令本身和 --chdir）
        """
        args: list[str] = []

        # ---- 1. 系统目录只读挂载 ----
        for d in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/alternatives"]:
            if os.path.exists(d):
                args += ["--ro-bind", d, d]

        # ---- 2. /etc 最小化挂载 ----
        etc_files = ["resolv.conf", "hosts", "nsswitch.conf"]
        for f in etc_files:
            p = f"/etc/{f}"
            if os.path.exists(p):
                args += ["--ro-bind", p, p]

        etc_dirs = ["ssl", "ca-certificates", "pki"]
        for d in etc_dirs:
            p = f"/etc/{d}"
            if os.path.exists(p):
                args += ["--ro-bind", p, p]

        # ---- 3. Python prefix（非系统路径时挂载到中性沙箱路径）----
        if python_info and not BwrapBuilder.is_system_path(python_info["prefix"]):
            args += ["--ro-bind", python_info["prefix"], SANDBOX_PYTHON_PREFIX]
            # libDir 不在 prefix 下时额外挂载（保持沙箱内相对位置 prefix/lib）
            lib_dir = python_info.get("libDir", "")
            if lib_dir and lib_dir != python_info["prefix"] and not lib_dir.startswith(python_info["prefix"] + "/"):
                if os.path.exists(lib_dir):
                    args += ["--ro-bind", lib_dir, f"{SANDBOX_PYTHON_PREFIX}/lib"]

        # ---- 4. Node prefix（非系统路径时挂载到中性沙箱路径）----
        if node_info and not BwrapBuilder.is_system_path(node_info["prefix"]):
            args += ["--ro-bind", node_info["prefix"], SANDBOX_NODE_PREFIX]

        # ---- 4.5 git prefix（非系统路径时挂载到中性沙箱路径）----
        # 内置 git 的编译期前缀随包分发后失效（--exec-path 指向旧路径、
        # init 报 templates not found），故按中性路径重算运行时变量注入
        if git_info and not BwrapBuilder.is_system_path(git_info["prefix"]):
            prefix = git_info["prefix"]
            args += ["--ro-bind", prefix, SANDBOX_GIT_PREFIX]
            for key, val in (git_info.get("env") or {}).items():
                rel = os.path.relpath(val, prefix)
                if not rel.startswith(".."):
                    args += ["--setenv", key, os.path.join(SANDBOX_GIT_PREFIX, rel)]

        # ---- 5. workspace 读写挂载 ----
        args += ["--bind", workspace_dir, "/workspace"]
        # Existing Git workspaces keep their metadata in the workspace itself.
        # The extracted kit only protected .git when it lived in system_dir;
        # overlay an existing in-place .git as read-only as well.
        git_metadata = os.path.join(workspace_dir, ".git")
        if os.path.lexists(git_metadata):
            args += ["--ro-bind", git_metadata, "/workspace/.git"]

        # ---- 5.5 额外只读挂载（skills 等目录 → /workspace/<虚拟段>）----
        for virt, host_path in (extra_ro_mounts or {}).items():
            if host_path and os.path.exists(host_path):
                args += ["--ro-bind", host_path, f"/workspace/{virt}"]

        # ---- 6. 系统数据段挂回（覆盖挂载）----
        # 系统数据（.git / .tmp / .screenshots / .playwright-mcp）物理落在
        # system_dir，与用户文件（workspace_dir）分离；沙箱内以虚拟段挂回
        # /workspace/<名称>，agent 视角契约不变。bwrap 按参数顺序叠加挂载，
        # 后挂载覆盖先挂载：.git 以只读重挂使沙箱内 rm -rf 无法破坏版本历史；
        # 宿主侧 git_service 直接操作文件系统，不受沙箱挂载影响。
        # 已知行为（接受）：挂载目标落在已 bind 的宿主目录内时，bwrap 会
        # 在宿主侧为目标创建空目录——用户目录可能出现同名空壳（无内容）
        if system_dir:
            for name in SYSTEM_DATA_DIR_NAMES:
                host = os.path.join(system_dir, name)
                os.makedirs(host, exist_ok=True)
                flag = "--ro-bind" if name == config.GIT_DIR_NAME else "--bind"
                args += [flag, host, f"/workspace/{name}"]

        # ---- 7. 设备/进程/tmp ----
        args += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]

        # ---- 8. 环境变量 ----
        path_entries = ["/usr/local/bin", "/usr/bin", "/bin"]
        if python_info and not BwrapBuilder.is_system_path(python_info["prefix"]):
            path_entries.insert(0, f"{SANDBOX_PYTHON_PREFIX}/bin")
        if node_info and not BwrapBuilder.is_system_path(node_info["prefix"]):
            path_entries.insert(0, f"{SANDBOX_NODE_PREFIX}/bin")
        if git_info and not BwrapBuilder.is_system_path(git_info["prefix"]):
            path_entries.insert(0, f"{SANDBOX_GIT_PREFIX}/bin")
        args += ["--setenv", "PATH", ":".join(path_entries)]
        if python_info:
            args += ["--setenv", "PYTHON_EXECUTABLE", BwrapBuilder.sandbox_python_bin(python_info)]
        if node_info:
            args += ["--setenv", "NODE_EXECUTABLE",
                     BwrapBuilder.sandbox_node_bin(node_info)]
        args += ["--setenv", "HOME", "/tmp"]

        # ---- 9. 隔离参数 ----
        args += ["--die-with-parent"]
        args += ["--unshare-user-try"]
        args += ["--new-session"]
        args += ["--unshare-pid"]

        return args

    @staticmethod
    def sandbox_python_bin(python_info: Optional[dict]) -> str:
        """返回 python 解释器的沙箱内执行路径（运行时挂载在 SANDBOX_PYTHON_PREFIX）"""
        if not python_info:
            return "python3"
        if BwrapBuilder.is_system_path(python_info["prefix"]):
            return python_info["realPath"]
        return f"{SANDBOX_PYTHON_PREFIX}/bin/{os.path.basename(python_info['realPath'])}"

    @staticmethod
    def sandbox_node_bin(node_info: Optional[dict]) -> str:
        """返回 node 解释器的沙箱内执行路径（运行时挂载在 SANDBOX_NODE_PREFIX）"""
        if not node_info:
            return "node"
        if BwrapBuilder.is_system_path(node_info["prefix"]):
            return node_info["realPath"]
        return f"{SANDBOX_NODE_PREFIX}/bin/{os.path.basename(node_info['realPath'])}"


class BwrapRunner(SandboxRunner):
    """bwrap 会话级运行器（隔离外壳 + seccomp 私有封装）"""

    def __init__(self, workspace_dir: str,
                 extra_ro_mounts: Optional[dict[str, str]] = None,
                 system_dir: Optional[str] = None):
        self._workspace_dir = workspace_dir
        self._extra_ro_mounts = extra_ro_mounts or {}
        self._system_mounts = system_mounts_for(system_dir) if system_dir else {}
        self._python_info = detect_python_info()
        self._node_info = detect_node_info()
        self._args = BwrapBuilder.build_bwrap_args(
            workspace_dir=workspace_dir,
            python_info=self._python_info, node_info=self._node_info,
            git_info=detect_git_info(), extra_ro_mounts=extra_ro_mounts,
            system_dir=system_dir)
        self._seccomp = ensure_seccomp_filter()

    def agent_root(self) -> str:
        # bwrap 将 workspace 挂载为 /workspace 虚拟根——shell 视角与产品语言恒等
        return WORKSPACE_AGENT_ROOT

    def agent_path(self, shell_path: str) -> str:
        return shell_path

    def shell_path(self, agent_path: str) -> str:
        return agent_path

    def build_command(self, argv: list[str], chdir: str) -> list[str]:
        cmd = ["bwrap", *self._args, "--chdir", chdir, *argv]
        if not self._seccomp:
            return cmd
        # seccomp: 通过 sh 在 fd 3 打开过滤器后 exec bwrap（--seccomp 3），
        # 避免动父进程 fd 表
        script = f'exec 3<{shlex.quote(self._seccomp)}; exec "$@"'
        return ["/bin/sh", "-c", script, "bwrap-run", *cmd]

    def run(self, argv: list[str], chdir: str, timeout: Optional[int] = None,
            extra_env: Optional[dict] = None) -> subprocess.CompletedProcess:
        env = {**os.environ, **extra_env} if extra_env else None
        return subprocess.run(
            self.build_command(argv, chdir), capture_output=True, text=True,
            timeout=timeout or config.PYTHON_MAX_TIMEOUT_SECONDS, env=env)

    def spawn(self, argv: list[str], chdir: str,
              extra_env: Optional[dict] = None) -> subprocess.Popen:
        env = {**os.environ, **extra_env} if extra_env else None
        return subprocess.Popen(
            self.build_command(argv, chdir), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)

    def agent_python_bin(self) -> str:
        return BwrapBuilder.sandbox_python_bin(self._python_info)

    def agent_node_bin(self) -> str:
        return BwrapBuilder.sandbox_node_bin(self._node_info)

    def host_to_agent_path(self, path: str,
                           extra_ro_mounts: Optional[dict] = None,
                           system_mounts: Optional[dict] = None) -> Optional[str]:
        return host_to_sandbox(
            path, self._workspace_dir,
            extra_ro_mounts if extra_ro_mounts is not None else self._extra_ro_mounts,
            system_mounts if system_mounts is not None else self._system_mounts)


class BwrapBackend(SandboxBackend):
    """bwrap 后端（Linux，STRONG）"""

    name = "bwrap"
    level = SANDBOX_LEVEL_STRONG

    def probe(self) -> None:
        """
        冒烟自检：复用生产参数构建器，在沙箱内执行 /bin/true。

        覆盖 user namespace / pid namespace / 设备与 /proc 挂载等内核能力，
        避免"已安装但无法创建沙箱"的环境（如禁用 unprivileged userns 的
        宿主）带病启动。不可用抛 SandboxProbeError（形态分类见 base.py）。
        """
        if shutil.which("bwrap") is None:
            raise SandboxProbeError(
                "未安装 bubblewrap（bwrap）— 沙箱命令执行必需，"
                "请先安装（Debian/Ubuntu: apt-get install -y bubblewrap）",
                PROBE_MISSING)
        try:
            with tempfile.TemporaryDirectory() as tmp_ws:
                args = BwrapBuilder.build_bwrap_args(workspace_dir=tmp_ws)
                cmd = ["bwrap", *args, "--chdir", "/workspace", "/bin/true"]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=BWRAP_SMOKE_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise SandboxProbeError(
                f"bwrap 沙箱冒烟测试超时（>{BWRAP_SMOKE_TIMEOUT}s）", PROBE_DEFECT)
        except OSError as e:
            raise SandboxProbeError(f"无法启动 bwrap: {e}", PROBE_MISSING)
        if r.returncode != 0:
            detail = (r.stderr or "").strip() or f"exit code {r.returncode}"
            raise SandboxProbeError(
                f"bwrap 沙箱冒烟测试失败（沙箱内执行 /bin/true）: {detail}",
                PROBE_DEFECT)

    def make_runner(self, workspace_dir: str,
                    extra_ro_mounts: Optional[dict[str, str]] = None,
                    system_dir: Optional[str] = None) -> SandboxRunner:
        return BwrapRunner(workspace_dir,
                           extra_ro_mounts=extra_ro_mounts, system_dir=system_dir)
