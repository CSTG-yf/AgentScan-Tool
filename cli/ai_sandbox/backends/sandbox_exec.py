# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2026/09/16'
__desc__ = 'sandbox-exec 沙箱后端（macOS Seatbelt，WEAK）'

"""
sandbox-exec 沙箱后端（macOS，WEAK）

全部行为按 2026-09-16 mac 真机探针定稿（28/28 + 14/14 PASS，
见 app/probe/macprobe/ 与《多平台适配macOS探针验证报告》）：

- SBPL：deny-default 白名单模型；路径规则必须 canonical 规范化
  （父链 realpath + 末段字面量——/tmp→/private/tmp 字面形态永不命中）；
- 必备规则：`(allow sysctl-read)`（zsh 5.9 darwin25 启动读 hw.*，缺失
  = 静默死亡）、`(allow file-write* (literal "/dev/null"))`（cd 前奏
  2>/dev/null 必需）、`$TMPDIR` 显式放行；
- 网络默认放行（对齐 bwrap 现状，可配置收紧）；
- `.git` 保护 = 双路径 canonical deny（物理目标 + farm 链接路径末段
  字面量），否则 rm/mv 链接本体可断裂 farm；
- 无挂载命名空间 → 虚拟段用 workspace 内 symlink farm（.skills/.git/
  .tmp → 宿主物理目录），只读由"目标路径不放行"实现（subpath 按解析
  后路径匹配，farm 天然无逃逸）；
- agent 视角 workspace = 宿主真实路径（sandbox-exec 无路径重映射，
  LLM 自由文本命令不可翻译——业界同构），由 Runner.agent_root()/双向
  翻译与产品路径语言（/workspace，config.SANDBOX_WORKSPACE_ROOT）衔接；
- kill wrapper 即级联（探针 T13：kill sandbox-exec 后沙箱内子进程一并
  终止），_PersistentShell 的 proc.kill() 模式可直接复用。
"""

import os
import shutil
import subprocess
import tempfile
from typing import Optional

from .. import settings as config
from ..base import (
    PROBE_DEFECT, PROBE_MISSING, PROBE_NESTED, SANDBOX_LEVEL_WEAK,
    SandboxBackend, SandboxProbeError, SandboxRunner,
    agent_path_to_host, host_to_sandbox,
)

# 冒烟测试超时（秒）
SANDBOX_EXEC_SMOKE_TIMEOUT = 20

SBPL_SMOKE = """\
(version 1)
(deny default)
(allow file-read*)
(allow process-exec*)
(allow process-fork)
(allow sysctl-read)
"""


def canonical_path(p: str) -> str:
    """路径规范化（探针 T8 定稿）：解析父目录全部符号链接、保留末段字面量。

    /tmp/… → /private/tmp/…（两种访问形态都命中）；farm 链接段（ws/.git）
    保留链接路径本身用于 deny（防 rm/mv 链接本体）。
    """
    return os.path.join(os.path.realpath(os.path.dirname(p)), os.path.basename(p))


def build_sbpl_profile(workspace_dir: str,
                       writable_paths: list[str],
                       deny_paths: list[str],
                       allow_network: bool = True) -> str:
    """生成 SBPL profile（探针 MAIN 模板逐字复刻，规则顺序经验证）。

    writable_paths/deny_paths 均按 canonical 形态写入；deny 声明在 allow
    之后（探针 T6 验证：ws/.git 链接路径 deny 覆盖 ws 子路径 allow）。
    """
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow file-read*)",
        "(allow process-exec*)",
        "(allow process-fork)",
    ]
    if allow_network:
        lines.append("(allow network*)")
    lines.append("(allow sysctl-read)")
    # zsh 5.9 darwin25 启动读 hw.* sysctl；缺失 = 静默死亡（探针 T12b）
    lines.append('(allow file-write* (literal "/dev/null"))')
    # cd 前奏 2>/dev/null 必需（缺失 = 前奏整条中止，探针 Z9a）
    for p in writable_paths:
        lines.append(f'(allow file-write* (subpath "{canonical_path(p)}"))')
    for p in deny_paths:
        lines.append(f'(deny file-write* (subpath "{canonical_path(p)}"))')
    return chr(10).join(lines) + chr(10)


def _ensure_farm_link(link_path: str, target: str) -> None:
    """幂等创建虚拟段 symlink（farm）；脏链接重建，非链接同名项报错。

    单树布局下 target 物理就在 workspace 内（system_root == host_root），
    此时 link 与 target 同一路径——直接确保目录存在，无 farm 必要。
    """
    if os.path.normpath(link_path) == os.path.normpath(target):
        os.makedirs(target, exist_ok=True)
        return
    if os.path.islink(link_path):
        if os.path.realpath(link_path) == os.path.realpath(target):
            return  # 已正确指向
        os.unlink(link_path)  # 脏链接（目标漂移）重建
    elif os.path.exists(link_path):
        raise ValueError(
            f"[SANDBOX] 虚拟段路径已被非链接条目占用: {link_path}")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    os.makedirs(target, exist_ok=True)
    os.symlink(target, link_path)


class SandboxExecRunner(SandboxRunner):
    """sandbox-exec 会话级运行器（profile 长持 + symlink farm）"""

    def __init__(self, workspace_dir: str,
                 extra_ro_mounts: Optional[dict[str, str]] = None,
                 system_dir: Optional[str] = None):
        from ..workspace import system_mounts_for
        self._workspace_dir = workspace_dir
        self._extra_ro_mounts = extra_ro_mounts or {}
        self._system_mounts = system_mounts_for(system_dir) if system_dir else {}

        # ---- symlink farm：虚拟段 → 宿主物理目录（替代 bwrap 挂载）----
        # 只读段（skills 等）：目标不进白名单 → 天然只读（探针 T7）。
        # 系统数据段全部建链接（含 .git：agent 视角可读，删改由 profile
        # 双路径 deny 拦截——物理目标 + 链接本体，探针 T5b/T6 定稿）；
        # .git 目标目录先确保存在。
        for virt, host_path in self._extra_ro_mounts.items():
            if host_path:
                _ensure_farm_link(os.path.join(workspace_dir, virt), host_path)
        for name, host_path in self._system_mounts.items():
            if not host_path:
                continue
            if name == config.GIT_DIR_NAME:
                os.makedirs(host_path, exist_ok=True)
            _ensure_farm_link(os.path.join(workspace_dir, name), host_path)

        # ---- SBPL profile（会话生命周期长持的临时文件）----
        writable = [workspace_dir, tempfile.gettempdir()]
        # tempfile.gettempdir() 已覆盖 $TMPDIR（per-user /private/var/folders/…）
        for name, host_path in self._system_mounts.items():
            if host_path and name != config.GIT_DIR_NAME:
                writable.append(host_path)
        deny = [os.path.join(self._system_mounts[config.GIT_DIR_NAME], "")
                if config.GIT_DIR_NAME in self._system_mounts else None,
                os.path.join(workspace_dir, config.GIT_DIR_NAME)]
        deny = [p for p in deny if p]
        profile = build_sbpl_profile(workspace_dir, writable, deny)
        fd, self._profile_path = tempfile.mkstemp(suffix=".sb", prefix="aa-sbx-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(profile)

    def build_command(self, argv: list[str], chdir: str) -> list[str]:
        # chdir 不进 argv（sandbox-exec 无 --chdir），由 run/spawn 以 cwd 落实
        return ["sandbox-exec", "-f", self._profile_path, *argv]

    def run(self, argv: list[str], chdir: str, timeout: Optional[int] = None,
            extra_env: Optional[dict] = None) -> subprocess.CompletedProcess:
        env = {**os.environ, **extra_env} if extra_env else None
        return subprocess.run(
            self.build_command(argv, chdir), cwd=chdir,
            capture_output=True, text=True,
            timeout=timeout or config.PYTHON_MAX_TIMEOUT_SECONDS, env=env)

    def spawn(self, argv: list[str], chdir: str,
              extra_env: Optional[dict] = None) -> subprocess.Popen:
        env = {**os.environ, **extra_env} if extra_env else None
        return subprocess.Popen(
            self.build_command(argv, chdir), cwd=chdir,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=env)

    def close(self) -> None:
        """Remove the per-session Seatbelt profile after all children exit."""
        try:
            os.unlink(self._profile_path)
        except FileNotFoundError:
            pass

    # ---- 路径语言（shell 视角 = 宿主真实路径）----

    def agent_root(self) -> str:
        return self._workspace_dir

    def agent_path(self, shell_path: str) -> str:
        """shell 视角（真实路径）→ 产品语言（/workspace）"""
        return host_to_sandbox(shell_path, self._workspace_dir,
                               self._extra_ro_mounts, self._system_mounts) \
            or shell_path

    def shell_path(self, agent_path: str) -> str:
        """产品语言（/workspace/...）→ shell 视角（真实路径）"""
        return agent_path_to_host(agent_path, self._workspace_dir,
                                  self._extra_ro_mounts, self._system_mounts)

    def host_to_agent_path(self, path: str,
                           extra_ro_mounts: Optional[dict] = None,
                           system_mounts: Optional[dict] = None) -> Optional[str]:
        return host_to_sandbox(
            path, self._workspace_dir,
            extra_ro_mounts if extra_ro_mounts is not None else self._extra_ro_mounts,
            system_mounts if system_mounts is not None else self._system_mounts)

    def agent_python_bin(self) -> str:
        # 真实路径直接可见（无中性挂载），python/node 同 PATH 解析
        return config.PYTHON_PATH

    def agent_node_bin(self) -> str:
        return config.resolve_node_bin() or "node"


class SandboxExecBackend(SandboxBackend):
    """sandbox-exec 后端（macOS Seatbelt，WEAK）"""

    name = "sandbox-exec"
    level = SANDBOX_LEVEL_WEAK

    def probe(self) -> None:
        """
        冒烟自检：最小 profile 下沙箱内执行 /usr/bin/true。

        失败形态分流：二进制缺失 / profile 语法错
        （rc=65，stderr 带 line/column）/ 父进程已沙箱（rc=71，
        Seatbelt 不可嵌套——换未沙箱终端运行）。
        """
        if shutil.which("sandbox-exec") is None:
            raise SandboxProbeError(
                "未找到 sandbox-exec（macOS 系统自带；若在非 macOS 平台"
                "出现此错误属注册异常）", PROBE_MISSING)
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False) as f:
                f.write(SBPL_SMOKE)
                profile_path = f.name
            try:
                r = subprocess.run(
                    ["sandbox-exec", "-f", profile_path, "/usr/bin/true"],
                    capture_output=True, text=True,
                    timeout=SANDBOX_EXEC_SMOKE_TIMEOUT)
            finally:
                os.unlink(profile_path)
        except subprocess.TimeoutExpired:
            raise SandboxProbeError(
                f"sandbox-exec 冒烟测试超时（>{SANDBOX_EXEC_SMOKE_TIMEOUT}s）",
                PROBE_DEFECT)
        except OSError as e:
            raise SandboxProbeError(f"无法启动 sandbox-exec: {e}", PROBE_MISSING)
        if r.returncode != 0:
            detail = (r.stderr or "").strip() or f"exit code {r.returncode}"
            if r.returncode == 71 or "Operation not permitted" in detail:
                # Seatbelt 一次性且不可嵌套：父进程已在沙箱内（IDE 终端等）
                raise SandboxProbeError(
                    f"无法应用沙箱 profile（rc={r.returncode}）: {detail}。"
                    "当前父进程可能已运行在沙箱内（Seatbelt 不可嵌套），"
                    "请在未沙箱化的终端（如系统 Terminal）运行", PROBE_NESTED)
            raise SandboxProbeError(
                f"sandbox-exec 冒烟测试失败（沙箱内执行 /usr/bin/true）: {detail}",
                PROBE_DEFECT)

    def make_runner(self, workspace_dir: str,
                    extra_ro_mounts: Optional[dict[str, str]] = None,
                    system_dir: Optional[str] = None) -> SandboxRunner:
        return SandboxExecRunner(workspace_dir,
                                 extra_ro_mounts=extra_ro_mounts,
                                 system_dir=system_dir)
