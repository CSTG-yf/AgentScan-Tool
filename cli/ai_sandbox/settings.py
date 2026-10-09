# -*- coding: utf-8 -*-
"""沙箱层配置（可移植接缝之二）

本文件 = 「原项目 config 包中沙箱相关常量的自包含替代」。
- 第一部分（本段）是环境变量读取器与路径派生，等价于原 config/_env.py +
  config/paths.py + config/tools.py + config/agent.py 中沙箱用到的部分；
- 第二部分（文件末尾）**逐字复制**原项目 config/sandbox.py 的策略与正则，
  不做任何改动——审批档位、危险命令正则、只读白名单、路径黑名单以原文为准。

取值优先级（高 → 低）：
    进程环境变量 > <安装根>/.env > 代码默认值

与源项目的差异（仅为可移植性，不影响安全语义）：
1) PYTHON_PATH / NODE_BIN / GIT_BIN 缺省值改为「内置 runtime 目录若存在则用，
   否则回落 sys.executable / PATH 探测」——源项目假定 runtime/ 随包分发，
   独立移植时该目录通常不存在；
2) 安装根由本包位置推导，可用 AA_INSTALL_ROOT 覆盖。
"""

import os
import platform
import shutil
import sys

# ============================================================
#  一、环境变量读取器（逐字来自原 config/_env.py，仅调整 _install_root）
# ============================================================

__all__ = ["env_str", "env_int", "env_float", "env_bool", "env_list", "load_env_file"]

_DEFAULT_LOADED = False


def _install_root() -> str:
    """安装根目录（ai_sandbox/ -> <安装根>）；可用 AA_INSTALL_ROOT 覆盖。"""
    override = os.environ.get("AA_INSTALL_ROOT")
    if override:
        return os.path.abspath(override)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env_file(path: str | None = None) -> str | None:
    """加载 .env 到进程环境（不覆盖已存在的变量）；默认 <安装根>/.env。"""
    global _DEFAULT_LOADED
    if path is None:
        if _DEFAULT_LOADED:
            return None
        _DEFAULT_LOADED = True
        path = os.path.join(_install_root(), ".env")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, val = line.partition("=")
        if not sep:
            continue
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        else:
            idx = val.find(" #")
            if idx != -1:
                val = val[:idx].rstrip()
        if key and key not in os.environ:
            os.environ[key] = val
    return path


def env_str(name: str, default: str) -> str:
    """读取字符串环境变量；未设置或为空串时取默认值"""
    val = os.environ.get(name)
    return default if val is None or val == "" else val


def env_int(name: str, default: int) -> int:
    """读取整型环境变量；未设置或非法时取默认值"""
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    """读取浮点环境变量；未设置或非法时取默认值"""
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    try:
        return float(val.strip())
    except ValueError:
        return default


def env_bool(name: str, default: bool) -> bool:
    """读取布尔环境变量（1/true/yes/on 为真，0/false/no/off 为假）"""
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    v = val.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def env_list(name: str, default: list[str], sep: str = ",") -> list[str]:
    """读取列表环境变量（默认逗号分隔）；未设置取默认值"""
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return list(default)
    items = [item.strip() for item in val.split(sep)]
    return [item for item in items if item] or list(default)


load_env_file()   # 子模块导入期即可读到 .env（与源项目一致）

# ============================================================
#  二、运行画像（原 config/profile.py，唯一事实源）
# ============================================================
PROFILE = env_str(
    "AA_PROFILE", "server" if sys.platform.startswith("linux") else "desktop")

# ============================================================
#  三、路径（原 config/paths.py 中沙箱用到的部分）
# ============================================================
INSTALL_ROOT = _install_root()
RUNTIME_ROOT = os.path.join(INSTALL_ROOT, "runtime")


def runtime_platform_key() -> str:
    """当前平台目录名（runtime/ 下分层：linux-x86_64 / darwin-arm64 / windows-x86_64 ...）"""
    if os.name == "nt":
        os_name = "windows"
    elif sys.platform == "darwin":
        os_name = "darwin"
    else:
        os_name = "linux"
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64" if os_name == "darwin" else "aarch64"
    elif machine in ("loongarch64", "loongarch"):
        arch = "loongarch64"
    else:
        arch = machine
    return f"{os_name}-{arch}"


RUNTIME_DIR = os.path.join(RUNTIME_ROOT, runtime_platform_key())
SHARED_RUNTIME_DIR = os.path.join(RUNTIME_ROOT, "shared")

_WIN = os.name == "nt"

# 会话数据根目录（平台感知；源项目同款默认值）
def _default_session_dir() -> str:
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/autonomous-agent")
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "autonomous-agent")
    return os.path.expanduser("~/autonomous-agent-workspace")


SESSION_DIR = env_str("AA_SESSION_DIR", _default_session_dir())


def _bundled_or(default_path: str, fallback: str) -> str:
    """内置 runtime 存在则用内置，否则回落（独立移植时的可移植性改进）"""
    return default_path if os.path.exists(default_path) else fallback


# Python 解释器（沙箱 python 工具用）
PYTHON_PATH = env_str("AA_PYTHON_PATH", _bundled_or(
    os.path.join(RUNTIME_DIR, "python",
                 "python.exe" if _WIN else os.path.join("bin", "python3")),
    sys.executable))

# Node.js（置空则回退系统 PATH 探测）
NODE_BIN = env_str("AA_NODE_BIN", _bundled_or(
    os.path.join(RUNTIME_DIR, "node", "node.exe" if _WIN else os.path.join("bin", "node")),
    ""))

# git（内置优先，回退系统 PATH；darwin 不回退，见 resolve_git）
GIT_BIN = env_str("AA_GIT_BIN", _bundled_or(
    os.path.join(RUNTIME_DIR, "git",
                 os.path.join("cmd", "git.exe") if _WIN else os.path.join("bin", "git")),
    ""))
GIT_EXEC_PATH = os.path.join(RUNTIME_DIR, "git", "libexec", "git-core")
GIT_TEMPLATE_DIR = os.path.join(RUNTIME_DIR, "git", "share", "git-core", "templates")

# 隐藏名统一约定（"." 前缀 = 内部数据，对用户/模型隐藏）
TMP_DIR_NAME = ".tmp"
GIT_DIR_NAME = ".git"
SCREENSHOTS_DIR_NAME = ".screenshots"
PLAYWRIGHT_MCP_DIR_NAME = ".playwright-mcp"

# 沙箱内虚拟只读挂载段名（/workspace/<段名>）
WORKSPACE_SKILLS_VIRT = ".skills"
WORKSPACE_SESSION_SKILLS_VIRT = ".session_skills"
WORKSPACE_RO_VIRT_NAMES = [WORKSPACE_SKILLS_VIRT, WORKSPACE_SESSION_SKILLS_VIRT]

# 系统数据段名（物理外置于 system_root，沙箱内经虚拟段挂回 /workspace/<名称>）
WORKSPACE_SYSTEM_VIRT_NAMES = [
    GIT_DIR_NAME, TMP_DIR_NAME, SCREENSHOTS_DIR_NAME, PLAYWRIGHT_MCP_DIR_NAME,
]
# 沙箱内强制只读保护的 workspace 隐藏目录（bwrap ro-bind 覆盖挂载）
WORKSPACE_SANDBOX_RO_DIRS = [GIT_DIR_NAME]

# 沙箱内工作空间挂载点（agent 侧契约路径，跨平台恒定）
SANDBOX_WORKSPACE_ROOT = "/workspace"

# seccomp 过滤器落点与共享目录
SHARED_DIR = os.path.join(SESSION_DIR, ".shared")
SECCOMP_FILTER_PATH = os.path.join(SHARED_DIR, "seccomp.bpf")


def ensure_session_dir() -> str:
    """确保会话目录与共享目录存在（沙箱写 seccomp 过滤器前调用）"""
    os.makedirs(SESSION_DIR, exist_ok=True)
    os.makedirs(SHARED_DIR, exist_ok=True)
    return SESSION_DIR


# ---- Node / git 解析（原 config/paths.py 同源）----

def resolve_node_bin() -> str | None:
    """定位 node 可执行文件（沙箱 node 工具用）"""
    if NODE_BIN:
        return NODE_BIN if os.access(NODE_BIN, os.X_OK) else None
    return shutil.which("node")


def resolve_git() -> tuple[str | None, dict[str, str]]:
    """定位 git 及其运行时环境变量（内置 git 需注入 exec-path/模板目录）。

    darwin 不回退系统 git：/usr/bin/git 为 xcrun shim，未装 CLT 时执行会
    触发 GUI 安装弹窗（源项目 06 号文档定稿）。
    """
    if GIT_BIN and os.access(GIT_BIN, os.X_OK):
        env = {}
        if os.path.isdir(GIT_EXEC_PATH):
            env["GIT_EXEC_PATH"] = GIT_EXEC_PATH
        if os.path.isdir(GIT_TEMPLATE_DIR):
            env["GIT_TEMPLATE_DIR"] = GIT_TEMPLATE_DIR
        return GIT_BIN, env
    if sys.platform == "darwin":
        return None, {}
    return shutil.which("git"), {}


# ---- 工具执行限制（原 config/tools.py + config/agent.py 中沙箱用到的项）----
PYTHON_MAX_OUTPUT_BYTES = env_int("AA_PYTHON_MAX_OUTPUT_BYTES", 102_400)   # 100KB
PYTHON_MAX_TIMEOUT_SECONDS = env_int("AA_PYTHON_MAX_TIMEOUT_SECONDS", 120)
SHELL_OUTPUT_INLINE_MAX_CHARS = env_int("AA_SHELL_OUTPUT_INLINE_MAX_CHARS", 20_000)


# ============================================================
#  四、以上为可移植接缝；以下为沙箱策略常量（source: config/sandbox.py，逐字复制）
# ============================================================
# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2024/7/19 09:27'
__desc__ = '沙箱配置（后端选择策略 + bwrap 私有参数 + 审批正则）'

"""沙箱配置"""


# ---- 沙箱后端选择（src/sandbox/registry.py 消费）----
# 按平台候选链自动探测（linux: bwrap→null；darwin: sandbox-exec→null；
# win32: appcontainer→null），首个 probe 通过者生效，不做人工指定入口。

# 沙箱策略（跟随运行画像，不做人工覆盖）：strict = 强隔离后端不可用即
# 启动失败（服务器/受控环境，等价"锁定强隔离"）；graded = 客户端允许
# 降级 null 无隔离直执 + 醒目上报（可用性优先）
SANDBOX_POLICY = "strict" if PROFILE == "server" else "graded"

# 运行时挂载的中性沙箱路径（避免宿主路径如 /root/miniconda3 暴露沙箱目录结构）
SANDBOX_PYTHON_PREFIX = env_str("AA_SANDBOX_PYTHON_PREFIX", "/opt/sbx-python")
SANDBOX_NODE_PREFIX = env_str("AA_SANDBOX_NODE_PREFIX", "/opt/sbx-node")
SANDBOX_GIT_PREFIX = env_str("AA_SANDBOX_GIT_PREFIX", "/opt/sbx-git")

# 工作空间根路径准入黑名单（含子路径，支持 ~ 前缀；逗号分隔覆盖）：
# 登记工作空间时命中即拒绝，防止凭据等敏感目录被 agent 读写。
# ~ 前缀按 HOME（Unix）/ USERPROFILE（Windows，见 workspace 展开逻辑）
# 展开；平台专属追加项见下方 _DENIED_*（11 号 §6 缺口 6/12 补全）
_DENIED_BASE = [
    "~/.ssh", "~/.aws", "~/.gnupg",
    "/etc/shadow", "/etc/ssh", "/root",
    "/var/run", "/var/lib/secrets",
]
# Windows：密钥存储 + 注册表 hive 文件 + 页面文件 + 回收站
_DENIED_WINDOWS = [
    "~/AppData/Local/Microsoft/Crypto",
    "~/NTUSER.DAT", "~/pagefile.sys", "~/hiberfil.sys",
    "~/$Recycle.Bin",
]
# macOS：钥匙串 + Apple 应用数据 + 系统卷 + 系统数据库
_DENIED_MACOS = [
    "~/Library/Keychains",
    "~/Library/Application Support/Com.apple.*",
    "/System", "/private/var/db",
]
if sys.platform == "win32":
    _DENIED_BASE += _DENIED_WINDOWS
elif sys.platform == "darwin":
    _DENIED_BASE += _DENIED_MACOS
DENIED_HOST_PATHS = env_list("AA_DENIED_HOST_PATHS", _DENIED_BASE)

# 会话级持久 Shell：bash 工具路由到长驻 bwrap+bash 进程，
# 环境变量 / 后台进程 / shell 函数 / 工作目录跨调用保持；
# 命令超时或 shell 死亡自动重启，不可用时回退一次性执行
SHELL_PERSISTENT_ENABLED = env_bool("AA_SHELL_PERSISTENT_ENABLED", True)

# ---- bash 危险命令审批 ----
# 命中以下任一模式的命令须人工批准后才执行（LangGraph interrupt 挂起，
# 上游经 tool_approval SSE 事件展示，POST /session/interact 回复
# "approved" 批准 / 其它任何值拒绝；超时自动拒绝）。
# 子代理（delegate_agent）无审批通道，命中即拒绝（安全默认）。
BASH_APPROVAL_ENABLED = env_bool("AA_BASH_APPROVAL_ENABLED", True)
# (说明, 正则) — 说明会出现在拒绝消息与 tool_approval 事件中
# 注意：删除类命令统一收口在下方"文件删除高危档"（DELETE_*_PATTERNS），
# 不在此逐个枚举 API/命令名，避免遗漏导致漏审
BASH_DANGEROUS_PATTERNS = [
    ("强制推送 git push --force",
     r"\bgit\s+push\b[^|;&]*(?:--force(?!-with-lease)|(?<![\w-])-f\b)"),
    ("硬重置 git reset --hard",
     r"\bgit\s+reset\s+--hard\b"),
    ("磁盘格式化 mkfs",
     r"\bmkfs(?:\.\w+)?\b"),
    ("裸设备写入 dd of=/dev/…",
     r"\bdd\b[^|;&]*\bof=/dev/"),
    ("设备覆写 > /dev/sd…",
     r">\s*/dev/sd[a-z]"),
    ("系统电源操作 shutdown/reboot/halt",
     r"\b(?:shutdown|reboot|halt|poweroff)\b"),
    ("远程脚本直接执行 curl|wget … | sh",
     r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b"),
    ("根目录全开放权限 chmod -R 777 /",
     r"\bchmod\s+-R\s+777\s+/"),
]

# ---- 文件删除高危档（统一"删除动作"整类，高优先）----
# 业界教训：按 API 名逐个枚举删除操作必然漏网（fs.unlinkSync/os.remove/
# Path.unlink/单条 rm 等），且可被 bash -c / Base64 / 脚本套壳绕过。故把
# "删除"整类拎出为高优先档，命中即人工审批，不依赖枚举完整性。
# DELETE_SHELL_PATTERNS 对 bash 命令与 python/node 内嵌命令统一匹配；
# DELETE_CODE_PATTERNS 为原生删除 API，仅在 python/node（include_code_api）
# 时叠加。说明会出现在拒绝消息与 tool_approval 事件中。
DELETE_SHELL_PATTERNS = [
    ("删除文件/目录 rm（含 rm -rf 递归强删）", r"(?<![\w-])rm\s"),
    ("删除空目录 rmdir", r"(?<![\w-])rmdir\s"),
    ("删除文件 unlink", r"(?<![\w-])unlink\s"),
    ("粉碎文件 shred", r"(?<![\w-])shred\s"),
]

# pwsh 版删除高危档（Windows 探针 ⑤a + 11 号 §4 要点 5 定稿）：按解析后
# 语义匹配 Remove-Item 全部别名（ri/del/erase/rd/rm——rm 在 pwsh 也是
# Remove-Item 别名，单文件照样删，仅 rm -rf 因 Unix 旗标报错）与
# cmd 外置 del
PWSH_DELETE_SHELL_PATTERNS = [
    ("删除文件/目录 Remove-Item（含 -Recurse -Force）",
     r"(?<![\w-])(?:Remove-Item|ri|del|erase|rd|rimraf|rm)\s"),
    ("cmd 外置删除 del/erase（cmd /c 套壳）", r"(?i)\bcmd\s+/c\b[^|;&]*\b(?:del|erase|rd)\s"),
]

# pwsh 危险命令审批档（11 号 §4 首版 4 条起步，Windows 适配落地）
PWSH_DANGEROUS_PATTERNS = [
    ("强制推送 git push --force",
     r"(?i)\bgit\s+push\b[^|;&]*(?:--force(?!-with-lease)|(?<![\w-])\-f\b)"),
    ("卷格式化 Format-Volume / Initialize-Disk / Clear-Disk",
     r"(?i)\b(?:Format-Volume|Initialize-Disk|Clear-Disk|format\.com)\b"),
    ("注册表删除 reg delete / Remove-Item HK…",
     r"(?i)\b(?:reg\s+delete|Remove-Item\s+(?:-Path\s+)?HK\w*[:\\])"),
    ("强杀进程 Stop-Process / taskkill /f",
     r"(?i)\b(?:Stop-Process|taskkill)\b[^|;&]*(?:/f|-Force)"),
]

# pwsh 绝对拒绝档（deny，不进人工审批，11 号 §4 要点 1）：密文无法
# 审查，主图命中也直接拒绝（区别于子代理 deny：无审批通道可解锁）。
# 参数缩写按任意前缀匹配（PowerShell 缩写机制：-e/-en/-enc/…/
# -encodedcommand 均合法且大小写不敏感，枚举交替项必漏），逐字母可选
PWSH_DENY_PATTERNS = [
    ("Base64 密文执行 -EncodedCommand（无法审查）",
     r"(?i)(?:^|[\s/])-en?c?o?d?e?d?c?o?m?m?a?n?d?\s+[A-Za-z0-9+/=]{16,}"),
]

# pwsh 只读白名单（11 号 §5 判定原则：无等价的不进，宁缺勿滥）
PWSH_ALLOWLIST_PREFIXES = [
    "ls", "cat", "pwd", "echo", "cd", "date", "git status", "git diff",
    "git log", "git show", "git blame", "git rev-parse", "git ls-files",
    "git tag",
    "Get-ChildItem", "Get-Content", "Get-Item", "Get-Location",
    "Get-Command", "Select-String", "Select-Object", "Measure-Object",
    "Compare-Object", "Write-Output", "Test-Path", "Get-Date", "whoami",
    "tree.com",
]

# ---- cmd 版（AppContainer 后端降级通道，真机定稿 2026-09-29）----
# AC 后端内 pwsh 全系无法启动（"拒绝访问"），shell 工具降级 cmd 语义
# （get_shell_profile 后端感知 → CmdShellProfile）。正则与 pwsh 版
# 同源收口：删除动作整类拎出、危险档覆盖 Windows 破坏性命令、白名单
# 只收只读内建命令（dir 枚举在 AC 内被拒，仅靠白名单放行后自然报错，
# 工具描述引导改用文件工具）。
CMD_DELETE_SHELL_PATTERNS = [
    ("删除文件/目录 del/erase/rd/rmdir",
     r"(?i)(?<![\w.-])(?:del|erase|rd|rmdir)\s"),
]

CMD_DANGEROUS_PATTERNS = [
    ("强制推送 git push --force",
     r"(?i)\bgit\s+push\b[^|;&]*(?:--force(?!-with-lease)|(?<![\w-])\-f\b)"),
    ("卷格式化 format / diskpart",
     r"(?i)\b(?:format(?:\.com)?|diskpart)\b"),
    ("注册表删除 reg delete",
     r"(?i)\breg\s+delete\b"),
    ("强杀进程 taskkill /f",
     r"(?i)\btaskkill\b[^|;&]*/f"),
    ("系统电源操作 shutdown",
     r"(?i)\bshutdown\b"),
]

CMD_ALLOWLIST_PREFIXES = [
    "dir", "type", "cd", "echo", "ver", "where", "findstr", "more",
    "sort", "whoami",
    "git status", "git diff", "git log", "git show", "git blame",
    "git rev-parse", "git ls-files", "git tag",
]

DELETE_CODE_PATTERNS = [
    ("Python 删除文件 os.remove/os.unlink/Path.unlink",
     r"(?:\bos\.(?:remove|unlink)|(?<!fs)\.unlink)\s*\("),
    ("Python 删除目录 shutil.rmtree/os.rmdir",
     r"\b(?:shutil\.rmtree|os\.rmdir|os\.removedirs)\s*\("),
    ("Node 删除文件 fs.unlink/fs.rm/fs.rmdir",
     r"\b(?:fs\.(?:unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync)"
     r"|(?:unlinkSync|rmSync|rmdirSync))\s*\("),
]

# ---- bash 只读白名单（默认 ask 的 allow 层）----
# 业界做法（Claude Code 规则链 deny > ask > allow）：manual 模式下未命中
# 危险档的 bash 命令默认需人工审批（堵枚举遗漏），仅"分段后每段均命中
# 本白名单"的只读命令直接放行。匹配为词元边界前缀（"git status" 匹配
# git status …），VAR=val 前缀与安全重定向（2>&1、>/dev/null 等）会先
# 剥离；命令含命令替换/非安全重定向/引号不闭合时不套用白名单（保守 ask）。
# 注意：危险档判定优先于白名单（ask 高于 allow），即使误配 rm 也放不了行；
# sed(-i)/awk(可写)/find(-delete/-exec)/xargs(链式)/env(执行任意) 等
# 看似只读实可写的命令一律不收录。
BASH_ALLOWLIST_PREFIXES = [
    "ls", "cat", "head", "tail", "wc", "pwd", "echo", "printf", "date",
    "file", "stat", "du", "df", "tree", "grep", "rg", "diff", "which",
    "whoami", "uname", "cd",
    "git status", "git diff", "git log", "git show", "git blame",
    "git rev-parse", "git ls-files", "git tag",
]

__all__ = [
    "PROFILE", "INSTALL_ROOT", "RUNTIME_DIR", "SESSION_DIR", "SHARED_DIR",
    "SECCOMP_FILTER_PATH", "PYTHON_PATH", "NODE_BIN", "GIT_BIN",
    "SANDBOX_WORKSPACE_ROOT", "WORKSPACE_SYSTEM_VIRT_NAMES",
    "WORKSPACE_SANDBOX_RO_DIRS", "SANDBOX_POLICY",
    "resolve_node_bin", "resolve_git", "ensure_session_dir",
    "SANDBOX_PYTHON_PREFIX", "SANDBOX_NODE_PREFIX", "SANDBOX_GIT_PREFIX",
    "DENIED_HOST_PATHS", "SHELL_PERSISTENT_ENABLED", "BASH_APPROVAL_ENABLED",
    "BASH_DANGEROUS_PATTERNS", "BASH_ALLOWLIST_PREFIXES",
    "DELETE_SHELL_PATTERNS", "DELETE_CODE_PATTERNS",
    "PWSH_DANGEROUS_PATTERNS", "PWSH_DELETE_SHELL_PATTERNS",
    "PWSH_DENY_PATTERNS", "PWSH_ALLOWLIST_PREFIXES",
    "CMD_DANGEROUS_PATTERNS", "CMD_DELETE_SHELL_PATTERNS",
    "CMD_ALLOWLIST_PREFIXES",
    "PYTHON_MAX_OUTPUT_BYTES", "PYTHON_MAX_TIMEOUT_SECONDS",
    "SHELL_OUTPUT_INLINE_MAX_CHARS",
]
