# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2026/09/16'
__desc__ = 'ShellProfile 协议层（轴 B：Shell 工具链）'

"""
ShellProfile 协议层 — 轴 B（Shell 工具链）

双正交轴设计的轴 B：持久 Shell 的标记/引号/编码/启动旗标与审批正则版本
跟 shell 走（bash / zsh / pwsh）；隔离与路径翻译跟轴 A（SandboxBackend）走。

协议五要素：
    quote        引号规则（bash/zsh: shlex.quote）
    cwd_sync     cd 前奏（bash/zsh: cd X 2>/dev/null || true）
    marker       结束标记（含 rc/pwd 回传语法）
    spawn_argv   长驻 shell 旗标（bash: --noprofile --norc；zsh: -f）
    encoding     输入/输出编码（bash/zsh: utf-8）

BashShellProfile 为现状行为固化（零变化）。zsh 探针定稿（2026-09-16，
14/14 PASS）：zsh 版五要素与 bash **字节级等价**（`zsh -f` = NO_RCS 屏蔽
全部启动脚本且 CDPATH 未设 cd 无回显 / 标记协议原样 / `$?` 语义一致 /
shlex.quote 前奏 / UTF-8），仅 spawn/oneshot 旗标不同。pwsh 的合成 rc
表达式与编码三件套见设计细案（随 Windows 适配落地）。
"""

import re
import shlex
import subprocess
import sys
from abc import ABC, abstractmethod

from . import settings as config

# 标记协议版本：标记/前奏/扫描语法整体变更时 +1（消费方按版本对齐）
SHELL_PROTOCOL_VERSION = 1


class ShellProfile(ABC):
    """Shell 工具链协议（轴 B）"""

    name: str = ""            # "bash" | "zsh" | "pwsh"
    display_name: str = ""
    protocol_version: int = SHELL_PROTOCOL_VERSION

    # ---- 审批正则集（11 号 §4 要点 7：挂 profile 按 shell 版本选择，
    # 消费方 sandbox_tools 不做 if-else）----
    # ask 档危险模式（主图人工审批 / 子代理拒绝）：(说明, 正则) 列表
    dangerous_patterns: list[tuple[str, str]] = []
    # deny 档（绝对拒绝，主图也不进审批——密文无法审查类）
    denied_patterns: list[tuple[str, str]] = []
    # 只读白名单词条（manual 模式 allow 层，词元边界前缀匹配）
    allowlist_prefixes: list[str] = []
    # 安全重定向剥离（白名单判定前预处理；None = 不剥离）
    safe_redirect_re: re.Pattern | None = None
    # 前导赋值词元（白名单判定前剥离；bash: VAR=val；pwsh: $var 两词元 + =）
    assign_token_re: re.Pattern | None = None
    # 白名单词条元匹配是否大小写不敏感（pwsh cmdlet 名大小写不敏感）
    allowlist_case_insensitive: bool = False

    def strip_assignments(self, tokens: list[str]) -> list[str]:
        """剥离前导赋值：bash 形态 VAR=val（单词元）。

        pwsh 覆写为 $var 两词元形态（`$x = 1`），见 PwshShellProfile。
        """
        while (tokens and self.assign_token_re
               and self.assign_token_re.match(tokens[0])):
            tokens.pop(0)
        return tokens

    def has_command_substitution(self, command: str) -> bool:
        """是否含命令替换（白名单不适用，保守 ask）"""
        return "`" in command or "$(" in command

    @abstractmethod
    def quote(self, path: str) -> str:
        """路径引号规则（前奏/命令拼接用）"""

    @abstractmethod
    def cwd_sync(self, target: str) -> str:
        """cwd 同步前奏（cd 工具切目录后在下条命令前生效；失败不致命）"""

    @abstractmethod
    def marker(self, uid: str) -> str:
        """命令结束标记行脚本（printf 尾标，先取 rc 再回传 pwd）"""

    @abstractmethod
    def marker_prefix(self, uid: str) -> bytes:
        """标记行扫描前缀（读线程滚动窗口匹配用）"""

    @abstractmethod
    def marker_terminator(self) -> bytes:
        """标记行结束序列（标记元组后的行尾）"""

    @abstractmethod
    def spawn_argv(self) -> list[str]:
        """长驻 shell 启动 argv（shell 名 + 屏蔽启动脚本/噪声的旗标）"""

    @abstractmethod
    def oneshot_argv(self, command: str) -> list[str]:
        """一次性执行 argv（-c 形态，持久化不可用时的兜底）"""

    def oneshot(self, runner, command: str, chdir: str,
                timeout: int | None = None,
                extra_env: dict | None = None
                ) -> subprocess.CompletedProcess:
        """一次性执行钩子（默认走 oneshot argv 通道）。

        cmd 语义 profile 覆写为批处理通道（AC 后端 raw_command，
        见 CmdShellProfile.oneshot）——list2cmdline 的 CRT 转义与
        cmd 引号规则不兼容，引号语法必须走 raw 通道。
        """
        return runner.run(self.oneshot_argv(command), chdir=chdir,
                          timeout=timeout, extra_env=extra_env)

    @abstractmethod
    def encoding(self) -> str:
        """stdin 写入 / stdout 解码编码"""

    def session_init(self) -> str:
        """shell 启动后首条输入（编码/环境钉死；空 = 无需）。

        pwsh 覆写为编码三件套（5.1 三重陷阱），bash/zsh 的 locale 由
        运行环境保证，无需注入。
        """
        return ""


class BashShellProfile(ShellProfile):
    """bash（现状行为固化，零变化）"""

    name = "bash"
    display_name = "Bash"

    # 审批正则集（bash 版 = config 现状行为固化）
    dangerous_patterns = (config.BASH_DANGEROUS_PATTERNS
                          + config.DELETE_SHELL_PATTERNS)
    allowlist_prefixes = config.BASH_ALLOWLIST_PREFIXES
    safe_redirect_re = re.compile(
        r"(?:2>&1|1>&1|>&1|[&12]?>\s*/dev/null|<\s*/dev/null)(?=\s|$)")
    assign_token_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

    def quote(self, path: str) -> str:
        return shlex.quote(path)

    def cwd_sync(self, target: str) -> str:
        return f"cd {shlex.quote(target)} 2>/dev/null || true\n"

    def marker(self, uid: str) -> str:
        # 先取 $? 再跑子命令，避免 $(pwd) 展开（如果有）先覆盖退出码
        return (f"__shell_rc=$?; printf '\\n__SHELL_END__{uid}__%s__%s__\\n' "
                f'"$PWD" "$__shell_rc"\n')

    def marker_prefix(self, uid: str) -> bytes:
        return b"__SHELL_END__" + uid.encode("ascii") + b"__"

    def marker_terminator(self) -> bytes:
        return b"__\n"

    def spawn_argv(self) -> list[str]:
        return ["bash", "--noprofile", "--norc"]

    def oneshot_argv(self, command: str) -> list[str]:
        return ["bash", "-c", command]

    def encoding(self) -> str:
        return "utf-8"


class ZshShellProfile(ShellProfile):
    """zsh（macOS）—— 探针定稿：五要素与 bash 字节级等价，仅旗标不同。

    `zsh -f` = NO_RCS：屏蔽 .zshenv 等全部启动脚本（ZDOTDIR 陷阱实测），
    CDPATH 未设、cd 无回显、非交互无 PS1 噪声。
    """

    name = "zsh"
    display_name = "zsh"

    # 与 bash 同源（zsh 兼容 POSIX 语法，探针定稿）
    dangerous_patterns = (config.BASH_DANGEROUS_PATTERNS
                          + config.DELETE_SHELL_PATTERNS)
    allowlist_prefixes = config.BASH_ALLOWLIST_PREFIXES
    safe_redirect_re = re.compile(
        r"(?:2>&1|1>&1|>&1|[&12]?>\s*/dev/null|<\s*/dev/null)(?=\s|$)")
    assign_token_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

    def quote(self, path: str) -> str:
        return shlex.quote(path)

    def cwd_sync(self, target: str) -> str:
        return f"cd {shlex.quote(target)} 2>/dev/null || true\n"

    def marker(self, uid: str) -> str:
        return (f"__shell_rc=$?; printf '\\n__SHELL_END__{uid}__%s__%s__\\n' "
                f'"$PWD" "$__shell_rc"\n')

    def marker_prefix(self, uid: str) -> bytes:
        return b"__SHELL_END__" + uid.encode("ascii") + b"__"

    def marker_terminator(self) -> bytes:
        return b"__\n"

    def spawn_argv(self) -> list[str]:
        return ["zsh", "-f"]

    def oneshot_argv(self, command: str) -> list[str]:
        return ["zsh", "-f", "-c", command]

    def encoding(self) -> str:
        return "utf-8"


class PwshShellProfile(ShellProfile):
    """pwsh（Windows）—— Windows 探针 ⑤a 定稿（14/14 PASS）。

    与 bash/zsh 的语义差异及定稿依据：
    - rc 语义：`$LASTEXITCODE` 只对原生 exe 有效、cmdlet 失败不设值——
      合成表达式（5.1/7 双版本实测一致）：
      `if (!$?) { if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 1 } }
       else { if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } else { 0 } }`
    - 标记：printf 不可用（pwsh 非内置）→ Write-Output；pwd 用 $PWD
      （PathInfo，字符串化与 bash $PWD 一致，含尾部反斜杠差异可容忍）；
      路径与 rc 经 -f 格式串回传（{} 占位，逗号传参），与读线程的
      `__SHELL_END__<uid>__<pwd>__<rc>__` 解析结构保持一致；
    - cwd 前奏：`cd 'X' 2>$null;` —— pwsh 无 `2>/dev/null`（null 设备
      是 $null 重定向）也无 `|| true`（非零不中止）；失败时 cd 抛错但
      ErrorAction 默认 Continue，命令照常执行；
    - 引号：单引号 literal（内部 ' 双写转义），等价 bash shlex.quote
      的防展开语义；
    - spawn 旗标：`-NoProfile -ExecutionPolicy Bypass`（5.1 默认
      Restricted，.ps1 不带此旗标直接被拒——探针 §2.6）；
    - 编码：5.1 三重陷阱（Out-File UTF-16LE+BOM / $OutputEncoding
      us-ascii / console CP 936）→ session_init 钉编码三件套（见下）。
    """

    name = "pwsh"
    display_name = "PowerShell"

    # 审批正则集（11 号 §4/§5 定稿；Windows 探针 §2 实测）
    dangerous_patterns = (config.PWSH_DANGEROUS_PATTERNS
                          + config.PWSH_DELETE_SHELL_PATTERNS)
    denied_patterns = config.PWSH_DENY_PATTERNS
    allowlist_prefixes = config.PWSH_ALLOWLIST_PREFIXES
    # pwsh 无 /dev/null，安全重定向形态为 2>$null / *>$null / 1>$null
    # 与流合并 2>&1（不落盘，仅改流走向）
    safe_redirect_re = re.compile(r"(?:[2*1]?>\s*\$null|2>&1)(?=\s|$)")
    # 前导赋值（白名单判定前剥离）：pwsh 无 VAR=val 形态，是 $var 两词元
    # + = 的语句形态；探针要点 2。
    assign_token_re = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")
    allowlist_case_insensitive = True  # cmdlet 名大小写不敏感（探针 §2）

    def strip_assignments(self, tokens: list[str]) -> list[str]:
        """剥离前导赋值：pwsh 形态 `$x =`（$var 词元后随 '=' 词元）。"""
        while (len(tokens) >= 2
               and self.assign_token_re.match(tokens[0]) and tokens[1] == "="):
            tokens.pop(0)
            tokens.pop(0)
        return tokens

    def has_command_substitution(self, command: str) -> bool:
        """命令替换/子表达式/调用操作符（11 号 §4 要点 4）。"""
        return ("`" in command or "$(" in command or "& (" in command
                or "&(" in command)

    # 合成 rc 表达式（cmdlet 失败合成 1 / 原生 exe 透传，双版本一致）
    _RC_EXPR = ("if (!$?) { if ($LASTEXITCODE -is [int]) { $LASTEXITCODE } "
                "else { 1 } } else { if ($LASTEXITCODE -is [int]) "
                "{ $LASTEXITCODE } else { 0 } }")

    # 编码三件套（5.1 必需；7 默认即 UTF-8 无害）：
    # chcp 65001 钉 console CP；[Console]::OutputEncoding 钉子进程
    # 输出解码；$OutputEncoding 钉管道给原生 exe 的编码。$ErrorAction
    # 默认 Continue 无需显式设置；-NoProfile 已屏蔽 profile 噪声。
    SESSION_INIT = (
        "chcp 65001 > $null\n"
        "[Console]::OutputEncoding = [Text.UTF8Encoding]::new()\n"
        "$OutputEncoding = [Text.UTF8Encoding]::new()\n"
    )

    def quote(self, path: str) -> str:
        # 单引号 literal + ' 双写转义（探针 §2.7，5.1/7 一致）
        return "'" + path.replace("'", "''") + "'"

    def cwd_sync(self, target: str) -> str:
        return f"cd {self.quote(target)} 2>$null;\n"

    def marker(self, uid: str) -> str:
        # 标记行：__SHELL_END__<uid>__<pwd>__<rc>__（-f 格式串回传，
        # 逗号传参绕开路径内插值/引号陷阱；Write-Output 末尾自带 CRLF，
        # marker_terminator 为 __\r\n）
        return (f"$__rc = {self._RC_EXPR}; "
                f"Write-Output ('__SHELL_END__{uid}__' + $PWD + "
                f"'__' + $__rc + '__')\n")

    def marker_prefix(self, uid: str) -> bytes:
        return b"__SHELL_END__" + uid.encode("ascii") + b"__"

    def marker_terminator(self) -> bytes:
        return b"__\r\n"

    def spawn_argv(self) -> list[str]:
        # 実行策略：5.1 默认 Restricted，Bypass 免 .ps1 落盘场景被拒
        return ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass"]

    def oneshot_argv(self, command: str) -> list[str]:
        # 编码三件套同样拼入一次性执行（console CP 936 乱码陷阱，
        # 与持久模式 SESSION_INIT 同源；-Command 支持多行脚本）
        return ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-Command", self.SESSION_INIT + command]

    def encoding(self) -> str:
        return "utf-8"

    def session_init(self) -> str:
        return self.SESSION_INIT


class CmdShellProfile(ShellProfile):
    """cmd（Windows AppContainer 降级通道）—— 探针 #4-#7 真机定稿。

    适用场景：AppContainer 后端内 pwsh 全系无法启动（"拒绝访问"，
    get_shell_profile 后端感知切至此 profile）。AC 无长驻管道
    （lowbox 无法使用宿主 std 句柄，spawn 抛 NotImplementedError 由
    _PersistentShell 捕获回退 oneshot）——一切执行走批处理通道。

    批处理通道的必要性（探针 #6 定稿）：cmd /c 内联整行在解析期展开
    %RC%（拿到旧值），errlevel/多行命令语义只有批处理分行写才正确；
    批处理必须相对路径调用（AC 内绝对路径批处理被拒）。

    协议五要素仅为占位实现（长驻 shell 在 AC 不可用，永不消费）。
    """

    name = "cmd"
    display_name = "cmd"

    # 审批正则集（config cmd 版，与 pwsh 版同源收口）
    dangerous_patterns = (config.CMD_DANGEROUS_PATTERNS
                          + config.CMD_DELETE_SHELL_PATTERNS)
    allowlist_prefixes = config.CMD_ALLOWLIST_PREFIXES
    # cmd 安全重定向：>nul / 2>nul / 1>nul 与流合并 2>&1（nul 大小写均可）
    safe_redirect_re = re.compile(r"(?:[12]?>\s*nul|2>&1)(?=\s|$)",
                                  re.IGNORECASE)
    # cmd 无 VAR=val cmd 前导赋值形态（环境经批处理 @set 行注入）
    assign_token_re = None
    allowlist_case_insensitive = True  # cmd 内建命令大小写不敏感

    def has_command_substitution(self, command: str) -> bool:
        # cmd 无 `$(...)`/反引号命令替换；for /f 套壳等价物走危险档兜底
        return False

    def quote(self, path: str) -> str:
        # 双引号包裹（内部双引号加倍；路径含 " 在 Windows 本就非法）
        return '"' + path.replace('"', '""') + '"'

    def cwd_sync(self, target: str) -> str:
        return f"cd /d {self.quote(target)} 2>nul & rem sync\r\n"

    def marker(self, uid: str) -> str:
        # 延迟展开取 rc（cmd 整行解析期展开 %RC% 是旧值，探针 #6）；
        # 仅协议占位（AC 无长驻 shell，永不消费）
        return (f"set \"__shell_rc=!ERRORLEVEL!\"\r\n"
                f"echo __SHELL_END__{uid}__!CD!__!__shell_rc!__\r\n")

    def marker_prefix(self, uid: str) -> bytes:
        return b"__SHELL_END__" + uid.encode("ascii") + b"__"

    def marker_terminator(self) -> bytes:
        return b"__\r\n"

    def spawn_argv(self) -> list[str]:
        return ["cmd", "/d"]

    def oneshot_argv(self, command: str) -> list[str]:
        # 非 AC 宿主直接调用时的兜底形态（不经引号陷阱场景）
        return ["cmd", "/d", "/c", command]

    def encoding(self) -> str:
        return "gbk"  # cmd 控制台输出 OEM CP936（run 解码链 utf-8→gbk）

    def oneshot(self, runner, command: str, chdir: str,
                timeout: int | None = None,
                extra_env: dict | None = None
                ) -> subprocess.CompletedProcess:
        r"""批处理通道（探针 #6 定稿形态）。

        - 命令落 `<workspace>/.tmp/shell/shell-<pid>-<uuid>.cmd`（GBK +
          CRLF + errors=replace；.tmp 系统段 junction 已授 AC 写权）；
        - extra_env 走批处理头部 `@set "K=V"` 行（不走 run 的单行 set
          前缀——值含 & | > 等特殊字符时引号内才安全）；
        - 执行形态 `"cmd" /d /c <relpath>`：短名带引号走 PATH 解析
          （AC 内绝对路径不带引号必"拒绝访问"、带引号被 /c 剥引号规则
          破坏，探针 #4/#5 定稿）；relpath 相对 chdir（子目录 cwd 生成
          `..\.tmp\shell\x.cmd` 亦可，探针 #6 实证）；
        - finally 删除批处理（会话内不留痕）。
        """
        import os
        import uuid as _uuid
        batch_dir = os.path.join(runner.agent_root(), ".tmp", "shell")
        os.makedirs(batch_dir, exist_ok=True)
        batch = os.path.join(
            batch_dir, f"shell-{os.getpid()}-{_uuid.uuid4().hex[:8]}.cmd")
        lines = [f'@set "{k}={v}"' for k, v in (extra_env or {}).items()]
        lines.append("@echo off")
        lines.extend(command.splitlines() or ["rem"])
        try:
            with open(batch, "w", encoding="gbk", errors="replace",
                      newline="") as f:
                f.write("\r\n".join(lines) + "\r\n")
            rel = os.path.relpath(batch, chdir)
            return runner.run(None, chdir, timeout=timeout,
                              raw_command=f'"cmd" /d /c {rel}')
        finally:
            try:
                os.unlink(batch)
            except OSError:
                pass


_BASH = BashShellProfile()
_ZSH = ZshShellProfile()
_PWSH = PwshShellProfile()
_CMD = CmdShellProfile()


def get_shell_profile(platform: str | None = None,
                      backend: str | None = None) -> ShellProfile:
    """轴 B 解析：按平台选择 shell 工具链（bash: Linux/服务器；zsh: macOS；
    pwsh: Windows）。platform 参数供测试注入。

    后端感知（真机定稿 2026-09-29）：platform 未显式注入、Windows 且
    运行时后端为 appcontainer 时降级 cmd 语义（AC 内 pwsh 全系启动失败
    "拒绝访问"，探针 #4-#7 定稿）。backend 缺省时惰性查询 registry
    （resolve 有启动缓存，读缓存廉价；显式注入 platform 的测试路径
    不触发查询，保持确定性）。
    """
    plat = platform or sys.platform
    if plat == "darwin":
        return _ZSH
    if plat == "win32":
        if platform is None:
            if backend is None:
                from .registry import get_sandbox_backend
                try:
                    backend = get_sandbox_backend().name
                except RuntimeError:
                    backend = None
            if backend == "appcontainer":
                return _CMD
        return _PWSH
    return _BASH
