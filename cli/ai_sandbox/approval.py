# -*- coding: utf-8 -*-
"""命令审批决策引擎 —— AI 安全层的「第二道防线」（策略代码逐字来自原项目）

原项目位置：src/tools/sandbox_tools.py（_match_dangerous / _match_denied /
_split_shell_segments / _segment_allowlisted / _shell_allowlisted / _decide
/ _approval_gate）。此处**正则与判定顺序一字未改**，只做两件移植改造：

1) 去掉 langchain / langgraph 硬依赖：原来的 `_ask_via_interrupt` 挂到
   LangGraph 的 interrupt 上；现在改为可插拔回调 `ask_handler(source, tool,
   reasons) -> str`，返回 "approved" 即放行，其它任何值即拒绝。
   需要原行为时用 `langgraph_ask_handler()`（惰性 import langgraph）。
2) 决策结果从 tuple 升级为 `Decision` 数据类（语义完全一致）。

规则链（业界 deny > ask > allow，源项目 11 号文档定稿）：
- deny 档（denied_patterns，密文无法审查类）：优先于一切，含 full 免审模式；
- 危险档（dangerous_patterns）优先于白名单：主会话 ask，子代理无审批通道直接 deny；
- 未命中危险档：子代理放行（fail-open，沙箱兜底）；python/node 任意代码无前缀
  可判且全程在沙箱内，沿用「危险才问、其余放行」；shell 在 manual 模式下翻转
  —— 只读白名单（分段词元前缀）命中才放行，否则默认 ask（未匹配即问，堵枚举遗漏）。
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import settings as config
from .logging_compat import log
from .shell_profile import ShellProfile, get_shell_profile

__all__ = [
    "Decision", "decide", "match_dangerous", "match_denied",
    "split_shell_segments", "segment_allowlisted", "shell_allowlisted",
    "ApprovalGate", "langgraph_ask_handler",
]

# shell 分隔符（两字符优先于单字符）；pwsh 5.1 不支持 && / ||（解析直接报错）
_POSIX_SEPARATORS_TWO = ("&&", "||", "|&")
_PWSH_SEPARATORS_TWO: tuple[str, ...] = ()


def match_dangerous(source: str, include_code_api: bool = False,
                    profile: ShellProfile | None = None) -> list[str]:
    """返回命中的危险模式说明列表（空 = 无需审批）"""
    profile = profile or get_shell_profile()
    matched = [label for label, pattern in profile.dangerous_patterns
               if re.search(pattern, source)]
    if include_code_api:
        matched += [label for label, pattern in config.DELETE_CODE_PATTERNS
                    if re.search(pattern, source)]
    return matched


def match_denied(source: str, profile: ShellProfile | None = None) -> list[str]:
    """返回命中的绝对拒绝模式（deny 档，不进人工审批）"""
    profile = profile or get_shell_profile()
    return [label for label, pattern in profile.denied_patterns
            if re.search(pattern, source)]


def split_shell_segments(command: str,
                         profile: ShellProfile | None = None) -> list[str] | None:
    """按未加引号的 shell 分隔符切段（引号不闭合返回 None，保守不放行）"""
    profile = profile or get_shell_profile()
    is_pwsh = profile.name == "pwsh"
    seps_two = _PWSH_SEPARATORS_TWO if is_pwsh else _POSIX_SEPARATORS_TWO
    segments: list[str] = []
    cur: list[str] = []
    quote = None
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if quote:
            if c == quote:
                quote = None
            cur.append(c)
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            cur.append(c)
            i += 1
            continue
        two = command[i:i + 2]
        # "&" 仅在非重定向语境才作为分隔符（2>&1 / &>/dev/null 属重定向）；
        # pwsh 的 & 是调用操作符（& cmd），不切段
        is_sep = (two in seps_two or c in (";", "|", "\n")
                  or (c == "&" and not is_pwsh
                      and not (i > 0 and command[i - 1] in "><")
                      and command[i + 1:i + 2] != ">"))
        if is_sep:
            segments.append("".join(cur))
            cur = []
            i += 2 if two in seps_two else 1
            continue
        cur.append(c)
        i += 1
    if quote:
        return None
    segments.append("".join(cur))
    return segments


def segment_allowlisted(segment: str,
                        profile: ShellProfile | None = None) -> bool:
    """单个命令段是否命中只读白名单（词元边界前缀匹配）"""
    profile = profile or get_shell_profile()
    stripped = (profile.safe_redirect_re.sub(" ", segment)
                if profile.safe_redirect_re else segment)
    tokens = profile.strip_assignments(stripped.split())
    if not tokens:
        return False
    if any("<" in t or ">" in t for t in tokens):
        return False
    lowered = [t.lower() for t in tokens] if profile.allowlist_case_insensitive else tokens
    for entry in profile.allowlist_prefixes:
        words = (entry.lower().split() if profile.allowlist_case_insensitive
                 else entry.split())
        if lowered[:len(words)] == words:
            return True
    return False


def shell_allowlisted(command: str,
                      profile: ShellProfile | None = None) -> bool:
    """shell 命令是否整体命中只读白名单（分段后每段均须命中）"""
    profile = profile or get_shell_profile()
    if profile.has_command_substitution(command):
        return False
    segments = split_shell_segments(command, profile)
    if segments is None:
        return False
    for seg in segments:
        if not seg.strip():
            continue  # 连续分隔符/结尾 & 产生的空段：无操作，跳过
        if not segment_allowlisted(seg, profile):
            return False
    return True


@dataclass(frozen=True)
class Decision:
    """审批决策结果"""

    action: str                                  # allow | ask | deny
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def needs_approval(self) -> bool:
        return self.action == "ask"

    @property
    def denied(self) -> bool:
        return self.action == "deny"


def decide(source: str, tool: str = "shell", mode: str = "manual",
           include_code_api: bool = False, is_subagent: bool = False,
           profile: ShellProfile | None = None) -> Decision:
    """审批规则链（deny > ask > allow）

    source           待判定的命令或代码文本
    tool             "shell" | "python" | "node"
    mode             manual（默认，白名单外均问）| auto（非危险自动过）| full（跳过审批）
    include_code_api python/node 是否叠加「原生删除 API」正则
    is_subagent      子代理上下文：无审批通道，命中危险档直接拒绝
    """
    profile = profile or get_shell_profile()
    if not config.BASH_APPROVAL_ENABLED:
        return Decision("allow", [])
    denied = match_denied(source, profile)
    if denied:
        # 绝对拒绝档优先于一切（含 full 免审模式）：密文无法审查
        return Decision("deny", denied)
    if mode == "full":
        return Decision("allow", [])
    matched = match_dangerous(source, include_code_api, profile)
    if matched:
        return Decision("deny" if is_subagent else "ask", matched)
    if is_subagent or tool != "shell":
        return Decision("allow", [])
    if mode == "auto" or shell_allowlisted(source, profile):
        return Decision("allow", [])
    return Decision("ask", ["未命中只读白名单，默认需人工确认"])


def langgraph_ask_handler() -> Callable[[str, str, list], str]:
    """把审批挂到 LangGraph interrupt 上的处理器（需安装 langgraph）。

    与源项目 _ask_via_interrupt 行为一致：挂起整图 → 上游回答 "approved"
    即放行，其它任何值/超时即拒绝。
    """
    def _handler(source: str, tool: str, reasons: list) -> str:
        from langgraph.types import interrupt
        preview = source if len(source) <= 400 else source[:400] + "\n…（内容过长，已截断）"
        return interrupt({
            "type": "tool_approval",
            "tool": tool,
            "command": preview,
            "reasons": reasons,
        })

    return _handler


class ApprovalGate:
    """危险操作审批门（与源项目 _approval_gate 同契约）

    check(...) 返回 None = 放行执行；返回字符串 = 拒绝说明（不执行）。
    未提供 ask_handler（即没有可用的审批 UI）时，ask 档一律**拒绝**
    （安全默认：宁可拒绝也不静默放行）。

    典型接线（自建 UI / 终端 / Web 弹窗均可）：
        gate = ApprovalGate(ask_handler=lambda src, tool, why: ask_user_ui(...))
        rejected = gate.check(command, tool="shell")
        if rejected:
            return rejected        # 把说明回给模型
        run(command)
    """

    def __init__(self, ask_handler: Optional[Callable[[str, str, list], str]] = None,
                 default_mode: str = "manual", enabled: Optional[bool] = None):
        self._ask = ask_handler
        self.default_mode = default_mode
        self._enabled = enabled

    # ---- 决策 ----
    def decide(self, source: str, tool: str = "shell", mode: Optional[str] = None,
               include_code_api: bool = False, is_subagent: bool = False,
               profile: ShellProfile | None = None) -> Decision:
        if self._enabled is False:
            return Decision("allow", [])
        return decide(source, tool, mode if mode is not None else self.default_mode,
                      include_code_api, is_subagent, profile)

    # ---- 门禁 ----
    def check(self, source: str, tool: str = "shell", mode: Optional[str] = None,
              include_code_api: bool = False, is_subagent: bool = False,
              profile: ShellProfile | None = None) -> Optional[str]:
        decision = self.decide(source, tool, mode, include_code_api,
                               is_subagent, profile)
        if decision.action == "allow":
            return None
        if decision.action == "deny":
            if match_denied(source, profile):
                return (f"请求被拒绝：{'；'.join(decision.reasons)}。"
                        "该类内容不支持审批放行，请以可审查的明文形式执行。")
            return (f"请求被拒绝：命中危险模式（{'；'.join(decision.reasons)}）。"
                    "子代理无审批通道，请在主会话中直接执行（将触发人工审批）。")
        # ask 档
        if self._ask is None:
            log.warning("审批档命中但未接入审批通道，按拒绝处理",
                        extra={"tool": tool, "reasons": decision.reasons})
            return (f"请求未被批准：{'；'.join(decision.reasons)}。"
                    "当前未接入人工审批通道，如需执行请由人工确认后重试。")
        answer = self._ask(source, tool, decision.reasons)
        if answer == "approved":
            return None
        return (f"用户拒绝了该{tool}执行请求（{'；'.join(decision.reasons)}）。"
                f"决策: {answer!r}。请调整方案或改用安全做法。")
