# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2026/09/16'
__desc__ = '沙箱后端注册与选择（唯一决策点）'

"""
沙箱后端 registry — 平台候选链自动探测（"沙箱后端选择机制"）

① auto（唯一路径，无人工指定入口）：sys.platform 确定候选链 →
   逐个 probe → 首个可用者；降级允许，但是否放行由 SANDBOX_POLICY
   决定（server/strict 拒绝降级硬失败；desktop/graded 醒目上报后放行——
   strict 语义等价"锁定强隔离"）
② 解析时机：启动时一次（resolve() 缓存），进程生命周期内不变
   理由：冒烟测试有成本；会话间沙箱变化会造成行为不可解释；日志只打一次

strict/graded 的失败判定在 env_check（启动门禁）落地，本模块只提供事实
（report.degraded / failures）；/config 与会话工具经 get_sandbox_backend()
取单例。
"""

import dataclasses
import sys
from typing import Callable, Optional

from .logging_compat import log
from .base import SandboxBackend, SandboxProbeError
from .backends.bwrap import BwrapBackend
from .backends.null import NullBackend
from .backends.sandbox_exec import SandboxExecBackend
from .detect import candidate_chain

# 后端工厂表：appcontainer 仅 win32 惰性加载（模块级 ctypes.WinDLL
# 在非 Windows 导入即炸；链上非 win32 平台本就到不了该候选）
_BACKENDS: dict[str, Callable[[], SandboxBackend]] = {
    "bwrap": BwrapBackend,
    "sandbox-exec": SandboxExecBackend,
    "null": NullBackend,
}


def _lazy_appcontainer() -> SandboxBackend:
    from .backends.appcontainer import AppContainerBackend
    return AppContainerBackend()


if sys.platform == "win32":
    _BACKENDS["appcontainer"] = _lazy_appcontainer

# 进程级单例（resolve 缓存，生命周期内不变）
_REPORT: Optional["SandboxReport"] = None
_BACKEND: Optional[SandboxBackend] = None


@dataclasses.dataclass
class ProbeFailure:
    """单个候选后端的 probe 失败记录（上报/日志用）"""
    backend: str
    form: str      # base.PROBE_*（missing / defect / nested）
    message: str


@dataclasses.dataclass
class SandboxReport:
    """解析结果（env_check 门禁 / /config 暴露 / 日志共用）"""
    chain: list[str] = dataclasses.field(default_factory=list)  # 实际探测链
    name: Optional[str] = None        # 选定后端（失败为 None）
    level: str = "none"
    degraded: bool = False            # 落到 level=none（降级直执）
    failures: list[ProbeFailure] = dataclasses.field(default_factory=list)
    error: Optional[str] = None       # 异常状态描述（正常不可达）


def register_backend(name: str, factory: Callable[[], SandboxBackend]) -> None:
    """注册后端（平台后端落地时调用）"""
    _BACKENDS[name] = factory


def reset() -> None:
    """清空解析缓存（单测用；运行期不应调用——解析时机契约：启动一次）"""
    global _REPORT, _BACKEND
    _REPORT = None
    _BACKEND = None


def resolve() -> SandboxReport:
    """解析沙箱后端（缓存；平台候选链逐个 probe，首个可用者）"""
    global _REPORT, _BACKEND
    if _REPORT is not None:
        return _REPORT

    report = SandboxReport(chain=[
        name for name in candidate_chain(sys.platform) if name in _BACKENDS])
    for name in report.chain:
        backend = _BACKENDS[name]()
        try:
            backend.probe()
        except SandboxProbeError as e:
            report.failures.append(ProbeFailure(name, e.form, str(e)))
            log.info(f"沙箱后端 {name} 不可用，尝试下一候选",
                     extra={"form": e.form, "error": str(e)})
            continue
        report.name, report.level = backend.name, backend.level
        break

    if report.name is None:
        # 候选链耗尽（null 恒可用，正常不可达；防御性兜底）
        report.error = "沙箱候选链全部不可用（含 null——异常状态）"
    report.degraded = report.name is not None and report.level == "none"
    _REPORT, _BACKEND = report, None
    if report.name is not None:
        _BACKEND = _BACKENDS[report.name]()
    return report


def get_report() -> SandboxReport:
    """取解析报告（未解析时触发解析）"""
    return resolve()


def get_sandbox_backend() -> SandboxBackend:
    """取后端单例。解析失败（候选链异常耗尽）抛 RuntimeError——
    启动门禁（env_check）先于会话创建拦截，正常不可达。"""
    report = resolve()
    if _BACKEND is None:
        if report.error:
            raise RuntimeError(report.error)
        detail = "; ".join(f"{f.backend}: {f.message}" for f in report.failures)
        raise RuntimeError(f"沙箱后端不可用: {detail}")
    return _BACKEND
