# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2026/09/16'
__desc__ = '沙箱后端平台候选链（纯函数，可单测）'

"""
平台候选链 — auto 模式下按序探测的后端名列表（registry 消费）。

未注册的后端名由 registry 过滤（appcontainer 随 Windows 适配
注册，注册前对应平台 auto 链实际只剩 [null]）。
"""

LINUX_CHAIN = ["bwrap", "null"]
MACOS_CHAIN = ["sandbox-exec", "null"]
WINDOWS_CHAIN = ["appcontainer", "null"]
FALLBACK_CHAIN = ["null"]


def candidate_chain(platform: str) -> list[str]:
    """按 sys.platform 返回 auto 探测候选链（副本，调用方可安全修改）"""
    if platform == "linux":
        return list(LINUX_CHAIN)
    if platform == "darwin":
        return list(MACOS_CHAIN)
    if platform == "win32":
        return list(WINDOWS_CHAIN)
    return list(FALLBACK_CHAIN)
