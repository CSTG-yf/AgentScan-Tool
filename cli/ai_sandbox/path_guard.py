# -*- coding: utf-8 -*-
"""路径越界守卫（源自原项目 src/tools/file_tools.py 的同名函数，逐字保留语义）

纯字符串前缀判断挡不住两类逃逸：
1. ``/workspace/a/../../etc/passwd`` —— join 后带 ``..``，需 normpath 归一；
2. 工作空间内指向外部的软链接（shell/node 工具可自由创建）—— 需 realpath
   展开全部软链接后再判定，否则 write 会顺着链接落到 /etc、~/.ssh 等处。

返回 normpath 结果而非 realpath：上层用 to_workspace_path 反查 /workspace
展示路径，审计与回滚都以该前缀为键，不能被宿主真实路径替换。
"""

import os
from typing import Optional

from . import settings as config
from .base import WORKSPACE_AGENT_ROOT, host_to_sandbox

__all__ = ["guard_within", "resolve_path", "is_readonly_mount"]


def guard_within(resolved: str, workspace_dir: str,
                 extra_ro_mounts: Optional[dict[str, str]] = None,
                 system_mounts: Optional[dict[str, str]] = None) -> str:
    """校验解析结果仍落在工作空间 / 只读挂载 / 系统数据段范围内"""
    lexical = os.path.normpath(resolved)
    real = os.path.realpath(lexical)
    roots = [os.path.realpath(workspace_dir)]
    roots += [os.path.realpath(v) for v in (extra_ro_mounts or {}).values() if v]
    roots += [os.path.realpath(v) for v in (system_mounts or {}).values() if v]
    if not any(real == r or real.startswith(r + os.sep) for r in roots):
        raise ValueError(f"路径必须在 /workspace 范围内: {lexical}")
    return lexical


def resolve_path(path: str, workspace_dir: str,
                 extra_ro_mounts: Optional[dict[str, str]] = None,
                 system_mounts: Optional[dict[str, str]] = None) -> str:
    """将 /workspace/xxx 或相对路径解析为宿主机绝对路径（越界即抛 ValueError）"""
    if path.startswith("/workspace/"):
        rest = path[len("/workspace/"):]
        for virt, host_path in (extra_ro_mounts or {}).items():
            if host_path and (rest == virt or rest.startswith(virt + "/")):
                inner = rest[len(virt):].lstrip("/")
                return guard_within(
                    host_path if not inner else os.path.join(host_path, inner),
                    workspace_dir, extra_ro_mounts, system_mounts)
        for virt, host_path in (system_mounts or {}).items():
            if host_path and (rest == virt or rest.startswith(virt + "/")):
                inner = rest[len(virt):].lstrip("/")
                return guard_within(
                    host_path if not inner else os.path.join(host_path, inner),
                    workspace_dir, extra_ro_mounts, system_mounts)
        return guard_within(os.path.join(workspace_dir, rest),
                            workspace_dir, extra_ro_mounts, system_mounts)
    if path == "/workspace":
        return guard_within(workspace_dir, workspace_dir,
                            extra_ro_mounts, system_mounts)
    if os.path.isabs(path) and not path.startswith("/workspace"):
        # 容错：模型可能传入宿主机绝对路径（如 MCP 返回的落点）
        converted = host_to_sandbox(path, workspace_dir, extra_ro_mounts,
                                    system_mounts)
        if converted:
            return resolve_path(converted, workspace_dir, extra_ro_mounts,
                                system_mounts)
        raise ValueError(f"路径必须在 /workspace 范围内: {path}")
    return guard_within(os.path.join(workspace_dir, path),
                        workspace_dir, extra_ro_mounts, system_mounts)


def is_readonly_mount(host_path: str, workspace_dir: str,
                      extra_ro_mounts: Optional[dict[str, str]] = None) -> bool:
    """判断宿主路径是否落在额外只读挂载（skills 等）范围内"""
    for host_path_mount in (extra_ro_mounts or {}).values():
        if host_path_mount and (host_path == host_path_mount
                                or host_path.startswith(host_path_mount + "/")):
            return True
    return False
