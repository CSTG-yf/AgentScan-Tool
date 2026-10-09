# -*- coding: utf-8 -*-
"""工作空间路径语言与系统数据段（源自原项目 src/core/workspace.py 的纯函数子集）

产品语言：对模型/用户/审计统一使用 `/workspace/...` 前缀，跨平台恒定；
宿主语言：各沙箱后端内部的真实路径。两者互译由本模块 + sandbox.base 负责。

只保留与沙箱/路径翻译相关的部分（原文件还有注册表、用户级工作空间管理等，
与沙箱解耦，未收录）。逐字保留原实现，未改语义。
"""

import os

from . import settings as config

__all__ = [
    "SANDBOX_WORKSPACE_ROOT", "SYSTEM_DATA_DIR_NAMES",
    "system_data_dir_names", "system_mounts_for", "is_system_data_path",
    "to_workspace_path", "from_workspace_path",
]

SANDBOX_WORKSPACE_ROOT = config.SANDBOX_WORKSPACE_ROOT

# 系统数据目录名（落 system_root；.git 只读保护，其余可写）
SYSTEM_DATA_DIR_NAMES = list(config.WORKSPACE_SYSTEM_VIRT_NAMES)


def system_data_dir_names() -> list[str]:
    """系统数据段名副本（调用方可安全修改）"""
    return list(SYSTEM_DATA_DIR_NAMES)


def system_mounts_for(system_root: str) -> dict[str, str]:
    """按 system_root 构建系统数据段表 {段名: 宿主绝对路径}"""
    return {name: os.path.join(system_root, name) for name in SYSTEM_DATA_DIR_NAMES}


def is_system_data_path(workspace_path: str) -> bool:
    """判断 /workspace 规范路径是否落在平台系统数据段内（.git/.tmp 等）

    只按首段名精确匹配：/workspace/.tmp/a.js 命中，/workspace/.tmpfoo/x 不命中。
    """
    p = workspace_path.replace("\\", "/")
    prefix = SANDBOX_WORKSPACE_ROOT + "/"
    rel = p[len(prefix):] if p.startswith(prefix) else p.lstrip("/")
    return rel.split("/", 1)[0] in SYSTEM_DATA_DIR_NAMES


def to_workspace_path(host_path: str, workspace_dir: str,
                      system_dir: str = None) -> str:
    """宿主机路径 → /workspace/xxx 展示路径；越界（只读挂载等）回退原样"""
    if host_path == workspace_dir or host_path.startswith(workspace_dir + os.sep):
        return SANDBOX_WORKSPACE_ROOT + \
            host_path[len(workspace_dir):].replace(os.sep, "/")
    if system_dir:
        for name in SYSTEM_DATA_DIR_NAMES:
            sys_path = os.path.join(system_dir, name)
            if host_path == sys_path or host_path.startswith(sys_path + os.sep):
                return f"{SANDBOX_WORKSPACE_ROOT}/{name}" + \
                    host_path[len(sys_path):].replace(os.sep, "/")
    return host_path


def from_workspace_path(path: str, workspace_dir: str,
                        system_dir: str = None) -> str:
    """/workspace/xxx 或相对路径 → 宿主机路径（不做越界校验，调用方自查）"""
    _prefix = SANDBOX_WORKSPACE_ROOT + "/"
    if path.startswith(_prefix) and system_dir:
        rest = path[len(_prefix):]
        for name in SYSTEM_DATA_DIR_NAMES:
            if rest == name or rest.startswith(name + "/"):
                return os.path.join(system_dir, *rest.split("/"))
    if path.startswith(_prefix):
        return os.path.join(workspace_dir, *path[len(_prefix):].split("/"))
    if os.path.isabs(path) and (path == workspace_dir
                                or path.startswith(workspace_dir + os.sep)
                                or (system_dir and (path == system_dir
                                                    or path.startswith(system_dir + os.sep)))):
        return path
    return os.path.join(workspace_dir, path)
