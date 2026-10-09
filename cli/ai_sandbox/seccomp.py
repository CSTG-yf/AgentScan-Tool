# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2024/7/19 09:27'
__desc__ = 'seccomp 过滤器（cBPF deny-list 字节码）'

"""
seccomp 过滤器

生成 cBPF deny-list 字节码，用于 bwrap --seccomp 参数。
黑名单包含 28 个危险系统调用（内核模块/调试/密钥环/进程窥探等）。
"""

import struct
import os
from typing import Optional

from .logging_compat import log


# ============================================================
#  常量
# ============================================================

# SECCOMP 返回值
RET_ALLOW = 0x7fff0000          # SECCOMP_RET_ALLOW
RET_ERRNO_EPERM = 0x00050001   # SECCOMP_RET_ERRNO | EPERM
RET_KILL_PROCESS = 0x80000000   # SECCOMP_RET_KILL_PROCESS

# 架构标识
AUDIT_ARCH_X64 = 0xc000003e
AUDIT_ARCH_ARM64 = 0xc00000b7

# seccomp_data 结构体偏移
# struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }
OFFSET_NR = 0    # 系统调用号（4 字节）
OFFSET_ARCH = 4  # 架构标识（4 字节）

# ============================================================
#  系统调用号表
# ============================================================

# x86_64 内置系统调用号（当宿主缺 /usr/include/asm/unistd_64.h 时回退）
SYSCALL_FALLBACK_X64 = {
    "init_module": 175,
    "finit_module": 313,
    "delete_module": 176,
    "kexec_load": 246,
    "kexec_file_load": 320,
    "bpf": 321,
    "perf_event_open": 298,
    "userfaultfd": 323,
    "keyctl": 250,
    "add_key": 248,
    "request_key": 249,
    "ptrace": 101,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "open_by_handle_at": 304,
    "name_to_handle_at": 303,
    "swapon": 167,
    "swapoff": 168,
    "reboot": 169,
    "acct": 163,
    "quotactl": 179,
    "vhangup": 153,
    "syslog": 103,
    "iopl": 172,
    "ioperm": 173,
    "io_uring_setup": 425,
    "sethostname": 170,
    "setdomainname": 171,
}

# arm64 内置系统调用号（asm-generic 统一 ABI；当宿主缺
# /usr/include/asm-generic/unistd.h 时回退）。号表源：内核
# include/uapi/asm-generic/unistd.h（arm64 唯一 syscall ABI），
# 逐号对照 2026-09 真机头文件核准。
# iopl/ioperm 为 x86 专属 I/O 端口指令，arm64 无此调用（不在表内）。
SYSCALL_FALLBACK_ARM64 = {
    "vhangup": 58,
    "quotactl": 60,
    "acct": 89,
    "kexec_load": 104,
    "init_module": 105,
    "delete_module": 106,
    "syslog": 116,
    "ptrace": 117,
    "reboot": 142,
    "sethostname": 161,
    "setdomainname": 162,
    "add_key": 217,
    "request_key": 218,
    "keyctl": 219,
    "swapon": 224,
    "swapoff": 225,
    "perf_event_open": 241,
    "name_to_handle_at": 264,
    "open_by_handle_at": 265,
    "process_vm_readv": 270,
    "process_vm_writev": 271,
    "finit_module": 273,
    "bpf": 280,
    "userfaultfd": 282,
    "kexec_file_load": 294,
    "io_uring_setup": 425,
}

# 黑名单系统调用（备注：asm-generic ABI 中不存在的调用（iopl/ioperm 为
# x86 专属 I/O 端口指令）无 arm64 号，arm64 实际可拦截 26/28 个）
SECCOMP_DENY_SYSCALLS = [
    # 内核模块
    "init_module", "finit_module", "delete_module",
    # 内核执行/调试
    "kexec_load", "kexec_file_load", "bpf", "perf_event_open", "userfaultfd",
    # 密钥环
    "keyctl", "add_key", "request_key",
    # 进程窥探/注入
    "ptrace", "process_vm_readv", "process_vm_writev",
    # 文件句柄逃逸
    "open_by_handle_at", "name_to_handle_at",
    # 系统管理
    "swapon", "swapoff", "reboot", "acct", "quotactl", "vhangup", "syslog",
    # I/O 端口
    "iopl", "ioperm",
    # io_uring
    "io_uring_setup",
    # UTS
    "sethostname", "setdomainname",
]

# ============================================================
#  BPF 指令常量
# ============================================================

BPF_LD = 0x00    # 加载
BPF_JMP = 0x05   # 跳转
BPF_RET = 0x06   # 返回
BPF_W = 0x00     # 32 位字
BPF_ABS = 0x20   # 绝对偏移（linux/filter.h: #define BPF_ABS 0x20，非 0）
BPF_JEQ = 0x10   # 等于跳转
BPF_K = 0x00     # 常量


class SeccompFilter:
    """seccomp 过滤器生成器"""

    @staticmethod
    def _bpf_stmt(code: int, jt: int, jf: int, k: int) -> bytes:
        """构建一条 BPF 指令（8 字节）"""
        # struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }
        # k 为无符号 32 位（如 AUDIT_ARCH_X64=0xc000003e、RET_KILL_PROCESS=0x80000000），
        # 必须用 "I" 而非有符号 "i"，否则 struct.error
        return struct.pack("<HBBI", code, jt, jf, k & 0xFFFFFFFF)

    @staticmethod
    def get_syscall_numbers() -> dict[str, int]:
        """获取系统调用号（优先读取宿主头文件，回退到内置表）

        头文件按架构选择：x86_64 读 asm/unistd_64.h（仅 x86_64 装
        linux-libc-dev 才有），arm64 读 asm-generic/unistd.h（arm64
        唯一 syscall ABI 的内核头）。**跨架构读取会得到号表污染**——
        asm-generic 是 arm64 的号表，若被 x86_64 宿主误读会产生
        "x64 号 + arm64 号"混合脏表，生成"拦错系统调用"的过滤器
        （如 init_module x64=175 / arm64=105），故头文件候选链必须
        与 detect_arch() 一致。头文件全缺失时回退到对应架构的内置表
        （SYSCALL_FALLBACK_X64 / SYSCALL_FALLBACK_ARM64）。
        """
        numbers = {}

        # 按架构选择头文件候选链（跨架构头文件不进候选，见 docstring）
        arch = SeccompFilter.detect_arch()
        if arch == AUDIT_ARCH_X64:
            header_paths = [
                "/usr/include/asm/unistd_64.h",
                "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
            ]
        elif arch == AUDIT_ARCH_ARM64:
            header_paths = [
                "/usr/include/asm-generic/unistd.h",
            ]
        else:
            header_paths = []

        import re
        for header_path in header_paths:
            if not os.path.exists(header_path):
                continue
            try:
                with open(header_path) as f:
                    content = f.read()
                # 匹配 #define __NR_xxx N 或 #define xxx N
                pattern = r'#define\s+(?:__NR_)?(\w+)\s+(\d+)'
                for match in re.finditer(pattern, content):
                    name = match.group(1)
                    nr = int(match.group(2))
                    numbers[name] = nr
                if numbers:
                    break
            except Exception:
                continue

        # 回退到内置表（与头文件同架构，见 docstring）
        fallback = (
            SYSCALL_FALLBACK_X64 if arch == AUDIT_ARCH_X64
            else SYSCALL_FALLBACK_ARM64 if arch == AUDIT_ARCH_ARM64
            else {}
        )
        for name, nr in fallback.items():
            if name not in numbers:
                numbers[name] = nr

        return numbers

    @staticmethod
    def detect_arch() -> Optional[int]:
        """检测当前架构"""
        import platform
        machine = platform.machine()
        if machine in ("x86_64", "amd64"):
            return AUDIT_ARCH_X64
        elif machine in ("aarch64", "arm64"):
            return AUDIT_ARCH_ARM64
        return None

    @staticmethod
    def write_filter(
        filter_path: str,
        deny_names: Optional[list[str]] = None,
    ) -> Optional[str]:
        """
        生成 cBPF 字节码写入 filter_path，返回路径（失败返回 None）。

        参数:
            filter_path: 过滤器文件路径
            deny_names: 要拒绝的系统调用名列表（默认 SECCOMP_DENY_SYSCALLS）

        返回:
            过滤器文件路径，或 None（无匹配调用时）
        """
        if deny_names is None:
            deny_names = SECCOMP_DENY_SYSCALLS

        arch = SeccompFilter.detect_arch()
        if arch is None:
            log.warning("无法检测架构，seccomp 过滤器未启用")
            return None

        syscall_numbers = SeccompFilter.get_syscall_numbers()

        # 收集有效的系统调用号
        deny_numbers = []
        for name in deny_names:
            nr = syscall_numbers.get(name)
            if nr is not None:
                deny_numbers.append(nr)

        if not deny_numbers:
            log.warning("无匹配的系统调用号，seccomp 过滤器未启用")
            return None

        # 构建 cBPF 字节码
        filters = bytearray()

        # 1. 校验架构（offset 4），非本机架构 → KILL_PROCESS
        filters += SeccompFilter._bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0, 0, OFFSET_ARCH)
        filters += SeccompFilter._bpf_stmt(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, arch)
        filters += SeccompFilter._bpf_stmt(BPF_RET | BPF_K, 0, 0, RET_KILL_PROCESS)

        # 2. 加载系统调用号（offset 0）
        filters += SeccompFilter._bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0, 0, OFFSET_NR)

        # 3. 对每个黑名单系统调用：匹配 → ERRNO|EPERM
        for nr in deny_numbers:
            # JEQ nr → 跳到 return_errno（jt=1），否则继续（jf=0）
            filters += SeccompFilter._bpf_stmt(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, nr)

        # 4. 默认 ALLOW
        filters += SeccompFilter._bpf_stmt(BPF_RET | BPF_K, 0, 0, RET_ALLOW)

        # 5. return_errno: ERRNO|EPERM
        filters += SeccompFilter._bpf_stmt(BPF_RET | BPF_K, 0, 0, RET_ERRNO_EPERM)

        # 写入文件
        os.makedirs(os.path.dirname(filter_path), exist_ok=True)
        with open(filter_path, "wb") as f:
            f.write(bytes(filters))
        os.chmod(filter_path, 0o400)

        log.info("seccomp 过滤器已生成", extra={
            "path": filter_path,
            "deny_count": len(deny_numbers),
            "size": len(filters),
        })

        return filter_path
