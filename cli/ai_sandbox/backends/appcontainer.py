# -*- coding: utf-8 -*-
__author__ = '川穹'
__time__ = '2026/09/17'
__desc__ = 'AppContainer 沙箱后端（Windows，WEAK）'

"""
AppContainer 沙箱后端（Windows，WEAK）

全部行为按 2026-09-16 Windows 真机探针定稿（AppContainer PoC 9/10
PASS，见 app/probe/winprobe/ac_poc.py 与《多平台适配Windows探针验证报告》）：

- 进程创建链：CreateProcessW + EXTENDED_STARTUPINFO_PRESENT +
  PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES；产物 Low 完整性
  （S-1-16-4096）；
- ACL 隔离：deny ACE 对 AC SID 无效（实测 deny+继承 allow 仍可写）——
  workspace ACL 仅授 AC SID (OI)(CI)F；`.git` 保护 = 断继承 + 仅授 RX
  （icacls /inheritance:r 后授 AC RX + SYSTEM F + Everyone F）；
- Profile 生命周期：DeriveAppContainerSidFromAppContainerName 对不存在
  的 profile 也返回 S_OK——不能用作存在性检查；正确姿势是无条件
  Delete + Create（6 参签名，第 5 参 dwCapabilityCount 是 DWORD）；
- Capability：SID_AND_ATTRIBUTES.Attributes 必须为 0x4（SE_GROUP_ENABLED），
  WFP 只认启用的组——=1（SE_GROUP_MANDATORY）时 capability 进
  TokenCapabilities 但出网被 UWP BLOCK 拦截，=0 静默失效
  （2026-09-20 真机定稿）；internetClient = S-1-15-3-1（默认授予，
  对齐 bwrap 网络默认放行；attrs 正确时无需防火墙规则即可出网）；
- Job Object：JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 承接级联终止
  （对齐 bwrap --die-with-parent）；AssignProcessToJobObject 传
  OpenProcess 句柄而非 pid；
- 无挂载命名空间 → 虚拟段用 workspace 内 NTFS junction/symlink farm
  （对齐 sandbox-exec 后端的 farm 模式），只读由"目标目录 ACL 不授 AC
  SID"实现；
- agent 视角 workspace = 宿主真实路径（无路径重映射），路径语言与
  sandbox-exec 后端同构（host_to_sandbox/agent_path_to_host 纯函数）。

本模块仅 win32 可导入（registry 惰性注册）。
"""

import ctypes
import ctypes.wintypes as wt
import os
import stat
import subprocess
import tempfile
from typing import Optional

from .. import settings as config
from ..base import (
    PROBE_DEFECT, PROBE_MISSING, SANDBOX_LEVEL_WEAK,
    SandboxBackend, SandboxProbeError, SandboxRunner,
    agent_path_to_host, host_to_sandbox,
)

# 冒烟测试超时（秒）
APPCONTAINER_SMOKE_TIMEOUT = 20

# AC profile 名（本产品专用，注册表落盘一次）
APPCONTAINER_PROFILE_NAME = "autonomous-agent-sandbox"

# capability SID（SDDL 字符串；Attributes=1 才生效——探针 T7 定稿）
INTERNET_CLIENT_SDDL = "S-1-15-3-1"

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_SUSPENDED = 0x00000004
# 无窗口 conhost（真机定稿 2026-09-29）：无 std 的 AC 控制台进程启动时
# attach 父控制台被拒，每次运行向宿主控制台泄漏一条裸 "Access is
# denied."——CREATE_NO_WINDOW 改走无窗口会话，实测裸行归零且功能不变
CREATE_NO_WINDOW = 0x08000000

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wt.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [("AppContainerSid", ctypes.c_void_p),
                ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
                ("CapabilityCount", wt.DWORD), ("Reserved", wt.DWORD)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", ctypes.c_void_p),
                ("lpDesktop", ctypes.c_void_p), ("lpTitle", ctypes.c_void_p),
                ("dwX", wt.DWORD), ("dwY", wt.DWORD),
                ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD),
                ("dwXCountChars", wt.DWORD), ("dwYCountChars", wt.DWORD),
                ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD),
                ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE),
                ("hStdError", wt.HANDLE)]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", wt.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wt.LARGE_INTEGER),
                ("LimitFlags", wt.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wt.DWORD),
                ("Affinity", ctypes.POINTER(wt.ULONG)),
                ("PriorityClass", wt.DWORD),
                ("SchedulingClass", wt.DWORD)]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "ReadOperationCount", "WriteOperationCount",
        "OtherOperationCount", "ReadTransferCount",
        "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


JobObjectExtendedLimitInformation = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

kernel32.UpdateProcThreadAttribute.restype = wt.BOOL
kernel32.UpdateProcThreadAttribute.argtypes = (
    ctypes.c_void_p, wt.DWORD, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p)
kernel32.CreateProcessW.restype = wt.BOOL
kernel32.CreateProcessW.argtypes = (
    ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p,
    wt.BOOL, wt.DWORD, ctypes.c_void_p, ctypes.c_wchar_p,
    ctypes.c_void_p, ctypes.c_void_p)
kernel32.InitializeProcThreadAttributeList.restype = wt.BOOL
kernel32.InitializeProcThreadAttributeList.argtypes = (
    ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.POINTER(ctypes.c_size_t))
userenv.CreateAppContainerProfile.restype = ctypes.HRESULT
userenv.CreateAppContainerProfile.argtypes = (
    ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
    ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p))
userenv.DeleteAppContainerProfile.restype = ctypes.HRESULT
userenv.DeleteAppContainerProfile.argtypes = (ctypes.c_wchar_p,)
advapi32.ConvertSidToStringSidW.restype = wt.BOOL
advapi32.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_wchar_p))
advapi32.ConvertStringSidToSidW.restype = wt.BOOL
advapi32.ConvertStringSidToSidW.argtypes = (ctypes.c_wchar_p,
                                            ctypes.POINTER(ctypes.c_void_p))


def get_appcontainer_sid(profile_name: str = APPCONTAINER_PROFILE_NAME):
    """无条件 Delete + Create 落盘 AC profile，返回 (psid, sddl)。

    Derive…FromName 对不存在的 profile 也返回 S_OK（探针陷阱 1），
    不能用作存在性检查——直接重建最可靠。
    """
    userenv.DeleteAppContainerProfile(profile_name)
    psid = ctypes.c_void_p()
    hr = userenv.CreateAppContainerProfile(
        profile_name, ctypes.c_wchar_p("autonomous-agent"),
        ctypes.c_wchar_p("AppContainer sandbox"), None, 0,
        ctypes.byref(psid))
    if hr != 0:
        raise OSError(
            f"CreateAppContainerProfile hr=0x{hr & 0xffffffff:08x}")
    sddl = ctypes.c_wchar_p()
    advapi32.ConvertSidToStringSidW(psid, ctypes.byref(sddl))
    return psid, sddl.value


def _make_capabilities(ac_psid, capability_sdds: list[str]):
    """AC SID + SDDL capability 列表 → SECURITY_CAPABILITIES。

    AppContainerSid 必须显式传入（真机验证 2026-09-17：None + capability
    组合 CreateProcessW 直接 err=87 ERROR_INVALID_PARAMETER）；
    Attributes=0x4(SE_GROUP_ENABLED) 才生效（2026-09-20 真机实测定稿：
    attrs=1 时 capability 在 TokenCapabilities 中存在但 WFP SD 检查不认，
    出站被 UWP Default Outbound Block 拦截）。
    """
    entries = None
    count = 0
    if capability_sdds:
        entries = (SID_AND_ATTRIBUTES * len(capability_sdds))()
        for i, sddl in enumerate(capability_sdds):
            sid = ctypes.c_void_p()
            if not advapi32.ConvertStringSidToSidW(
                    ctypes.c_wchar_p(sddl), ctypes.byref(sid)):
                raise OSError("ConvertStringSidToSidW failed")
            entries[i].Sid = sid
            entries[i].Attributes = 0x4  # SE_GROUP_ENABLED
        count = len(capability_sdds)
    return SECURITY_CAPABILITIES(ac_psid, entries, count, 0), entries


def _apply_workspace_acl(workspace_dir: str, ac_sddl: str,
                         extra_ro_mounts: dict, system_mounts: dict) -> None:
    """ACL 隔离（探针定稿 + 真机验证 2026-09-17 补全）：

    - workspace 授 AC 全权；
    - `.git` 断继承仅授 RX（deny ACE 对 AC SID 无效，只能用"断继承 +
      只授所需"表达只读）；
    - 外置 system_root 的其余系统段（.tmp/.screenshots/.playwright-mcp）
      授 AC 全权——AppContainer 访问检查只认 AC SID 显式授权，宿主继承
      ACL（user:F）对 AC 不生效，不授则沙箱内写入被拒；
    - 只读 farm 段（skills 等）授 AC RX：不授则连读都被拒（AC 语义下
      宿主继承 user ACL 不生效）。

    每会话幂等重授（icacls /grant 幂等；/inheritance:r 对已断继承目录
    无害）。调用时机：farm 建立之后（.git 等目标目录须先物理就位）。
    """
    def _icacls(*args: str) -> None:
        # 超时 240s：授 (OI)(CI) 继承 ACE 时 icacls 同步等待向全子树传播
        # ——runtime node_modules/site-packages 数万文件首次授权可达分钟
        # 级（AC SID 由 profile 名确定性派生，ACL 已在时幂等重授秒过）
        subprocess.run(["icacls", *args], capture_output=True, timeout=240)

    _icacls(workspace_dir, "/grant", f"*{ac_sddl}:(OI)(CI)F")
    for host_path in (extra_ro_mounts or {}).values():
        if host_path:
            _icacls(host_path, "/grant", f"*{ac_sddl}:(OI)(CI)RX")
    for name, host_path in (system_mounts or {}).items():
        if not host_path or name == config.GIT_DIR_NAME:
            continue
        _icacls(host_path, "/grant", f"*{ac_sddl}:(OI)(CI)F")
    # 解释器目录授 AC 读执行（真机定稿 2026-09-17：AC 默认无权读取
    # 用户目录/非系统位置（Program Files 有 ALL APPLICATION PACKAGES
    # 兜底）——不授则沙箱内 python 等工具直接"拒绝访问"）
    git_bin, _ = config.resolve_git()
    for bin_path in (config.PYTHON_PATH,
                     config.resolve_node_bin() or "",
                     git_bin or ""):
        if bin_path:
            bin_dir = os.path.dirname(os.path.abspath(bin_path))
            if os.path.isdir(bin_dir):
                _icacls(bin_dir, "/grant", f"*{ac_sddl}:(OI)(CI)RX")
    git_dir = system_mounts.get(config.GIT_DIR_NAME)
    if git_dir and os.path.isdir(git_dir):
        _icacls(git_dir, "/inheritance:r")
        _icacls(git_dir, "/grant",
                f"*{ac_sddl}:(OI)(CI)RX",  # AC 只读
                "SYSTEM:(F)",               # 系统全权（快照写走宿主侧）
                r"*S-1-1-0:(OI)(CI)F")      # workspace 内 Everyone 全权


def _create_job_object():
    """KILL_ON_JOB_CLOSE Job Object（级联终止，对齐 bwrap --die-with-parent）"""
    job = kernel32.CreateJobObjectW(None, None)
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    kernel32.SetInformationJobObject(
        job, JobObjectExtendedLimitInformation,
        ctypes.byref(info), ctypes.sizeof(info))
    return job


def spawn_in_appcontainer(argv: Optional[list[str]], chdir: str, ac_psid,
                          capability_sdds: Optional[list[str]] = None,
                          raw_cmdline: Optional[str] = None):
    """在 AC 内创建进程（无 std 管道形态）。

    - argv：常规参数表（经 list2cmdline 拼接）；
    - raw_cmdline：显式命令行（cmd 重定向等含引号语法必须走此参数——
      list2cmdline 的 CRT 转义与 cmd /c 的引号规则不兼容，真机实测
      2026-09-17）；
    返回 (hProcess, hThread, pid, job)。

    真机验证定稿（2026-09-17，Win11）：
    - lowbox（AppContainer）进程无法使用宿主继承的 std 管道句柄——
      一律 STATUS_DLL_INIT_FAILED(0xC0000142)；且 HANDLE_LIST 属性
      与 SECURITY_CAPABILITIES 互斥（err=87）→ 管道协议在 AC 不可行，
      stdio 一律经 cmd 文件重定向（见 AppContainerRunner.run）；
    - 进程以 CREATE_SUSPENDED 创建，调用方 ResumeThread 前已赋入
      Job Object（防窗口期逃逸）。
    """
    sec_caps, _cap_keepalive = _make_capabilities(
        ac_psid, capability_sdds or [INTERNET_CLIENT_SDDL])

    size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not kernel32.InitializeProcThreadAttributeList(
            buf, 1, 0, ctypes.byref(size)):
        raise SandboxProbeError(
            "InitializeProcThreadAttributeList 失败", PROBE_DEFECT)
    try:
        if not kernel32.UpdateProcThreadAttribute(
                buf, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ctypes.byref(sec_caps), ctypes.sizeof(sec_caps),
                None, None):
            raise OSError(f"UpdateProcThreadAttribute 失败 "
                          f"err={ctypes.get_last_error()}")

        si = STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        si.lpAttributeList = ctypes.cast(buf, ctypes.c_void_p)

        cmdline = raw_cmdline or subprocess.list2cmdline(argv or [])
        cmd = ctypes.create_unicode_buffer(cmdline)
        pi = PROCESS_INFORMATION()
        created = kernel32.CreateProcessW(
            None, cmd, None, None, False,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            None, chdir, ctypes.byref(si.StartupInfo), ctypes.byref(pi))
        if not created:
            raise OSError(f"CreateProcessW 失败 "
                          f"err={ctypes.get_last_error()}")
    finally:
        kernel32.DeleteProcThreadAttributeList(buf)

    # Job Object 承接级联终止（resume 前赋入，防窗口期逃逸）
    # 真机定稿 2026-09-17：AssignProcessToJobObject 需要
    # PROCESS_SET_QUOTA(0x0100)|PROCESS_TERMINATE(0x0001)——误用
    # 0x0002(CREATE_THREAD) 会静默拒绝（Assign 失败不报错，Job 空挂，
    # KILL_ON_JOB_CLOSE 形同虚设，级联终止实测失效）
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = (wt.DWORD, wt.BOOL, wt.DWORD)
    kernel32.AssignProcessToJobObject.restype = wt.BOOL
    kernel32.AssignProcessToJobObject.argtypes = (wt.HANDLE, wt.HANDLE)
    job = _create_job_object()
    h_proc_for_job = kernel32.OpenProcess(
        0x0100 | 0x0001, False, pi.dwProcessId)  # SET_QUOTA|TERMINATE
    if not h_proc_for_job or not kernel32.AssignProcessToJobObject(
            job, h_proc_for_job):
        err = ctypes.get_last_error()
        kernel32.TerminateProcess(pi.hProcess, 1)
        kernel32.CloseHandle(pi.hProcess)
        kernel32.CloseHandle(pi.hThread)
        if h_proc_for_job:
            kernel32.CloseHandle(h_proc_for_job)
        kernel32.CloseHandle(job)
        raise OSError(f"AssignProcessToJobObject 失败 err={err}")
    kernel32.CloseHandle(h_proc_for_job)
    return pi.hProcess, pi.hThread, pi.dwProcessId, job


def _ac_wait(h_process: int, job: int, timeout_s: float) -> int:
    """等待 AC 进程退出并回收句柄；超时终止 Job（级联）后抛
    subprocess.TimeoutExpired。返回退出码。"""
    import time as _time
    deadline = _time.monotonic() + timeout_s
    rc = wt.DWORD()
    while True:
        if kernel32.WaitForSingleObject(h_process, 500) == 0:
            break
        if _time.monotonic() > deadline:
            kernel32.CloseHandle(job)  # KILL_ON_JOB_CLOSE 级联终止
            kernel32.WaitForSingleObject(h_process, 5000)
            kernel32.GetExitCodeProcess(h_process, ctypes.byref(rc))
            kernel32.CloseHandle(h_process)
            raise subprocess.TimeoutExpired([], int(timeout_s))
    kernel32.GetExitCodeProcess(h_process, ctypes.byref(rc))
    kernel32.CloseHandle(job)
    kernel32.CloseHandle(h_process)
    return rc.value


def _is_link_entry(path: str) -> bool:
    """junction / symlink 判定（lexists 前提下）。

    Python 对 NTFS junction 的 os.path.islink() 恒 False（lstat 不为
    mount point 设 S_IFLNK，只标 st_reparse_tag，bpo-37834），必须按
    reparse tag 判定——否则 farm 幂等会把上次会话建的 junction 误判为
    "非链接实体目录"（2026-09-29 真机定稿，同一工作空间第二次会话必炸）。
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return (stat.S_ISLNK(st.st_mode)
            or st.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT)


class AppContainerRunner(SandboxRunner):
    """AppContainer 会话级运行器（AC profile + ACL + junction farm）"""

    def __init__(self, workspace_dir: str,
                 extra_ro_mounts: Optional[dict[str, str]] = None,
                 system_dir: Optional[str] = None):
        from ..workspace import system_mounts_for
        self._workspace_dir = workspace_dir
        self._extra_ro_mounts = extra_ro_mounts or {}
        self._system_mounts = system_mounts_for(system_dir) if system_dir else {}

        self._ac_psid, self._ac_sddl = get_appcontainer_sid()

        # ---- junction farm：虚拟段 → 宿主物理目录（对齐 sandbox-exec）----
        # 先建立 farm（.git 等目标目录物理就位），ACL 后置覆盖全部段
        # （.git 断继承依赖目录已存在；只读段授 AC RX、可写系统段授 AC F）
        import _winapi
        for virt, host_path in self._extra_ro_mounts.items():
            if host_path:
                self._ensure_farm_link(
                    os.path.join(workspace_dir, virt), host_path)
        for name, host_path in self._system_mounts.items():
            if not host_path:
                continue
            if name == config.GIT_DIR_NAME:
                os.makedirs(host_path, exist_ok=True)
            self._ensure_farm_link(
                os.path.join(workspace_dir, name), host_path)
        _apply_workspace_acl(workspace_dir, self._ac_sddl,
                             self._extra_ro_mounts, self._system_mounts)

    @staticmethod
    def _ensure_farm_link(link_path: str, target: str) -> None:
        """幂等创建虚拟段 junction（farm）。脏链接重建，非链接同名项报错。

        单树布局（link == target）时直接确保目录存在。junction 不需要
        特权且不穿透末段符号链接语义，对齐 sandbox-exec 的 farm 行为：
        已正确指向 → 幂等返回（junction 识别按 reparse tag，见
        _is_link_entry——os.path.islink 对 junction 恒 False）。
        """
        if os.path.normpath(link_path) == os.path.normpath(target):
            os.makedirs(target, exist_ok=True)
            return
        if os.path.lexists(link_path):
            if _is_link_entry(link_path):
                if os.path.realpath(link_path) == os.path.realpath(target):
                    os.makedirs(target, exist_ok=True)  # 悬空但指对：目标可能被外部删
                    return  # 已正确指向
                os.rmdir(link_path)  # 脏链接（目标漂移）重建；junction 删除不递归目标内容
            else:
                raise ValueError(
                    f"[SANDBOX] 虚拟段路径已被非链接条目占用: {link_path}")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.makedirs(target, exist_ok=True)
        import _winapi
        _winapi.CreateJunction(target, link_path)

    def build_command(self, argv: list[str], chdir: str) -> list[str]:
        # AC 进程创建走 CreateProcessW（spawn 层），此处仅语义占位
        return list(argv)

    def run(self, argv: Optional[list[str]], chdir: str, timeout: Optional[int] = None,
            extra_env: Optional[dict] = None,
            raw_command: Optional[str] = None) -> subprocess.CompletedProcess:
        """一次性执行（真机定稿 2026-09-29：ver 两段式 + CREATE_NO_WINDOW）。

        lowbox 进程无法使用宿主继承的 std 管道（0xC0000142）→ 由 AC 内
        的 cmd 自行完成 `> out 2>&1` 重定向，宿主读取落盘文件。输出文件
        落 .tmp 系统段（已授 AC 写权），读后即删。

        命令形态（探针 #3-#7 真机定稿，每条均有实证）：
        - 前段 `ver >nul 2>&1 &` 占位：cmd /c 尾串首字符必须非引号——
          否则 cmd 剥首引号+最后一个引号且先于重定向解析，inner 以
          `"{exe}"` 开头时重定向目标必然损坏（out 落盘失败 + rc=1）；
          ver 为纯内建零副作用（原 chcp 65001 前缀已删：chcp 在无控制
          台 AC 内必失败，且是裸"拒绝访问"噪声源之一）；
        - 可执行文件路径必须加引号——AC 内 cmd 对无引号的完整路径解析
          直接"拒绝访问"；
        - raw_command：显式 inner 命令串（含引号语法必须走此参数——
          list2cmdline 的 CRT 转义与 cmd 引号规则不兼容；cmd 语义
          oneshot 批处理 `"cmd" /d /c <相对路径>.cmd` 走此通道，
          绝对路径批处理在 AC 内被拒、相对路径正常）；
        - 输出解码 utf-8 → gbk（replace）链：批处理/中文输出为 CP936。

        已知限制（挂账）：pwsh 语法命令在 AC 内不可执行（PowerShell
        全系在 AC 内启动失败，见验证报告）；dir 枚举在 AC 内被拒
        （读单文件正常）。
        """
        import uuid as _uuid
        out_dir = self._system_mounts.get(config.TMP_DIR_NAME) \
            or self._workspace_dir
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(
            out_dir, f".ac-run-{os.getpid()}-{_uuid.uuid4().hex[:8]}.out")
        cmd_exe = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
        # extra_env 经 cmd set 注入（AC 进程环境继承宿主，无法在
        # CreateProcessW 层传入——沙箱 node 工具的 NODE_PATH 等走此通道）
        env_prefix = ""
        if extra_env:
            sets = " ".join(f'set "{k}={v}" &' for k, v in extra_env.items())
            env_prefix = f"{sets} "
        if raw_command is not None:
            inner = raw_command
        else:
            inner = f'"{argv[0]}" {subprocess.list2cmdline(list(argv[1:]))}'
        raw = (f'"{cmd_exe}" /d /c ver >nul 2>&1 & '
               f'{env_prefix}{inner} > "{out_file}" 2>&1')
        h_proc, h_thread, pid, job = spawn_in_appcontainer(
            None, chdir, self._ac_psid, raw_cmdline=raw)
        kernel32.ResumeThread(h_thread)
        kernel32.CloseHandle(h_thread)
        try:
            rc = _ac_wait(h_proc, job,
                          timeout or config.PYTHON_MAX_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.unlink(out_file)
            except OSError:
                pass
            raise
        raw_out = b""
        try:
            if os.path.exists(out_file):
                with open(out_file, "rb") as f:
                    raw_out = f.read()
        finally:
            try:
                os.unlink(out_file)
            except OSError:
                pass
        try:
            text = raw_out.decode("utf-8")
        except UnicodeDecodeError:
            text = raw_out.decode("gbk", errors="replace")
        return subprocess.CompletedProcess(argv, rc, stdout=text, stderr="")

    def spawn(self, argv: list[str], chdir: str,
              extra_env: Optional[dict] = None):
        """长驻 Shell（stdin/stdout 管道协议）在 AC 不可用——lowbox 进程
        无法使用宿主继承的 std 管道句柄（真机定稿，见 run 注释）。
        抛出 NotImplementedError，_PersistentShell 捕获后自动回退
        一次性执行（产品已有降级路径）。"""
        raise NotImplementedError(
            "AppContainer 不支持长驻 Shell 管道（lowbox 限制），"
            "已回退一次性执行")

    # ---- 路径语言（shell 视角 = 宿主真实路径，对齐 sandbox-exec）----

    def agent_root(self) -> str:
        return self._workspace_dir

    def agent_path(self, shell_path: str) -> str:
        return host_to_sandbox(shell_path, self._workspace_dir,
                               self._extra_ro_mounts, self._system_mounts) \
            or shell_path

    def shell_path(self, agent_path: str) -> str:
        return agent_path_to_host(agent_path, self._workspace_dir,
                                  self._extra_ro_mounts, self._system_mounts)

    def host_to_agent_path(self, path: str,
                           extra_ro_mounts: Optional[dict[str, str]] = None,
                           system_mounts: Optional[dict[str, str]] = None) -> Optional[str]:
        return host_to_sandbox(
            path, self._workspace_dir,
            extra_ro_mounts if extra_ro_mounts is not None else self._extra_ro_mounts,
            system_mounts if system_mounts is not None else self._system_mounts)

    def agent_python_bin(self) -> str:
        return config.PYTHON_PATH

    def agent_node_bin(self) -> str:
        return config.resolve_node_bin() or "node"


class AppContainerBackend(SandboxBackend):
    """AppContainer 后端（Windows，WEAK）"""

    name = "appcontainer"
    level = SANDBOX_LEVEL_WEAK

    def probe(self) -> None:
        """冒烟自检：AC 内执行 cmd /c exit 0（最小权限链路）。

        失败形态：非 win32（注册异常）/ 创建链 OSError（defect，含
        profile 落盘失败）。
        """
        import sys as _sys
        if _sys.platform != "win32":
            raise SandboxProbeError(
                "appcontainer 仅 Windows 可用（注册异常）", PROBE_MISSING)
        try:
            psid, _ = get_appcontainer_sid()
            h, t, pid, job = spawn_in_appcontainer(
                [os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"),
                 "/c", "exit", "0"],
                tempfile.gettempdir(), psid)
            # CREATE_SUSPENDED 创建：resume 后线程句柄即无用
            kernel32.ResumeThread(t)
            kernel32.CloseHandle(t)
            kernel32.WaitForSingleObject(h, APPCONTAINER_SMOKE_TIMEOUT * 1000)
            rc = wt.DWORD()
            kernel32.GetExitCodeProcess(h, ctypes.byref(rc))
            kernel32.CloseHandle(job)
            kernel32.CloseHandle(h)
        except OSError as e:
            raise SandboxProbeError(
                f"AppContainer 创建链失败: {e}", PROBE_DEFECT)
        if rc.value != 0:
            raise SandboxProbeError(
                f"AppContainer 冒烟测试失败（AC 内 cmd exit 0）: "
                f"exit code {rc.value}", PROBE_DEFECT)

    def make_runner(self, workspace_dir: str,
                    extra_ro_mounts: Optional[dict[str, str]] = None,
                    system_dir: Optional[str] = None) -> SandboxRunner:
        return AppContainerRunner(workspace_dir,
                                  extra_ro_mounts=extra_ro_mounts,
                                  system_dir=system_dir)
