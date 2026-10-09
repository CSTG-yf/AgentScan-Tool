# -*- coding: utf-8 -*-
"""沙箱内执行：一次性命令 + 会话级持久 Shell + 输出封口/落盘

来源：
- `PersistentShell` / `cap_proc_output` / `offload_large_output` /
  `write_temp_code`：原项目 src/tools/sandbox_tools.py 的同名实现（逐字保留
  逻辑：标记协议、cwd 双轨、超时杀整个 shell、输出封口与落盘保留上限）；
- `SandboxSession`：本工具包新增的便捷门面，把「解析后端 → 建 runner →
  跑 shell/python/node」串成三行代码，供不接 LangChain 的项目直接使用；
  python/node 的原实现在源项目里是 LangChain 工具（含脚本参数、curl、
  node wrapper 等），此处按同一 argv 语义精简复刻，差异见 README。

持久 Shell 的价值：export 的环境变量、cd 的工作目录、后台进程、shell 函数
跨多次调用保持；命令超时或 shell 死亡则下次调用自动重启（因为沙箱内无法
只杀单条命令，故终止整个 shell —— --die-with-parent + PID namespace 级联）。
"""

import os
import posixpath
import subprocess
import tempfile
import threading
import time
import uuid

from . import settings as config
from .base import WORKSPACE_AGENT_ROOT
from .logging_compat import log
from .registry import get_sandbox_backend
from .shell_profile import ShellProfile, get_shell_profile

__all__ = ["cap_proc_output", "offload_large_output", "write_temp_code",
           "PersistentShell", "SandboxSession"]

# ---- 大输出源端捕获（借鉴 deepagents capture-at-source）----
_LARGE_OUTPUT_SUBDIR = "large-outputs"   # .tmp 下落盘子目录名
_LARGE_OUTPUT_KEEP_FILES = 100           # 落盘文件保留数量上限
_LARGE_OUTPUT_PREVIEW_CHARS = 1000       # 头/尾预览长度（字符）
_TOOL_OUTPUT_LOG_PREVIEW_CHARS = 2000    # 日志预览长度上限


# ============================================================
#  文件系统横切（源：src/utils/fsops.py，仅收录沙箱层用到的一项）
# ============================================================
def _prune_dir_keep_newest(directory: str, keep: int,
                           pattern: str = "*.txt") -> int:
    """目录保留清理：按 mtime 保留最新 keep 个文件，其余删除（失败静默）"""
    import glob
    try:
        entries = glob.glob(os.path.join(directory, pattern))
        entries.sort(key=os.path.getmtime, reverse=True)
    except OSError:
        return 0
    removed = 0
    for path in entries[keep:]:
        try:
            os.unlink(path)
            removed += 1
        except OSError:
            pass
    return removed


def _timestamped_name(name: str = "", fallback: str = "tool") -> str:
    """时间戳文件名主体：{清洗名}-{毫秒:x}-{随机hex}"""
    stamp = f"{int(time.time() * 1000):x}-{os.urandom(3).hex()}"
    safe = "".join(ch if (ch.isalnum() or ch in "_.-") else "_"
                   for ch in (name or ""))[:64] or (fallback if name else "")
    return f"{safe}-{stamp}" if safe else stamp


# ============================================================
#  输出封口与落盘
# ============================================================
def cap_proc_output(output: str) -> str:
    """进程输出统一封口：超 PYTHON_MAX_OUTPUT_BYTES 截断，空输出替占位文案"""
    if len(output) > config.PYTHON_MAX_OUTPUT_BYTES:
        output = output[:config.PYTHON_MAX_OUTPUT_BYTES] + "\n... (输出截断)"
    return output if output.strip() else "(无输出)"


def log_tool_output(tool: str, command: str, output: str) -> None:
    """沙箱命令输出落日志（超长仅记头尾预览）"""
    preview = output
    if len(preview) > _TOOL_OUTPUT_LOG_PREVIEW_CHARS:
        head = preview[:_TOOL_OUTPUT_LOG_PREVIEW_CHARS // 2]
        tail = preview[-_TOOL_OUTPUT_LOG_PREVIEW_CHARS // 2:]
        preview = (head + f"\n...[日志预览截断，全文 {len(output)} 字符]...\n"
                   + tail)
    log.info(f"[{tool}] 命令输出 | command: {command[:500]}\n{preview}")


def offload_large_output(text: str, workspace_dir: str, tool_name: str,
                         system_dir: str = None) -> str:
    """大输出源端捕获：超限全文写入 .tmp/large-outputs/，内联只留头尾预览 + 路径。

    落盘失败回退为头尾拼接（绝不让工具因落盘报错）。
    """
    if len(text) <= config.SHELL_OUTPUT_INLINE_MAX_CHARS:
        return text
    head = text[:_LARGE_OUTPUT_PREVIEW_CHARS]
    tail = text[-_LARGE_OUTPUT_PREVIEW_CHARS:]
    try:
        filename = _timestamped_name(tool_name) + ".txt"
        tmp_base = (os.path.join(system_dir, config.TMP_DIR_NAME)
                    if system_dir else os.path.join(workspace_dir, config.TMP_DIR_NAME))
        out_dir = os.path.join(tmp_base, _LARGE_OUTPUT_SUBDIR)
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as f:
            f.write(text)
        _prune_dir_keep_newest(out_dir, _LARGE_OUTPUT_KEEP_FILES)
        sandbox_path = (f"{WORKSPACE_AGENT_ROOT}/{config.TMP_DIR_NAME}/"
                        f"{_LARGE_OUTPUT_SUBDIR}/{filename}")
        return (head
                + f"\n...[输出过长，已完整保存至 {sandbox_path}，可用 read 工具查看]...\n"
                + tail)
    except Exception as e:
        log.warning("大输出落盘失败，回退头尾拼接",
                    extra={"tool": tool_name, "error": str(e)})
        return (head
                + f"\n...[输出过长（{len(text)} 字符），落盘失败，仅保留头尾预览]...\n"
                + tail)


def write_temp_code(workspace_dir: str, subdir: str, suffix: str, code: str,
                    system_dir: str = None) -> tuple[str, str]:
    """写入临时代码到系统数据区 .tmp/<subdir>/，返回 (宿主路径, 沙箱内路径)"""
    tmp_base = (os.path.join(system_dir, config.TMP_DIR_NAME)
                if system_dir else os.path.join(workspace_dir, config.TMP_DIR_NAME))
    tmp_dir = os.path.join(tmp_base, subdir)
    os.makedirs(tmp_dir, exist_ok=True)
    fd, host_path = tempfile.mkstemp(suffix=suffix, dir=tmp_dir)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(code)
    sandbox_path = (f"{WORKSPACE_AGENT_ROOT}/{config.TMP_DIR_NAME}/"
                    f"{subdir}/{os.path.basename(host_path)}")
    return host_path, sandbox_path


# ============================================================
#  会话级持久 Shell
# ============================================================
class PersistentShell:
    """会话级持久 Shell：长驻沙箱+shell 进程，跨调用保持状态。

    沙箱外壳与协议语法分属两轴：
    - 轴 A（runner）：隔离外壳（spawn/build_command）+ 路径语言双向翻译；
    - 轴 B（profile）：shell 协议（标记/前奏/编码/启动旗标）。

    cwd 双轨：self._cwd 为 shell 内视角，cwd_state["current"] 为产品语言。
    """

    def __init__(self, runner, profile: ShellProfile, cwd_state: dict,
                 extra_env: dict | None = None):
        self._runner = runner
        self._profile = profile
        self._cwd_state = cwd_state
        self._extra_env = extra_env or None
        self._cwd = runner.shell_path(
            cwd_state.get("current") or WORKSPACE_AGENT_ROOT)
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()          # 串行化命令执行
        self._dead = True
        self._unavailable = False              # 持久模式不可用（回退一次性）
        self._done = threading.Event()
        self._uid = b""
        self._buf = bytearray()
        self._tail = bytearray()
        self._truncated = False
        self._marker_found = False
        self._result_pwd: str | None = None
        self._result_rc: int | None = None

    # ---- 进程生命周期 ----
    def _spawn(self):
        """启动（或重启）常驻 shell 进程"""

        def _popen(chdir: str) -> subprocess.Popen:
            return self._runner.spawn(self._profile.spawn_argv(), chdir,
                                      self._extra_env)

        try:
            self._proc = _popen(self._cwd)
        except OSError:
            # cwd 可能已被删除，回退 workspace 根
            self._cwd = self._runner.agent_root()
            self._proc = _popen(self._cwd)
        self._dead = False
        init = self._profile.session_init()
        if init:
            try:
                self._proc.stdin.write(init.encode(self._profile.encoding()))
                self._proc.stdin.flush()
            except (OSError, ValueError):
                log.warning("session_init 注入失败", extra={"shell": self._profile.name})
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _kill_proc(self):
        """终止 shell（bwrap 死 → 沙箱内全组进程终止）"""
        proc, self._proc = self._proc, None
        self._dead = True
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        if self._done:
            self._done.set()

    def dispose(self):
        """会话释放时终止常驻 shell"""
        with self._lock:
            self._kill_proc()

    # ---- 读线程 ----
    def _read_loop(self):
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            while True:
                chunk = proc.stdout.read1(65536)
                if not chunk:
                    break
                self._on_chunk(chunk)
        except (OSError, ValueError):
            pass
        finally:
            self._dead = True
            self._done.set()

    def _on_chunk(self, chunk: bytes):
        """读线程：输出入缓冲（超限截断保头部），滚动窗口扫描结束标记"""
        cap = config.PYTHON_MAX_OUTPUT_BYTES
        if len(self._buf) < cap:
            space = cap - len(self._buf)
            self._buf += chunk[:space]
            if len(chunk) > space:
                self._truncated = True
        elif chunk:
            self._truncated = True
        self._tail += chunk
        if len(self._tail) > 8192:
            del self._tail[:-8192]     # 滚动窗口防跨 chunk 截断
        if self._marker_found or not self._uid:
            return
        prefix = self._profile.marker_prefix(self._uid.decode("ascii"))
        idx = self._tail.find(prefix)
        if idx < 0:
            return
        end = self._tail.find(self._profile.marker_terminator(),
                              idx + len(prefix))
        if end < 0:
            return  # 标记行不完整，等下个 chunk
        meta = self._tail[idx + len(prefix):end]
        pwd_b, _, rc_b = meta.rpartition(b"__")
        self._marker_found = True
        self._result_pwd = pwd_b.decode(self._profile.encoding(), "replace")
        try:
            self._result_rc = int(rc_b)
        except ValueError:
            pass
        self._done.set()

    # ---- 命令执行 ----
    def _reset_for_command(self, uid: str):
        self._uid = uid.encode()
        self._buf = bytearray()
        self._tail = bytearray()
        self._truncated = False
        self._marker_found = False
        self._result_pwd = None
        self._result_rc = None
        self._done = threading.Event()

    def _build_script(self, command: str, uid: str) -> str:
        # cwd_state（产品语言）→ shell 视角后对比生成 cd 前奏
        target = self._cwd_state.get("current") or WORKSPACE_AGENT_ROOT
        shell_target = self._runner.shell_path(target)
        prologue = ""
        if shell_target != self._cwd:
            prologue = self._profile.cwd_sync(shell_target)
        trailer = self._profile.marker(uid)
        return prologue + command.rstrip("\n") + "\n" + trailer

    def _send(self, script: str):
        self._proc.stdin.write(script.encode(self._profile.encoding()))
        self._proc.stdin.flush()

    def _extract_output(self) -> str:
        data = bytes(self._buf)
        prefix = self._profile.marker_prefix(self._uid.decode("ascii"))
        idx = data.find(prefix)
        if idx >= 0:
            data = data[:idx]
            # 去掉标记行前补的换行（printf \n / Write-Output CRLF 均容忍）
            if data.endswith(b"\n"):
                data = data[:-1]
            if data.endswith(b"\r"):
                data = data[:-1]
        text = data.decode(self._profile.encoding(), errors="replace")
        if self._truncated:
            text = text[:config.PYTHON_MAX_OUTPUT_BYTES] + "\n... (输出截断)"
        return text

    # ---- 状态 ----
    @property
    def persistent_available(self) -> bool:
        """常驻 shell 是否在用；False = 本后端不支持，已回退一次性执行。

        （典型：Windows AppContainer 的 lowbox 不允许标准句柄管道，
        源项目在此明确回退并告警，而不是假装成功。）
        """
        return not self._unavailable

    def run(self, command: str, timeout: float = None) -> str:
        """入口：持久模式启用且可用走常驻 shell，否则一次性执行"""
        if not config.SHELL_PERSISTENT_ENABLED or self._unavailable:
            return self._oneshot(command)
        return self.execute(command, timeout)

    def execute(self, command: str, timeout: float = None) -> str:
        timeout = timeout or config.PYTHON_MAX_TIMEOUT_SECONDS
        with self._lock:
            if self._dead or self._proc is None:
                try:
                    self._spawn()
                except Exception as e:
                    self._unavailable = True
                    log.warning("持久 shell 启动失败，回退一次性执行",
                                extra={"error": str(e)})
                    return self._oneshot(command)

            uid = uuid.uuid4().hex[:12]
            script = self._build_script(command, uid)
            try:
                self._reset_for_command(uid)
                self._send(script)
            except (OSError, ValueError):
                # 闲置期间死亡（被杀/OOM）：重启重试一次
                log.info("持久 shell 闲置期间死亡，重启重试")
                self._kill_proc()
                try:
                    self._spawn()
                    self._reset_for_command(uid)
                    self._send(script)
                except Exception:
                    self._unavailable = True
                    return self._oneshot(command)

            if not self._done.wait(timeout):
                log.warning("持久 shell 命令超时，终止 shell",
                            extra={"timeout": timeout})
                self._kill_proc()
                return (f"命令超时（{int(timeout)}s）。持久 shell 已终止"
                        "（包括后台进程），下次调用将自动重启。")

            if self._result_rc is None:
                # shell 已退出（exit 命令/EOF）且未产生标记
                self._kill_proc()
                out = self._extract_output()
                return ((out + "\n[shell 进程已退出，下次调用将自动重启]")
                        .strip() or "(无输出)")

            # shell 实际工作目录回写（cd xxx && cmd 对会话状态生效）
            shell_pwd = self._result_pwd
            agent_pwd = (self._runner.agent_path(shell_pwd)
                         if shell_pwd else None)
            if agent_pwd and (agent_pwd == WORKSPACE_AGENT_ROOT
                              or agent_pwd.startswith(WORKSPACE_AGENT_ROOT + "/")):
                self._cwd = shell_pwd
                self._cwd_state["current"] = agent_pwd

            out = self._extract_output()
            if self._result_rc != 0:
                out += f"\n[exit code: {self._result_rc}]"
            return out if out.strip() else "(无输出)"

    def _oneshot(self, command: str) -> str:
        """一次性执行（持久化 shell 不可用时的兜底）"""
        try:
            chdir = self._runner.shell_path(
                self._cwd_state.get("current") or WORKSPACE_AGENT_ROOT)
            result = self._profile.oneshot(
                self._runner, command, chdir, extra_env=self._extra_env)
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr if output else result.stderr
            return cap_proc_output(output)
        except subprocess.TimeoutExpired:
            return f"命令超时（{config.PYTHON_MAX_TIMEOUT_SECONDS}s）"
        except Exception as e:
            return f"执行失败: {e}"


# ============================================================
#  便捷门面
# ============================================================
class SandboxSession:
    """一个工作空间的沙箱会话（解析后端 → 建 runner → 跑 shell/python/node）。

    用法：
        with SandboxSession("/tmp/ws") as s:
            print(s.shell("echo hi && pwd"))
            print(s.python(code="print(1+1)"))

    参数：
        workspace_dir   宿主侧可写工作目录（沙箱内映射为 /workspace）
        system_dir      系统数据段落点（.tmp/.git 等）；缺省用 workspace_dir
        extra_ro_mounts {虚拟段名: 宿主路径} 只读挂载（如技能目录）
        extra_env       注入沙箱进程的环境变量（如凭据）
        backend/profile 显式指定（缺省走 registry 解析 / 平台默认）
    """

    def __init__(self, workspace_dir: str, system_dir: str = None,
                 extra_ro_mounts: dict | None = None,
                 extra_env: dict | None = None, backend=None,
                 profile: ShellProfile | None = None):
        backend = backend or get_sandbox_backend()
        self.backend = backend
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.system_dir = os.path.abspath(system_dir) if system_dir else None
        self.extra_ro_mounts = extra_ro_mounts or None
        self.extra_env = extra_env or None
        self.profile = profile or get_shell_profile(backend=backend.name)
        os.makedirs(self.workspace_dir, exist_ok=True)
        self.runner = backend.make_runner(self.workspace_dir,
                                          self.extra_ro_mounts, self.system_dir)
        self.cwd_state = {"current": WORKSPACE_AGENT_ROOT}
        self._shell = PersistentShell(self.runner, self.profile,
                                      self.cwd_state, self.extra_env)

    # ---- shell ----
    @property
    def persistent_available(self) -> bool:
        """常驻 shell 是否在用（False = 本后端回退一次性执行，无状态保持）"""
        return self._shell.persistent_available

    def shell(self, command: str, timeout: float = None) -> str:
        """在沙箱内执行 shell 命令（会话级持久：cd/export/后台进程跨调用保持）"""
        return self._shell.run(command, timeout)

    def oneshot(self, command: str, timeout: float = None) -> str:
        """强制一次性执行（不起常驻 shell）"""
        return self._shell._oneshot(command)

    # ---- python / node ----
    def python(self, code: str = "", script: str = "", args: list = None,
               timeout: float = None) -> str:
        """执行 Python 代码或脚本（在沙箱内）。code 与 script 二选一。"""
        if code and script:
            return "错误: code 与 script 参数只能二选一"
        if not code and not script:
            return "错误: 必须提供 code 或 script 参数"
        temp_host_path = None
        try:
            if script:
                if os.path.isabs(script) and not script.startswith("/workspace"):
                    converted = self.runner.host_to_agent_path(
                        script, self.extra_ro_mounts,
                        _system_mounts(self.system_dir))
                    if not converted:
                        return f"错误: script 路径必须在 /workspace 范围内: {script}"
                    script = converted
                if not script.startswith("/"):
                    current = self.cwd_state.get("current") or WORKSPACE_AGENT_ROOT
                    script = posixpath.normpath(posixpath.join(current, script))
                if script != WORKSPACE_AGENT_ROOT and \
                        not script.startswith(WORKSPACE_AGENT_ROOT + "/"):
                    return f"错误: script 路径必须在 /workspace 范围内: {script}"
                argv = [self.runner.agent_python_bin(),
                        self.runner.shell_path(script),
                        *[str(a) for a in (args or [])]]
            else:
                temp_host_path, sandbox_path = write_temp_code(
                    self.workspace_dir, "python", ".py", code, self.system_dir)
                argv = [self.runner.agent_python_bin(),
                        self.runner.shell_path(sandbox_path)]
            result = self.runner.run(
                argv,
                chdir=self.runner.shell_path(
                    self.cwd_state.get("current") or WORKSPACE_AGENT_ROOT),
                timeout=timeout, extra_env=self.extra_env)
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr if output else result.stderr
            output = cap_proc_output(output)
            log_tool_output("python", script or "inline-code", output)
            return offload_large_output(output, self.workspace_dir, "python",
                                        self.system_dir)
        except subprocess.TimeoutExpired:
            return f"Python 执行超时（{config.PYTHON_MAX_TIMEOUT_SECONDS}s）"
        except Exception as e:
            return f"执行失败: {e}"
        finally:
            if temp_host_path:
                try:
                    os.unlink(temp_host_path)
                except OSError:
                    pass

    def node(self, code: str, timeout: float = None) -> str:
        """执行 Node.js 代码（在沙箱内）"""
        host_path, sandbox_path = write_temp_code(
            self.workspace_dir, "node", ".js", code, self.system_dir)
        try:
            result = self.runner.run(
                [self.runner.agent_node_bin(),
                 self.runner.shell_path(sandbox_path)],
                chdir=self.runner.shell_path(
                    self.cwd_state.get("current") or WORKSPACE_AGENT_ROOT),
                timeout=timeout, extra_env=self.extra_env)
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr if output else result.stderr
            output = cap_proc_output(output)
            log_tool_output("node", "inline-code", output)
            return offload_large_output(output, self.workspace_dir, "node",
                                        self.system_dir)
        except subprocess.TimeoutExpired:
            return f"Node.js 执行超时（{config.PYTHON_MAX_TIMEOUT_SECONDS}s）"
        except Exception as e:
            return f"执行失败: {e}"
        finally:
            try:
                os.unlink(host_path)
            except OSError:
                pass

    # ---- 生命周期 ----
    def dispose(self):
        self._shell.dispose()
        close = getattr(self.runner, "close", None)
        if close is not None:
            close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.dispose()
        return False


def _system_mounts(system_dir: str | None):
    """系统数据段表（无 system_dir 时返回 None）"""
    if not system_dir:
        return None
    from .workspace import system_mounts_for
    return system_mounts_for(system_dir)
