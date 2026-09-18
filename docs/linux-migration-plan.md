# TraceBastion Linux 桌面迁移与发布计划

## 目标与验收口径

在保留现有 Windows 桌面端、NSIS 安装器和 Windows Service 的前提下，提供功能对等的 Linux 桌面版本，并发布可安装的 Linux setup 包。首个 Linux 发布目标为 Ubuntu 22.04/24.04、Debian 12、x86_64，产物为 `.deb` 与 `.AppImage`。

验收必须覆盖：桌面启动、Gateway 生命周期、Agent 发现、静态资源扫描、Agent 进程及子进程监控、策略应用、命中审计、进程树终止、文件活动审计、`returnEmptyContent` 行为的能力反馈、AgentRange 生命周期、升级/卸载和安装包冒烟测试。

## 架构改造

平台代码使用清晰的物理目录隔离，而不是在同一个大文件中堆叠条件编译：

```text
desktop/src-tauri/src/
  platform/
    mod.rs                 # 稳定的跨平台接口
    windows/
      mod.rs               # Windows 进程、服务、提权与文件审计
    linux/
      mod.rs               # /proc、signal、systemd/pkexec 与 Linux 文件监控
  process_guard.rs         # 共享策略匹配、审计与进程树逻辑
  process_guard_service.rs # 共享服务入口，委托给 platform
```

发布相关文件同样按平台隔离：

```text
desktop/scripts/windows/   # 现有 PowerShell 构建与验收
desktop/scripts/linux/     # Linux 构建、安装器和冒烟测试
desktop/src-tauri/windows/ # NSIS hooks
desktop/src-tauri/linux/   # systemd unit、维护脚本和资源
dist/windows/              # Windows 发布产物
dist/linux/                # Linux 发布产物
```

共享接口至少包含：进程快照、经启动时间校验后的终止、服务安装/启动/停止/卸载、策略安装、守护状态和平台能力描述。

## 分阶段实施

### 1. 进程与 Agent 检测

- Linux 从 `/proc/<pid>/stat`、`/proc/<pid>/comm` 和系统启动时间生成 PID、PPID、进程名、启动标识与运行时长。
- 启动标识用于防止 PID 复用后误杀；终止按子孙深度从叶到根发送 `SIGTERM`，宽限期后按策略升级为 `SIGKILL`。
- Agent 名称匹配统一去除 Windows `.exe` 后缀，使同一策略可跨平台工作；知识库增加 Linux 进程名字段，默认策略按当前平台选择名称。
- 增加 Linux `/proc` 解析、祖先归因、PID 复用和进程树终止测试。

### 2. Linux 守护与状态管理

- 增加 systemd system service，数据目录使用 `/var/lib/defenseclaw`，配置使用 `/etc/defenseclaw`，审计使用 `/var/log/defenseclaw`。
- 桌面端通过 `pkexec` 调用固定参数的自身管理入口；不拼接 shell 命令，策略路径先规范化和校验。
- `install/start/stop/apply/uninstall` 在 Windows 继续调用 SCM，在 Linux 调用 systemd；环境页面展示当前平台名称和真实服务状态。
- AppImage 允许无守护服务运行 UI/Gateway；系统级监控明确显示为“未安装”，不伪装成正常。

### 3. 文件监控与 `returnEmptyContent`

- Windows 保留 Security Event Log/SACL 实现。
- Linux 文件事件由 inotify/fanotify 适配层采集，并沿 `/proc` 进程树归因到 Agent。
- `terminateAgentTree` 可在命中后执行；`returnEmptyContent` 只有通过 TraceBastion 启动/注入的受控 Agent 文件代理才能在读取前返回零字节内容。
- 对普通、未注入进程，Linux 内核审计只能观察或拒绝访问，不能透明替换读取结果；此时必须记录 `unsupportedForUnmanagedProcess`，UI 展示降级状态，绝不误报“已返回空文件”。首版 setup 包包含受控代理入口，后续可选 FUSE/eBPF 模块不阻塞基础发布。

### 4. 桌面功能与跨平台命令

- 移除 `docker.exe`、`explorer.exe`、`sc.exe` 等硬编码，分别选择 `docker`、`xdg-open` 和平台服务适配器。
- Gateway、AgentRange、导出、策略、扫描、事件、攻击链、设置等共用 API 保持不变。
- 页面文案从“Windows 进程守护”改为平台中性名称，能力详情由后端动态返回。

### 5. Linux setup 与 CI 发布

- Tauri 配置启用 Linux `deb` 与 `appimage`，Linux 包携带 systemd unit 和安装/卸载维护脚本。
- `desktop/scripts/linux/build.sh` 构建 Gateway、Web UI、Rust 宿主并归档到 `dist/linux/`；`test-installer.sh` 在干净 Ubuntu runner 验证安装、服务、卸载和数据保留策略。
- 新增独立 `desktop-linux.yml`，与 Windows workflow 和产物目录完全分开；tag 发布同时上传 Windows `.exe`、Linux `.deb` 和 `.AppImage`。

## 执行顺序

1. 建立平台接口和 Linux `/proc` 实现，迁移 Windows 实现但不改变行为。
2. 接入跨平台策略校验、Agent 名称和进程守护测试。
3. 实现 systemd/pkexec 管理、环境状态与 UI 平台化。
4. 实现 Linux 文件事件与空内容能力反馈。
5. 增加 Linux Tauri 配置、构建脚本、维护脚本和 CI。
6. 运行 Rust、TypeScript、Go/Python 相关回归；在 Linux CI/主机生成并冒烟验证 setup 产物。

## 发布门槛与已知边界

- Windows 回归和 NSIS 产物不得变化或退化。
- Linux Rust 单测、前端类型检查、Gateway 测试和安装器冒烟必须通过。
- `.deb` 服务模式需要 systemd 与管理员授权；AppImage 本身不自动取得系统级监控权限。
- 未受控进程的 `returnEmptyContent` 不作为“成功执行”上报。这是操作系统拦截语义的限制，而非静默降级；产品界面和审计均需可见。
