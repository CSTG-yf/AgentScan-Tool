# TraceBastion Desktop for Linux

## 安装

Debian、Ubuntu 推荐安装 DEB：

```bash
sudo apt install ./TraceBastion-Desktop-Setup-Linux-x86_64.deb
```

AppImage 可直接运行：

```bash
chmod +x TraceBastion-Desktop-Setup-Linux-x86_64.AppImage
./TraceBastion-Desktop-Setup-Linux-x86_64.AppImage
```

系统级进程守护使用 systemd；受控 Agent 文件视图使用 Linux user/mount namespace 与 FUSE 3。

## 受控启动 Agent

只有通过受控启动器启动的 Agent 才能保证 `returnEmptyContent`。启动器创建 Agent 私有的 mount namespace，加载只读零字节 FUSE 文件，并将命中规则的路径仅在该 namespace 中覆盖。宿主文件以及其他进程看到的内容不会改变。

先在桌面“策略”页面保存 Linux 绝对路径规则，例如：

```json
{
  "id": "hide-private-key",
  "enabled": true,
  "path": "/home/alice/.ssh/id_rsa",
  "matchKind": "exact",
  "access": ["read"],
  "action": "returnEmptyContent",
  "description": "Agent 读取时返回空内容"
}
```

然后使用桌面主程序的受控启动入口：

```bash
/usr/bin/defenseclaw-desktop \
  --run-controlled-agent "$HOME/.config/dev.defenseclaw.desktop/process-guard.json" \
  codex
```

传递 Agent 参数：

```bash
/usr/bin/defenseclaw-desktop \
  --run-controlled-agent "$HOME/.config/dev.defenseclaw.desktop/process-guard.json" \
  codex --resume
```

受控 Agent 中会设置：

```text
TRACEBASTION_CONTROLLED=1
TRACEBASTION_FILE_GUARD=fuse-namespace
```

可以通过 shim 固定入口：

```bash
#!/usr/bin/env bash
exec /usr/bin/defenseclaw-desktop \
  --run-controlled-agent "$HOME/.config/dev.defenseclaw.desktop/process-guard.json" \
  /real/path/to/codex "$@"
```

不要让 shim 再通过 `PATH` 查找同名程序，否则可能递归调用自身。

## 规则行为

- `matchKind: exact`：目标必须是启动时已存在的普通文件。
- `matchKind: subtree`：启动 Agent 时递归展开当时存在的普通文件；Agent 启动后新建的文件不会自动加入这一版的覆盖集合。
- `returnEmptyContent`：`stat` 显示大小为 0，`read`/`pread` 返回 EOF，原文件不变。
- 写访问不会透传到空文件；FUSE 虚拟文件是只读的。
- 未通过启动器运行的 Agent 不属于受控环境，不能上报 `returnEmptyContent` 成功。

## 系统要求和诊断

要求：

- 内核允许非特权 user namespace；
- `/dev/fuse` 可访问；
- 已安装 `fuse3` 和 `fusermount3`；
- 容器或加固系统没有禁止 `CLONE_NEWUSER`/`CLONE_NEWNS`。

检查：

```bash
test -r /dev/fuse
command -v fusermount3
sysctl kernel.unprivileged_userns_clone
```

如果系统策略禁用了非特权 user namespace，需要由管理员评估后启用，或通过具有 `CAP_SYS_ADMIN` 的受限 systemd launcher 服务启动。不要给 Agent 本身授予 `CAP_SYS_ADMIN`。

Agent 退出后，启动器会卸载 FUSE、结束辅助进程并删除会话临时目录。异常终止产生的挂载可使用：

```bash
fusermount3 -u -z /tmp/tracebastion-agent-*/fuse
```
