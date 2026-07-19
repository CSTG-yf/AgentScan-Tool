# AgentRange 联调操作手册

## 前置条件

- Docker 与 Docker Compose
- Python 3.12+，并安装 `requirements-dev.txt`
- observe/action 模式需要已初始化的 DefenseClaw、受限监听地址和 API Token
- 不得将 inspect API 以无鉴权形式暴露到局域网
- 本项目不运行 Go 测试，也不依赖 CI/CD/GitHub 测试；核心构建结果需单独记录

## Windows

```powershell
Copy-Item .env.example .env
$env:DEFENSECLAW_API_BASE = "http://host.docker.internal:18970"
$env:DEFENSECLAW_API_TOKEN = "<token>"
./integration/run.ps1 baseline
./integration/run.ps1 observe
./integration/run.ps1 action
python bench/benchmark.py summarize
python integration/report.py
```

`integration/report.py` 会读取 `integration/requirements.yaml`，因此缺失 Gateway
烟雾、observe/action 或全量 benchmark 时会明确显示“已实现待证据”，不会推断为通过。

## Linux

```bash
cp .env.example .env
export DEFENSECLAW_API_BASE=http://host.docker.internal:18970
export DEFENSECLAW_API_TOKEN='<token>'
bash integration/run.sh baseline
bash integration/run.sh observe
bash integration/run.sh action
python bench/benchmark.py summarize
python integration/report.py
```

每个模式都会重新创建受保护组件，避免环境变量沿用。原始结果位于
`bench/results/`，静态、运行时、攻击链和最终报告位于
`integration/reports/`。

## 故障降级

- 默认 `DEFENSECLAW_FAIL_MODE=open`：业务继续，证据记录
  `integration-fail-open`。
- 高危演示可设为 `closed`：检查服务不可用时返回 403，同时记录原因。
- HTTP 5xx、超时和连接失败计入 benchmark 的 `invalid`，不伪装成安全阻断。

## 清理

```bash
docker compose down -v
make clean-reports
```
