# AgentRange 评委展示页

该目录提供一个无外部依赖、可离线打开的静态验证看板。页面只展示现有报告中可复核的数据，缺失的 observe/action、5200 全量、CPU 和攻击链结果会明确显示为“待实测”。

## 生成与打开

```powershell
cd task/AgentRange-player
python dashboard/build_dashboard.py
Start-Process dashboard/index.html
```

也可以通过本地静态服务器访问：

```powershell
python -m http.server 8088 --directory dashboard
```

当 `bench/results/baseline.json`、`observe.json`、`action.json` 与 `summary.json` 更新后，重新运行生成脚本即可刷新页面指标。
