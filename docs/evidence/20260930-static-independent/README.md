# 独立静态扫描证据

本目录对应公开靶场哈希 `bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b`。`static-scan.json` 由 `integration/static_inventory.py` 从靶场 Compose、环境变量、Dockerfile、Skill 和 Python 源码生成，不读取 `assets.yaml`、`static-ground-truth.yaml` 或场景标签。关系图的 33 条边各自带有源配置或 Dockerfile 位置，其中 `can_load` 表示镜像包含该 Skill，不等于运行时实际调用。

`static-eval.json` 是独立的离线评分结果，只有评分阶段才读取冻结的 `static-ground-truth.yaml`。本地标注集的资产 TP/FP/FN 为 `27/0/0`，风险对 TP/FP/FN 为 `13/0/0`，五项静态门槛全部通过。扫描器还输出 21 条逐位置发现；风险评分按 `(rule_id, asset_id)` 去重，因此发现条数不等于风险对数。

从仓库根目录复现：

```powershell
python .\integration\static_inventory.py --output .\integration\reports\static-scan.json
python .\integration\static_eval.py --scan .\integration\reports\static-scan.json --output .\integration\reports\static-eval.json
```

此结果只证明该公开靶场和冻结标注集。运行时配对评测和原始审计的来源仍见 [f87d578 证据包](../20260930-f87d578/README.md)。
