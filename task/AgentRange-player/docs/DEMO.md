# 固定 Demo 顺序

1. `make static-scan`：展示资产分母、关系边和 meeting-summary/notes-sync 风险。
2. `make rules`：展示每条规则的攻击/两个良性夹具及性能。
3. `integration/run.{ps1,sh} observe`：回放 C1/C2 与 normal，只留证不阻断。
4. `integration/run.{ps1,sh} action`：重点展示 C2-D 在副作用前返回 403。
5. `make attack-chain`：展示污染输入、工具参数、Decision、阻断点和 raw_ref。
6. `make benchmark-summary`：展示 Precision/Recall/FPR/FNR、p50/p95/p99、CPU/内存和正常成功率。
7. 单独回放 C1-A/C1-B：展示请求由 langflow-guard 起始并在转发前阻断。

演示不得调用 `/admin/trajectories` 作为检测或报告证据。该接口只由回放器
负责注入确定性模型桩轨迹。
