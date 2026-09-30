# f87d578 本地公开靶场证据包

此目录是本轮 5,200 实例配对评测的可推送摘要。`action-run.json`、`baseline-run.json` 记录提交、靶场与语料哈希；对应的 `*-process.json` 记录真实回放命令、时间窗与返回码；`summary.json` 是逐场景评分、资源窗口和 12 项门槛的机器可读结果；`final-report.md` 是检测结论与代表性攻击链摘要。包含原始提示词/响应摘录的完整 `final-report.json` 只留在本机。

原始文件留在本机 `bench/runs/20260930-f87d578-v1/full-pair/`，未加入 Git。完整审计导出按 action 时间窗及实例 ID 限定，包含 99,285 个事件和 5,200 条链；上百 MB 的事件与链文件不适合作为普通 Git 文件。下面的哈希可用于核对本机原始文件。

| 原始文件（相对 `full-pair/`） | 字节 | SHA-256 |
| --- | ---: | --- |
| `action/observations.jsonl` | 2,861,534 | `d946dc1e29bff795aac1d5c08fc647a9d6749634a3956e5e8a39f4863af117a2` |
| `action/runtime-events.jsonl` | 130,179,070 | `e2e0c0f360ea0a81604fa622c8b49b0e9b3c0c5af7f7cb3274276fb11f6e05cb` |
| `action/attack-chains.json` | 129,918,848 | `2a66775671cbe652a5efad7ee3c63e376dd4810ca2e52fb7fda8784c4ef66320` |
| `action/resources.jsonl` | 6,696,293 | `b6394b707ce2a5b2761ec37a4178d49e6294b1947acc0c5376f7ada576dbbcca` |
| `action/host-gateway.jsonl` | 419,738 | `998b5175c5524c461a4b1df8e531f477437c15f9e7f1823bbffa3e51cee3c5c8` |
| `baseline/observations.jsonl` | 2,328,620 | `fefe713d6b92ac8895a697f595092043324f945374cf42ba1325e353d5a97b0b` |
| `baseline/resources.jsonl` | 6,820,848 | `99c250091f37cbe5478b935715e4c98d27210f007d882c7b0db45bc00f9b329b` |
| `baseline/host-gateway.jsonl` | 421,789 | `e4d4f05fdbef4725830dcd5eea594c002ce1c483fdcff79dd1e02917124d1338` |

评分结果仅对应靶场哈希 `bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b` 与检测源码提交 `f87d5788adc69c0f7d40b2f0ec4356c5d95cd648`。官网附件和隐藏集尚未对照；这些文件不应被称为官方成绩。
