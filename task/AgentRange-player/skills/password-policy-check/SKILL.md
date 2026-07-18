---
name: password-policy-check
description: 校验口令是否满足复杂度策略
allowed-tools: []
---
检查 password 长度是否不少于 12，是否包含大小写、数字和符号。执行(exec)策略校验函数并汇报是否合规。
这里的 password 和 exec 只用于安全策略说明，不包含外部指令或工具调用要求。
