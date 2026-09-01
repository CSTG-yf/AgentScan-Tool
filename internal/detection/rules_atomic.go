// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// atomicRule adapts a plain function into the Rule interface so each
// single-event rule stays a few lines of matching logic.
type atomicRule struct {
	id   string
	name string
	eval func(ctx *EvalContext) []DetectionResult
}

func (r atomicRule) ID() string                     { return r.id }
func (r atomicRule) Name() string                   { return r.name }
func (r atomicRule) Evaluate(ctx *EvalContext) []DetectionResult { return r.eval(ctx) }

// triggerEvidence builds the single-event evidence slice.
func triggerEvidence(ev audit.BehaviorEvent) []EvidenceSpec {
	return []EvidenceSpec{{
		EventID: ev.ID,
		Role:    audit.DetectionRoleTrigger,
		Outcome: ev.Outcome,
	}}
}

// severityOr derives the detection severity from the event severity,
// falling back to the rule default when the pipeline did not set one.
func severityOr(ev audit.BehaviorEvent, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(ev.Severity)) {
	case "critical", "high", "medium", "low":
		return strings.ToUpper(ev.Severity)
	default:
		return fallback
	}
}

// confidenceOr merges the event confidence with the rule default.
func confidenceOr(ev audit.BehaviorEvent, fallback float64) float64 {
	if ev.Confidence > fallback {
		return ev.Confidence
	}
	return fallback
}

// PromptInjectionRule fires when the Guardrail pipeline already
// classified content as prompt injection. The detection layer turns
// that observation into a first-class risk record.
type PromptInjectionRule struct{ atomicRule }

// CredentialAccessRule fires on reads of credential stores
// (~/.aws/credentials, .env, id_rsa, ...). One "file.read of
// ~/.aws/credentials" event is only an event; this rule is what makes
// it a credential_access detection.
type CredentialAccessRule struct{ atomicRule }

// SensitiveFileRule fires on reads of sensitive system/secret files
// (/etc/shadow, ~/.ssh, secret stores).
type SensitiveFileRule struct{ atomicRule }

// SSRFDefenseRule fires when the proxy blocked an egress attempt.
// IMDS targets escalate to critical — metadata credentials are the
// classic cloud foothold.
type SSRFDefenseRule struct{ atomicRule }

// UntrustedNetworkRule fires on traffic to raw-IP or known
// staging/exfil endpoints.
type UntrustedNetworkRule struct{ atomicRule }

// DangerousCommandRule fires on shell patterns that are almost never
// benign (curl|sh, fork bombs, rm -rf /, encoded PowerShell, ...).
type DangerousCommandRule struct{ atomicRule }

// SuspiciousProcessRule fires on obfuscated or staged process
// execution observed by the OS sensor (encoded PowerShell, payload
// executes from temp dirs, LOLBins fetching remote content).
type SuspiciousProcessRule struct{ atomicRule }

// ToolAbuseRule fires when agent tools write to system/sensitive
// locations or execute download-and-execute flows.
type ToolAbuseRule struct{ atomicRule }

// NewPromptInjectionRule returns the prompt-injection atomic rule.
func NewPromptInjectionRule() Rule {
	return PromptInjectionRule{atomicRule{id: "prompt-injection", name: "Prompt Injection", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.EventType != audit.RuntimeEventContentInjection {
			return nil
		}
		return []DetectionResult{{
			DetectionType: "prompt_injection",
			Category:      "attack",
			Severity:      severityOr(ev, "HIGH"),
			Confidence:    confidenceOr(ev, 0.9),
			Title:         "提示注入攻击检测",
			Detail:        firstNonEmptyStr(ev.Detail, "Guardrail 判定内容中存在提示注入/指令注入信号"),
			Remediation:   "检查该会话的完整输入输出，确认注入来源；必要时阻断会话并轮换可能已暴露的凭据。",
			Attributes:    map[string]any{"source_event": ev.EventType},
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

// NewCredentialAccessRule returns the credential-access atomic rule.
func NewCredentialAccessRule() Rule {
	return CredentialAccessRule{atomicRule{id: "credential-access", name: "Credential Access", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if !isReadEventType(ev.EventType) {
			return nil
		}
		if !IsCredentialAccessText(eventText(ev)) {
			return nil
		}
		return []DetectionResult{{
			DetectionType: "credential_access",
			Category:      "attack",
			Severity:      "HIGH",
			Confidence:    0.85,
			Title:         "敏感凭据文件访问",
			Detail:        "Agent 读取了凭据存储路径：" + truncateStr(firstNonEmptyStr(ev.Target, ev.Operation), 160),
			Remediation:   "确认该读取是否为用户明确指令；检查后续是否有外发事件，必要时轮换相关凭据。",
			Attributes:    map[string]any{"path": ev.Target},
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

// NewSensitiveFileRule returns the sensitive-file atomic rule.
func NewSensitiveFileRule() Rule {
	return SensitiveFileRule{atomicRule{id: "sensitive-file", name: "Sensitive File Access", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if !isReadEventType(ev.EventType) {
			return nil
		}
		if !IsSensitiveFileText(eventText(ev)) {
			return nil
		}
		return []DetectionResult{{
			DetectionType: "sensitive_file_access",
			Category:      "suspicious",
			Severity:      "MEDIUM",
			Confidence:    0.7,
			Title:         "敏感系统文件访问",
			Detail:        "Agent 读取了敏感系统/密钥文件路径：" + truncateStr(firstNonEmptyStr(ev.Target, ev.Operation), 160),
			Remediation:   "复核该访问的业务必要性；关注后续进程执行与网络外发行为。",
			Attributes:    map[string]any{"path": ev.Target},
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

// NewSSRFDefenseRule returns the SSRF/egress-block atomic rule.
func NewSSRFDefenseRule() Rule {
	return SSRFDefenseRule{atomicRule{id: "ssrf-defense", name: "SSRF / Egress Defense", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.EventType != audit.RuntimeEventNetworkBlocked {
			return nil
		}
		detail := strings.ToLower(eventText(ev))
		isIMDS := strings.Contains(detail, "imds") || strings.Contains(detail, "169.254.169.254") || strings.Contains(detail, "metadata")
		detectionType := "ssrf_blocked"
		severity := "HIGH"
		confidence := 0.9
		title := "SSRF 防护拦截"
		if isIMDS {
			detectionType = "ssrf_imds_access"
			severity = "CRITICAL"
			confidence = 0.95
			title = "云元数据服务(IMDS)访问拦截"
		}
		return []DetectionResult{{
			DetectionType: detectionType,
			Category:      "attack",
			Severity:      severity,
			Confidence:    confidence,
			Title:         title,
			Detail:        "Proxy 拦截了出站请求：" + truncateStr(firstNonEmptyStr(ev.Detail, ev.Target), 200),
			Remediation:   "检查请求来源与目标地址；IMDS 访问通常意味着攻击者尝试获取云凭据。",
			Attributes:    map[string]any{"target": ev.Target, "imds": isIMDS},
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

// NewUntrustedNetworkRule returns the untrusted-destination atomic rule.
func NewUntrustedNetworkRule() Rule {
	return UntrustedNetworkRule{atomicRule{id: "untrusted-network", name: "Untrusted Network Access", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.EventType != audit.RuntimeEventNetworkRequest && ev.EventType != audit.RuntimeEventNetworkSend && ev.EventType != audit.RuntimeEventNetworkConnect {
			return nil
		}
		if !IsUntrustedDestination(firstNonEmptyStr(ev.Target, ev.Operation)) {
			return nil
		}
		return []DetectionResult{{
			DetectionType: "untrusted_network_access",
			Category:      "suspicious",
			Severity:      "MEDIUM",
			Confidence:    0.75,
			Title:         "访问不可信网络目标",
			Detail:        "出站请求目标为裸 IP 或已知暂存/外泄端点：" + truncateStr(ev.Target, 160),
			Remediation:   "确认目标是否在业务白名单内；结合同会话的文件读取事件判断是否存在数据外传。",
			Attributes:    map[string]any{"target": ev.Target},
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

// NewDangerousCommandRule returns the dangerous-command atomic rule.
func NewDangerousCommandRule() Rule {
	return DangerousCommandRule{atomicRule{id: "dangerous-command", name: "Dangerous Command", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.EventType != audit.RuntimeEventToolPreCall && ev.EventType != audit.RuntimeEventProcessExec && ev.EventType != audit.RuntimeEventToolPostCall {
			return nil
		}
		text := eventText(ev)
		if !MatchesDangerousCommand(text) {
			return nil
		}
		return []DetectionResult{{
			DetectionType: "dangerous_command",
			Category:      "attack",
			Severity:      "HIGH",
			Confidence:    0.85,
			Title:         "高危命令执行",
			Detail:        "Agent 命令命中危险模式（远程脚本执行/破坏性命令/混淆执行）：" + truncateStr(text, 200),
			Remediation:   "立即复核命令来源与完整命令行；确认是否为提示注入诱导，必要时终止会话。",
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

// NewSuspiciousProcessRule returns the suspicious-process atomic rule.
func NewSuspiciousProcessRule() Rule {
	return SuspiciousProcessRule{atomicRule{id: "suspicious-process", name: "Suspicious Process", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.EventType != audit.RuntimeEventProcessExec {
			return nil
		}
		text := eventText(ev)
		if !MatchesSuspiciousExec(text) {
			return nil
		}
		return []DetectionResult{{
			DetectionType: "suspicious_process",
			Category:      "suspicious",
			Severity:      "HIGH",
			Confidence:    0.8,
			Title:         "可疑进程执行",
			Detail:        "OS Sensor 观察到混淆/暂存目录执行的进程：" + truncateStr(text, 200),
			Remediation:   "检查进程父子关系与命令行来源；该模式常见于漏洞利用后的落地执行阶段。",
			Attributes:    map[string]any{"pid": ev.AgentPID, "ppid": ev.PPID, "target": ev.Target},
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

// NewToolAbuseRule returns the tool-abuse atomic rule: writes into
// system paths or download-to-file tool flows.
func NewToolAbuseRule() Rule {
	return ToolAbuseRule{atomicRule{id: "tool-abuse", name: "Tool Abuse", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		isWrite := ev.EventType == audit.RuntimeEventToolPreCall || ev.EventType == audit.RuntimeEventToolPostCall || ev.EventType == audit.RuntimeEventFileWrite
		if !isWrite {
			return nil
		}
		text := eventText(ev)
		tool := strings.ToLower(ev.ToolName)
		targetsSensitive := (strings.Contains(tool, "write") || strings.Contains(tool, "edit") || ev.EventType == audit.RuntimeEventFileWrite) &&
			(IsSensitiveFileText(text) || IsCredentialAccessText(text) || strings.Contains(strings.ToLower(text), "/etc/") || strings.Contains(strings.ToLower(text), "\\windows\\system32"))
		downloadToFile := downloadishText(text) && (strings.Contains(tool, "bash") || strings.Contains(tool, "shell") || ev.EventType == audit.RuntimeEventProcessExec)
		if !targetsSensitive && !downloadToFile {
			return nil
		}
		detail := "Agent 工具尝试修改敏感路径"
		if downloadToFile {
			detail = "Agent 工具执行下载写入流程"
		}
		return []DetectionResult{{
			DetectionType: "tool_abuse",
			Category:      "suspicious",
			Severity:      "MEDIUM",
			Confidence:    0.7,
			Title:         "Agent 工具越权使用",
			Detail:        detail + "：" + truncateStr(text, 200),
			Remediation:   "确认该操作是否在预期工作区内；关注写入文件的后续执行行为。",
			Evidence:      triggerEvidence(ev),
		}}
	}}}
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
