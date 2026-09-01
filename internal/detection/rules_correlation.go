// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Correlation rules join multiple events from one session/trace
// window into a single higher-order detection. They are the Phase-2
// core: the attack chains (injection → credential read → exfiltration;
// shell → download → write → payload exec) are only visible when
// events are correlated, never from any single event.

// correlatedRule adapts a function; identical shape to atomicRule but
// kept separate for documentation clarity.
type correlatedRule struct {
	id   string
	name string
	eval func(ctx *EvalContext) []DetectionResult
}

func (r correlatedRule) ID() string                     { return r.id }
func (r correlatedRule) Name() string                   { return r.name }
func (r correlatedRule) Evaluate(ctx *EvalContext) []DetectionResult { return r.eval(ctx) }

// priorEvents returns window events strictly before the trigger
// (older timestamp, or same timestamp but different row), oldest
// first. Correlation only looks backwards: the trigger completes the
// chain.
func priorEvents(ctx *EvalContext) []audit.BehaviorEvent {
	out := make([]audit.BehaviorEvent, 0, len(ctx.Window))
	for _, w := range ctx.Window {
		if w.ID == ctx.Event.ID {
			continue
		}
		if w.Timestamp.After(ctx.Event.Timestamp) {
			continue
		}
		out = append(out, w)
	}
	return out
}

// credentialExposureEvents finds events indicating credential material
// became available to the agent: direct credential-store reads
// (file/tool) or guardrail secret findings in content.
func credentialExposureEvents(events []audit.BehaviorEvent) []audit.BehaviorEvent {
	var out []audit.BehaviorEvent
	for _, w := range events {
		switch {
		case isReadEventType(w.EventType) && IsCredentialAccessText(eventText(w)):
			out = append(out, w)
		case w.EventType == audit.RuntimeEventContentSecret:
			out = append(out, w)
		}
	}
	return out
}

// lastN keeps at most n newest events from an oldest-first slice.
func lastN(events []audit.BehaviorEvent, n int) []audit.BehaviorEvent {
	if len(events) <= n {
		return events
	}
	return events[len(events)-n:]
}

// DataExfiltrationRule: credential/sensitive material read followed by
// outbound traffic in the same session ⇒ credential exfiltration.
// Works for every agent: the rule sees only unified events.
type DataExfiltrationRule struct{ correlatedRule }

// NewDataExfiltrationRule returns the credential-exfiltration
// correlation rule. Trigger: any network.send / network.request.
func NewDataExfiltrationRule() Rule {
	return DataExfiltrationRule{correlatedRule{id: "credential-exfiltration", name: "Credential Exfiltration", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if !isSendEventType(ev.EventType) {
			return nil
		}
		prior := priorEvents(ctx)
		exposures := credentialExposureEvents(prior)
		if len(exposures) == 0 {
			return nil
		}
		exposures = lastN(exposures, 3)

		evidence := make([]EvidenceSpec, 0, len(exposures)+1)
		for _, w := range exposures {
			evidence = append(evidence, EvidenceSpec{
				EventID: w.ID,
				Role:    audit.DetectionRoleSupporting,
				Outcome: w.Outcome,
			})
		}
		evidence = append(evidence, EvidenceSpec{
			EventID: ev.ID,
			Role:    audit.DetectionRoleTrigger,
			Outcome: ev.Outcome,
		})

		detail := "同一会话中先出现凭据/敏感内容暴露，随后发生网络外发："
		for i, w := range exposures {
			if i >= 2 {
				detail += " 等"
				break
			}
			detail += truncateStr(firstNonEmptyStr(w.Target, w.Detail, w.EventType), 80) + "；"
		}
		detail += "外发目标 " + truncateStr(firstNonEmptyStr(ev.Target, ev.Operation), 80)

		return []DetectionResult{{
			DetectionType: "credential_exfiltration",
			Category:      "attack",
			Severity:      "CRITICAL",
			Confidence:    0.9,
			Title:         "凭据外泄攻击链",
			Detail:        detail,
			Remediation:   "立即轮换相关凭据；检查外发目标与数据量；回溯会话中的注入信号确认攻击入口。",
			Attributes: map[string]any{
				"destination":    ev.Target,
				"exposure_count": len(exposures),
				"blocked":        strings.EqualFold(ev.Outcome, "blocked"),
			},
			Evidence: evidence,
		}}
	}}}
}

// PromptInjectionDrivenExfiltrationRule: prompt injection → credential
// read → network send in one session. This is the flagship chain for
// "Prompt 攻击导致越权、敏感数据读取、外泄".
type PromptInjectionDrivenExfiltrationRule struct{ correlatedRule }

// NewPromptInjectionDrivenExfiltrationRule returns the
// injection-driven-exfiltration correlation rule. Trigger: any
// network.send / network.request.
func NewPromptInjectionDrivenExfiltrationRule() Rule {
	return PromptInjectionDrivenExfiltrationRule{correlatedRule{id: "injection-driven-exfiltration", name: "Prompt Injection Driven Exfiltration", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if !isSendEventType(ev.EventType) {
			return nil
		}
		prior := priorEvents(ctx)
		var injections, exposures []audit.BehaviorEvent
		for _, w := range prior {
			switch {
			case w.EventType == audit.RuntimeEventContentInjection:
				injections = append(injections, w)
			}
		}
		if len(injections) == 0 {
			return nil
		}
		exposures = credentialExposureEvents(prior)
		if len(exposures) == 0 {
			return nil
		}
		injection := injections[len(injections)-1]
		exposures = lastN(exposures, 3)

		evidence := []EvidenceSpec{{
			EventID: injection.ID,
			Role:    audit.DetectionRoleTrigger,
			Outcome: injection.Outcome,
		}}
		for _, w := range exposures {
			evidence = append(evidence, EvidenceSpec{
				EventID: w.ID,
				Role:    audit.DetectionRoleSupporting,
				Outcome: w.Outcome,
			})
		}
		evidence = append(evidence, EvidenceSpec{
			EventID: ev.ID,
			Role:    audit.DetectionRoleTrigger,
			Outcome: ev.Outcome,
		})

		return []DetectionResult{{
			DetectionType: "prompt_injection_driven_exfiltration",
			Category:      "attack",
			Severity:      "CRITICAL",
			Confidence:    0.96,
			Title:         "提示注入驱动的数据外泄",
			Detail: "完整攻击链命中：提示注入 → 凭据/敏感内容读取（" +
				truncateStr(firstNonEmptyStr(exposures[len(exposures)-1].Target, exposures[len(exposures)-1].EventType), 80) +
				"）→ 网络外发（" + truncateStr(firstNonEmptyStr(ev.Target, ev.Operation), 80) + "）",
			Remediation:   "终止该会话；轮换全部已暴露凭据；审查注入内容的来源（用户输入/工具返回/网页内容）。",
			Attributes: map[string]any{
				"chain":          "injection->credential_access->exfiltration",
				"destination":    ev.Target,
				"blocked":        strings.EqualFold(ev.Outcome, "blocked"),
			},
			Evidence: evidence,
		}}
	}}}
}

// ExploitBehaviorRule: shell execution → remote download → payload
// write → payload execution, the classic 漏洞利用导致异常行为
// chain that never touches Prompt/LLM/Tool hooks and is only visible
// via the OS sensor.
type ExploitBehaviorRule struct{ correlatedRule }

// NewExploitBehaviorRule returns the runtime-exploitation correlation
// rule. Trigger: process.exec.
func NewExploitBehaviorRule() Rule {
	return ExploitBehaviorRule{correlatedRule{id: "exploit-behavior", name: "Runtime Exploitation", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.EventType != audit.RuntimeEventProcessExec && ev.EventType != audit.RuntimeEventToolPreCall {
			return nil
		}
		text := eventText(ev)
		if !shellishText(text) && !MatchesSuspiciousExec(text) {
			return nil
		}
		prior := priorEvents(ctx)

		var shellExec, download, write []audit.BehaviorEvent
		for _, w := range prior {
			wText := eventText(w)
			switch {
			case isExecEventType(w.EventType) && shellishText(wText):
				shellExec = append(shellExec, w)
			case w.EventType == audit.RuntimeEventNetworkDownload || (isSendEventType(w.EventType) && downloadishText(wText)):
				download = append(download, w)
			case w.EventType == audit.RuntimeEventFileWrite || (w.EventType == audit.RuntimeEventToolPreCall && (strings.Contains(strings.ToLower(w.ToolName), "write") || strings.Contains(strings.ToLower(w.ToolName), "edit"))):
				write = append(write, w)
			}
		}
		// The trigger itself can be the shell stage of the chain.
		if ev.EventType == audit.RuntimeEventToolPreCall && len(shellExec) == 0 {
			shellExec = []audit.BehaviorEvent{ev}
		}
		if len(download) == 0 || len(write) == 0 {
			return nil
		}

		payloadExec := MatchesSuspiciousExec(text) || ev.EventType == audit.RuntimeEventProcessExec
		severity := "HIGH"
		confidence := 0.75
		title := "疑似漏洞利用行为链"
		if payloadExec {
			severity = "CRITICAL"
			confidence = 0.9
			title = "运行时漏洞利用攻击链"
		}

		evidence := make([]EvidenceSpec, 0, 4)
		if len(shellExec) > 0 {
			s := shellExec[len(shellExec)-1]
			evidence = append(evidence, EvidenceSpec{EventID: s.ID, Role: audit.DetectionRoleSupporting, Outcome: s.Outcome})
		}
		d := download[len(download)-1]
		evidence = append(evidence, EvidenceSpec{EventID: d.ID, Role: audit.DetectionRoleSupporting, Outcome: d.Outcome})
		w := write[len(write)-1]
		evidence = append(evidence, EvidenceSpec{EventID: w.ID, Role: audit.DetectionRoleSupporting, Outcome: w.Outcome})
		evidence = append(evidence, EvidenceSpec{EventID: ev.ID, Role: audit.DetectionRoleTrigger, Outcome: ev.Outcome})

		return []DetectionResult{{
			DetectionType: "possible_runtime_exploitation",
			Category:      "attack",
			Severity:      severity,
			Confidence:    confidence,
			Title:         title,
			Detail: "攻击链命中：Shell 执行（" + truncateStr(firstNonEmptyStr(shellExec[len(shellExec)-1].Target, shellExec[len(shellExec)-1].Operation), 60) +
				"）→ 远程下载（" + truncateStr(firstNonEmptyStr(d.Target, d.Operation), 60) +
				"）→ 载荷写入（" + truncateStr(firstNonEmptyStr(w.Target, w.Operation), 60) +
				"）→ 执行（" + truncateStr(firstNonEmptyStr(ev.Target, ev.Operation), 60) + "）",
			Remediation:   "立即隔离相关进程；对写入的载荷做静态扫描；回溯执行来源确认是否为漏洞利用或提示注入诱导。",
			Attributes: map[string]any{
				"chain":     "shell->download->write->exec",
				"payload":   ev.Target,
				"blocked":   strings.EqualFold(ev.Outcome, "blocked"),
			},
			Evidence: evidence,
		}}
	}}}
}
