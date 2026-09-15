package detection

import (
	"encoding/json"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"strings"
)

// InspectFinding carries rule metadata only, never request or evidence text.
type InspectFinding struct {
	RuleID     string   `json:"rule_id"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Tags       []string `json:"tags"`
}

func NewInspectFindingsRule() Rule {
	return atomicRule{id: "inspect-findings", name: "Structured Inspection Findings", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.Attributes["inspection_status"] != "complete" {
			return nil
		}
		b, err := json.Marshal(ev.Attributes["inspect_findings"])
		if err != nil {
			return nil
		}
		var findings []InspectFinding
		if json.Unmarshal(b, &findings) != nil {
			return nil
		}
		groups := map[string]*DetectionResult{}
		var order []string
		for _, f := range findings {
			severity := strings.ToUpper(f.Severity)
			if f.RuleID == "" || audit.SeverityRank(severity) <= 1 {
				continue
			}
			kind, title, category := "inspection_risk", "请求或内容检查发现风险", "suspicious"
			id := strings.ToUpper(f.RuleID)
			tags := strings.ToLower(strings.Join(f.Tags, " "))
			switch {
			case strings.HasPrefix(id, "CMD-"):
				kind, title = "dangerous_code_submission", "提交内容包含危险命令或代码模式"
			case strings.Contains(tags, "injection") || strings.Contains(id, "INJECTION"):
				kind, title, category = "prompt_injection", "请求或返回内容包含提示注入", "attack"
			case strings.HasPrefix(id, "SEC-") || strings.Contains(tags, "credential"):
				kind, title = "credential_exposure", "请求或返回内容包含凭据"
			case strings.HasPrefix(id, "PII-") || strings.Contains(tags, "pii"):
				kind, title = "pii_exposure", "请求或返回内容包含个人敏感信息"
			}
			r := groups[kind]
			if r == nil {
				r = &DetectionResult{DetectionType: kind, Category: category, Severity: severity, Confidence: f.Confidence,
					Title: title, Detail: "安全检查命中结构化规则；此记录不证明代码或命令已执行。",
					Remediation: "结合行为、检查模式及操作结果复核风险。",
					Evidence:    triggerEvidence(ev), Attributes: map[string]any{"source": "inspect", "enforcement_owner": "inspect", "rule_ids": []string{}, "call_id": ev.Attributes["call_id"], "inspection_mode": ev.Attributes["inspection_mode"], "raw_action": ev.Attributes["raw_action"]}}
				groups[kind] = r
				order = append(order, kind)
			}
			if audit.SeverityRank(severity) > audit.SeverityRank(r.Severity) {
				r.Severity = severity
			}
			if f.Confidence > r.Confidence {
				r.Confidence = f.Confidence
			}
			ids := r.Attributes["rule_ids"].([]string)
			found := false
			for _, v := range ids {
				if v == f.RuleID {
					found = true
				}
			}
			if !found {
				r.Attributes["rule_ids"] = append(ids, f.RuleID)
			}
		}
		out := make([]DetectionResult, 0, len(order))
		for _, kind := range order {
			out = append(out, *groups[kind])
		}
		return out
	}}
}
