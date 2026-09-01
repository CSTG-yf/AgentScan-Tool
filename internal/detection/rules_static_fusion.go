// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// KnownMaliciousResourceRule is the Phase-3 static↔runtime fusion: a
// tool/MCP invocation that touches a resource the scanner already
// flagged malicious becomes a CRITICAL detection immediately —
//
//	Static Finding (scan_findings → static_resources.malicious)
//	        +
//	Runtime Event (tool.pre_call / tool.post_call)
//	        ↓
//	Detection: known_malicious_resource_invocation
//	        ↓
//	Decision: BLOCK (MCP enforcement point)
//
// The agent NEVER gets to invoke a known-malicious skill/MCP server
// just because the static scan happened offline.
type KnownMaliciousResourceRule struct{ atomicRule }

// NewKnownMaliciousResourceRule returns the static-fusion atomic rule.
func NewKnownMaliciousResourceRule() Rule {
	return KnownMaliciousResourceRule{atomicRule{id: "known-malicious-resource", name: "Known Malicious Resource Invocation", eval: func(ctx *EvalContext) []DetectionResult {
		ev := ctx.Event
		if ev.EventType != audit.RuntimeEventToolPreCall && ev.EventType != audit.RuntimeEventToolPostCall {
			return nil
		}
		if len(ctx.MaliciousResources) == 0 {
			return nil
		}
		for _, res := range ctx.MaliciousResources {
			if !invocationTouchesResource(ev, res) {
				continue
			}
			return []DetectionResult{{
				DetectionType: "known_malicious_resource_invocation",
				Category:      "attack",
				Severity:      "CRITICAL",
				Confidence:    0.95,
				Title:         "已知恶意资源调用",
				Detail:        "工具调用命中静态扫描判定为恶意的资源 " + res.Name + "（" + res.Target + "），风险等级 " + res.RiskLevel,
				Remediation:   "立即停止使用该资源；按静态扫描报告清除或隔离该 MCP/Skill，并审查本次会话中它已接触的数据。",
				Attributes: map[string]any{
					"static_resource_id": res.ResourceID,
					"resource_name":      res.Name,
					"resource_target":    res.Target,
					"risk_level":         res.RiskLevel,
				},
				Evidence: triggerEvidence(ev),
			}}
		}
		return nil
	}}}
}

// invocationTouchesResource conservatively matches one tool event
// against one malicious static resource: MCP server name equality,
// the mcp__<server>__<tool> naming convention, or a file operand
// inside the resource's scanned target path. Loose substring matches
// are deliberately avoided to keep false positives near zero.
func invocationTouchesResource(ev audit.BehaviorEvent, res audit.MaliciousStaticResource) bool {
	name := strings.ToLower(strings.TrimSpace(res.Name))
	target := normalizeResourcePath(res.Target)

	if name != "" {
		if ev.MCPServer != "" && strings.EqualFold(strings.TrimSpace(ev.MCPServer), name) {
			return true
		}
		tool := strings.ToLower(ev.ToolName)
		if tool != "" && name != "" {
			// Claude Code MCP tools are named mcp__<server>__<tool>.
			if strings.Contains(tool, "__"+name+"__") || tool == "mcp__"+name {
				return true
			}
		}
	}

	if target != "" {
		op := normalizeResourcePath(ev.Target)
		if op != "" && (op == target || strings.HasPrefix(op, target+"/") || strings.HasPrefix(op, target+"\\")) {
			return true
		}
	}
	return false
}

// normalizeResourcePath lowercases and slashes a path-ish string for
// cross-platform (Windows/Unix) prefix matching.
func normalizeResourcePath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}
