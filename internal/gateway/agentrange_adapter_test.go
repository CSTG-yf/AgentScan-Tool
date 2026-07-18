package gateway

import (
	"encoding/json"
	"testing"
)

func TestGenericRulesCoverAgentFrameworkExploitShapes(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		ruleID string
	}{
		{
			name:   "python validator subprocess shell",
			input:  `{"code":"def f(_=__import__('subprocess').run('id', shell=True)): pass"}`,
			ruleID: "CMD-PY-SUBPROCESS-SHELL",
		},
		{
			name:   "multipart traversal into cron directory",
			input:  `filename=../../../../../etc/cron.d/job`,
			ruleID: "PATH-CRON-PERSIST",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := ScanAllRules(tc.input, "http_request")
			if !hasFindingID(findings, tc.ruleID) {
				t.Fatalf("findings=%v, want %s", FindingStrings(findings), tc.ruleID)
			}
		})
	}
}

func TestToolAuthorizationContextTenantScope(t *testing.T) {
	contextPayload, _ := json.Marshal(map[string]interface{}{
		"principal": map[string]interface{}{
			"sub":   "lwang",
			"scope": map[string]interface{}{"tenant": "acme"},
		},
	})
	tests := []struct {
		name      string
		args      string
		wantBlock bool
	}{
		{"same tenant", `{"tenant":"acme"}`, false},
		{"other tenant", `{"tenant":"globex"}`, true},
		{"wildcard tenant", `{"tenant":"*"}`, true},
		{"unrelated args", `{"name":"latency"}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := inspectToolAuthorizationContext(&ToolInspectRequest{
				Tool: "query", Args: json.RawMessage(tc.args), Context: contextPayload,
			})
			if got := len(findings) > 0; got != tc.wantBlock {
				t.Fatalf("findings=%v, blocked=%v want=%v", findings, got, tc.wantBlock)
			}
		})
	}
}

func hasFindingID(findings []RuleFinding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}
