// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func newRuntimeSettingsAPI(t *testing.T) (*APIServer, int64, int64) {
	t.Helper()
	s, err := audit.NewStore(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { SetRuntimeEventStore(nil); s.Close() })
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	SetRuntimeEventStore(s)
	a, err := s.CreateGovernanceAgentType(audit.GovernanceAgentTypeInput{TypeKey: "runtime-api-a", Name: "Runtime A", Vendor: "Test Vendor", Runtime: "Go", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateGovernanceAgentType(audit.GovernanceAgentTypeInput{TypeKey: "runtime-api-b", Name: "Runtime B", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return &APIServer{store: s}, a.ID, b.ID
}

func runtimeSettingsRequest(t *testing.T, a *APIServer, method, path, body string, want int) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	a.handleRuntimeDetectionSettingsAPI(rec, httptest.NewRequest(method, runtimeSettingsPrefix+path, strings.NewReader(body)))
	if rec.Code != want {
		t.Fatalf("%s %s: %d want %d; %s", method, path, rec.Code, want, rec.Body.String())
	}
	var result map[string]any
	if want < 300 && rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func TestRuntimeSettingsAPIRuleCRUDPaginationAndErrors(t *testing.T) {
	a, typeA, typeB := newRuntimeSettingsAPI(t)
	list := runtimeSettingsRequest(t, a, "GET", "/rules?page_size=1&source=builtin", "", 200)
	if list["total"] != float64(12) || len(list["items"].([]any)) != 1 {
		t.Fatalf("builtin page: %+v", list)
	}
	builtin := list["items"].([]any)[0].(map[string]any)
	builtinPath := fmt.Sprintf("/rules/%.0f", builtin["id"])
	runtimeSettingsRequest(t, a, "PATCH", builtinPath, `{"rule_id":"forged"}`, 409)
	runtimeSettingsRequest(t, a, "DELETE", builtinPath, "", 200)
	list = runtimeSettingsRequest(t, a, "GET", "/rules?enabled=false&source=builtin", "", 200)
	if list["total"] != float64(1) {
		t.Fatalf("builtin was removed instead of disabled: %+v", list)
	}
	path := fmt.Sprintf("/agent-types/%d/rules", typeA)
	input := `{"rule_id":"api-test-rule","rule_name":"API Test","detection_type":"custom_signal","matcher":{"kind":"event_match","event_type":"tool.pre_call"}}`
	created := runtimeSettingsRequest(t, a, "POST", path, input, 201)
	itemPath := fmt.Sprintf("%s/%.0f", path, created["id"])
	runtimeSettingsRequest(t, a, "POST", path, input, 409)
	runtimeSettingsRequest(t, a, "POST", fmt.Sprintf("/agent-types/%d/rules", typeB), input, 201)
	runtimeSettingsRequest(t, a, "PATCH", fmt.Sprintf("/agent-types/%d/rules/%.0f", typeB, created["id"]), `{"enabled":false}`, 404)
	updated := runtimeSettingsRequest(t, a, "PATCH", itemPath, `{"severity":"critical","confidence":0.95}`, 200)
	if updated["severity"] != "CRITICAL" || updated["version"] != float64(2) {
		t.Fatalf("patch: %+v", updated)
	}
	runtimeSettingsRequest(t, a, "PATCH", itemPath, `{"enabled":false,"version":1}`, 409)
	list = runtimeSettingsRequest(t, a, "GET", path+"?keyword=api-test&enabled=true&pageSize=999", "", 200)
	if list["total"] != float64(1) || list["page_size"] != float64(200) {
		t.Fatalf("filters: %+v", list)
	}
	list = runtimeSettingsRequest(t, a, "GET", path+"?page=9223372036854775807", "", 200)
	if len(list["items"].([]any)) != 0 || list["total"] != float64(1) {
		t.Fatalf("large page: %+v", list)
	}
	for _, suffix := range []string{"?enabled=maybe", "?page=0", "?source=blacklist", "?scope=global"} {
		runtimeSettingsRequest(t, a, "GET", path+suffix, "", 400)
	}
	for _, body := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"matcher":{"kind":"event_match","target":{"match_type":"regex","value":"["}}}`} {
		runtimeSettingsRequest(t, a, "PATCH", itemPath, body, 400)
	}
	runtimeSettingsRequest(t, a, "DELETE", itemPath, "", 200)
	runtimeSettingsRequest(t, a, "PATCH", itemPath, `{"enabled":true}`, 404)
	runtimeSettingsRequest(t, a, "GET", "/agent-types/0", "", 400)
	runtimeSettingsRequest(t, a, "GET", "/agent-types/99999999", "", 404)
	runtimeSettingsRequest(t, a, "POST", "/risk-policy/global", `{}`, 405)
}

func TestRuntimeSettingsAPITypePolicyBlacklistAndEffective(t *testing.T) {
	a, typeA, typeB := newRuntimeSettingsAPI(t)
	base := fmt.Sprintf("/agent-types/%d", typeA)
	runtimeSettingsRequest(t, a, "PATCH", base+"/settings", `{"inherit_global_rules":false}`, 200)
	created := runtimeSettingsRequest(t, a, "POST", base+"/blacklist", `{"target_type":"command","match_type":"contains","value":"restricted","detection_type":"blacklisted_command","severity":"CRITICAL","confidence":1}`, 201)
	itemPath := fmt.Sprintf("%s/blacklist/%.0f", base, created["id"])
	runtimeSettingsRequest(t, a, "DELETE", fmt.Sprintf("/agent-types/%d/blacklist/%.0f", typeB, created["id"]), "", 404)
	list := runtimeSettingsRequest(t, a, "GET", base+"/blacklist?target_type=command&keyword=restricted", "", 200)
	if list["total"] != float64(1) {
		t.Fatalf("blacklist filters: %+v", list)
	}
	rules := audit.DefaultRuntimeRiskPolicyRules()
	rules[2].Decision = "ASK"
	payload, _ := json.Marshal(map[string]any{"use_global_risk_policy": false, "policy": map[string]any{"name": "Custom policy", "rules": rules}})
	risk := runtimeSettingsRequest(t, a, "PUT", base+"/risk-policy", string(payload), 200)
	if risk["mode"] != "custom" {
		t.Fatalf("risk: %+v", risk)
	}
	policy := risk["policy"].(map[string]any)
	high := policy["rules"].([]any)[2].(map[string]any)
	if high["decision"] != "CONFIRM" || high["display_decision"] != "ASK" {
		t.Fatalf("normalization: %+v", high)
	}
	rules[1].MinScore = .39
	payload, _ = json.Marshal(map[string]any{"use_global_risk_policy": false, "policy": map[string]any{"name": "Bad", "rules": rules}})
	runtimeSettingsRequest(t, a, "PUT", base+"/risk-policy", string(payload), 400)
	detail := runtimeSettingsRequest(t, a, "GET", base, "", 200)
	if detail["effective_summary"].(map[string]any)["effective_rule_count"] != float64(1) {
		t.Fatalf("effective summary: %+v", detail)
	}
	effective := runtimeSettingsRequest(t, a, "GET", base+"/effective", "", 200)
	if effective["rules"].([]any)[0].(map[string]any)["source"] != "blacklist" || effective["risk_policy"].(map[string]any)["source"] != "agent_type" {
		t.Fatalf("effective origin: %+v", effective)
	}
	list = runtimeSettingsRequest(t, a, "GET", "/agent-types?keyword=Test%20Vendor&inherit_global_rules=false&risk_policy=custom", "", 200)
	if list["total"] != float64(1) {
		t.Fatalf("type filters: %+v", list)
	}
	overview := runtimeSettingsRequest(t, a, "GET", "/overview", "", 200)
	if overview["blacklist_count"] != float64(1) || overview["custom_risk_policy_count"] != float64(1) || overview["custom_agent_type_count"] != float64(1) {
		t.Fatalf("overview: %+v", overview)
	}
	if err := activeDetectionEngine().Policy().SetMode(audit.RuntimeSecurityModeAction); err != nil {
		t.Fatal(err)
	}
	before, err := a.store.ChangesSince(0, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	result := runtimeSettingsRequest(t, a, "POST", base+"/evaluate", `{"event":{"event_type":"tool.pre_call","target":"restricted command"}}`, 200)
	if result["matched"] != true || result["decision"] != "BLOCK" || result["matched_rules"].([]any)[0].(map[string]any)["source"] != "blacklist" {
		t.Fatalf("preview: %+v", result)
	}
	after, err := a.store.ChangesSince(before.NextCursor, nil, 100)
	if err != nil || after.NextCursor != before.NextCursor {
		t.Fatalf("preview changed DB: %+v %v", after, err)
	}
	runtimeSettingsRequest(t, a, "PATCH", itemPath, `{"enabled":false}`, 200)
	result = runtimeSettingsRequest(t, a, "POST", base+"/evaluate", `{"event":{"event_type":"tool.pre_call","target":"restricted command"}}`, 200)
	if result["matched"] != false {
		t.Fatalf("disabled blacklist cached: %+v", result)
	}
	runtimeSettingsRequest(t, a, "PUT", base+"/risk-policy", `{"use_global_risk_policy":true}`, 200)
	risk = runtimeSettingsRequest(t, a, "GET", base+"/risk-policy", "", 200)
	if risk["mode"] != "global" || risk["policy"] != nil {
		t.Fatalf("global inheritance: %+v", risk)
	}
	custom := risk["custom_policy"].(map[string]any)
	if custom["name"] != "Custom policy" || custom["version"] != policy["version"] || risk["effective_policy"].(map[string]any)["scope"] != "global" {
		t.Fatalf("saved custom policy lost or incorrectly activated: %+v", risk)
	}
	detail = runtimeSettingsRequest(t, a, "GET", base, "", 200)
	if detail["risk_policy"].(map[string]any)["custom_policy"].(map[string]any)["name"] != "Custom policy" {
		t.Fatalf("editor cannot restore saved custom policy: %+v", detail)
	}
	runtimeSettingsRequest(t, a, "DELETE", itemPath, "", 200)
	SetRuntimeEventStore(nil)
	runtimeSettingsRequest(t, a, "POST", base+"/evaluate", `{"event":{"event_type":"tool.pre_call"}}`, 503)
}

func TestRuntimeSettingsAPIRequiresGatewayAuthAndCSRF(t *testing.T) {
	a, typeID, _ := newRuntimeSettingsAPI(t)
	a.scannerCfg = &config.Config{}
	a.scannerCfg.Gateway.Token = "settings-test-token"
	handler := a.tokenAuth(a.apiCSRFProtect(http.HandlerFunc(a.handleRuntimeDetectionSettingsAPI)))
	for _, tc := range []struct {
		token, client string
		want          int
	}{{"", "", 401}, {"wrong", "desktop", 401}, {"settings-test-token", "", 403}, {"settings-test-token", "desktop", 200}} {
		req := httptest.NewRequest("PATCH", fmt.Sprintf("%s/agent-types/%d/settings", runtimeSettingsPrefix, typeID), strings.NewReader(`{"enabled":false}`))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		req.Header.Set("X-DefenseClaw-Client", tc.client)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("auth (%q,%q): %d want %d; %s", tc.token, tc.client, rec.Code, tc.want, rec.Body.String())
		}
	}
}

func TestRuntimeSettingsReplayIsExplicitAndScopedByInventoryType(t *testing.T) {
	a, typeA, typeB := newRuntimeSettingsAPI(t)
	for _, typeID := range []int64{typeA, typeB} {
		agent, err := a.store.EnsureAgent(audit.AgentIdentityInput{AgentID: fmt.Sprintf("replay-agent-%d", typeID), AgentTypeID: typeID, AgentName: "Replay agent", Source: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.store.RecordRuntimeEvent(audit.RuntimeEventInput{CanonicalAgentID: agent.ID, EventType: audit.RuntimeEventContentInjection, EventSource: audit.RuntimeSourceGuardrail, Severity: "HIGH", Attributes: map[string]any{"agent_type_id": typeA}}); err != nil {
			t.Fatal(err)
		}
	}
	runtimeSettingsRequest(t, a, "PATCH", fmt.Sprintf("/agent-types/%d/settings", typeA), `{"inherit_global_rules":true}`, 200)
	detections, err := a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 100})
	if err != nil || len(detections) != 0 {
		t.Fatalf("save replayed events: %+v %v", detections, err)
	}
	for _, tc := range []struct {
		scope string
		want  int
	}{{`0`, 400}, {`1.5`, 400}, {`"1"`, 400}, {`null`, 400}, {`99999999`, 404}} {
		rec := httptest.NewRecorder()
		a.handleJobsAPI(rec, httptest.NewRequest("POST", "/api/v1/jobs", strings.NewReader(`{"kind":"event_replay","scope":{"agent_type_id":`+tc.scope+`}}`)))
		if rec.Code != tc.want {
			t.Fatalf("bad scope %s: %d want %d; %s", tc.scope, rec.Code, tc.want, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	a.handleJobsAPI(rec, httptest.NewRequest("POST", "/api/v1/jobs", strings.NewReader(fmt.Sprintf(`{"kind":"event_replay","scope":{"agent_type_id":%d}}`, typeA))))
	if rec.Code != 202 {
		t.Fatalf("replay create: %d %s", rec.Code, rec.Body.String())
	}
	var accepted apiScanStatus
	if err = json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		job, ok, err := a.store.GetScanJob(accepted.ScanID)
		if err != nil || !ok {
			t.Fatalf("job lookup: %+v %v", job, err)
		}
		if job.Status == "completed" {
			break
		}
		if job.Status == "failed" || job.Status == "cancelled" || time.Now().After(deadline) {
			t.Fatalf("replay failed or timed out: %+v", job)
		}
		time.Sleep(10 * time.Millisecond)
	}
	detections, err = a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 100})
	if err != nil || len(detections) != 1 || detections[0].AgentTypeID != typeA || detections[0].EvaluationJobID != accepted.ScanID {
		t.Fatalf("replay scope/provenance: %+v %v", detections, err)
	}
}
