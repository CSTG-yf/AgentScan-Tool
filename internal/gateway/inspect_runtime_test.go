package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/google/uuid"
)

func runtimeInspectContext() *InspectRuntimeContext {
	return &InspectRuntimeContext{Connector: "agentrange", SessionID: "runtime-session", TraceID: "runtime-trace", CallID: uuid.NewString(), EventID: uuid.NewString(), ProxyKind: "langflow", Phase: "pre", Operation: "code.validate", HTTPMethod: "POST", HTTPPath: "/api/v1/validate/code", Target: "langflow"}
}

func runtimeTestAPI(t *testing.T) *APIServer {
	t.Helper()
	a := testAPIServerWithConfig(t, "observe")
	a.scannerCfg.Gateway.Token = "runtime-test-token"
	SetRuntimeEventStore(a.store)
	t.Cleanup(func() { SetRuntimeEventStore(nil) })
	return a
}

func TestInspectRuntimeMCPPreCallDeclaresBlockingSurface(t *testing.T) {
	a := runtimeTestAPI(t)
	c := runtimeInspectContext()
	c.ProxyKind = "mcp"
	c.Operation = "mcp.invoke"
	c.ToolName = "mcp__jira__createIssue"
	c.MCPServer = "jira"
	c.HTTPPath = "/api/v1/inspect/tool"
	r := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil)
	r.Header.Set("X-DefenseClaw-Connector", "agentrange")
	id, ok := a.beginInspectRuntime(httptest.NewRecorder(), r, c, c.SessionID)
	if !ok || id <= 0 {
		t.Fatal("authenticated MCP pre-call was not recorded")
	}
	event, exists, err := a.store.GetRuntimeEvent(id)
	if err != nil || !exists || event.MCPServer != "jira" || event.Attributes["pre_call_block_capable"] != true {
		t.Fatalf("MCP pre-call capability = %+v, exists=%v err=%v", event, exists, err)
	}
}

func callRuntimeInspect(a *APIServer, c *InspectRuntimeContext, content string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(RequestInspectRequest{Content: content, SessionID: c.SessionID, RuntimeContext: c})
	r := httptest.NewRequest("POST", "/api/v1/inspect/request", bytes.NewReader(b))
	r.Header.Set("X-DefenseClaw-Connector", "agentrange")
	w := httptest.NewRecorder()
	a.handleInspectRequest(w, r)
	return w
}

func TestInspectRuntimeEndToEndAndFrontendQueries(t *testing.T) {
	a := runtimeTestAPI(t)
	safe := runtimeInspectContext()
	if w := callRuntimeInspect(a, safe, "hello world"); w.Code != 200 || w.Header().Get("X-DefenseClaw-Runtime-Status") != "recorded" {
		t.Fatalf("safe: %d %s headers=%v", w.Code, w.Body, w.Header())
	}
	ds, err := a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 100})
	if err != nil || len(ds) != 0 {
		t.Fatalf("safe detections: %v %v", ds, err)
	}
	c := runtimeInspectContext()
	start := time.Now()
	w := callRuntimeInspect(a, c, `{"code":"def f(_=__import__('subprocess').run('id', shell=True)): pass"}`)
	if w.Code != 200 || w.Header().Get("X-DefenseClaw-Runtime-Status") != "recorded" {
		t.Fatalf("risk: %d %s headers=%v", w.Code, w.Body, w.Header())
	}
	t.Logf("inspection including persistence/evaluation: %s", time.Since(start))
	var v ToolInspectVerdict
	json.Unmarshal(w.Body.Bytes(), &v)
	if v.Action != "allow" || len(v.DetailedFindings) == 0 {
		t.Fatalf("observe verdict: %+v", v)
	}
	ds, err = a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 100})
	if err != nil || len(ds) != 1 || ds[0].DetectionType != "dangerous_code_submission" {
		t.Fatalf("detections: %+v %v", ds, err)
	}
	d, evidence, err := a.store.GetRuntimeDetectionDetail(ds[0].DetectionID)
	if err != nil || len(evidence) != 1 || evidence[0].Event.EventType != audit.RuntimeEventToolPreCall || evidence[0].Event.Outcome != "flagged" {
		t.Fatalf("evidence: %+v %v", evidence, err)
	}
	if evidence[0].Event.ToolName != "langflow.validate_code" || evidence[0].Event.Attributes["call_id"] != c.CallID {
		t.Fatalf("operation identity: %+v", evidence[0].Event)
	}
	decisions, _, err := a.store.ListRuntimeDecisions(audit.RuntimeDecisionFilter{DetectionID: d.DetectionID, Limit: 10})
	if err != nil || len(decisions) != 1 || decisions[0].Mode != "observe" {
		t.Fatalf("decisions: %+v %v", decisions, err)
	}
	for _, path := range []string{"/api/v1/runtime-detections?page=1&page_size=1", "/api/v1/runtime-detections/summary/agent-types", "/api/v1/runtime-detections/" + d.DetectionID, "/api/v1/runtime-detections/" + d.DetectionID + "/events"} {
		q := httptest.NewRecorder()
		a.handleRuntimeDetections(q, httptest.NewRequest("GET", path, nil))
		if q.Code != 200 || !bytes.Contains(q.Body.Bytes(), []byte("langflow")) && !bytes.Contains(q.Body.Bytes(), []byte("total")) {
			t.Fatalf("query %s: %d %s", path, q.Code, q.Body)
		}
	}
	q := httptest.NewRecorder()
	a.handleBehaviorEvents(q, httptest.NewRequest("GET", "/api/v1/behavior-events", nil))
	if q.Code != 200 || !bytes.Contains(q.Body.Bytes(), []byte(c.CallID)) || !bytes.Contains(q.Body.Bytes(), []byte("langflow.validate_code")) {
		t.Fatalf("frontend behavior: %d %s", q.Code, q.Body)
	}
	snap, err := a.buildPageGatewayAudit(500, "")
	if err != nil || len(snap.Events) == 0 {
		t.Fatalf("audit missing: %+v %v", snap, err)
	}
}

func TestInspectRuntimeConcurrentRetriesAndRecovery(t *testing.T) {
	a := runtimeTestAPI(t)
	a.scannerCfg.Gateway.Token = "runtime-test-token"
	c := runtimeInspectContext()
	// An event is durable before a failed inspection and can be retried.
	r := httptest.NewRequest("POST", "/api/v1/inspect/request", nil)
	r.Header.Set("X-DefenseClaw-Connector", "agentrange")
	id, ok := a.beginInspectRuntime(httptest.NewRecorder(), r, c, c.SessionID)
	if !ok || id <= 0 {
		t.Fatal("begin failed")
	}
	a.failInspectRuntime(id)
	const content = `subprocess.run('id', shell=True)`
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := callRuntimeInspect(a, c, content)
			if w.Code != 200 || w.Header().Get("X-DefenseClaw-Runtime-Status") != "recorded" {
				t.Errorf("retry: %d %s %v", w.Code, w.Body, w.Header())
			}
		}()
	}
	wg.Wait()
	events, err := a.store.ListRuntimeEvents(audit.RuntimeEventFilter{Limit: 100})
	if err != nil || len(events) != 1 {
		t.Fatalf("duplicate events: %d %v", len(events), err)
	}
	ds, err := a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 100})
	if err != nil || len(ds) != 1 || ds[0].EventCount != 1 {
		t.Fatalf("duplicate detections: %+v %v", ds, err)
	}
	decisions, _, _ := a.store.ListRuntimeDecisions(audit.RuntimeDecisionFilter{Limit: 100})
	if len(decisions) != 1 {
		t.Fatalf("duplicate decisions: %d", len(decisions))
	}
	// Re-evaluation recovers after missing engine; no new event is required.
	c2 := runtimeInspectContext()
	SetRuntimeEventStore(nil)
	w := callRuntimeInspect(a, c2, content)
	if w.Header().Get("X-DefenseClaw-Runtime-Status") != "failed" {
		t.Fatal("failure not exposed")
	}
	SetRuntimeEventStore(a.store)
	w = callRuntimeInspect(a, c2, content)
	if w.Header().Get("X-DefenseClaw-Runtime-Status") != "recorded" {
		t.Fatal("recovery failed")
	}
}

func TestInspectRuntimeResultSemanticsAndValidation(t *testing.T) {
	a := runtimeTestAPI(t)
	c := runtimeInspectContext()
	callRuntimeInspect(a, c, "hello")
	original := c.EventID
	c.Phase = "result"
	c.EventID = uuid.NewString()
	req := inspectRuntimeResult{Context: *c, Outcome: "response_received", HTTPStatus: 200, InspectionEventIDs: []string{original}}
	post := func(req inspectRuntimeResult) *httptest.ResponseRecorder {
		b, _ := json.Marshal(req)
		r := httptest.NewRequest("POST", "/api/v1/runtime-results", bytes.NewReader(b))
		r.Header.Set("X-DefenseClaw-Connector", "agentrange")
		w := httptest.NewRecorder()
		a.handleInspectRuntimeResult(w, r)
		return w
	}
	for i := 0; i < 2; i++ {
		if w := post(req); w.Code != 200 {
			t.Fatalf("result: %d %s", w.Code, w.Body)
		}
	}
	ev, ok, err := a.store.RuntimeEventByIngestKey(c.key())
	if err != nil || !ok || ev.Outcome != "observed" || ev.Attributes["operation_result"] != "response_received" {
		t.Fatalf("HTTP 200 misrepresented: %+v %v", ev, err)
	}
	events, _ := a.store.ListRuntimeEvents(audit.RuntimeEventFilter{Limit: 100})
	if len(events) != 2 {
		t.Fatalf("result duplicate: %d", len(events))
	}
	req.Context.CallID = uuid.NewString()
	req.Context.EventID = uuid.NewString()
	if w := post(req); w.Code != 400 {
		t.Fatalf("foreign call accepted: %d", w.Code)
	}
	for _, outcome := range []string{"rejected", "forward_failed", "response_blocked"} {
		req.Context = *c
		req.Context.EventID = uuid.NewString()
		req.Outcome = outcome
		if w := post(req); w.Code != 200 {
			t.Fatalf("%s: %d %s", outcome, w.Code, w.Body)
		}
	}
	bad := runtimeInspectContext()
	bad.Connector = "codex"
	if w := callRuntimeInspect(a, bad, "hello"); w.Code != 400 {
		t.Fatal("foreign connector accepted")
	}
	unauth := httptest.NewRecorder()
	a.tokenAuth(http.HandlerFunc(a.handleInspectRuntimeResult)).ServeHTTP(unauth, httptest.NewRequest("POST", "/api/v1/runtime-results", bytes.NewBufferString(`{}`)))
	if unauth.Code != 401 {
		t.Fatalf("unauthenticated result: %d", unauth.Code)
	}
}

func TestInspectRuntimeDoesNotDependOnAuditWrite(t *testing.T) {
	a := runtimeTestAPI(t)
	closedStore, closedLogger := testStoreAndLogger(t)
	if err := closedStore.Close(); err != nil {
		t.Fatal(err)
	}
	a.logger = closedLogger
	w := callRuntimeInspect(a, runtimeInspectContext(), `subprocess.run('id', shell=True)`)
	if w.Code != 200 || w.Header().Get("X-DefenseClaw-Runtime-Status") != "recorded" {
		t.Fatalf("audit failure broke inspection: %d %s", w.Code, w.Body)
	}
	events, err := a.store.ListRuntimeEvents(audit.RuntimeEventFilter{Limit: 100})
	if err != nil || len(events) != 1 {
		t.Fatalf("behavior missing: %d %v", len(events), err)
	}
	ds, err := a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 100})
	if err != nil || len(ds) != 1 {
		t.Fatalf("detection missing: %d %v", len(ds), err)
	}
}
