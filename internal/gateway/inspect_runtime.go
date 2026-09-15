package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/detection"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/google/uuid"
)

// Runtime context is optional; legacy inspect clients keep their old contract.
// The normal tokenAuth middleware protects both inspect and result routes.
type InspectRuntimeContext struct {
	Connector  string `json:"connector"`
	SessionID  string `json:"session_id"`
	TraceID    string `json:"trace_id"`
	CallID     string `json:"call_id"`
	EventID    string `json:"event_id"`
	ProxyKind  string `json:"proxy_kind"`
	Phase      string `json:"phase"`
	Operation  string `json:"operation"`
	ToolName   string `json:"tool_name,omitempty"`
	MCPServer  string `json:"mcp_server,omitempty"`
	HTTPMethod string `json:"http_method"`
	HTTPPath   string `json:"http_path"`
	Target     string `json:"target"`
}

func (c *InspectRuntimeContext) validate(r *http.Request) error {
	if c.Connector != "agentrange" || r.Header.Get("X-DefenseClaw-Connector") != "agentrange" {
		return fmt.Errorf("runtime context requires authenticated AgentRange connector")
	}
	if _, err := uuid.Parse(c.CallID); err != nil {
		return fmt.Errorf("invalid call_id")
	}
	if _, err := uuid.Parse(c.EventID); err != nil {
		return fmt.Errorf("invalid event_id")
	}
	switch c.ProxyKind {
	case "opspilot", "langflow", "llm", "mcp":
	default:
		return fmt.Errorf("invalid proxy_kind")
	}
	switch c.Phase {
	case "pre", "post", "result":
	default:
		return fmt.Errorf("invalid phase")
	}
	if c.SessionID == "" || c.TraceID == "" {
		return fmt.Errorf("session_id and trace_id required")
	}
	for _, v := range []string{c.SessionID, c.TraceID, c.Operation, c.ToolName, c.MCPServer, c.HTTPMethod, c.HTTPPath, c.Target} {
		if len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("invalid runtime metadata")
		}
	}
	return nil
}

var runtimeLabelPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:/-]{0,159}$`)

func safeRuntimeLabel(value string) string {
	if value == "" {
		return ""
	}
	if runtimeLabelPattern.MatchString(value) && redaction.AssertNoCredentials(value) == nil {
		return value
	}
	return redaction.ForSinkMessageContent(value)
}

func (c *InspectRuntimeContext) key() string {
	return "inspect:agentrange:" + c.ProxyKind + ":" + c.EventID
}

func (a *APIServer) beginInspectRuntime(w http.ResponseWriter, r *http.Request, c *InspectRuntimeContext, session string) (int64, bool) {
	if c == nil {
		return 0, true
	}
	if err := c.validate(r); err != nil || (session != "" && session != c.SessionID) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid runtime context"})
		return 0, false
	}
	if c.Phase == "result" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "result context is not an inspect request"})
		return 0, false
	}
	expectedPhase := "pre"
	if strings.HasSuffix(r.URL.Path, "/response") || strings.HasSuffix(r.URL.Path, "/tool-response") {
		expectedPhase = "post"
	}
	if c.Phase != expectedPhase {
		a.writeJSON(w, 400, map[string]string{"error": "inspection phase does not match endpoint"})
		return 0, false
	}
	if a.store == nil {
		w.Header().Set("X-DefenseClaw-Runtime-Status", "unavailable")
		log.Printf("[inspect-runtime] store unavailable")
		return 0, true
	}
	kind := audit.RuntimeEventContentInspected
	tool := c.ToolName
	if c.ProxyKind == "opspilot" && c.Phase == "pre" {
		kind = audit.RuntimeEventPromptSubmit
	}
	if c.ProxyKind == "mcp" || strings.HasSuffix(r.URL.Path, "/tool") || strings.HasSuffix(r.URL.Path, "/tool-response") || (c.ProxyKind == "langflow" && strings.Split(c.HTTPPath, "?")[0] == "/api/v1/validate/code") {
		kind = audit.RuntimeEventToolPreCall
		if c.Phase == "post" {
			kind = audit.RuntimeEventToolPostCall
		}
		if c.ProxyKind == "langflow" {
			tool = "langflow.validate_code"
		}
	}
	id, err := a.store.RecordRuntimeEvent(audit.RuntimeEventInput{
		IngestKey: c.key(), EventType: kind, EventSource: audit.RuntimeSourceGuardrail,
		// Agent identity is server-owned; request context cannot impersonate
		// an arbitrary canonical inventory id or executable.
		AgentName: "AgentRange / OpsPilot", SessionID: c.SessionID, TraceID: c.TraceID,
		Operation: safeRuntimeLabel(c.Operation), Target: safeRuntimeLabel(c.ProxyKind),
		ToolName: safeRuntimeLabel(tool), MCPServer: safeRuntimeLabel(c.MCPServer),
		Outcome: "observed", Timestamp: time.Now().UTC(),
		Attributes: map[string]any{"connector": "agentrange", "call_id": c.CallID, "phase": c.Phase, "proxy_kind": c.ProxyKind, "inspection_status": "pending", "http_method": c.HTTPMethod, "http_path": redaction.ForSinkMessageContent(strings.Split(c.HTTPPath, "?")[0])},
	})
	if err != nil {
		w.Header().Set("X-DefenseClaw-Runtime-Status", "failed")
		log.Printf("[inspect-runtime] begin call=%s: %v", c.CallID, err)
		return 0, true
	}
	existing, exists, readErr := a.store.GetRuntimeEvent(id)
	if readErr != nil || !exists {
		w.Header().Set("X-DefenseClaw-Runtime-Status", "failed")
		log.Printf("[inspect-runtime] begin read failed event=%d: %v", id, readErr)
		return 0, true
	}
	if existing.SessionID != c.SessionID || existing.Attributes["call_id"] != c.CallID {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": "runtime event id belongs to another operation"})
		return 0, false
	}
	w.Header().Set("X-DefenseClaw-Runtime-Event-Id", fmt.Sprint(id))
	return id, true
}

func (a *APIServer) completeInspectRuntime(w http.ResponseWriter, id int64, v *ToolInspectVerdict) {
	if id <= 0 || v == nil {
		return
	}
	findings := make([]detection.InspectFinding, 0, len(v.DetailedFindings))
	for _, f := range v.DetailedFindings {
		findings = append(findings, detection.InspectFinding{RuleID: f.RuleID, Severity: f.Severity, Confidence: f.Confidence, Tags: f.Tags})
	}
	// Block is still a prevention decision here. Only the sidecar result
	// confirms that forwarding/delivery was actually denied.
	outcome := "allowed"
	if len(findings) > 0 {
		outcome = "flagged"
	}
	err := a.store.CompleteRuntimeInspection(id, outcome, v.Severity, v.Confidence, map[string]any{
		"inspection_status": "complete", "inspect_findings": findings, "action": v.Action,
		"raw_action": v.RawAction, "inspection_mode": v.Mode, "would_block": v.WouldBlock,
	})
	if err == nil {
		engine := activeDetectionEngine()
		if engine == nil || activeRuntimeEventStore() != a.store {
			err = fmt.Errorf("runtime engine unavailable for inspect store")
		} else {
			err = engine.EvaluateEventWithError(id)
		}
	}
	if err != nil {
		w.Header().Set("X-DefenseClaw-Runtime-Status", "failed")
		log.Printf("[inspect-runtime] complete event=%d: %v", id, err)
	} else {
		w.Header().Set("X-DefenseClaw-Runtime-Status", "recorded")
	}
}

func (a *APIServer) failInspectRuntime(id int64) {
	if id <= 0 {
		return
	}
	if err := a.store.CompleteRuntimeInspection(id, "error", "NONE", 0, map[string]any{"inspection_status": "error", "inspection_error": "scan timeout"}); err != nil {
		log.Printf("[inspect-runtime] fail event=%d: %v", id, err)
	}
}

// Audit is a separate sink of the request/check, never an event source.
func (a *APIServer) logInspectAudit(r *http.Request, c *InspectRuntimeContext, id int64, action, target, details string, v *ToolInspectVerdict) {
	if c == nil {
		if a.logger != nil {
			if err := a.logger.LogActionCtx(r.Context(), action, target, details); err != nil {
				log.Printf("[inspect-audit] write failed: %v", err)
			}
		}
		return
	}
	var ev audit.BehaviorEvent
	if a.store != nil && id > 0 {
		ev, _, _ = a.store.GetRuntimeEvent(id)
	}
	err := persistAuditEvent(a.logger, a.store, audit.Event{Action: action, Target: safeRuntimeLabel(target), Actor: "inspect", Details: details,
		AgentName: "AgentRange / OpsPilot", CanonicalAgentID: ev.CanonicalAgentID, Connector: "agentrange", SessionID: c.SessionID, TraceID: c.TraceID,
		Severity: v.Severity, Structured: map[string]any{"call_id": c.CallID, "behavior_event_id": id, "stage": c.Phase, "decision": v.Action, "raw_action": v.RawAction, "mode": v.Mode, "would_block": v.WouldBlock, "reason": redaction.ForSinkReason(v.Reason)}})
	if err != nil {
		log.Printf("[inspect-audit] call=%s write failed: %v", c.CallID, err)
	}
}

type inspectRuntimeResult struct {
	Context            InspectRuntimeContext `json:"runtime_context"`
	Outcome            string                `json:"outcome"`
	HTTPStatus         int                   `json:"http_status,omitempty"`
	InspectionEventIDs []string              `json:"inspection_event_ids,omitempty"`
}

func (a *APIServer) handleInspectRuntimeResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if a.store == nil {
		a.writeJSON(w, 503, map[string]string{"error": "runtime store unavailable"})
		return
	}
	var req inspectRuntimeResult
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
		a.writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	c := req.Context
	if err := c.validate(r); err != nil || c.Phase != "result" {
		a.writeJSON(w, 400, map[string]string{"error": "invalid runtime context"})
		return
	}
	switch req.Outcome {
	case "rejected", "response_received", "forward_failed", "response_blocked":
	default:
		a.writeJSON(w, 400, map[string]string{"error": "invalid outcome"})
		return
	}
	if len(req.InspectionEventIDs) > 64 || req.HTTPStatus < 0 || req.HTTPStatus > 599 {
		a.writeJSON(w, 400, map[string]string{"error": "invalid result metadata"})
		return
	}
	var inspected []audit.BehaviorEvent
	for _, eventID := range req.InspectionEventIDs {
		if _, err := uuid.Parse(eventID); err != nil {
			a.writeJSON(w, 400, map[string]string{"error": "invalid inspection event id"})
			return
		}
		key := "inspect:agentrange:" + c.ProxyKind + ":" + eventID
		ev, ok, err := a.store.RuntimeEventByIngestKey(key)
		if err != nil || !ok {
			a.writeJSON(w, 409, map[string]string{"error": "inspection event unavailable; retry original check"})
			return
		}
		if ev.SessionID != c.SessionID || ev.Attributes["call_id"] != c.CallID {
			a.writeJSON(w, 400, map[string]string{"error": "result does not own inspection"})
			return
		}
		inspected = append(inspected, ev)
	}
	outcome := "observed"
	if req.Outcome == "forward_failed" {
		outcome = "error"
	}
	if req.Outcome == "rejected" || req.Outcome == "response_blocked" {
		outcome = "blocked"
	}
	id, err := a.store.RecordRuntimeEvent(audit.RuntimeEventInput{IngestKey: c.key(), EventType: audit.RuntimeEventContentInspected, EventSource: audit.RuntimeSourceProxy, AgentName: "AgentRange / OpsPilot", SessionID: c.SessionID, TraceID: c.TraceID, Operation: "proxy.result", Outcome: outcome, Target: safeRuntimeLabel(c.ProxyKind), Attributes: map[string]any{"connector": "agentrange", "call_id": c.CallID, "phase": "result", "proxy_kind": c.ProxyKind, "operation_result": req.Outcome, "http_status": req.HTTPStatus, "inspection_event_ids": req.InspectionEventIDs}})
	if err == nil {
		ev, exists, readErr := a.store.GetRuntimeEvent(id)
		if readErr != nil || !exists {
			err = fmt.Errorf("result event unavailable")
		} else if ev.SessionID != c.SessionID || ev.Attributes["call_id"] != c.CallID || ev.Attributes["operation_result"] != req.Outcome {
			a.writeJSON(w, 409, map[string]string{"error": "result id conflicts with an existing operation result"})
			return
		}
	}
	if err == nil {
		engine := activeDetectionEngine()
		if engine == nil || activeRuntimeEventStore() != a.store {
			err = fmt.Errorf("detection engine unavailable")
		} else {
			for _, ev := range inspected {
				if ev.Attributes["inspection_status"] == "complete" {
					if err = engine.EvaluateEventWithError(ev.ID); err != nil {
						break
					}
				}
			}
		}
	}
	if err == nil && (req.Outcome == "rejected" || req.Outcome == "response_blocked") && len(inspected) > 0 {
		err = a.store.ConfirmInspectionBlocked(inspected[len(inspected)-1].ID)
	}
	if err != nil {
		log.Printf("[inspect-runtime] result call=%s: %v", c.CallID, err)
		a.writeJSON(w, 503, map[string]string{"error": "runtime result persistence or evaluation failed"})
		return
	}
	a.writeJSON(w, 200, map[string]any{"status": "recorded", "event_id": id})
}
