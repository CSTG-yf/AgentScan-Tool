// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/detection"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// Phase-1 unified runtime event collection + Phase-2 runtime
// detection. The three runtime pipelines (Guardrail / Agent Hook /
// Proxy) and the OS Runtime Sensor translate their native payloads
// onto the audit package's unified event vocabulary here and append
// one behavior_events row per event through
// audit.Store.RecordRuntimeEvent. scan_findings deliberately stays out
// of this path — static scan results are static risk context, not
// runtime events.
//
// Layout:
//
//	Guardrail  ──recordGuardrailRuntimeEvent──┐
//	Agent Hook ──recordHookRuntimeEvent──────┼── behavior_events (发生了什么)
//	Proxy     ──recordEgressRuntimeEvent─────┤         │
//	OS Sensor ──POST /api/v1/runtime-events──┘         ▼
//	                                        Detection Engine (通用规则)
//	                                                   │
//	                                          runtime_detections (有什么安全问题)
//	                                                   │
//	                              runtime_detection_events (证据链)
//
// audit_events keeps its legacy role (审计记录) and remains the primary
// data source for buildPageEventDetections in Phase 1, so the frontend
// needs no changes yet.

var (
	runtimeEventStoreMu sync.RWMutex
	runtimeEventStore   *audit.Store
	runtimeDetection    *detection.Engine
)

// SetRuntimeEventStore installs the process-wide audit store used by
// the runtime event adapters and boots the Phase-2 detection engine
// with the default generic rule set. The sidecar calls this once at
// boot, right after the store is opened.
func SetRuntimeEventStore(s *audit.Store) {
	runtimeEventStoreMu.Lock()
	defer runtimeEventStoreMu.Unlock()
	runtimeEventStore = s
	if s != nil {
		runtimeDetection = detection.NewEngine(s, detection.DefaultRules())
	} else {
		runtimeDetection = nil
	}
}

func activeRuntimeEventStore() *audit.Store {
	runtimeEventStoreMu.RLock()
	defer runtimeEventStoreMu.RUnlock()
	return runtimeEventStore
}

func activeDetectionEngine() *detection.Engine {
	runtimeEventStoreMu.RLock()
	defer runtimeEventStoreMu.RUnlock()
	return runtimeDetection
}

// activeRuntimeBlocklist exposes the Phase-3 network blocklist for the
// proxy's egress guards. nil when the detection engine is off.
func activeRuntimeBlocklist() *detection.NetworkBlocklist {
	if engine := activeDetectionEngine(); engine != nil {
		return engine.Policy().Blocklist()
	}
	return nil
}

// activeRuntimePolicyMode reports the current runtime security mode
// (observe | action) for handlers that need it.
func activeRuntimePolicyMode() string {
	if engine := activeDetectionEngine(); engine != nil && engine.Policy() != nil {
		return engine.Policy().Mode()
	}
	return audit.RuntimeSecurityModeObserve
}

// setRuntimePolicyMode switches the runtime security mode and
// persists it via app_settings.
func setRuntimePolicyMode(mode string) error {
	if engine := activeDetectionEngine(); engine != nil && engine.Policy() != nil {
		return engine.Policy().SetMode(mode)
	}
	return nil
}

// hookRuntimeEventType maps connector-native hook event names onto the
// unified vocabulary. Agent-specific naming differences live HERE and
// only here — a Codex event with a different native label produces the
// same prompt.submit / tool.pre_call the Detection Engine consumes.
func hookRuntimeEventType(hookEvent string) string {
	switch strings.TrimSpace(hookEvent) {
	case "UserPromptSubmit", "user_prompt_submit", "prompt_submit":
		return audit.RuntimeEventPromptSubmit
	case "PreToolUse", "pre_tool_use":
		return audit.RuntimeEventToolPreCall
	case "PostToolUse", "post_tool_use":
		return audit.RuntimeEventToolPostCall
	case "Stop", "SubagentStop", "stop", "subagent_stop":
		return audit.RuntimeEventAgentStop
	case "SessionStart", "session_start":
		return audit.RuntimeEventAgentSessionStart
	case "SessionEnd", "session_end":
		return audit.RuntimeEventAgentSessionEnd
	default:
		// Unknown lifecycle events keep a stable, namespaced shape.
		return "agent." + strings.ToLower(strings.ReplaceAll(strings.TrimSpace(hookEvent), " ", "_"))
	}
}

// hookOutcomeFromAction maps a hook decision action onto the unified
// outcome vocabulary.
func hookOutcomeFromAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny":
		return "blocked"
	case "confirm", "ask":
		return "flagged"
	case "warn":
		return "flagged"
	default:
		return "allowed"
	}
}

// hookToolTargetText extracts the primary operand (command / file
// path / URL) from tool arguments so detection rules can match on the
// actual payload, not just the tool name.
func hookToolTargetText(toolName string, args json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	var parsed map[string]any
	if err := json.Unmarshal(args, &parsed); err != nil {
		return ""
	}
	keys := []string{"command", "cmd", "file_path", "path", "file", "url", "uri", "script", "content", "code"}
	if strings.EqualFold(toolName, "Bash") || strings.EqualFold(toolName, "bash") {
		keys = []string{"command", "cmd", "script"}
	}
	for _, k := range keys {
		if v, ok := parsed[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return truncate(redaction.ForSinkString(s), 300)
			}
		}
	}
	return ""
}

// recordHookRuntimeEvent is the Agent Hook adapter. It runs after the
// hook decision is final (same section as emitHookDecisionEvent) and
// appends one unified runtime event, then feeds the event to the
// Phase-2 detection engine. agent.stop additionally marks the runtime
// session ended.
func (a *APIServer) recordHookRuntimeEvent(ctx context.Context, req agentHookRequest, resp agentHookResponse) {
	store := activeRuntimeEventStore()
	if store == nil {
		return
	}
	env := audit.EnvelopeFromContext(ctx)
	identity := AgentIdentityFromContext(ctx)

	eventType := hookRuntimeEventType(req.HookEventName)
	in := audit.RuntimeEventInput{
		EventType:     eventType,
		EventSource:   audit.RuntimeSourceAgentHook,
		SessionID:     firstNonEmpty(req.SessionID, env.SessionID),
		TraceID:       firstNonEmpty(env.TraceID, TraceIDFromContext(ctx)),
		AgentName:     firstNonEmpty(req.AgentName, identity.AgentName, req.ConnectorName),
		ToolName:      req.ToolName,
		Target:        hookToolTargetText(req.ToolName, req.ToolArgs),
		Operation:     firstNonEmpty(req.ToolName, req.HookEventName),
		Severity:      resp.Severity,
		Outcome:       hookOutcomeFromAction(resp.Action),
		Timestamp:     time.Now().UTC(),
		Attributes: map[string]any{
			"connector":     req.ConnectorName,
			"hook_event":    req.HookEventName,
			"action":        resp.Action,
			"raw_action":    resp.RawAction,
			"mode":          resp.Mode,
			"would_block":   resp.WouldBlock,
			"finding_count": len(resp.Findings),
		},
	}
	in.CanonicalAgentID = firstNonEmpty(req.AgentID, env.AgentID, identity.AgentID)
	if len(resp.Findings) > 0 {
		in.Attributes["findings"] = resp.Findings
	}
	if resp.Reason != "" {
		in.Detail = truncate(redaction.ForSinkReason(resp.Reason), 200)
	}
	if resp.EvaluationID != "" {
		in.Attributes["evaluation_id"] = resp.EvaluationID
	}
	if len(resp.RuleIDs) > 0 {
		in.Attributes["rule_ids"] = resp.RuleIDs
	}
	// agent.stop closes the runtime session; session lifecycle events
	// carry the working directory for the sessions page.
	sessionIn := audit.EnsureRuntimeSessionInput{
		SessionID:        in.SessionID,
		CanonicalAgentID: in.CanonicalAgentID,
		StartedAt:        in.Timestamp,
		WorkingDirectory: req.CWD,
	}
	switch eventType {
	case audit.RuntimeEventAgentStop, audit.RuntimeEventAgentSessionEnd:
		sessionIn.Status = "ended"
	}
	eventID, _ := store.RecordRuntimeEvent(in)
	if in.SessionID != "" && in.CanonicalAgentID != "" {
		_ = store.EnsureRuntimeSession(sessionIn)
	}
	// Phase-2: run the generic detection rules over this event
	// (atomic + session-window correlation).
	if engine := activeDetectionEngine(); engine != nil {
		engine.EvaluateEvent(eventID)
	}
}

// guardrailCategoryEventType maps a normalized finding category onto
// the unified content.* vocabulary.
func guardrailCategoryEventType(category string) string {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case CatPromptInjection, CatCognitiveTamper:
		return audit.RuntimeEventContentInjection
	case CatCredentialLeak:
		return audit.RuntimeEventContentSecret
	case CatPIIExposure:
		return audit.RuntimeEventContentPII
	case CatDataExfil:
		return audit.RuntimeEventContentExfilSignal
	default:
		return audit.RuntimeEventContentInspected
	}
}

// recordGuardrailRuntimeEvent is the Guardrail adapter: one unified
// event per verdict. The event type is derived from the highest-purity
// finding category (injection > exfiltration > secret > pii) so the
// timeline stays readable; the full category list rides in Attributes.
func recordGuardrailRuntimeEvent(ctx context.Context, direction, model string, verdict *ScanVerdict) {
	store := activeRuntimeEventStore()
	if store == nil || verdict == nil {
		return
	}
	env := audit.EnvelopeFromContext(ctx)

	outcome := "allowed"
	if strings.EqualFold(verdict.Action, "block") {
		outcome = "blocked"
	} else if strings.EqualFold(verdict.Action, "alert") {
		outcome = "flagged"
	}

	attrs := map[string]any{
		"direction":     direction,
		"action":        verdict.Action,
		"model":         model,
		"finding_count": len(verdict.Findings),
	}
	if verdict.Scanner != "" {
		attrs["scanner"] = verdict.Scanner
	}
	if verdict.EvaluationID != "" {
		attrs["evaluation_id"] = verdict.EvaluationID
	}
	if len(verdict.RuleIDs) > 0 {
		attrs["rule_ids"] = verdict.RuleIDs
	}

	// Category decomposition: prefer structured categories, then fall
	// back to keyword hints inside the raw finding strings so the REST
	// guardrail event path (plain []string findings) classifies too.
	eventType := audit.RuntimeEventContentInspected
	var categories []string
	if nfs := NormalizeScanVerdict(verdict); len(nfs) > 0 {
		seen := map[string]bool{}
		priority := map[string]int{
			audit.RuntimeEventContentInjection:   4,
			audit.RuntimeEventContentExfilSignal: 3,
			audit.RuntimeEventContentSecret:      2,
			audit.RuntimeEventContentPII:         1,
		}
		best := 0
		for _, nf := range nfs {
			catType := guardrailCategoryEventType(nf.Category)
			if !seen[nf.Category] {
				seen[nf.Category] = true
				categories = append(categories, nf.Category)
			}
			if p := priority[catType]; p > best {
				best = p
				eventType = catType
			}
			if nf.Confidence > 0 {
				if c, ok := attrs["confidence"].(float64); !ok || nf.Confidence > c {
					attrs["confidence"] = nf.Confidence
				}
			}
		}
	} else if len(verdict.Findings) > 0 {
		joined := strings.ToLower(strings.Join(verdict.Findings, " "))
		switch {
		case strings.Contains(joined, "injection") || strings.Contains(joined, "tamper"):
			eventType = audit.RuntimeEventContentInjection
		case strings.Contains(joined, "exfil"):
			eventType = audit.RuntimeEventContentExfilSignal
		case strings.Contains(joined, "credential") || strings.Contains(joined, "secret") || strings.Contains(joined, "api key"):
			eventType = audit.RuntimeEventContentSecret
		case strings.Contains(joined, "pii") || strings.Contains(joined, "ssn"):
			eventType = audit.RuntimeEventContentPII
		}
	}
	if len(categories) > 0 {
		attrs["categories"] = categories
	}

	in := audit.RuntimeEventInput{
		EventType:       eventType,
		EventSource:     audit.RuntimeSourceGuardrail,
		SessionID:       env.SessionID,
		TraceID:         env.TraceID,
		CanonicalAgentID: env.AgentID,
		AgentName:       env.AgentName,
		Target:          model,
		Severity:        verdict.Severity,
		Outcome:         outcome,
		Timestamp:       time.Now().UTC(),
		Attributes:      attrs,
	}
	if verdict.Reason != "" {
		in.Detail = truncate(redaction.ForSinkReason(verdict.Reason), 200)
	}
	eventID, _ := store.RecordRuntimeEvent(in)
	// Phase-2: guardrail findings feed the detection engine (prompt
	// injection is an atomic detection; content.secret arms the
	// credential-exfiltration correlation).
	if engine := activeDetectionEngine(); engine != nil {
		engine.EvaluateEvent(eventID)
	}
}

// recordEgressRuntimeEvent is the Proxy adapter. Every egress decision
// observed by the passthrough proxy (Layer 1) or reported by the
// TypeScript fetch-interceptor (Layer 3) lands here; blocked egress
// becomes network.blocked with the SSRF/bypass reason.
func recordEgressRuntimeEvent(ctx context.Context, p gatewaylog.EgressPayload) {
	store := activeRuntimeEventStore()
	if store == nil {
		return
	}
	env := audit.EnvelopeFromContext(ctx)

	eventType := audit.RuntimeEventNetworkRequest
	outcome := "allowed"
	severity := "INFO"
	switch {
	case p.Decision == "block" && p.Branch == "shape":
		eventType = audit.RuntimeEventNetworkBlocked
		outcome = "blocked"
		severity = "HIGH"
	case p.Decision == "block":
		eventType = audit.RuntimeEventNetworkBlocked
		outcome = "blocked"
		severity = "MEDIUM"
	case p.Branch == "shape":
		severity = "MEDIUM"
	}

	target := p.TargetHost
	if p.TargetPath != "" && p.TargetPath != "/" {
		target += p.TargetPath
	}
	attrs := map[string]any{
		"branch":       p.Branch,
		"decision":     p.Decision,
		"body_shape":   p.BodyShape,
		"looks_like_llm": p.LooksLikeLLM,
	}
	if p.Source != "" {
		attrs["layer"] = p.Source
	}

	in := audit.RuntimeEventInput{
		EventType:        eventType,
		EventSource:      audit.RuntimeSourceProxy,
		SessionID:        env.SessionID,
		TraceID:          env.TraceID,
		CanonicalAgentID: env.AgentID,
		AgentName:        env.AgentName,
		Target:           target,
		Severity:         severity,
		Outcome:          outcome,
		Timestamp:        time.Now().UTC(),
		Attributes:       attrs,
	}
	if p.Reason != "" {
		in.Detail = truncate(p.Reason, 200)
	}
	eventID, _ := store.RecordRuntimeEvent(in)
	// Phase-2: egress events complete the exfiltration correlation
	// chains and drive the SSRF/untrusted-network atomic detections.
	if engine := activeDetectionEngine(); engine != nil {
		engine.EvaluateEvent(eventID)
	}
}

// runtimeEventPostRequest is the OS Runtime Sensor report shape for
// POST /api/v1/runtime-events. The first-version sensor surface is
// process.exec / process.exit / file.read / file.write /
// network.connect — the activity that never flows through Prompt, LLM
// or Tool Hook pipelines and where exploit chains live.
type runtimeEventPostRequest struct {
	EventType string `json:"event_type"`
	AgentID   string `json:"agent_id,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
	PID       uint32 `json:"pid,omitempty"`
	PPID      uint32 `json:"ppid,omitempty"`
	Operation string `json:"operation,omitempty"`
	Target    string `json:"target,omitempty"`
	ToolName  string `json:"tool_name,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
	Detail    string `json:"detail,omitempty"`
	// Redacted upstream: the sensor must scrub command lines and paths
	// before reporting; the gateway re-redacts defensively.
	Command  string         `json:"command,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// handleRuntimeEvents serves the unified runtime event surface:
//
//	GET  /api/v1/runtime-events?agent_id=&session_id=&trace_id=
//	     &event_type=&source=&severity=&limit=  (timeline, chronological)
//	POST /api/v1/runtime-events                   (OS Runtime Sensor report)
//
// POSTed events are normalized through RecordRuntimeEvent and then
// evaluated by the detection engine, exactly like Guardrail / Agent
// Hook / Proxy events.
func (a *APIServer) handleRuntimeEvents(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.handleRuntimeEventsGet(w, r)
	case http.MethodPost:
		a.handleRuntimeEventsPost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleRuntimeEventsGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 300
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 2000 {
			limit = parsed
		}
	}
	events, err := a.store.ListRuntimeEvents(audit.RuntimeEventFilter{
		AgentID:     strings.TrimSpace(q.Get("agent_id")),
		SessionID:   strings.TrimSpace(q.Get("session_id")),
		TraceID:     strings.TrimSpace(q.Get("trace_id")),
		EventType:   strings.TrimSpace(q.Get("event_type")),
		EventSource: strings.TrimSpace(q.Get("source")),
		Severity:    strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		Limit:       limit,
	})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
	})
}

func (a *APIServer) handleRuntimeEventsPost(w http.ResponseWriter, r *http.Request) {
	store := activeRuntimeEventStore()
	if store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runtime event store unavailable"})
		return
	}
	var req runtimeEventPostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	req.EventType = strings.TrimSpace(req.EventType)
	if req.EventType == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "event_type is required"})
		return
	}
	// The unified vocabulary is the contract; unknown types are
	// accepted as agent.* lifecycle shapes so sensors can extend
	// without gateway round-trips.
	in := audit.RuntimeEventInput{
		EventType:       req.EventType,
		EventSource:     audit.RuntimeSourceOSSensor,
		CanonicalAgentID: req.AgentID,
		AgentName:       req.AgentName,
		SessionID:       req.SessionID,
		TraceID:         req.TraceID,
		PID:             req.PID,
		PPID:            req.PPID,
		Operation:       req.Operation,
		Target:          truncate(redaction.ForSinkString(firstNonEmpty(req.Target, req.Command)), 300),
		ToolName:        req.ToolName,
		Severity:        strings.ToUpper(req.Severity),
		Outcome:         firstNonEmpty(req.Outcome, "observed"),
		Detail:          truncate(redaction.ForSinkString(req.Detail), 300),
		Timestamp:       time.Now().UTC(),
	}
	if len(req.Metadata) > 0 {
		in.Attributes = req.Metadata
	}
	eventID, err := store.RecordRuntimeEvent(in)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if engine := activeDetectionEngine(); engine != nil {
		engine.EvaluateEvent(eventID)
	}
	a.writeJSON(w, http.StatusCreated, map[string]any{
		"event_id":  eventID,
		"evaluated": activeDetectionEngine() != nil,
	})
}

// handleRuntimeDetections serves the Phase-2 detection surface:
//
//	GET /api/v1/runtime-detections?agent_id=&session_id=&severity=
//	    &category=&type=&status=&limit=      (list, newest first)
//	GET /api/v1/runtime-detections/{id}      (detail + evidence chain)
//	PATCH /api/v1/runtime-detections/{id}    (status transition)
func (a *APIServer) handleRuntimeDetections(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/runtime-detections"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleRuntimeDetectionsList(w, r)
		return
	}
	detectionID := strings.Split(rest, "/")[0]
	if detectionID == "" || strings.ContainsAny(detectionID, `/\`) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		d, evidence, err := a.store.GetRuntimeDetectionDetail(detectionID)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if d.DetectionID == "" {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "detection not found"})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{
			"detection": d,
			"evidence":  evidence,
		})
	case http.MethodPatch, http.MethodPut:
		var body struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if err := a.store.UpdateRuntimeDetectionStatus(detectionID, body.Status); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		d, _, err := a.store.GetRuntimeDetectionDetail(detectionID)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"detection": d})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleRuntimeDetectionsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 200
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	detections, err := a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{
		AgentID:       strings.TrimSpace(q.Get("agent_id")),
		SessionID:     strings.TrimSpace(q.Get("session_id")),
		TraceID:       strings.TrimSpace(q.Get("trace_id")),
		DetectionType: strings.TrimSpace(q.Get("type")),
		Category:      strings.TrimSpace(q.Get("category")),
		Severity:      strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		Status:        strings.ToLower(strings.TrimSpace(q.Get("status"))),
		Limit:         limit,
	})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Summary counts so the page can headline critical/attack numbers
	// without client-side aggregation.
	summary := map[string]int{
		"total": len(detections), "attack": 0, "critical": 0, "high": 0, "open": 0,
	}
	for _, d := range detections {
		if d.Category == "attack" {
			summary["attack"]++
		}
		switch strings.ToLower(d.Severity) {
		case "critical":
			summary["critical"]++
		case "high":
			summary["high"]++
		}
		if d.Status == audit.RuntimeDetectionStatusOpen {
			summary["open"]++
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"detections": detections,
		"summary":    summary,
		"count":      len(detections),
	})
}

// handleRuntimeEvents serves GET /api/v1/runtime-sessions?agent_id=&limit=
// — the per-agent run inventory (started/ended, working directory,
// event count) that lets a dangerous event be traced back to the exact
// run that produced it.
func (a *APIServer) handleRuntimeSessions(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	limit := 100
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	sessions, err := a.store.ListRuntimeSessions(strings.TrimSpace(q.Get("agent_id")), limit)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// handleRuntimeDecisions serves the Phase-3 decision surface:
//
//	GET /api/v1/runtime-decisions?agent_id=&session_id=&decision=
//	    &detection_id=&limit=       (list, newest first)
//	GET /api/v1/runtime-decisions/{id}   (detail + response actions)
//
// Decisions answer "应该怎么处理？" — the unified verdict derived from
// each detection; response actions answer "实际执行了什么？".
func (a *APIServer) handleRuntimeDecisions(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/runtime-decisions"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleRuntimeDecisionsList(w, r)
		return
	}
	decisionID := strings.Split(rest, "/")[0]
	if decisionID == "" || strings.ContainsAny(decisionID, `/\`) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	decision, responses, err := a.store.GetRuntimeDecisionDetail(decisionID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if decision.DecisionID == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "decision not found"})
		return
	}
	var detection audit.RuntimeDetection
	var evidence []audit.DetectionEvidence
	if decision.DetectionID != "" {
		detection, evidence, _ = a.store.GetRuntimeDetectionDetail(decision.DetectionID)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"decision":   decision,
		"responses":  responses,
		"detection":  detection,
		"evidence":   evidence,
	})
}

func (a *APIServer) handleRuntimeDecisionsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 200
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	decisions, detections, err := a.store.ListRuntimeDecisions(audit.RuntimeDecisionFilter{
		AgentID:     strings.TrimSpace(q.Get("agent_id")),
		SessionID:   strings.TrimSpace(q.Get("session_id")),
		TraceID:     strings.TrimSpace(q.Get("trace_id")),
		DetectionID: strings.TrimSpace(q.Get("detection_id")),
		Decision:    strings.ToUpper(strings.TrimSpace(q.Get("decision"))),
		Mode:        strings.ToLower(strings.TrimSpace(q.Get("mode"))),
		Limit:       limit,
	})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Pair each decision with its detection for one-row rendering.
	type decisionRow struct {
		audit.RuntimeDecision
		Detection audit.RuntimeDetection `json:"detection"`
	}
	rows := make([]decisionRow, 0, len(decisions))
	summary := map[string]int{
		"total": len(decisions), "block": 0, "confirm": 0,
		"alert": 0, "audit": 0, "allow": 0, "would_block": 0,
	}
	for i := range decisions {
		d := audit.RuntimeDetection{}
		if i < len(detections) {
			d = detections[i]
		}
		rows = append(rows, decisionRow{RuntimeDecision: decisions[i], Detection: d})
		switch decisions[i].Decision {
		case audit.RuntimeDecisionBlock:
			summary["block"]++
		case audit.RuntimeDecisionConfirm:
			summary["confirm"]++
		case audit.RuntimeDecisionAlert:
			summary["alert"]++
		case audit.RuntimeDecisionAudit:
			summary["audit"]++
		case audit.RuntimeDecisionAllow:
			summary["allow"]++
		}
		if decisions[i].WouldBlock {
			summary["would_block"]++
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"decisions": rows,
		"summary":   summary,
		"count":     len(rows),
	})
}

// handleRuntimeSecurityMode serves the Runtime Security Mode switch:
//
//	GET /api/v1/runtime-security-mode   → {"mode":"observe"|"action"}
//	PUT /api/v1/runtime-security-mode   body {"mode":"action"}
//
// observe (default) records would-block decisions without enforcing —
// the false-positive tuning loop; action executes responses (proxy
// blocklist, enforcement dispatch).
func (a *APIServer) handleRuntimeSecurityMode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, map[string]any{
			"mode": activeRuntimePolicyMode(),
		})
	case http.MethodPut, http.MethodPost:
		var body struct {
			Mode string `json:"mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		mode := strings.ToLower(strings.TrimSpace(body.Mode))
		if mode != audit.RuntimeSecurityModeObserve && mode != audit.RuntimeSecurityModeAction {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be observe or action"})
			return
		}
		if err := setRuntimePolicyMode(mode); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"mode": mode})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
