// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
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
// audit_events keeps its audit-log role. Runtime security pages now read
// behavior_events, runtime_detections, runtime_decisions, and
// runtime_response_actions through the /api/v1 runtime-security surface.

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
		EventType:   eventType,
		EventSource: audit.RuntimeSourceAgentHook,
		SessionID:   firstNonEmpty(req.SessionID, env.SessionID),
		TraceID:     firstNonEmpty(env.TraceID, TraceIDFromContext(ctx)),
		AgentName:   firstNonEmpty(req.AgentName, identity.AgentName, req.ConnectorName),
		ToolName:    req.ToolName,
		Target:      hookToolTargetText(req.ToolName, req.ToolArgs),
		Operation:   firstNonEmpty(req.ToolName, req.HookEventName),
		Severity:    resp.Severity,
		Outcome:     hookOutcomeFromAction(resp.Action),
		Timestamp:   time.Now().UTC(),
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
		EventType:        eventType,
		EventSource:      audit.RuntimeSourceGuardrail,
		SessionID:        env.SessionID,
		TraceID:          env.TraceID,
		CanonicalAgentID: env.AgentID,
		AgentName:        env.AgentName,
		Target:           model,
		Severity:         verdict.Severity,
		Outcome:          outcome,
		Timestamp:        time.Now().UTC(),
		Attributes:       attrs,
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
		"branch":         p.Branch,
		"decision":       p.Decision,
		"body_shape":     p.BodyShape,
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
	EventType       string `json:"event_type"`
	AgentID         string `json:"agent_id,omitempty"`
	AgentName       string `json:"agent_name,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
	TraceID         string `json:"trace_id,omitempty"`
	PID             uint32 `json:"pid,omitempty"`
	PPID            uint32 `json:"ppid,omitempty"`
	AgentExecutable string `json:"agent_executable,omitempty"`
	ActorPID        uint32 `json:"actor_pid,omitempty"`
	ActorExecutable string `json:"actor_executable,omitempty"`
	AgentInstanceID string `json:"agent_instance_id,omitempty"`
	Path            string `json:"path,omitempty"`
	Action          string `json:"action,omitempty"`
	Operation       string `json:"operation,omitempty"`
	Target          string `json:"target,omitempty"`
	ToolName        string `json:"tool_name,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Outcome         string `json:"outcome,omitempty"`
	Detail          string `json:"detail,omitempty"`
	Timestamp       string `json:"timestamp,omitempty"`
	// Redacted upstream: the sensor must scrub command lines and paths
	// before reporting; the gateway re-redacts defensively.
	Command  string         `json:"command,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type runtimeEventBatchRequest struct {
	Events []runtimeEventPostRequest `json:"events"`
}

type runtimeDetectionListItem struct {
	DetectionID   string         `json:"detection_id"`
	AgentID       string         `json:"agent_id"`
	AgentName     string         `json:"agent_name,omitempty"`
	AgentTypeID   int64          `json:"agent_type_id,omitempty"`
	AgentTypeName string         `json:"agent_type_name,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	TraceID       string         `json:"trace_id,omitempty"`
	Type          string         `json:"type"`
	DetectionType string         `json:"detection_type"`
	Category      string         `json:"category"`
	Severity      string         `json:"severity"`
	Confidence    float64        `json:"confidence"`
	RuleID        string         `json:"rule_id"`
	RuleVersion   string         `json:"rule_version,omitempty"`
	Status        string         `json:"status"`
	Title         string         `json:"title"`
	Description   string         `json:"description,omitempty"`
	Detail        string         `json:"detail,omitempty"`
	Remediation   string         `json:"remediation,omitempty"`
	Source        string         `json:"source"`
	CreatedAt     string         `json:"created_at,omitempty"`
	FirstSeenAt   string         `json:"first_seen_at,omitempty"`
	LastSeenAt    string         `json:"last_seen_at,omitempty"`
	EventCount    int            `json:"event_count"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

type runtimeDetectionAgentContext struct {
	AgentID       string `json:"agent_id"`
	Name          string `json:"name"`
	AgentTypeID   int64  `json:"agent_type_id,omitempty"`
	AgentTypeName string `json:"agent_type_name,omitempty"`
}

type runtimeDetectionSessionContext struct {
	SessionID string `json:"session_id,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
}

type runtimeDetectionDetailResponse struct {
	runtimeDetectionListItem
	Detection      runtimeDetectionListItem       `json:"detection"`
	Evidence       []runtimeDetectionEvidenceItem `json:"evidence"`
	Agent          runtimeDetectionAgentContext   `json:"agent"`
	RuntimeSession runtimeDetectionSessionContext `json:"runtime_session"`
	Trace          runtimeDetectionSessionContext `json:"trace"`
}

type runtimeDetectionEvidenceItem struct {
	DetectionID   string         `json:"detection_id,omitempty"`
	EventID       int64          `json:"event_id"`
	EventType     string         `json:"event_type"`
	EventSource   string         `json:"event_source,omitempty"`
	EventCategory string         `json:"event_category,omitempty"`
	Timestamp     string         `json:"timestamp,omitempty"`
	Sequence      int            `json:"sequence"`
	Role          string         `json:"role,omitempty"`
	AgentID       string         `json:"agent_id,omitempty"`
	AgentName     string         `json:"agent_name,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	TraceID       string         `json:"trace_id,omitempty"`
	ToolName      string         `json:"tool_name,omitempty"`
	Target        string         `json:"target,omitempty"`
	Operation     string         `json:"operation,omitempty"`
	Outcome       string         `json:"outcome,omitempty"`
	Severity      string         `json:"severity,omitempty"`
	Detail        string         `json:"detail,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

type runtimeTimelineBucket struct {
	Time    string `json:"time"`
	Bucket  string `json:"bucket"`
	Total   int    `json:"total"`
	Prompt  int    `json:"prompt"`
	Tool    int    `json:"tool"`
	Process int    `json:"process"`
	File    int    `json:"file"`
	Network int    `json:"network"`
	Content int    `json:"content"`
}

func runtimeDetectionFilterFromQuery(r *http.Request, limitDefault, limitMax int) audit.RuntimeDetectionFilter {
	q := r.URL.Query()
	page, pageSize := requestPage(r, 1, limitDefault, limitMax)
	limit := pageSize
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= limitMax {
			limit = parsed
		}
	}
	offset := (page - 1) * pageSize
	if v := strings.TrimSpace(q.Get("offset")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			offset = parsed
		}
	}
	status := strings.TrimSpace(q.Get("status"))
	switch strings.ToLower(status) {
	case "detected", "pending":
		status = audit.RuntimeDetectionStatusOpen
	case "blocked":
		status = audit.RuntimeDetectionStatusMitigated + ",blocked"
	case "audited":
		status = audit.RuntimeDetectionStatusResolved
	}
	return audit.RuntimeDetectionFilter{
		AgentID:       strings.TrimSpace(q.Get("agent_id")),
		AgentTypeID:   requestAgentTypeID(r),
		SessionID:     strings.TrimSpace(q.Get("session_id")),
		TraceID:       strings.TrimSpace(q.Get("trace_id")),
		DetectionType: firstNonEmpty(strings.TrimSpace(q.Get("detection_type")), strings.TrimSpace(q.Get("type"))),
		Category:      strings.TrimSpace(q.Get("category")),
		Severity:      strings.TrimSpace(q.Get("severity")),
		Source:        strings.TrimSpace(q.Get("source")),
		Status:        status,
		Keyword:       strings.TrimSpace(q.Get("keyword")),
		StartTime:     parseAPITime(q.Get("start_time")),
		EndTime:       parseAPITime(q.Get("end_time")),
		Sort:          strings.TrimSpace(q.Get("sort")),
		Limit:         limit,
		Offset:        offset,
	}
}

func runtimeDetectionListItemFromAudit(d audit.RuntimeDetection) runtimeDetectionListItem {
	return runtimeDetectionListItem{
		DetectionID:   d.DetectionID,
		AgentID:       d.AgentID,
		AgentName:     d.AgentName,
		AgentTypeID:   d.AgentTypeID,
		AgentTypeName: d.AgentTypeName,
		SessionID:     d.SessionID,
		TraceID:       d.TraceID,
		Type:          d.DetectionType,
		DetectionType: d.DetectionType,
		Category:      d.Category,
		Severity:      strings.ToLower(d.Severity),
		Confidence:    d.Confidence,
		RuleID:        d.RuleID,
		RuleVersion:   d.RuleVersion,
		Status:        d.Status,
		Title:         d.Title,
		Description:   firstNonEmpty(d.Detail, d.Remediation),
		Detail:        d.Detail,
		Remediation:   d.Remediation,
		Source:        runtimeDetectionSource(d),
		CreatedAt:     runtimeTimeString(d.LastSeenAt),
		FirstSeenAt:   runtimeTimeString(d.FirstSeenAt),
		LastSeenAt:    runtimeTimeString(d.LastSeenAt),
		EventCount:    d.EventCount,
		Attributes:    d.Attributes,
	}
}

func runtimeDetectionSource(d audit.RuntimeDetection) string {
	if source := strings.TrimSpace(d.Source); source != "" {
		return source
	}
	if source, ok := runtimeStringFromAttributes(d.Attributes, "source"); ok {
		return source
	}
	if d.EventCount > 1 ||
		strings.Contains(strings.ToLower(d.RuleID), "exfiltration") ||
		strings.Contains(strings.ToLower(d.DetectionType), "exfiltration") ||
		strings.Contains(strings.ToLower(d.DetectionType), "exploit") {
		return "correlation_engine"
	}
	return "runtime_detection"
}

func runtimeStringFromAttributes(attrs map[string]any, key string) (string, bool) {
	if len(attrs) == 0 {
		return "", false
	}
	if value, ok := attrs[key]; ok {
		if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s), true
		}
	}
	return "", false
}

func runtimeTimeString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func runtimeDetectionEvidenceItems(evidence []audit.DetectionEvidence) []runtimeDetectionEvidenceItem {
	items := make([]runtimeDetectionEvidenceItem, 0, len(evidence))
	for _, row := range evidence {
		ev := row.Event
		items = append(items, runtimeDetectionEvidenceItem{
			DetectionID:   row.DetectionID,
			EventID:       row.EventID,
			EventType:     ev.EventType,
			EventSource:   ev.EventSource,
			EventCategory: ev.EventCategory,
			Timestamp:     runtimeTimeString(ev.Timestamp),
			Sequence:      row.Sequence,
			Role:          row.Role,
			AgentID:       ev.CanonicalAgentID,
			AgentName:     ev.AgentName,
			SessionID:     ev.SessionID,
			TraceID:       ev.TraceID,
			ToolName:      ev.ToolName,
			Target:        ev.Target,
			Operation:     ev.Operation,
			Outcome:       ev.Outcome,
			Severity:      strings.ToLower(ev.Severity),
			Detail:        ev.Detail,
			Attributes:    ev.Attributes,
		})
	}
	return items
}

func runtimeDetectionSourceMatches(source string, filter string) bool {
	values := strings.Split(strings.ToLower(filter), ",")
	source = strings.ToLower(strings.TrimSpace(source))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == "all" || value == source {
			return true
		}
	}
	return false
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
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/runtime-events"), "/")
	if rest != "" {
		if rest == "batch" {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			a.handleRuntimeEventsBatch(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleRuntimeEventDetail(w, r, rest)
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

func (a *APIServer) handleRuntimeEventsTimeline(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	bucketSize := 5 * time.Minute
	if raw := strings.TrimSpace(q.Get("bucket")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed >= time.Minute && parsed <= 24*time.Hour {
			bucketSize = parsed
		}
	}
	since := time.Now().UTC().Add(-24 * time.Hour)
	if raw := strings.TrimSpace(q.Get("start_time")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			since = parsed.UTC()
		} else if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			since = parsed.UTC()
		}
	}
	var until time.Time
	if raw := strings.TrimSpace(q.Get("end_time")); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			until = parsed.UTC()
		} else if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			until = parsed.UTC()
		}
	}
	events, err := a.store.ListRuntimeEvents(audit.RuntimeEventFilter{
		AgentID:   strings.TrimSpace(q.Get("agent_id")),
		SessionID: strings.TrimSpace(q.Get("session_id")),
		TraceID:   strings.TrimSpace(q.Get("trace_id")),
		Since:     since,
		Limit:     2000,
	})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byBucket := map[string]*runtimeTimelineBucket{}
	for _, event := range events {
		if !until.IsZero() && event.Timestamp.After(until) {
			continue
		}
		bucketTime := event.Timestamp.UTC().Truncate(bucketSize)
		key := bucketTime.Format(time.RFC3339Nano)
		item := byBucket[key]
		if item == nil {
			item = &runtimeTimelineBucket{
				Time:   bucketTime.Format("15:04"),
				Bucket: key,
			}
			byBucket[key] = item
		}
		item.Total++
		switch runtimeTimelineCategory(event) {
		case audit.RuntimeCategoryPrompt:
			item.Prompt++
		case audit.RuntimeCategoryTool:
			item.Tool++
		case audit.RuntimeCategoryProcess:
			item.Process++
		case audit.RuntimeCategoryFile:
			item.File++
		case audit.RuntimeCategoryNetwork:
			item.Network++
		case audit.RuntimeCategoryContent:
			item.Content++
		}
	}
	buckets := make([]runtimeTimelineBucket, 0, len(byBucket))
	for _, item := range byBucket {
		buckets = append(buckets, *item)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Bucket < buckets[j].Bucket })
	a.writeJSON(w, http.StatusOK, map[string]any{"buckets": buckets})
}

func runtimeTimelineCategory(event audit.BehaviorEvent) string {
	if strings.TrimSpace(event.EventCategory) != "" {
		return event.EventCategory
	}
	switch {
	case strings.HasPrefix(event.EventType, "prompt."):
		return audit.RuntimeCategoryPrompt
	case strings.HasPrefix(event.EventType, "tool."):
		return audit.RuntimeCategoryTool
	case strings.HasPrefix(event.EventType, "process."):
		return audit.RuntimeCategoryProcess
	case strings.HasPrefix(event.EventType, "file."):
		return audit.RuntimeCategoryFile
	case strings.HasPrefix(event.EventType, "network."):
		return audit.RuntimeCategoryNetwork
	case strings.HasPrefix(event.EventType, "content."):
		return audit.RuntimeCategoryContent
	default:
		return audit.RuntimeCategoryLifecycle
	}
}

func (a *APIServer) handleRuntimeEventsGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, pageSize := requestPage(r, 1, 300, 2000)
	limit := pageSize
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 2000 {
			limit = parsed
		}
	}
	offset := (page - 1) * pageSize
	if v := strings.TrimSpace(q.Get("offset")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			offset = parsed
		}
	}
	var pid uint32
	if v := strings.TrimSpace(q.Get("pid")); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 32); err == nil {
			pid = uint32(parsed)
		}
	}
	filter := audit.RuntimeEventFilter{
		AgentID:       strings.TrimSpace(q.Get("agent_id")),
		SessionID:     strings.TrimSpace(q.Get("session_id")),
		TraceID:       strings.TrimSpace(q.Get("trace_id")),
		EventType:     strings.TrimSpace(q.Get("event_type")),
		EventCategory: strings.TrimSpace(q.Get("event_category")),
		EventSource:   strings.TrimSpace(q.Get("source")),
		Severity:      strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		PID:           pid,
		Keyword:       strings.TrimSpace(q.Get("keyword")),
		Since:         parseAPITime(q.Get("start_time")),
		Until:         parseAPITime(q.Get("end_time")),
		Limit:         limit,
		Offset:        offset,
	}
	events, err := a.store.ListRuntimeEvents(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	total, err := a.store.CountRuntimeEvents(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"events":    events,
		"items":     events,
		"count":     len(events),
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"limit":     limit,
		"offset":    offset,
	})
}

func (a *APIServer) handleRuntimeEventsPost(w http.ResponseWriter, r *http.Request) {
	if activeRuntimeEventStore() == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runtime event store unavailable"})
		return
	}
	var req runtimeEventPostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	eventID, err := a.ingestRuntimeEvent(req)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusCreated, map[string]any{"event_id": eventID, "evaluated": activeDetectionEngine() != nil})
}

// handleRuntimeEventsBatch accepts either {"events":[...]} or a bare JSON
// array. Each event is normalized and evaluated independently; one malformed
// item does not discard successfully persisted siblings.
func (a *APIServer) handleRuntimeEventsBatch(w http.ResponseWriter, r *http.Request) {
	if activeRuntimeEventStore() == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "runtime event store unavailable"})
		return
	}
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	var events []runtimeEventPostRequest
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		if err := json.Unmarshal(raw, &events); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "events must be a JSON array"})
			return
		}
	} else {
		var body runtimeEventBatchRequest
		if err := json.Unmarshal(raw, &body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid batch JSON body"})
			return
		}
		events = body.Events
	}
	if len(events) == 0 || len(events) > 1000 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "events must contain between 1 and 1000 items"})
		return
	}
	items := make([]map[string]any, 0, len(events))
	failed := 0
	for i, event := range events {
		eventID, err := a.ingestRuntimeEvent(event)
		if err != nil {
			failed++
			items = append(items, map[string]any{"index": i, "error": err.Error()})
			continue
		}
		items = append(items, map[string]any{"index": i, "event_id": eventID, "evaluated": activeDetectionEngine() != nil})
	}
	status := http.StatusCreated
	if failed > 0 {
		status = http.StatusMultiStatus
	}
	a.writeJSON(w, status, map[string]any{"items": items, "count": len(items), "failed": failed})
}

func (a *APIServer) ingestRuntimeEvent(req runtimeEventPostRequest) (int64, error) {
	store := activeRuntimeEventStore()
	if store == nil {
		return 0, fmt.Errorf("runtime event store unavailable")
	}
	req.EventType = strings.TrimSpace(req.EventType)
	if req.EventType == "" {
		return 0, fmt.Errorf("event_type is required")
	}
	timestamp := time.Now().UTC()
	if parsed := parseAPITime(req.Timestamp); !parsed.IsZero() {
		timestamp = parsed
	}
	in := audit.RuntimeEventInput{
		EventType:        req.EventType,
		EventSource:      audit.RuntimeSourceOSSensor,
		CanonicalAgentID: req.AgentID,
		AgentName:        req.AgentName,
		SessionID:        req.SessionID,
		TraceID:          req.TraceID,
		PID:              req.PID,
		PPID:             req.PPID,
		AgentExecutable:  req.AgentExecutable,
		ActorPID:         req.ActorPID,
		ActorExecutable:  req.ActorExecutable,
		AgentInstanceID:  req.AgentInstanceID,
		Path:             req.Path,
		Action:           req.Action,
		Operation:        req.Operation,
		Target:           truncate(redaction.ForSinkString(firstNonEmpty(req.Target, req.Path, req.Command)), 300),
		ToolName:         req.ToolName,
		Severity:         strings.ToUpper(req.Severity),
		Outcome:          firstNonEmpty(req.Outcome, "observed"),
		Detail:           truncate(redaction.ForSinkString(req.Detail), 300),
		Timestamp:        timestamp,
	}
	if len(req.Metadata) > 0 {
		in.Attributes = req.Metadata
	}
	eventID, err := store.RecordRuntimeEvent(in)
	if err != nil {
		return 0, err
	}
	if engine := activeDetectionEngine(); engine != nil {
		engine.EvaluateEvent(eventID)
	}
	return eventID, nil
}

// Legacy implementation retained as a compatibility reference while callers
// use the normalized helper above.
func (a *APIServer) handleRuntimeEventsPostLegacy(w http.ResponseWriter, r *http.Request) {
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
		EventType:        req.EventType,
		EventSource:      audit.RuntimeSourceOSSensor,
		CanonicalAgentID: req.AgentID,
		AgentName:        req.AgentName,
		SessionID:        req.SessionID,
		TraceID:          req.TraceID,
		PID:              req.PID,
		PPID:             req.PPID,
		AgentExecutable:  req.AgentExecutable,
		ActorPID:         req.ActorPID,
		ActorExecutable:  req.ActorExecutable,
		AgentInstanceID:  req.AgentInstanceID,
		Path:             req.Path,
		Action:           req.Action,
		Operation:        req.Operation,
		Target:           truncate(redaction.ForSinkString(firstNonEmpty(req.Target, req.Path, req.Command)), 300),
		ToolName:         req.ToolName,
		Severity:         strings.ToUpper(req.Severity),
		Outcome:          firstNonEmpty(req.Outcome, "observed"),
		Detail:           truncate(redaction.ForSinkString(req.Detail), 300),
		Timestamp:        time.Now().UTC(),
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
	parts := strings.Split(rest, "/")
	detectionID := parts[0]
	if detectionID == "" || strings.ContainsAny(detectionID, `/\`) {
		http.NotFound(w, r)
		return
	}
	if len(parts) > 1 {
		if len(parts) == 2 && parts[1] == "events" {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			a.handleRuntimeDetectionEvents(w, r, detectionID)
			return
		}
		if len(parts) == 2 && parts[1] == "actions" {
			a.handleRuntimeDetectionBlockAction(w, r, detectionID)
			return
		}
		if len(parts) == 3 && parts[1] == "actions" && parts[2] == "block" {
			a.handleRuntimeDetectionBlockAction(w, r, detectionID)
			return
		}
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
		item := runtimeDetectionListItemFromAudit(d)
		a.writeJSON(w, http.StatusOK, runtimeDetectionDetailResponse{
			runtimeDetectionListItem: item,
			Detection:                item,
			Evidence:                 runtimeDetectionEvidenceItems(evidence),
			Agent: runtimeDetectionAgentContext{
				AgentID:       d.AgentID,
				Name:          firstNonEmpty(d.AgentName, d.AgentID),
				AgentTypeID:   d.AgentTypeID,
				AgentTypeName: d.AgentTypeName,
			},
			RuntimeSession: runtimeDetectionSessionContext{SessionID: d.SessionID, TraceID: d.TraceID},
			Trace:          runtimeDetectionSessionContext{SessionID: d.SessionID, TraceID: d.TraceID},
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
		a.writeJSON(w, http.StatusOK, map[string]any{"detection": runtimeDetectionListItemFromAudit(d)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleRuntimeDetectionEvents(w http.ResponseWriter, r *http.Request, detectionID string) {
	d, evidence, err := a.store.GetRuntimeDetectionDetail(detectionID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if d.DetectionID == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "detection not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, runtimeDetectionEvidenceItems(evidence))
}

func (a *APIServer) handleRuntimeDetectionsList(w http.ResponseWriter, r *http.Request) {
	filter := runtimeDetectionFilterFromQuery(r, 200, 1000)
	sourceFilter := strings.TrimSpace(r.URL.Query().Get("source"))
	detections, err := a.store.ListRuntimeDetections(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	total, err := a.store.CountRuntimeDetections(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	items := make([]runtimeDetectionListItem, 0, len(detections))
	for _, d := range detections {
		item := runtimeDetectionListItemFromAudit(d)
		if sourceFilter != "" && !runtimeDetectionSourceMatches(item.Source, sourceFilter) {
			continue
		}
		items = append(items, item)
	}
	if sourceFilter != "" && !strings.EqualFold(sourceFilter, "all") {
		allFilter := filter
		allFilter.Limit = 5000
		allFilter.Offset = 0
		all, err := a.store.ListRuntimeDetections(allFilter)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		allItems := make([]runtimeDetectionListItem, 0, len(all))
		for _, d := range all {
			item := runtimeDetectionListItemFromAudit(d)
			if runtimeDetectionSourceMatches(item.Source, sourceFilter) {
				allItems = append(allItems, item)
			}
		}
		total = len(allItems)
		start := filter.Offset
		if start > len(allItems) {
			start = len(allItems)
		}
		end := start + filter.Limit
		if end > len(allItems) {
			end = len(allItems)
		}
		items = allItems[start:end]
	}
	summary := map[string]int{
		"total": total, "attack": 0, "blocked": 0, "critical": 0, "high": 0, "open": 0,
	}
	for _, d := range items {
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
		if d.Status == audit.RuntimeDetectionStatusMitigated || strings.EqualFold(d.Status, "blocked") {
			summary["blocked"]++
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"total":      total,
		"items":      items,
		"detections": items,
		"list":       items,
		"summary":    summary,
		"count":      len(items),
		"limit":      filter.Limit,
		"offset":     filter.Offset,
		"page":       filter.Offset/filter.Limit + 1,
		"page_size":  filter.Limit,
		"pagesize":   filter.Limit,
	})
}

func (a *APIServer) handleRuntimeSecuritySummary(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filter := runtimeDetectionFilterFromQuery(r, 200, 1000)
	filter.Limit = 0
	filter.Offset = 0
	summary, err := a.store.RuntimeSecuritySummary(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, summary)
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
	parts := strings.Split(rest, "/")
	decisionID := parts[0]
	if decisionID == "" || strings.ContainsAny(decisionID, `/\`) {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 && (parts[1] == "enforce" || parts[1] == "execute") {
		a.handleRuntimeDecisionEnforce(w, r, decisionID)
		return
	}
	if len(parts) > 1 {
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
		"decision":  decision,
		"responses": responses,
		"detection": detection,
		"evidence":  evidence,
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
//	GET /api/v1/runtime-security/mode   → {"mode":"observe"|"action"}
//	PUT /api/v1/runtime-security/mode   body {"mode":"action"}
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
