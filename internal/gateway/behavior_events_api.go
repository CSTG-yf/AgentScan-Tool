// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type pageBehaviorSnapshot struct {
	CapturedAt   string              `json:"capturedAt"`
	DatabasePath string              `json:"databasePath"`
	Events       []pageBehaviorEvent `json:"events"`
	Warning      string              `json:"warning,omitempty"`
}

type pageBehaviorEvent struct {
	ID               int64  `json:"id"`
	Timestamp        string `json:"timestamp"`
	EventType        string `json:"eventType"`
	Source           string `json:"source"`
	AgentPID         uint32 `json:"agentPid"`
	AgentExecutable  string `json:"agentExecutable"`
	ActorPID         uint32 `json:"actorPid"`
	ActorExecutable  string `json:"actorExecutable"`
	Path             string `json:"path,omitempty"`
	Action           string `json:"action,omitempty"`
	Outcome          string `json:"outcome"`
	Detail           string `json:"detail"`
	AgentName        string `json:"agentName,omitempty"`
	CanonicalAgentID string `json:"canonicalAgentId,omitempty"`
	SessionID        string `json:"sessionId,omitempty"`
	TraceID          string `json:"traceId,omitempty"`
}

func (a *APIServer) handleBehaviorEvents(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store is not attached"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := a.store.ListBehaviorEvents(pageLimit(r, 300, 50, 2000))
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		events := make([]pageBehaviorEvent, 0, len(rows))
		for _, row := range rows {
			events = append(events, pageBehaviorEventFromAudit(row))
		}
		warning := ""
		if len(events) == 0 {
			warning = "Go 后端 behavior_events 尚未记录 Agent 行为"
		}
		a.writeJSON(w, http.StatusOK, pageBehaviorSnapshot{
			CapturedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			DatabasePath: "audit.db:behavior_events",
			Events:       events,
			Warning:      warning,
		})
	case http.MethodPost:
		var request pageBehaviorEvent
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		inserted, err := a.store.InsertBehaviorEvent(auditBehaviorEventFromPage(request))
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if behaviorEventShouldAudit(inserted) {
			_ = a.store.LogEvent(audit.Event{
				Timestamp:        inserted.Timestamp,
				Action:           "behavior." + strings.TrimSpace(inserted.EventType),
				Target:           pageFirstNonEmpty(inserted.Path, inserted.ActorExecutable),
				Actor:            "desktop-process-guard",
				Details:          inserted.Detail,
				Severity:         behaviorEventSeverity(inserted),
				AgentName:        inserted.AgentName,
				AgentID:          inserted.CanonicalAgentID,
				CanonicalAgentID: inserted.CanonicalAgentID,
				SessionID:        inserted.SessionID,
				TraceID:          inserted.TraceID,
				ToolName:         inserted.ActorExecutable,
				Connector:        "desktop-behavior",
			})
		}
		a.writeJSON(w, http.StatusCreated, pageBehaviorEventFromAudit(inserted))
	case http.MethodDelete:
		retentionDays, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("retentionDays")))
		maxRows, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("maxRows")))
		if retentionDays <= 0 && maxRows <= 0 {
			maxRows = 300_000
		}
		if err := a.store.PruneBehaviorEvents(retentionDays, maxRows); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{
			"status":        "pruned",
			"retentionDays": retentionDays,
			"maxRows":       maxRows,
		})
	default:
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func pageBehaviorEventFromAudit(row audit.BehaviorEvent) pageBehaviorEvent {
	timestamp := ""
	if !row.Timestamp.IsZero() {
		timestamp = row.Timestamp.UTC().Format(time.RFC3339Nano)
	}
	return pageBehaviorEvent{
		ID:               row.ID,
		Timestamp:        timestamp,
		EventType:        row.EventType,
		Source:           row.Source,
		AgentPID:         row.AgentPID,
		AgentExecutable:  row.AgentExecutable,
		ActorPID:         row.ActorPID,
		ActorExecutable:  row.ActorExecutable,
		Path:             row.Path,
		Action:           row.Action,
		Outcome:          row.Outcome,
		Detail:           row.Detail,
		AgentName:        row.AgentName,
		CanonicalAgentID: row.CanonicalAgentID,
		SessionID:        row.SessionID,
		TraceID:          row.TraceID,
	}
}

func auditBehaviorEventFromPage(in pageBehaviorEvent) audit.BehaviorEvent {
	timestamp := time.Time{}
	if strings.TrimSpace(in.Timestamp) != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(in.Timestamp)); err == nil {
			timestamp = parsed.UTC()
		}
	}
	return audit.BehaviorEvent{
		ID:               in.ID,
		Timestamp:        timestamp,
		EventType:        in.EventType,
		Source:           in.Source,
		AgentPID:         in.AgentPID,
		AgentExecutable:  in.AgentExecutable,
		ActorPID:         in.ActorPID,
		ActorExecutable:  in.ActorExecutable,
		Path:             in.Path,
		Action:           in.Action,
		Outcome:          in.Outcome,
		Detail:           in.Detail,
		AgentName:        in.AgentName,
		CanonicalAgentID: in.CanonicalAgentID,
		SessionID:        in.SessionID,
		TraceID:          in.TraceID,
	}
}

func pageEventFromBehavior(row audit.BehaviorEvent) pageEvent {
	severity := behaviorEventSeverity(row)
	agent := pageCanonicalAgentDisplay(row.CanonicalAgentID, row.AgentName, row.AgentExecutable)
	runtime := pageCanonicalAgentRuntime(row.CanonicalAgentID, "desktop-behavior", row.Source, "Windows Process Guard")
	return pageEvent{
		ID:             "behavior-" + strconv.FormatInt(row.ID, 10),
		OccurredAt:     row.Timestamp.UTC().Format(time.RFC3339Nano),
		Kind:           "behavior",
		Agent:          agent,
		Runtime:        runtime,
		Category:       "Agent 行为",
		Subtype:        row.EventType,
		Title:          behaviorEventTitle(row),
		Severity:       severity,
		RiskScore:      pageRiskRank(severity),
		Status:         behaviorEventStatus(row),
		Evidence:       behaviorEventEvidence(row),
		Action:         row.Action,
		TraceID:        row.TraceID,
		SessionID:      row.SessionID,
		CorrelationKey: pageFirstNonEmpty(row.TraceID, row.SessionID, row.CanonicalAgentID, row.AgentExecutable),
		Source:         "behavior_events",
		RawAction:      row.EventType,
		Target:         pageFirstNonEmpty(row.Path, row.ActorExecutable),
		Actor:          row.ActorExecutable,
		Connector:      "desktop-behavior",
		ToolName:       row.ActorExecutable,
		Decision:       row.Outcome,
		Reason:         row.Detail,
		Remediation:    behaviorEventRemediation(row),
	}
}

func pageBehaviorEventRelevant(row audit.BehaviorEvent) bool {
	if behaviorEventShouldAudit(row) {
		return true
	}
	eventType := strings.ToLower(row.EventType)
	path := strings.ToLower(row.Path)
	return eventType == "filedelete" ||
		strings.Contains(path, ".env") ||
		strings.Contains(path, "credential") ||
		strings.Contains(path, "secret") ||
		strings.Contains(path, "token")
}

func behaviorEventShouldAudit(row audit.BehaviorEvent) bool {
	text := strings.ToLower(strings.Join([]string{row.EventType, row.Action, row.Outcome, row.Detail}, " "))
	return strings.Contains(text, "blacklist") ||
		strings.Contains(text, "terminate") ||
		strings.Contains(text, "terminated") ||
		strings.Contains(text, "failed")
}

func behaviorEventSeverity(row audit.BehaviorEvent) string {
	text := strings.ToLower(strings.Join([]string{row.EventType, row.Action, row.Outcome, row.Detail, row.Path}, " "))
	switch {
	case strings.Contains(text, "terminated") || strings.Contains(text, "blacklist"):
		return "HIGH"
	case strings.Contains(text, "terminationpending") || strings.Contains(text, "terminate"):
		return "MEDIUM"
	case strings.Contains(text, ".env") || strings.Contains(text, "credential") || strings.Contains(text, "secret") || strings.Contains(text, "token"):
		return "MEDIUM"
	default:
		return "INFO"
	}
}

func behaviorEventStatus(row audit.BehaviorEvent) string {
	switch strings.ToLower(strings.TrimSpace(row.Outcome)) {
	case "terminated":
		return "blocked"
	case "terminationpending", "terminationfailed":
		return "detected"
	default:
		return "observed"
	}
}

func behaviorEventTitle(row audit.BehaviorEvent) string {
	switch row.EventType {
	case "agentProcessStart":
		return "Agent 进程启动"
	case "agentCommandStart":
		return "Agent 命令执行"
	case "blacklistFileAccess":
		return "敏感文件访问命中策略"
	case "fileRead":
		return "Agent 文件读取"
	case "fileWrite":
		return "Agent 文件写入"
	case "fileCreate":
		return "Agent 文件创建"
	case "fileDelete", "fileDeleteIntent":
		return "Agent 文件删除"
	default:
		return row.EventType
	}
}

func behaviorEventEvidence(row audit.BehaviorEvent) string {
	parts := []string{
		"agent=" + pageFirstNonEmpty(row.AgentName, row.AgentExecutable),
		"agentPid=" + strconv.FormatUint(uint64(row.AgentPID), 10),
		"actor=" + row.ActorExecutable,
		"actorPid=" + strconv.FormatUint(uint64(row.ActorPID), 10),
	}
	if row.Path != "" {
		parts = append(parts, "path="+row.Path)
	}
	if row.Detail != "" {
		parts = append(parts, row.Detail)
	}
	return strings.Join(parts, " ")
}

func behaviorEventRemediation(row audit.BehaviorEvent) string {
	if behaviorEventSeverity(row) == "INFO" {
		return "保留行为证据，用于后续关联分析。"
	}
	return "复核 Agent 命令来源、文件路径和进程树，必要时收紧进程守护或文件访问策略。"
}
