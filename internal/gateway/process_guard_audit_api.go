// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type pageGuardAuditSnapshot struct {
	CapturedAt string                 `json:"capturedAt"`
	Path       string                 `json:"path"`
	Events     []pageGuardAuditRecord `json:"events"`
	Warning    string                 `json:"warning,omitempty"`
}

type pageGuardAuditRecord struct {
	Timestamp       string `json:"timestamp"`
	EventType       string `json:"eventType"`
	Outcome         string `json:"outcome"`
	Detail          string `json:"detail"`
	Mode            string `json:"mode,omitempty"`
	RuleID          string `json:"ruleId,omitempty"`
	Action          string `json:"action,omitempty"`
	ChildPID        uint32 `json:"childPid,omitempty"`
	ChildExecutable string `json:"childExecutable,omitempty"`
	AgentPID        uint32 `json:"agentPid,omitempty"`
	AgentExecutable string `json:"agentExecutable,omitempty"`
	TraceID         string `json:"traceId,omitempty"`
	SessionID       string `json:"sessionId,omitempty"`
	AgentName       string `json:"agentName,omitempty"`
	Connector       string `json:"connector,omitempty"`
	Stage           string `json:"stage,omitempty"`
	Source          string `json:"source,omitempty"`
	DestinationApp  string `json:"destinationApp,omitempty"`
	ToolName        string `json:"toolName,omitempty"`
	MCPServer       string `json:"mcpServer,omitempty"`
	Prompt          string `json:"prompt,omitempty"`
	Model           string `json:"model,omitempty"`
	Decision        string `json:"decision,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Reason          string `json:"reason,omitempty"`
	LatencyMs       uint64 `json:"latencyMs,omitempty"`
	RawRef          string `json:"rawRef,omitempty"`
}

func (a *APIServer) handleProcessGuardAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store is not attached"})
		return
	}
	rows, err := a.store.ListBehaviorEvents(pageLimit(r, 200, 1, 500))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	events := make([]pageGuardAuditRecord, 0, len(rows))
	for _, row := range rows {
		if !pageProcessGuardBehaviorEvent(row) {
			continue
		}
		events = append(events, pageGuardAuditRecordFromBehavior(row))
	}
	slices.Reverse(events)
	warning := ""
	if len(events) == 0 {
		warning = "Go 后端 behavior_events 尚未记录进程守护审计事件"
	}
	a.writeJSON(w, http.StatusOK, pageGuardAuditSnapshot{
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Path:       "audit.db:behavior_events",
		Events:     events,
		Warning:    warning,
	})
}

func pageProcessGuardBehaviorEvent(row audit.BehaviorEvent) bool {
	switch row.EventType {
	case "processGuardRuleMatch", "blacklistFileAccess":
		return true
	default:
		return false
	}
}

func pageGuardAuditRecordFromBehavior(row audit.BehaviorEvent) pageGuardAuditRecord {
	eventType := row.EventType
	if eventType == "processGuardRuleMatch" {
		eventType = "agent-command-rule-matched"
	}
	return pageGuardAuditRecord{
		Timestamp:       row.Timestamp.UTC().Format(time.RFC3339Nano),
		EventType:       eventType,
		Outcome:         row.Outcome,
		Detail:          row.Detail,
		Mode:            detailToken(row.Detail, "mode"),
		RuleID:          pageGuardRuleID(row),
		Action:          row.Action,
		ChildPID:        row.ActorPID,
		ChildExecutable: row.ActorExecutable,
		AgentPID:        row.AgentPID,
		AgentExecutable: row.AgentExecutable,
		TraceID:         row.TraceID,
		SessionID:       row.SessionID,
		AgentName:       row.AgentName,
		Connector:       "desktop-behavior",
		Stage:           row.EventType,
		Source:          row.Source,
		ToolName:        row.ActorExecutable,
		Decision:        row.Outcome,
		Severity:        behaviorEventSeverity(row),
		Reason:          row.Detail,
		RawRef:          "behavior_events:" + strconv.FormatInt(row.ID, 10),
	}
}

func pageGuardRuleID(row audit.BehaviorEvent) string {
	if id := detailToken(row.Detail, "rule_id"); id != "" {
		return id
	}
	fields := strings.Fields(row.Detail)
	for i, field := range fields {
		if field == "rule" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func detailToken(detail string, key string) string {
	prefix := key + "="
	for _, field := range strings.Fields(detail) {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(field, prefix))
		}
	}
	return ""
}
