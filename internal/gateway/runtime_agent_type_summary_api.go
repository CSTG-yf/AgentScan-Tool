// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// handleRuntimeDetectionAgentTypeSummary serves the anomaly page's
// AgentType rollup. The canonical path is
// GET /api/v1/runtime-detections/summary/agent-types. The handler is also
// used by the runtime-security summary aliases so older page integrations
// can opt into the same grouped response without changing their base path.
func (a *APIServer) handleRuntimeDetectionAgentTypeSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}

	items, err := a.store.ListRuntimeDetectionAgentTypeSummaries(runtimeDetectionFilterFromQuery(r, 200, 1000))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if agentType := agentTypeSummaryFilter(r); agentType != "" {
		items = filterRuntimeDetectionAgentTypeSummaries(items, agentType)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"list":        items,
		"total":       len(items),
		"count":       len(items),
		"captured_at": time.Now().UTC().Format(time.RFC3339Nano),
		"source":      "runtime_detections",
	})
}

// handleRuntimeAttackChainAgentTypeSummary serves the attack-chain page's
// AgentType rollup. The canonical path is
// GET /api/v1/attack-chains/summary/agent-types.
func (a *APIServer) handleRuntimeAttackChainAgentTypeSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}

	items, err := a.store.ListRuntimeAttackChainAgentTypeSummaries(attackChainSummaryFilterFromQuery(r))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if agentType := agentTypeSummaryFilter(r); agentType != "" {
		items = filterRuntimeAttackChainAgentTypeSummaries(items, agentType)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"list":        items,
		"total":       len(items),
		"count":       len(items),
		"captured_at": time.Now().UTC().Format(time.RFC3339Nano),
		"source":      "runtime_attack_chains",
	})
}

func agentTypeSummaryFilter(r *http.Request) string {
	q := r.URL.Query()
	return strings.TrimSpace(firstNonEmpty(q.Get("agent_type"), q.Get("agentType"), q.Get("AgentType")))
}

func filterRuntimeDetectionAgentTypeSummaries(items []audit.RuntimeDetectionAgentTypeSummary, filter string) []audit.RuntimeDetectionAgentTypeSummary {
	filter = strings.ToLower(strings.TrimSpace(filter))
	out := make([]audit.RuntimeDetectionAgentTypeSummary, 0, len(items))
	for _, item := range items {
		if strings.EqualFold(item.AgentType, filter) ||
			strings.EqualFold(item.AgentTypeKey, filter) ||
			strings.EqualFold(item.AgentTypeName, filter) ||
			strconv.FormatInt(item.AgentTypeID, 10) == filter {
			out = append(out, item)
		}
	}
	return out
}

func filterRuntimeAttackChainAgentTypeSummaries(items []audit.RuntimeAttackChainAgentTypeSummary, filter string) []audit.RuntimeAttackChainAgentTypeSummary {
	filter = strings.ToLower(strings.TrimSpace(filter))
	out := make([]audit.RuntimeAttackChainAgentTypeSummary, 0, len(items))
	for _, item := range items {
		if strings.EqualFold(item.AgentType, filter) ||
			strings.EqualFold(item.AgentTypeKey, filter) ||
			strings.EqualFold(item.AgentTypeName, filter) ||
			strconv.FormatInt(item.AgentTypeID, 10) == filter {
			out = append(out, item)
		}
	}
	return out
}

func attackChainSummaryFilterFromQuery(r *http.Request) audit.AttackChainFilter {
	q := r.URL.Query()
	return audit.AttackChainFilter{
		AgentID:     strings.TrimSpace(q.Get("agent_id")),
		AgentTypeID: requestAgentTypeID(r),
		SessionID:   strings.TrimSpace(q.Get("session_id")),
		TraceID:     strings.TrimSpace(q.Get("trace_id")),
		AttackType:  strings.TrimSpace(q.Get("attack_type")),
		Severity:    strings.TrimSpace(q.Get("severity")),
		Status:      attackChainStatusFilter(q.Get("status")),
		Keyword:     strings.TrimSpace(q.Get("keyword")),
		Sort:        strings.TrimSpace(q.Get("sort")),
		StartTime:   parseAPITime(q.Get("start_time")),
		EndTime:     parseAPITime(q.Get("end_time")),
	}
}
