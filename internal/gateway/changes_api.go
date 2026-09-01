// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strconv"
	"strings"
)

var changeDomains = []string{
	"agents", "static_resources", "scan_results", "scan_findings", "behavior_events", "runtime_detections",
	"runtime_decisions", "runtime_response_actions", "runtime_attack_chains",
	"runtime_attack_chain_events", "scan_jobs",
}

// handleChangesAPI is an invalidation endpoint for active desktop pages. It
// never returns business rows, so a cheap poll can tell the UI which read
// models need refreshing without repeatedly loading every table.
func (a *APIServer) handleChangesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	cursor := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cursor must be a non-negative integer"})
			return
		}
		cursor = parsed
	}
	limit := 32
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	domains := make([]string, 0)
	seenDomains := map[string]bool{}
	domainAliases := map[string]string{
		"agent": "agents", "agents": "agents",
		"resource": "static_resources", "resources": "static_resources", "static": "static_resources", "static_resources": "static_resources",
		"scan_results": "scan_results", "scan_findings": "scan_findings",
		"event": "behavior_events", "events": "behavior_events", "behavior_events": "behavior_events",
		"detection": "runtime_detections", "detections": "runtime_detections", "runtime_detections": "runtime_detections",
		"decision": "runtime_decisions", "decisions": "runtime_decisions", "runtime_decisions": "runtime_decisions",
		"response": "runtime_response_actions", "responses": "runtime_response_actions", "enforcement": "runtime_response_actions", "enforcements": "runtime_response_actions", "runtime_response_actions": "runtime_response_actions",
		"chain": "runtime_attack_chains", "chains": "runtime_attack_chains", "runtime_attack_chains": "runtime_attack_chains", "runtime_attack_chain_events": "runtime_attack_chain_events",
		"job": "scan_jobs", "jobs": "scan_jobs", "scan_jobs": "scan_jobs",
	}
	for _, raw := range strings.Split(r.URL.Query().Get("domains"), ",") {
		if value := strings.TrimSpace(raw); value != "" {
			canonical := value
			if mapped, ok := domainAliases[strings.ToLower(value)]; ok {
				canonical = mapped
			}
			if !seenDomains[canonical] {
				domains = append(domains, canonical)
				seenDomains[canonical] = true
			}
		}
	}
	changes, err := a.store.ChangesSince(cursor, domains, limit)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// The first sync establishes a consistent baseline. Existing rows predate
	// the change log migration, so report requested domains once at cursor 0.
	if cursor == 0 && changes.NextCursor > 0 && len(changes.ChangedDomains) == 0 {
		if len(domains) == 0 {
			changes.ChangedDomains = append(changes.ChangedDomains, changeDomains...)
		} else {
			changes.ChangedDomains = append(changes.ChangedDomains, domains...)
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"next_cursor":     changes.NextCursor,
		"changed_domains": changes.ChangedDomains,
		"latest_at":       changes.LatestAt,
		"source":          "sqlite",
	})
}
