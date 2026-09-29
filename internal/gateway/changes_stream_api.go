// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	changeStreamPollInterval = time.Second
	changeStreamKeepAlive    = 15 * time.Second
)

// handleChangeStreamAPI streams SQLite change cursors to active desktop views.
// It sends invalidations only; clients must still fetch authoritative read
// models after receiving an event. Last-Event-ID allows a reconnect to resume
// without making the browser or desktop client poll the changes endpoint.
func (a *APIServer) handleChangeStreamAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "audit store unavailable", http.StatusServiceUnavailable)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is unsupported", http.StatusInternalServerError)
		return
	}

	cursor := int64(0)
	rawCursor := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if rawCursor == "" {
		rawCursor = strings.TrimSpace(r.URL.Query().Get("cursor"))
	}
	if rawCursor != "" {
		parsed, err := strconv.ParseInt(rawCursor, 10, 64)
		if err != nil || parsed < 0 {
			http.Error(w, "cursor must be a non-negative integer", http.StatusBadRequest)
			return
		}
		cursor = parsed
	}
	domains := parseChangeDomains(r.URL.Query().Get("domains"))

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	poll := time.NewTicker(changeStreamPollInterval)
	defer poll.Stop()
	keepAlive := time.NewTicker(changeStreamKeepAlive)
	defer keepAlive.Stop()
	for {
		changes, err := a.store.ChangesSince(cursor, domains, 32)
		if err != nil {
			// The status code can no longer be changed after the stream starts.
			// Tell subscribers to reconnect and fall back to /api/v1/changes.
			_, _ = fmt.Fprintf(w, "event: error\ndata: %q\n\n", "change store unavailable")
			flusher.Flush()
			return
		}
		if cursor == 0 && changes.NextCursor > 0 && len(changes.ChangedDomains) == 0 {
			if len(domains) == 0 {
				changes.ChangedDomains = append(changes.ChangedDomains, changeDomains...)
			} else {
				changes.ChangedDomains = append(changes.ChangedDomains, domains...)
			}
		}
		if changes.NextCursor > cursor && len(changes.ChangedDomains) > 0 {
			payload, marshalErr := json.Marshal(changes)
			if marshalErr != nil {
				_, _ = fmt.Fprint(w, "event: error\ndata: \"could not encode change cursor\"\n\n")
				flusher.Flush()
				return
			}
			if _, err := fmt.Fprintf(w, "id: %d\nevent: change\ndata: %s\n\n", changes.NextCursor, payload); err != nil {
				return
			}
			flusher.Flush()
			cursor = changes.NextCursor
		} else if changes.NextCursor > cursor {
			// No subscribed domain changed. Advance the resume cursor so an
			// unrelated busy domain cannot make us repeatedly scan old rows.
			cursor = changes.NextCursor
		}

		select {
		case <-r.Context().Done():
			return
		case <-poll.C:
		case <-keepAlive.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func parseChangeDomains(raw string) []string {
	aliases := map[string]string{
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
	seen := make(map[string]bool)
	domains := make([]string, 0)
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		canonical := value
		if mapped, ok := aliases[strings.ToLower(value)]; ok {
			canonical = mapped
		}
		if !seen[canonical] {
			seen[canonical] = true
			domains = append(domains, canonical)
		}
	}
	return domains
}
