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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// jobCreateRequest is deliberately small and stable. Existing scan
// endpoints remain compatibility aliases, while new UI actions use this
// explicit task contract so a read never masquerades as a scan.
type jobCreateRequest struct {
	Kind       string `json:"kind"`
	Mode       string `json:"mode,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	TraceID    string `json:"trace_id,omitempty"`
	StartTime  string `json:"start_time,omitempty"`
	EndTime    string `json:"end_time,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

// handleJobsAPI exposes the durable job surface. The old /scans routes call
// the same startAPIScan function and therefore produce rows visible here.
func (a *APIServer) handleJobsAPI(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/jobs"), "/")
	if rest == "" {
		switch r.Method {
		case http.MethodGet:
			a.handleJobsList(w, r)
		case http.MethodPost:
			a.handleJobCreate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	parts := strings.Split(rest, "/")
	jobID := parts[0]
	if jobID == "" || strings.ContainsAny(jobID, `/\`) {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleJobCancel(w, jobID)
		return
	}
	if len(parts) != 1 || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	a.handleJobGet(w, jobID)
}

func (a *APIServer) handleJobsList(w http.ResponseWriter, r *http.Request) {
	limit := pageLimit(r, 100, 1, 500)
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			offset = parsed
		}
	}
	jobs, err := a.store.ListScanJobs(r.URL.Query().Get("kind"), r.URL.Query().Get("status"), limit, offset)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	total, err := a.store.CountScanJobs(r.URL.Query().Get("kind"), r.URL.Query().Get("status"))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"items": jobs,
		"jobs":  jobs,
		"count": len(jobs),
		"total": total,
		"limit": limit,
		"offset": offset,
	})
}

func (a *APIServer) handleJobGet(w http.ResponseWriter, jobID string) {
	if status, ok := a.lookupAPIScan(jobID); ok {
		a.writeJSON(w, http.StatusOK, status)
		return
	}
	job, ok, err := a.store.GetScanJob(jobID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, job)
}

func (a *APIServer) handleJobCancel(w http.ResponseWriter, jobID string) {
	job, ok, err := a.store.GetScanJob(jobID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	if job.Status == "completed" || job.Status == "failed" || job.Status == "cancelled" {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": "job already finished"})
		return
	}
	job.Status = "cancelled"
	job.Error = "cancelled by operator"
	job.FinishedAt = nowRFC3339()
	if err := a.store.UpdateScanJob(job); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.scanStatusMu.Lock()
	if current, exists := a.scanStatuses[jobID]; exists {
		current.Status = job.Status
		current.Error = job.Error
		current.FinishedAt = job.FinishedAt
		a.scanStatuses[jobID] = current
	}
	a.scanStatusMu.Unlock()
	a.writeJSON(w, http.StatusOK, job)
}

func (a *APIServer) handleJobCreate(w http.ResponseWriter, r *http.Request) {
	var req jobCreateRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
	}
	kind := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.Kind), "-", "_"))
	if kind == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind is required"})
		return
	}
	mode := strings.TrimSpace(req.Mode)
	switch kind {
	case "agent_discovery", "agents":
		status := a.startAPIScan("agent_discovery", firstNonEmpty(mode, "full"), "", "", func() error {
			_, err := a.buildPageAgentInventory(2000)
			return err
		})
		a.writeJSON(w, http.StatusAccepted, status)
	case "resource_scan", "static_resources":
		a.startResourceJob(w, req, mode)
	case "event_replay", "detection_replay":
		a.startEventReplayJob(w, req)
	case "attack_chain_rebuild", "chain_rebuild":
		engine := activeDetectionEngine()
		if engine == nil || engine.Policy() == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "detection engine unavailable"})
			return
		}
		status := a.startAPIScan("attack_chain_rebuild", mode, "", "", func() error {
			return engine.Policy().RebuildAttackChains(req.Limit)
		})
		a.writeJSON(w, http.StatusAccepted, status)
	default:
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported job kind"})
	}
}

func (a *APIServer) startResourceJob(w http.ResponseWriter, req jobCreateRequest, mode string) {
	scanOne, rescan := a.staticScanTriggers()
	if req.ResourceID != "" && scanOne == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "watcher scan pipeline unavailable"})
		return
	}
	if req.ResourceID == "" && rescan == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "watcher scan pipeline unavailable"})
		return
	}
	if !staticScanInFlight.CompareAndSwap(false, true) {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": "another manual scan is already running"})
		return
	}
	status := a.startAPIScan("resource_scan", mode, req.AgentID, req.ResourceID, func() error {
		defer staticScanInFlight.Store(false)
		if req.ResourceID != "" {
			return scanOne(req.ResourceID)
		}
		return rescan(req.AgentID)
	})
	a.writeJSON(w, http.StatusAccepted, status)
}

func (a *APIServer) startEventReplayJob(w http.ResponseWriter, req jobCreateRequest) {
	engine := activeDetectionEngine()
	if engine == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "detection engine unavailable"})
		return
	}
	status := a.startAPIScan("event_replay", req.Mode, req.AgentID, "", func() error {
		limit := req.Limit
		if limit <= 0 || limit > 50000 {
			limit = 50000
		}
		events, err := a.store.ListRuntimeEvents(audit.RuntimeEventFilter{
			AgentID: req.AgentID, SessionID: req.SessionID, TraceID: req.TraceID,
			Since: parseAPITime(req.StartTime), Until: parseAPITime(req.EndTime),
			IncludeDesktop: true, Limit: limit,
		})
		if err != nil {
			return err
		}
		for _, event := range events {
			engine.EvaluateEvent(event.ID)
		}
		return nil
	})
	a.writeJSON(w, http.StatusAccepted, status)
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// RunBackgroundJobs keeps the durable Agent discovery job alive when the
// desktop window is closed. Static resource periodic rescans are owned by the
// watcher; runtime detection is event-driven and does not need a polling scan.
func (a *APIServer) RunBackgroundJobs(ctx context.Context) {
	if a == nil || a.store == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastDiscovery := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			settings := defaultPageScanScheduleSettings()
			if ok, err := a.store.LoadJSONSetting(desktopScanScheduleSettingKey, &settings); err != nil || !ok {
				settings = defaultPageScanScheduleSettings()
			}
			settings = settings.normalize()
			if !settings.AgentDiscovery.Enabled {
				continue
			}
			interval := time.Duration(settings.AgentDiscovery.IntervalSec) * time.Second
			if !lastDiscovery.IsZero() && now.Sub(lastDiscovery) < interval {
				continue
			}
			if a.hasRunningScanKind("agent_discovery") {
				continue
			}
			a.startAPIScan("agent_discovery", "scheduled", "", "", func() error {
				_, err := a.buildPageAgentInventory(2000)
				return err
			})
			lastDiscovery = now
		}
	}
}

func (a *APIServer) hasRunningScanKind(kind string) bool {
	a.scanStatusMu.RLock()
	defer a.scanStatusMu.RUnlock()
	for _, status := range a.scanStatuses {
		matchesKind := status.Type == kind
		if kind == "agent_discovery" && status.Type == "agents" {
			matchesKind = true
		}
		if kind == "resource_scan" && status.Type == "static-resources" {
			matchesKind = true
		}
		if matchesKind && (status.Status == "running" || status.Status == "queued") {
			return true
		}
	}
	return false
}
