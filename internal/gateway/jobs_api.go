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
	Kind           string         `json:"kind"`
	Mode           string         `json:"mode,omitempty"`
	Trigger        string         `json:"trigger,omitempty"`
	Scope          map[string]any `json:"scope,omitempty"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	AgentID        string         `json:"agent_id,omitempty"`
	ResourceID     string         `json:"resource_id,omitempty"`
	SessionID      string         `json:"session_id,omitempty"`
	TraceID        string         `json:"trace_id,omitempty"`
	StartTime      string         `json:"start_time,omitempty"`
	EndTime        string         `json:"end_time,omitempty"`
	Limit          int            `json:"limit,omitempty"`
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
	kind := r.URL.Query().Get("kind")
	status := r.URL.Query().Get("status")
	filter := audit.ScanJobFilter{Kind: kind, Status: status, Since: parseAPITime(r.URL.Query().Get("start_time")), Until: parseAPITime(r.URL.Query().Get("end_time")), Limit: limit, Offset: offset}
	jobs, err := a.store.ListScanJobsFiltered(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	total, err := a.store.CountScanJobsFiltered(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"items":  jobs,
		"jobs":   jobs,
		"count":  len(jobs),
		"total":  total,
		"limit":  limit,
		"offset": offset,
		"next_offset": func() int {
			if offset+len(jobs) < total {
				return offset + len(jobs)
			}
			return 0
		}(),
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
	job.CancelRequested = true
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
		current.CancelRequested = true
		current.Phase = "cancelled"
		a.scanStatuses[jobID] = current
	}
	a.scanStatusMu.Unlock()
	a.scanCancelMu.Lock()
	if cancel := a.scanCancels[jobID]; cancel != nil {
		cancel()
	}
	a.scanCancelMu.Unlock()
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
	idempotencyKey := strings.TrimSpace(req.IdempotencyKey)
	if headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key")); headerKey != "" {
		idempotencyKey = headerKey
	}
	if len(idempotencyKey) > 200 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key must be at most 200 characters"})
		return
	}
	trigger := strings.TrimSpace(req.Trigger)
	if trigger == "" {
		trigger = "manual"
	}
	switch kind {
	case "agent_discovery", "agents":
		status := a.startAPIScanWithOptions("agent_discovery", firstNonEmpty(mode, "full"), "", "", trigger, req.Scope, idempotencyKey, func(ctx context.Context, _ string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := a.buildPageAgentInventory(2000)
			return err
		})
		a.writeJSON(w, http.StatusAccepted, status)
	case "resource_scan", "static_resources":
		a.startResourceJob(w, req, mode, trigger, idempotencyKey)
	case "event_replay", "detection_replay":
		a.startEventReplayJob(w, req, trigger, idempotencyKey)
	case "attack_chain_rebuild", "chain_rebuild":
		if status, ok := a.existingScanStatusForKey(idempotencyKey); ok {
			a.writeJSON(w, http.StatusAccepted, status)
			return
		}
		engine := activeDetectionEngine()
		if engine == nil || engine.Policy() == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "detection engine unavailable"})
			return
		}
		status := a.startAPIScanWithOptions("attack_chain_rebuild", mode, "", "", trigger, req.Scope, idempotencyKey, func(ctx context.Context, jobID string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return engine.Policy().RebuildAttackChainsForJob(req.Limit, jobID)
		})
		a.writeJSON(w, http.StatusAccepted, status)
	default:
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported job kind"})
	}
}

// existingScanStatusForKey resolves a previously accepted durable scan before
// touching any in-memory concurrency guard. Compatibility endpoints use this
// helper so a retried request cannot be rejected as "already running" or
// accidentally start a second worker.
func (a *APIServer) existingScanStatusForKey(key string) (apiScanStatus, bool) {
	key = strings.TrimSpace(key)
	if a == nil || a.store == nil || key == "" {
		return apiScanStatus{}, false
	}
	job, found, err := a.store.FindScanJobByIdempotencyKey(key)
	if err != nil || !found {
		return apiScanStatus{}, false
	}
	status := apiScanStatusFromAuditJob(job)
	_ = a.storeAPIScan(status)
	return status, true
}

func requestIdempotencyKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("Idempotency-Key"))
}

func (a *APIServer) startResourceJob(w http.ResponseWriter, req jobCreateRequest, mode, trigger, idempotencyKey string) {
	if status, ok := a.existingScanStatusForKey(idempotencyKey); ok {
		a.writeJSON(w, http.StatusAccepted, status)
		return
	}
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
	status := a.startAPIScanWithOptions("resource_scan", mode, req.AgentID, req.ResourceID, trigger, req.Scope, idempotencyKey, func(ctx context.Context, _ string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		defer staticScanInFlight.Store(false)
		if req.ResourceID != "" {
			return scanOne(req.ResourceID)
		}
		return rescan(req.AgentID)
	})
	if status.Status == "failed" {
		staticScanInFlight.Store(false)
	}
	a.writeJSON(w, http.StatusAccepted, status)
}

func (a *APIServer) startEventReplayJob(w http.ResponseWriter, req jobCreateRequest, trigger, idempotencyKey string) {
	if status, ok := a.existingScanStatusForKey(idempotencyKey); ok {
		a.writeJSON(w, http.StatusAccepted, status)
		return
	}
	engine := activeDetectionEngine()
	if engine == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "detection engine unavailable"})
		return
	}
	status := a.startAPIScanWithOptions("event_replay", req.Mode, req.AgentID, "", trigger, req.Scope, idempotencyKey, func(ctx context.Context, jobID string) error {
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
		a.updateAPIScanProgress(jobID, 0, len(events), "loaded", map[string]any{"events": len(events)})
		for i, event := range events {
			if err := ctx.Err(); err != nil {
				return err
			}
			engine.EvaluateEventForJob(event.ID, jobID)
			a.updateAPIScanProgress(jobID, i+1, len(events), "evaluating", map[string]any{"events": len(events)})
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
			settings = settings.normalize()
			if !settings.AgentDiscovery.Enabled {
				continue
			}
			interval := time.Duration(settings.AgentDiscovery.IntervalSec) * time.Second
			if lastDiscovery.IsZero() {
				if jobs, err := a.store.ListScanJobsFiltered(audit.ScanJobFilter{Kind: "agent_discovery", Limit: 1}); err == nil && len(jobs) > 0 {
					lastDiscovery = parseTimeOrNow(jobs[0].CreatedAt)
				}
			}
			if !lastDiscovery.IsZero() && now.Sub(lastDiscovery) < interval {
				continue
			}
			if a.hasRunningScanKind("agent_discovery") {
				continue
			}
			a.startAPIScanWithOptions("agent_discovery", "scheduled", "", "", "schedule", map[string]any{"interval_sec": settings.AgentDiscovery.IntervalSec}, "agent-discovery:"+now.UTC().Truncate(interval).Format(time.RFC3339), func(ctx context.Context, _ string) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				_, err := a.buildPageAgentInventory(2000)
				return err
			})
			lastDiscovery = now
		}
	}
}

func (a *APIServer) hasRunningScanKind(kind string) bool {
	a.scanStatusMu.RLock()
	for _, status := range a.scanStatuses {
		matchesKind := status.Type == kind
		if kind == "agent_discovery" && status.Type == "agents" {
			matchesKind = true
		}
		if kind == "resource_scan" && status.Type == "static-resources" {
			matchesKind = true
		}
		if matchesKind && (status.Status == "running" || status.Status == "queued") {
			a.scanStatusMu.RUnlock()
			return true
		}
	}
	a.scanStatusMu.RUnlock()
	if a.store != nil {
		jobs, err := a.store.ListScanJobsFiltered(audit.ScanJobFilter{Kind: kind, Limit: 20})
		if err == nil {
			for _, job := range jobs {
				if job.Status == "running" || job.Status == "queued" {
					return true
				}
			}
		}
	}
	return false
}

func parseTimeOrNow(value string) time.Time {
	if parsed := parseAPITime(value); !parsed.IsZero() {
		return parsed
	}
	return time.Now().UTC()
}
