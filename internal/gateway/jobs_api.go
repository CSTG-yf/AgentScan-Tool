// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
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
	TaskType       string         `json:"task_type,omitempty"`
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
	taskType := r.URL.Query().Get("task_type")
	status := r.URL.Query().Get("status")
	trigger := r.URL.Query().Get("trigger")
	filter := audit.ScanJobFilter{Kind: kind, TaskType: taskType, Trigger: trigger, Status: status, Since: parseAPITime(r.URL.Query().Get("start_time")), Until: parseAPITime(r.URL.Query().Get("end_time")), Limit: limit, Offset: offset}
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
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
	}
	taskType := audit.NormalizeScanTaskType(firstNonEmpty(req.TaskType, req.Kind))
	if taskType == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "task_type or kind is required"})
		return
	}
	if strings.TrimSpace(req.TaskType) != "" && strings.TrimSpace(req.Kind) != "" && audit.NormalizeScanTaskType(req.TaskType) != audit.NormalizeScanTaskType(req.Kind) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "task_type and kind refer to different tasks"})
		return
	}
	if req.Scope == nil {
		req.Scope = map[string]any{}
	}
	for key, target := range map[string]*string{
		"agent_id": &req.AgentID, "resource_id": &req.ResourceID, "session_id": &req.SessionID,
		"trace_id": &req.TraceID, "start_time": &req.StartTime, "end_time": &req.EndTime,
	} {
		if *target != "" || req.Scope[key] == nil {
			continue
		}
		value, ok := req.Scope[key].(string)
		if !ok {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scope." + key + " must be a string"})
			return
		}
		*target = strings.TrimSpace(value)
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" || mode == "scheduled" {
		mode = map[string]string{"agent_discovery": "full", "static_assets": "full", "runtime_detections": "replay", "attack_chains": "rebuild"}[taskType]
	}
	if !map[string]bool{"full": true, "incremental": true, "single": true, "replay": true, "rebuild": true}[mode] {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported scan mode"})
		return
	}
	req.Mode = mode
	idempotencyKey := strings.TrimSpace(req.IdempotencyKey)
	if headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key")); headerKey != "" {
		idempotencyKey = headerKey
	}
	if len(idempotencyKey) > 200 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key must be at most 200 characters"})
		return
	}
	rawTrigger := strings.ToLower(strings.TrimSpace(req.Trigger))
	if !map[string]bool{"": true, "manual": true, "schedule": true, "scheduled": true, "scheduler": true, "watcher": true}[rawTrigger] {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported scan trigger"})
		return
	}
	trigger := audit.NormalizeScanTrigger(req.Trigger)
	a.scanStartMu.Lock()
	defer a.scanStartMu.Unlock()
	if status, ok := a.existingScanStatusForKey(idempotencyKey); ok {
		a.writeJSON(w, http.StatusAccepted, status)
		return
	}
	if status, ok := a.runningScanStatusForKind(audit.ScanJobKind(taskType)); ok {
		a.writeJSON(w, http.StatusAccepted, status)
		return
	}
	switch taskType {
	case "agent_discovery":
		status := a.startAPIScanWithOptions("agent_discovery", firstNonEmpty(mode, "full"), "", "", trigger, req.Scope, idempotencyKey, func(ctx context.Context, _ string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := a.buildPageAgentInventory(2000)
			return err
		})
		a.writeJSON(w, http.StatusAccepted, status)
	case "static_assets":
		a.startResourceJob(w, req, mode, trigger, idempotencyKey)
	case "runtime_detections":
		a.startEventReplayJob(w, req, trigger, idempotencyKey)
	case "attack_chains":
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

func (a *APIServer) runningScanStatusForKind(kind string) (apiScanStatus, bool) {
	a.scanStatusMu.RLock()
	for _, status := range a.scanStatuses {
		if audit.NormalizeScanTaskType(status.Kind) == audit.NormalizeScanTaskType(kind) && (status.Status == "queued" || status.Status == "running") {
			a.scanStatusMu.RUnlock()
			return status, true
		}
	}
	a.scanStatusMu.RUnlock()
	if a.store == nil {
		return apiScanStatus{}, false
	}
	jobs, err := a.store.ListScanJobsFiltered(audit.ScanJobFilter{Kind: kind, Limit: 20})
	if err != nil {
		return apiScanStatus{}, false
	}
	for _, job := range jobs {
		if job.Status == "queued" || job.Status == "running" {
			return apiScanStatusFromAuditJob(job), true
		}
	}
	return apiScanStatus{}, false
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
	typeID := int64(0)
	if raw, supplied := req.Scope["agent_type_id"]; supplied {
		encoded, err := json.Marshal(raw)
		if err == nil {
			typeID, err = strconv.ParseInt(string(encoded), 10, 64)
		}
		if err != nil || typeID <= 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scope.agent_type_id must be a positive integer"})
			return
		}
		if _, ok, err := a.store.GetGovernanceAgentType(typeID); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		} else if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "AgentType not found"})
			return
		}
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
			AgentID: req.AgentID, AgentTypeID: typeID, SessionID: req.SessionID, TraceID: req.TraceID,
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
			if err := engine.EvaluateEventForJob(event.ID, jobID); err != nil {
				return err
			}
			a.updateAPIScanProgress(jobID, i+1, len(events), "evaluating", map[string]any{"events": len(events)})
		}
		return nil
	})
	a.writeJSON(w, http.StatusAccepted, status)
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// RunBackgroundJobs executes enabled durable scan schedules even when the
// desktop window is closed. Event-driven tasks remain owned by their native
// producers and therefore cannot be enabled as polling schedules.
func (a *APIServer) RunBackgroundJobs(ctx context.Context) {
	if a == nil || a.store == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastRun := map[string]time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			schedules, err := a.store.ListScanSchedules()
			if err != nil {
				continue
			}
			for _, schedule := range schedules {
				if !schedule.Enabled {
					continue
				}
				kind := audit.ScanJobKind(schedule.TaskType)
				interval := time.Duration(schedule.IntervalSec) * time.Second
				last := lastRun[schedule.TaskType]
				if last.IsZero() {
					if jobs, listErr := a.store.ListScanJobsFiltered(audit.ScanJobFilter{TaskType: schedule.TaskType, Trigger: "scheduler", Limit: 1}); listErr == nil && len(jobs) > 0 {
						last = parseTimeOrNow(jobs[0].CreatedAt)
						lastRun[schedule.TaskType] = last
					}
				}
				if !last.IsZero() && now.Sub(last) < interval {
					continue
				}
				a.scanStartMu.Lock()
				if a.hasRunningScanKind(kind) {
					a.scanStartMu.Unlock()
					continue
				}
				runner, ready := a.scheduledTaskRunner(schedule, kind)
				if !ready {
					a.scanStartMu.Unlock()
					continue
				}
				scope := schedule.Scope
				if scope == nil {
					scope = map[string]any{}
				}
				scope["interval_sec"] = schedule.IntervalSec
				key := "scheduler:" + schedule.TaskType + ":" + now.UTC().Truncate(interval).Format(time.RFC3339)
				a.startAPIScanWithOptions(kind, schedule.Mode, "", "", "scheduler", scope, key, runner)
				a.scanStartMu.Unlock()
				lastRun[schedule.TaskType] = now
			}
		}
	}
}

func (a *APIServer) scheduledTaskRunner(schedule audit.ScanSchedule, kind string) (func(context.Context, string) error, bool) {
	switch schedule.TaskType {
	case "agent_discovery":
		return func(ctx context.Context, _ string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			_, err := a.buildPageAgentInventory(2000)
			return err
		}, true
	case "static_assets":
		_, rescan := a.staticScanTriggers()
		if rescan == nil {
			return nil, false
		}
		agentID, _ := schedule.Scope["agent_id"].(string)
		return func(ctx context.Context, _ string) error {
			if !staticScanInFlight.CompareAndSwap(false, true) {
				return fmt.Errorf("another static resource scan is already running")
			}
			defer staticScanInFlight.Store(false)
			if err := ctx.Err(); err != nil {
				return err
			}
			return rescan(agentID)
		}, true
	case "runtime_detections":
		engine := activeDetectionEngine()
		if engine == nil {
			return nil, false
		}
		return func(ctx context.Context, jobID string) error {
			events, err := a.store.ListRuntimeEvents(audit.RuntimeEventFilter{IncludeDesktop: true, Limit: 50000})
			if err != nil {
				return err
			}
			a.updateAPIScanProgress(jobID, 0, len(events), "loaded", map[string]any{"events": len(events)})
			for index, event := range events {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := engine.EvaluateEventForJob(event.ID, jobID); err != nil {
					return err
				}
				a.updateAPIScanProgress(jobID, index+1, len(events), "evaluating", map[string]any{"events": len(events)})
			}
			return nil
		}, true
	case "attack_chains":
		engine := activeDetectionEngine()
		if engine == nil || engine.Policy() == nil {
			return nil, false
		}
		return func(ctx context.Context, jobID string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return engine.Policy().RebuildAttackChainsForJob(50000, jobID)
		}, true
	default:
		// Behavior trace is event-driven and environment collection is owned
		// by the native desktop host; neither is represented as a fake scan.
		return nil, false
	}
}

func (a *APIServer) hasRunningScanKind(kind string) bool {
	_, ok := a.runningScanStatusForKind(kind)
	return ok
}

func parseTimeOrNow(value string) time.Time {
	if parsed := parseAPITime(value); !parsed.IsZero() {
		return parsed
	}
	return time.Now().UTC()
}
