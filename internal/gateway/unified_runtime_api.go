package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/detection"
	"github.com/google/uuid"
)

type apiScanStatus struct {
	JobID           string         `json:"job_id"`
	ScanID          string         `json:"scan_id"`
	TaskType        string         `json:"task_type"`
	Kind            string         `json:"kind"`
	Type            string         `json:"type"`
	Mode            string         `json:"mode,omitempty"`
	AgentID         string         `json:"agent_id,omitempty"`
	ResourceID      string         `json:"resource_id,omitempty"`
	Trigger         string         `json:"trigger,omitempty"`
	Scope           map[string]any `json:"scope,omitempty"`
	Result          map[string]any `json:"result,omitempty"`
	Phase           string         `json:"phase,omitempty"`
	Current         int            `json:"current,omitempty"`
	Total           int            `json:"total,omitempty"`
	CancelRequested bool           `json:"cancel_requested,omitempty"`
	IdempotencyKey  string         `json:"idempotency_key,omitempty"`
	RuleVersion     string         `json:"rule_version,omitempty"`
	Status          string         `json:"status"`
	Progress        int            `json:"progress"`
	StartedAt       string         `json:"started_at"`
	FinishedAt      string         `json:"finished_at,omitempty"`
	Error           string         `json:"error,omitempty"`
}

type agentsListResponse struct {
	CapturedAt string          `json:"capturedAt"`
	Source     string          `json:"source"`
	Agents     []agentListItem `json:"agents"`
	Items      []agentListItem `json:"items"`
	Total      int             `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	PageSizeUI int             `json:"pageSize"`
	Summary    agentSummary    `json:"summary"`
	Warning    string          `json:"warning,omitempty"`
}

type agentListItem struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	Vendor                  string   `json:"vendor"`
	PrimaryPath             string   `json:"primaryPath"`
	RuntimeStatus           string   `json:"runtimeStatus"`
	PIDs                    []uint32 `json:"pids"`
	Kind                    string   `json:"kind"`
	Version                 string   `json:"version"`
	DiscoveryStatus         string   `json:"discoveryStatus"`
	FirstSeenScanAt         string   `json:"firstSeenScanAt,omitempty"`
	LastSeenScanAt          string   `json:"lastSeenScanAt,omitempty"`
	RuntimeDetectionCount   int      `json:"runtimeDetectionCount,omitempty"`
	RuntimeAttackCount      int      `json:"runtimeAttackCount,omitempty"`
	RuntimeBlockedCount     int      `json:"runtimeBlockedCount,omitempty"`
	RuntimeHighOrAboveCount int      `json:"runtimeHighOrAboveCount,omitempty"`
}

type agentSummary struct {
	TotalAgents     int    `json:"total_agents"`
	RunningAgents   int    `json:"running_agents"`
	StoppedAgents   int    `json:"stopped_agents"`
	RiskAgents      int    `json:"risk_agents"`
	CriticalAgents  int    `json:"critical_agents"`
	LastDiscoveryAt string `json:"last_discovery_at,omitempty"`
}

func (a *APIServer) handleAgentsAPI(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/agents"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleAgentsList(w, r)
		return
	}
	if rest == "summary" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleAgentsSummary(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	agentID, err := url.PathUnescape(parts[0])
	if err != nil || strings.TrimSpace(agentID) == "" || strings.ContainsAny(agentID, `/\`) {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.handleAgentDetail(w, r, agentID)
		return
	}
	if len(parts) == 3 && parts[1] == "static-resources" {
		switch parts[2] {
		case "summary":
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			a.handleAgentStaticResourceSummary(w, r, agentID)
			return
		case "scan":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			a.handleAgentStaticResourceScan(w, r, agentID)
			return
		}
	}
	http.NotFound(w, r)
}

func (a *APIServer) handleAgentsList(w http.ResponseWriter, r *http.Request) {
	snap, err := a.buildPageAgentInventoryReadOnly(pageLimit(r, 5000, 50, 5000))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	agents := a.enrichAgentsRuntimeSecurity(snap.Agents)
	filtered := filterAgentsForRequest(agents, r)
	page, pageSize := requestPage(r, 1, 5000, 5000)
	total := len(filtered)
	filtered = paginateAgents(filtered, page, pageSize)
	items := compactAgentListItems(filtered)
	a.writeJSON(w, http.StatusOK, agentsListResponse{
		CapturedAt: snap.CapturedAt,
		Source:     "agents",
		Agents:     items,
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		PageSizeUI: pageSize,
		Summary:    summarizeAgents(agents, snap.CapturedAt),
		Warning:    snap.Warning,
	})
}

func (a *APIServer) handleAgentsSummary(w http.ResponseWriter, r *http.Request) {
	snap, err := a.buildPageAgentInventoryReadOnly(pageLimit(r, 5000, 50, 5000))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	agents := a.enrichAgentsRuntimeSecurity(snap.Agents)
	a.writeJSON(w, http.StatusOK, summarizeAgents(agents, snap.CapturedAt))
}

func (a *APIServer) handleAgentDetail(w http.ResponseWriter, r *http.Request, agentID string) {
	snap, err := a.buildPageAgentInventoryReadOnly(pageLimit(r, 5000, 50, 5000))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	agents := a.enrichAgentsRuntimeSecurity(snap.Agents)
	for _, agent := range agents {
		if agent.ID == agentID {
			a.writeJSON(w, http.StatusOK, agent)
			return
		}
	}
	a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
}

func (a *APIServer) handleAgentStaticResourceSummary(w http.ResponseWriter, r *http.Request, agentID string) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	summary, err := a.store.GetAgentResourceTypeSummary(agentID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if summary == nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, summary)
}

func (a *APIServer) handleAgentStaticResourceScan(w http.ResponseWriter, r *http.Request, agentID string) {
	idempotencyKey := requestIdempotencyKey(r)
	if r.Body != nil {
		var body struct {
			IdempotencyKey string `json:"idempotency_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		if idempotencyKey == "" {
			idempotencyKey = strings.TrimSpace(body.IdempotencyKey)
		}
	}
	if status, ok := a.existingScanStatusForKey(idempotencyKey); ok {
		a.writeJSON(w, http.StatusAccepted, status)
		return
	}
	_, rescan := a.staticScanTriggers()
	if rescan == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "watcher scan pipeline unavailable"})
		return
	}
	if !staticScanInFlight.CompareAndSwap(false, true) {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": "another manual scan is already running"})
		return
	}
	status := a.startAPIScanWithOptions("resource_scan", "agent", agentID, "", "manual", map[string]any{"agent_id": agentID}, idempotencyKey, func(ctx context.Context, _ string) error {
		defer staticScanInFlight.Store(false)
		if err := ctx.Err(); err != nil {
			return err
		}
		return rescan(agentID)
	})
	if status.Status == "failed" {
		staticScanInFlight.Store(false)
	}
	a.writeJSON(w, http.StatusAccepted, status)
}

func (a *APIServer) handleAgentScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Mode           string `json:"mode"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
	}
	mode := strings.TrimSpace(body.Mode)
	if mode == "" {
		mode = "full"
	}
	idempotencyKey := requestIdempotencyKey(r)
	if idempotencyKey == "" {
		idempotencyKey = strings.TrimSpace(body.IdempotencyKey)
	}
	if status, ok := a.existingScanStatusForKey(idempotencyKey); ok {
		a.writeJSON(w, http.StatusAccepted, status)
		return
	}
	status := a.startAPIScanWithOptions("agent_discovery", mode, "", "", "manual", nil, idempotencyKey, func(ctx context.Context, _ string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := a.buildPageAgentInventory(2000)
		return err
	})
	a.writeJSON(w, http.StatusAccepted, status)
}

func (a *APIServer) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scanID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/scans/"), "/")
	if scanID == "" || strings.ContainsAny(scanID, `/\`) {
		http.NotFound(w, r)
		return
	}
	status, ok := a.lookupAPIScan(scanID)
	if !ok {
		if a.store != nil {
			if job, found, err := a.store.GetScanJob(scanID); err == nil && found {
				a.writeJSON(w, http.StatusOK, job)
				return
			}
		}
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, status)
}

func (a *APIServer) startAPIScan(kind, mode, agentID, resourceID string, run func() error) apiScanStatus {
	return a.startAPIScanWithOptions(kind, mode, agentID, resourceID, "manual", nil, "", func(context.Context, string) error {
		return run()
	})
}

func (a *APIServer) startAPIScanWithOptions(kind, mode, agentID, resourceID, trigger string, scope map[string]any, idempotencyKey string, run func(context.Context, string) error) apiScanStatus {
	if a.store != nil && strings.TrimSpace(idempotencyKey) != "" {
		if existing, found, err := a.store.FindScanJobByIdempotencyKey(idempotencyKey); err == nil && found {
			status := apiScanStatusFromAuditJob(existing)
			a.storeAPIScan(status)
			return status
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := apiScanStatus{
		JobID:    "scan_" + strings.ReplaceAll(kind, "-", "_") + "_" + uuid.NewString()[:8],
		TaskType: audit.NormalizeScanTaskType(kind), Kind: kind, Trigger: audit.NormalizeScanTrigger(trigger), Scope: scope,
		Mode: mode, AgentID: agentID, ResourceID: resourceID,
		Status: "queued", Progress: 0, StartedAt: now, IdempotencyKey: strings.TrimSpace(idempotencyKey),
	}
	status.ScanID = status.JobID
	status.Type = status.Kind
	if kind == "event_replay" || kind == "attack_chain_rebuild" {
		status.RuleVersion = detection.RuleVersion
	}
	if err := a.storeAPIScan(status); err != nil {
		if strings.TrimSpace(idempotencyKey) != "" && a.store != nil {
			if existing, found, lookupErr := a.store.FindScanJobByIdempotencyKey(idempotencyKey); lookupErr == nil && found {
				existingStatus := apiScanStatusFromAuditJob(existing)
				a.storeAPIScan(existingStatus)
				return existingStatus
			}
		}
		status.Status = "failed"
		status.Error = "persist scan job: " + err.Error()
		status.FinishedAt = nowRFC3339()
		_ = a.storeAPIScan(status)
		return status
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.scanCancelMu.Lock()
	if a.scanCancels == nil {
		a.scanCancels = map[string]context.CancelFunc{}
	}
	a.scanCancels[status.JobID] = cancel
	a.scanCancelMu.Unlock()
	go func() {
		defer func() {
			a.scanCancelMu.Lock()
			delete(a.scanCancels, status.JobID)
			a.scanCancelMu.Unlock()
			cancel()
		}()
		next := status
		next.Status = "running"
		next.Phase = "running"
		_ = a.storeAPIScan(next)
		err := run(ctx, status.JobID)
		if ctx.Err() != nil {
			err = context.Canceled
		}
		if a.store != nil {
			if current, ok, loadErr := a.store.GetScanJob(status.JobID); loadErr == nil && ok && (current.Status == "cancelled" || current.CancelRequested) {
				return
			}
		}
		if err != nil {
			next.Status = "failed"
			next.Error = err.Error()
			if errors.Is(err, context.Canceled) {
				next.Status = "cancelled"
			}
		} else {
			next.Status = "completed"
			next.Progress = 100
			next.Current = next.Total
			next.Phase = "completed"
		}
		next.FinishedAt = nowRFC3339()
		_ = a.storeAPIScan(next)
	}()
	return status
}

func apiScanStatusFromAuditJob(job audit.ScanJob) apiScanStatus {
	jobID := firstNonEmpty(job.JobID, job.ScanID)
	kind := firstNonEmpty(job.Kind, job.Type)
	return apiScanStatus{JobID: jobID, ScanID: jobID, TaskType: firstNonEmpty(job.TaskType, audit.NormalizeScanTaskType(kind)), Kind: kind, Type: kind, Mode: job.Mode, AgentID: job.AgentID, ResourceID: job.ResourceID, Trigger: job.Trigger, Scope: job.Scope, Result: job.Result, Phase: job.Phase, Current: job.Current, Total: job.Total, CancelRequested: job.CancelRequested, IdempotencyKey: job.IdempotencyKey, RuleVersion: job.RuleVersion, Status: job.Status, Progress: job.Progress, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt, Error: job.Error}
}

func (a *APIServer) storeAPIScan(status apiScanStatus) error {
	if status.JobID == "" {
		status.JobID = status.ScanID
	}
	if status.ScanID == "" {
		status.ScanID = status.JobID
	}
	if status.Kind == "" {
		status.Kind = status.Type
	}
	if status.Type == "" {
		status.Type = status.Kind
	}
	if status.TaskType == "" {
		status.TaskType = audit.NormalizeScanTaskType(status.Kind)
	}
	a.scanStatusMu.Lock()
	if a.scanStatuses == nil {
		a.scanStatuses = map[string]apiScanStatus{}
	}
	a.scanStatuses[status.ScanID] = status
	a.scanStatusMu.Unlock()

	if a.store == nil {
		return nil
	}
	job := audit.ScanJob{
		JobID: status.JobID, TaskType: status.TaskType, Kind: status.Kind, Mode: status.Mode,
		AgentID: status.AgentID, ResourceID: status.ResourceID,
		Trigger: status.Trigger, Scope: status.Scope, Result: status.Result, Phase: status.Phase,
		Current: status.Current, Total: status.Total, CancelRequested: status.CancelRequested, IdempotencyKey: status.IdempotencyKey,
		RuleVersion: status.RuleVersion,
		Status:      status.Status, Progress: status.Progress,
		StartedAt: status.StartedAt, FinishedAt: status.FinishedAt,
		Error: status.Error,
	}
	if existing, ok, err := a.store.GetScanJob(status.ScanID); err == nil && ok {
		job.CreatedAt = existing.CreatedAt
		return a.store.UpdateScanJob(job)
	}
	return a.store.CreateScanJob(job)
}

func (a *APIServer) updateAPIScanProgress(jobID string, current, total int, phase string, result map[string]any) {
	status, ok := a.lookupAPIScan(jobID)
	if !ok {
		if a.store == nil {
			return
		}
		job, found, err := a.store.GetScanJob(jobID)
		if err != nil || !found {
			return
		}
		status = apiScanStatusFromAuditJob(job)
	}
	if current < 0 {
		current = 0
	}
	if total < 0 {
		total = 0
	}
	if total > 0 && current > total {
		current = total
	}
	status.Current, status.Total, status.Phase, status.Result = current, total, phase, result
	if total > 0 {
		status.Progress = current * 100 / total
	}
	_ = a.storeAPIScan(status)
}

func (a *APIServer) lookupAPIScan(scanID string) (apiScanStatus, bool) {
	a.scanStatusMu.RLock()
	defer a.scanStatusMu.RUnlock()
	status, ok := a.scanStatuses[scanID]
	return status, ok
}

func (a *APIServer) enrichAgentsRuntimeSecurity(agents []pageAgent) []pageAgent {
	if a.store == nil {
		return agents
	}
	rows, err := a.store.ListRuntimeSecurityAgents(5000)
	if err != nil || len(rows) == 0 {
		return agents
	}
	byID := map[string]audit.RuntimeSecurityAgent{}
	for _, row := range rows {
		byID[row.AgentID] = row
	}
	for i := range agents {
		row, ok := byID[agents[i].ID]
		if !ok {
			continue
		}
		agents[i].RuntimeDetectionCount = row.DetectionCount
		agents[i].RuntimeAttackCount = row.AttackCount
		agents[i].RuntimeBlockedCount = row.BlockedCount
		agents[i].RuntimeHighOrAboveCount = row.HighOrAboveCount
		if row.LatestAt != "" {
			agents[i].RuntimeLatestAt = &row.LatestAt
		}
		delete(byID, agents[i].ID)
	}
	for _, row := range byID {
		if strings.TrimSpace(row.AgentID) == "" {
			continue
		}
		latest := row.LatestAt
		var latestAt *string
		if latest != "" {
			latestAt = &latest
		}
		status := row.RuntimeStatus
		if status == "" {
			status = "observed"
		}
		runtimeStatus := pageNormalizeRuntimeStatus(status)
		if runtimeStatus == "" {
			runtimeStatus = "unknown"
		}
		name := row.AgentName
		if name == "" {
			name = row.AgentID
		}
		kind := row.AgentType
		if kind == "" {
			kind = "Agent"
		}
		agents = append(agents, pageAgent{
			ID:                      row.AgentID,
			Product:                 name,
			Kind:                    kind,
			InventoryState:          "runtime_observed",
			Status:                  runtimeStatus,
			RuntimeStatus:           runtimeStatus,
			Running:                 false,
			PIDs:                    []uint32{},
			ExecutableNames:         []string{},
			ConfigRoots:             []pageConfigRoot{},
			Source:                  "runtime-detections",
			DiscoveryStatus:         "runtime_observed",
			PrimaryPath:             "runtime-detections",
			FirstSeenScanAt:         latestAt,
			LastSeenScanAt:          latestAt,
			RuntimeDetectionCount:   row.DetectionCount,
			RuntimeAttackCount:      row.AttackCount,
			RuntimeBlockedCount:     row.BlockedCount,
			RuntimeHighOrAboveCount: row.HighOrAboveCount,
			RuntimeLatestAt:         latestAt,
			Description:             "Observed from runtime detection events.",
		})
	}
	return agents
}

func filterAgentsForRequest(agents []pageAgent, r *http.Request) []pageAgent {
	q := r.URL.Query()
	keyword := strings.ToLower(strings.TrimSpace(firstNonEmptyQuery(q, "query", "keyword")))
	status := strings.ToLower(strings.TrimSpace(firstNonEmptyQuery(q, "runtimeStatus", "runtime_status", "status")))
	agentType := strings.ToLower(strings.TrimSpace(q.Get("agent_type")))
	riskLevel := strings.ToLower(strings.TrimSpace(q.Get("risk_level")))
	out := make([]pageAgent, 0, len(agents))
	for _, agent := range agents {
		if status != "" && status != "all" && strings.ToLower(agent.RuntimeStatus) != status {
			continue
		}
		if agentType != "" && agentType != "all" && !agentMatchesType(agent, agentType) {
			continue
		}
		if riskLevel != "" && riskLevel != "all" && agentRiskLevel(agent) != riskLevel {
			continue
		}
		if keyword != "" && !agentMatchesKeyword(agent, keyword) {
			continue
		}
		out = append(out, agent)
	}
	sortAgents(out, firstNonEmptyQuery(q, "sort", "orderBy"))
	return out
}

func compactAgentListItems(agents []pageAgent) []agentListItem {
	out := make([]agentListItem, 0, len(agents))
	for _, agent := range agents {
		out = append(out, compactAgentListItem(agent))
	}
	return out
}

func compactAgentListItem(agent pageAgent) agentListItem {
	firstSeen := agentFirstSeen(agent)
	lastSeen := agentLastSeen(agent)
	return agentListItem{
		ID:                      agent.ID,
		Name:                    pageFirstNonEmpty(agent.Product, agent.ID),
		Vendor:                  pageFirstNonEmpty(agent.Vendor, "Unknown"),
		PrimaryPath:             pageFirstNonEmpty(agent.PrimaryPath, firstConfigRootPath(agent.ConfigRoots), firstAgentString(agent.InstallPaths), agent.Source, "-"),
		RuntimeStatus:           pageFirstNonEmpty(pageNormalizeRuntimeStatus(agent.RuntimeStatus), pageNormalizeRuntimeStatus(agent.Status), "unknown"),
		PIDs:                    pageNormalizePIDs(agent.PIDs),
		Kind:                    pageFirstNonEmpty(agent.Kind, "agent"),
		Version:                 strings.TrimSpace(agent.Version),
		DiscoveryStatus:         pageFirstNonEmpty(agent.DiscoveryStatus, agent.InventoryState, "discovered"),
		FirstSeenScanAt:         firstSeen,
		LastSeenScanAt:          lastSeen,
		RuntimeDetectionCount:   agent.RuntimeDetectionCount,
		RuntimeAttackCount:      agent.RuntimeAttackCount,
		RuntimeBlockedCount:     agent.RuntimeBlockedCount,
		RuntimeHighOrAboveCount: agent.RuntimeHighOrAboveCount,
	}
}

func firstNonEmptyQuery(q url.Values, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(q.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

func agentMatchesType(agent pageAgent, value string) bool {
	haystack := strings.ToLower(strings.Join([]string{
		agent.Kind,
		agent.Product,
		agent.Description,
		agent.Source,
	}, " "))
	return strings.Contains(haystack, value)
}

func agentMatchesKeyword(agent pageAgent, keyword string) bool {
	values := []string{
		agent.ID,
		agent.Product,
		agent.Vendor,
		agent.Kind,
		agent.RuntimeStatus,
		agent.DiscoveryStatus,
		agent.Version,
		agent.Description,
		agent.Source,
		agent.PrimaryPath,
		strings.Join(agent.ExecutableNames, " "),
	}
	for _, root := range agent.ConfigRoots {
		values = append(values, root.Path, root.Kind)
	}
	for _, path := range agent.InstallPaths {
		values = append(values, path)
	}
	return strings.Contains(strings.ToLower(strings.Join(values, " ")), keyword)
}

func agentRiskLevel(agent pageAgent) string {
	switch {
	case agent.CriticalResourceCount > 0:
		return "critical"
	case agent.RiskResourceCount >= 5:
		return "high"
	case agent.RiskResourceCount > 0:
		return "medium"
	default:
		return "safe"
	}
}

func sortAgents(agents []pageAgent, sortValue string) {
	switch strings.ToLower(strings.TrimSpace(sortValue)) {
	case "risk", "risk:desc":
		sort.SliceStable(agents, func(i, j int) bool {
			return agentRiskRank(agents[i]) > agentRiskRank(agents[j])
		})
	case "status", "status:desc":
		sort.SliceStable(agents, func(i, j int) bool {
			left := pageNormalizeRuntimeStatus(agents[i].RuntimeStatus)
			right := pageNormalizeRuntimeStatus(agents[j].RuntimeStatus)
			if left != right {
				return runtimeStatusRank(left) > runtimeStatusRank(right)
			}
			return agents[i].Product < agents[j].Product
		})
	case "runtime_status", "runtimestatus", "runtime_status:desc", "runtimestatus:desc":
		sort.SliceStable(agents, func(i, j int) bool {
			left := pageNormalizeRuntimeStatus(agents[i].RuntimeStatus)
			right := pageNormalizeRuntimeStatus(agents[j].RuntimeStatus)
			if left != right {
				return runtimeStatusRank(left) > runtimeStatusRank(right)
			}
			return agents[i].Product < agents[j].Product
		})
	case "runtime_status:asc", "runtimestatus:asc":
		sort.SliceStable(agents, func(i, j int) bool {
			left := pageNormalizeRuntimeStatus(agents[i].RuntimeStatus)
			right := pageNormalizeRuntimeStatus(agents[j].RuntimeStatus)
			if left != right {
				return runtimeStatusRank(left) < runtimeStatusRank(right)
			}
			return agents[i].Product < agents[j].Product
		})
	case "resources", "resources:desc":
		sort.SliceStable(agents, func(i, j int) bool {
			return agents[i].StaticResourceCount > agents[j].StaticResourceCount
		})
	case "latest", "latest:desc", "last_seen_at", "last_seen_at:desc", "last_seen_scan_at", "last_seen_scan_at:desc", "lastseenscanat", "lastseenscanat:desc":
		sort.SliceStable(agents, func(i, j int) bool {
			return agentLastSeen(agents[i]) > agentLastSeen(agents[j])
		})
	case "latest:asc", "last_seen_at:asc", "last_seen_scan_at:asc", "lastseenscanat:asc":
		sort.SliceStable(agents, func(i, j int) bool {
			return agentLastSeen(agents[i]) < agentLastSeen(agents[j])
		})
	case "first_seen_at", "first_seen_at:asc", "first_seen_scan_at", "first_seen_scan_at:asc", "firstseenscanat", "firstseenscanat:asc":
		sort.SliceStable(agents, func(i, j int) bool {
			return agentFirstSeen(agents[i]) < agentFirstSeen(agents[j])
		})
	case "first_seen_at:desc", "first_seen_scan_at:desc", "firstseenscanat:desc":
		sort.SliceStable(agents, func(i, j int) bool {
			return agentFirstSeen(agents[i]) > agentFirstSeen(agents[j])
		})
	default:
		sort.SliceStable(agents, func(i, j int) bool {
			return strings.ToLower(agents[i].Product) < strings.ToLower(agents[j].Product)
		})
	}
}

func agentRiskRank(agent pageAgent) int {
	switch agentRiskLevel(agent) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func runtimeStatusRank(status string) int {
	switch pageNormalizeRuntimeStatus(status) {
	case "running":
		return 3
	case "stopped":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

func agentFirstSeen(agent pageAgent) string {
	switch {
	case agent.FirstSeenScanAt != nil:
		return *agent.FirstSeenScanAt
	case agent.StartedAt != nil:
		return *agent.StartedAt
	default:
		return ""
	}
}

func agentLastSeen(agent pageAgent) string {
	switch {
	case agent.LastSeenScanAt != nil:
		return *agent.LastSeenScanAt
	case agent.RuntimeLatestAt != nil:
		return *agent.RuntimeLatestAt
	case agent.LastStaticScanAt != nil:
		return *agent.LastStaticScanAt
	case agent.StartedAt != nil:
		return *agent.StartedAt
	default:
		return ""
	}
}

func firstConfigRootPath(roots []pageConfigRoot) string {
	for _, root := range roots {
		if strings.TrimSpace(root.Path) != "" {
			return root.Path
		}
	}
	return ""
}

func firstAgentString(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func paginateAgents(agents []pageAgent, page, pageSize int) []pageAgent {
	start := (page - 1) * pageSize
	if start >= len(agents) {
		return []pageAgent{}
	}
	end := start + pageSize
	if end > len(agents) {
		end = len(agents)
	}
	return agents[start:end]
}

func summarizeAgents(agents []pageAgent, fallbackLatest string) agentSummary {
	var out agentSummary
	latest := fallbackLatest
	for _, agent := range agents {
		out.TotalAgents++
		if agent.Running {
			out.RunningAgents++
		} else {
			out.StoppedAgents++
		}
		if agent.RiskResourceCount > 0 {
			out.RiskAgents++
		}
		if agent.CriticalResourceCount > 0 {
			out.CriticalAgents++
		}
		if seen := agentLastSeen(agent); seen > latest {
			latest = seen
		}
	}
	out.LastDiscoveryAt = latest
	return out
}

func requestPage(r *http.Request, defaultPage, defaultPageSize, maxPageSize int) (int, int) {
	q := r.URL.Query()
	page := defaultPage
	if v := strings.TrimSpace(q.Get("page")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			page = parsed
		}
	}
	pageSize := defaultPageSize
	if v := strings.TrimSpace(q.Get("page_size")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			pageSize = parsed
		}
	} else if v := strings.TrimSpace(q.Get("pageSize")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			pageSize = parsed
		}
	} else if v := strings.TrimSpace(q.Get("pagesize")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			pageSize = parsed
		}
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

func parseAPITime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed.UTC()
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC()
	}
	return time.Time{}
}

// requestAgentTypeID accepts the spelling used by the desktop contract and
// the two common JSON/API spellings. A non-positive or malformed value means
// "all types", preserving the gateway's existing tolerant query semantics.
func requestAgentTypeID(r *http.Request) int64 {
	q := r.URL.Query()
	raw := firstNonEmpty(q.Get("AgenttypeId"), q.Get("AgentTypeId"), q.Get("agent_type_id"), q.Get("agentTypeId"), q.Get("agentTypeID"))
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || value <= 0 {
		return 0
	}
	return value
}

func (a *APIServer) handleRuntimeEventDetail(w http.ResponseWriter, r *http.Request, rawID string) {
	rawID, err := url.PathUnescape(strings.TrimSpace(rawID))
	if err != nil || rawID == "" || strings.ContainsAny(rawID, `/\`) {
		http.NotFound(w, r)
		return
	}
	eventID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || eventID <= 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "runtime event id must be a positive integer"})
		return
	}
	event, ok, err := a.store.GetRuntimeEvent(eventID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "runtime event not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, event)
}

type runtimeEnforcementRow struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"`
	Target            string `json:"target,omitempty"`
	Host              string `json:"host,omitempty"`
	DecisionID        string `json:"decision_id,omitempty"`
	ResponseID        string `json:"response_id,omitempty"`
	ActionType        string `json:"action_type,omitempty"`
	Executor          string `json:"executor,omitempty"`
	Status            string `json:"status"`
	Reason            string `json:"reason,omitempty"`
	Source            string `json:"source,omitempty"`
	Result            string `json:"result,omitempty"`
	RollbackSupported bool   `json:"rollback_supported"`
	AddedAt           string `json:"added_at,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
}

func (a *APIServer) handleRuntimeEnforcements(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/enforcements"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rows, err := a.runtimeEnforcementRows()
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows)})
		return
	}
	parts := strings.Split(rest, "/")
	enforcementID, err := url.PathUnescape(parts[0])
	if err != nil || enforcementID == "" || strings.ContainsAny(enforcementID, `/\`) {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "rollback" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		a.rollbackRuntimeEnforcement(w, r, enforcementID)
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := a.runtimeEnforcementRows()
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for _, row := range rows {
			if row.ID == enforcementID || row.Host == enforcementID || row.DecisionID == enforcementID {
				a.writeJSON(w, http.StatusOK, row)
				return
			}
		}
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "enforcement not found"})
	case http.MethodDelete:
		blocklist := activeRuntimeBlocklist()
		networkRemoved := 0
		actionRemoved := 0
		matchedResponses := map[string]bool{}
		for _, row := range runtimeNetworkEnforcements() {
			if row.ID == enforcementID || row.Host == enforcementID || row.DecisionID == enforcementID {
				if blocklist != nil {
					blocklist.Remove(row.Host)
				}
				if row.ResponseID != "" {
					matchedResponses[row.ResponseID] = true
				}
				networkRemoved++
			}
		}
		if a.store != nil {
			actions, _ := a.store.ListResponseActionsAll(500, 0)
			for _, action := range actions {
				if action.ResponseID == "" || action.Status == audit.ResponseStatusRolledBack {
					continue
				}
				matches := matchedResponses[action.ResponseID] || action.ResponseID == enforcementID || action.DecisionID == enforcementID
				if !matches && action.Executor == "proxy" {
					matches = responseTargetMatches(action.Target, enforcementID)
				}
				if matches && (action.RollbackSupported || action.Executor == "proxy") {
					_ = a.store.UpdateResponseActionStatus(action.ResponseID, audit.ResponseStatusRolledBack, "removed by operator")
					actionRemoved++
					matchedResponses[action.ResponseID] = true
				}
			}
		}
		removed := networkRemoved
		if actionRemoved > 0 {
			removed = actionRemoved
		}
		if removed == 0 {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "enforcement not found"})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "removed": removed})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) rollbackRuntimeEnforcement(w http.ResponseWriter, _ *http.Request, enforcementID string) {
	blocklist := activeRuntimeBlocklist()
	removed := 0
	if blocklist != nil {
		for _, row := range runtimeNetworkEnforcements() {
			if row.ID == enforcementID || row.Host == enforcementID || row.DecisionID == enforcementID {
				blocklist.Remove(row.Host)
				if row.DecisionID != "" {
					removed++
				}
			}
		}
	}
	if a.store != nil {
		actions, _ := a.store.ListResponseActionsAll(500, 0)
		for _, action := range actions {
			if action.ResponseID == enforcementID || action.DecisionID == enforcementID || (action.Executor == "proxy" && responseTargetMatches(action.Target, enforcementID)) {
				if !action.RollbackSupported && action.Executor != "proxy" {
					continue
				}
				_ = a.store.UpdateResponseActionStatus(action.ResponseID, audit.ResponseStatusRolledBack, "rolled back by operator")
				removed++
			}
		}
	}
	if removed == 0 {
		a.writeJSON(w, http.StatusConflict, map[string]any{"status": "rollback_unsupported", "rollback_supported": false})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"status": audit.ResponseStatusRolledBack, "removed": removed, "rollback_supported": true})
}

func responseTargetMatches(target, enforcementID string) bool {
	target = strings.TrimSpace(target)
	enforcementID = strings.TrimSpace(enforcementID)
	if target == "" || enforcementID == "" {
		return false
	}
	for _, value := range strings.Split(target, ",") {
		if strings.EqualFold(strings.TrimSpace(value), enforcementID) {
			return true
		}
	}
	return false
}

func (a *APIServer) runtimeEnforcementRows() ([]runtimeEnforcementRow, error) {
	rows := runtimeNetworkEnforcements()
	if a.store == nil {
		return rows, nil
	}
	actions, err := a.store.ListResponseActionsAll(500, 0)
	if err != nil {
		return nil, err
	}
	for _, action := range actions {
		if action.Status == audit.ResponseStatusRolledBack || action.Status == audit.ResponseStatusWouldBlock || action.Status == audit.ResponseStatusFailed {
			continue
		}
		if action.Executor == "proxy" && action.Status == audit.ResponseStatusExecuted {
			// The live blocklist row is the canonical active projection for a
			// network action; do not render the same action twice.
			duplicate := false
			for _, network := range rows {
				if network.DecisionID == action.DecisionID && responseTargetMatches(action.Target, network.Host) {
					duplicate = true
					break
				}
			}
			if duplicate {
				for i := range rows {
					if rows[i].DecisionID == action.DecisionID && rows[i].Host != "" {
						rows[i].ResponseID = action.ResponseID
						rows[i].ActionType = action.ActionType
						rows[i].Executor = action.Executor
						rows[i].Result = action.Result
						rows[i].RollbackSupported = action.RollbackSupported
					}
				}
				continue
			}
		}
		rows = append(rows, runtimeEnforcementRow{
			ID: action.ResponseID, Kind: "runtime_response", Target: action.Target,
			DecisionID: action.DecisionID, ResponseID: action.ResponseID,
			ActionType: action.ActionType, Executor: action.Executor,
			Status: action.Status, Result: action.Result,
			RollbackSupported: action.RollbackSupported,
			AddedAt:           action.ExecutedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows, nil
}

func runtimeNetworkEnforcements() []runtimeEnforcementRow {
	blocklist := activeRuntimeBlocklist()
	if blocklist == nil {
		return []runtimeEnforcementRow{}
	}
	entries := blocklist.Entries()
	rows := make([]runtimeEnforcementRow, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, runtimeEnforcementRow{
			ID:         entry.Host,
			Kind:       "network_block",
			Target:     entry.Host,
			Host:       entry.Host,
			DecisionID: entry.DecisionID,
			Status:     "active",
			AddedAt:    entry.AddedAt.UTC().Format(time.RFC3339Nano),
			ExpiresAt:  entry.ExpiresAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return rows
}

func (a *APIServer) handleRuntimeDetectionBlockAction(w http.ResponseWriter, r *http.Request, detectionID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ActionType     string `json:"action_type"`
		Reason         string `json:"reason"`
		Preview        bool   `json:"preview"`
		DryRun         bool   `json:"dry_run"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	d, evidence, err := a.store.GetRuntimeDetectionDetail(detectionID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if d.DetectionID == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "detection not found"})
		return
	}
	point, actionType, err := manualActionPlan(body.ActionType, d.DetectionType)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "manual_operator_action"
	}
	idempotencyKey := strings.TrimSpace(body.IdempotencyKey)
	if headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key")); headerKey != "" {
		idempotencyKey = headerKey
	}
	if len(idempotencyKey) > 200 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key must be at most 200 characters"})
		return
	}
	if body.Preview || body.DryRun {
		target := strings.Join(runtimeEvidenceHosts(evidence), ", ")
		if target == "" {
			var values []string
			for _, row := range evidence {
				if row.Event.ActorPID > 0 {
					values = append(values, strconv.FormatUint(uint64(row.Event.ActorPID), 10))
				}
				if row.Event.AgentPID > 0 {
					values = append(values, strconv.FormatUint(uint64(row.Event.AgentPID), 10))
				}
			}
			target = strings.Join(values, ", ")
		}
		a.writeJSON(w, http.StatusOK, map[string]any{
			"status":   audit.ResponseStatusPlanned,
			"plan":     map[string]any{"enforcement_point": point, "action_type": actionType, "target": target, "reason": reason, "side_effects": []string{"写入决策审计记录", "在确认后调用对应执行器"}},
			"decision": map[string]any{"detection_id": d.DetectionID, "decision": audit.RuntimeDecisionBlock, "enforcement_point": point, "idempotency_key": idempotencyKey},
		})
		return
	}
	decision, _, err := a.store.RecordRuntimeDecision(audit.RuntimeDecisionInput{
		DetectionID:      d.DetectionID,
		AgentID:          d.AgentID,
		AgentName:        d.AgentName,
		SessionID:        d.SessionID,
		TraceID:          d.TraceID,
		Decision:         audit.RuntimeDecisionBlock,
		RiskScore:        detection.RiskScore(d.Severity, d.Category, d.Confidence),
		Confidence:       d.Confidence,
		PolicyID:         "manual-operator-action",
		Reason:           reason,
		EnforcementPoint: point,
		Mode:             audit.RuntimeSecurityModeAction,
		WouldBlock:       false,
		IdempotencyKey:   idempotencyKey,
		Source:           "manual",
		PolicyVersion:    "manual-operator-v1",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if decision.DecisionID != "" {
		if full, _, err := a.store.GetRuntimeDecisionDetail(decision.DecisionID); err == nil && full.DecisionID != "" {
			decision = full
		}
	}
	if idempotencyKey != "" {
		if _, responses, detailErr := a.store.GetRuntimeDecisionDetail(decision.DecisionID); detailErr == nil && len(responses) > 0 {
			status := runtimeResponseStatus(responses)
			a.writeJSON(w, http.StatusOK, map[string]any{"status": runtimeEnforcementHTTPStatus(status), "decision": decision, "responses": responses, "idempotent_replay": true})
			return
		}
	}
	responses, err := a.executeRuntimeDecisionResponse(decision, actionType, evidence, true)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	responseStatus := runtimeResponseStatus(responses)
	if responseStatus == audit.ResponseStatusExecuted {
		_ = a.store.UpdateRuntimeDetectionStatus(detectionID, audit.RuntimeDetectionStatusMitigated)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"status":    runtimeEnforcementHTTPStatus(responseStatus),
		"decision":  decision,
		"responses": responses,
	})
}

func (a *APIServer) handleRuntimeDecisionEnforce(w http.ResponseWriter, r *http.Request, decisionID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	decision, _, err := a.store.GetRuntimeDecisionDetail(decisionID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if decision.DecisionID == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "decision not found"})
		return
	}
	if decision.Decision != audit.RuntimeDecisionBlock {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only BLOCK decisions can be enforced"})
		return
	}
	var body struct {
		IdempotencyKey string `json:"idempotency_key"`
		Preview        bool   `json:"preview"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	idempotencyKey := strings.TrimSpace(body.IdempotencyKey)
	if headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key")); headerKey != "" {
		idempotencyKey = headerKey
	}
	if body.Preview {
		_, evidence, _ := a.store.GetRuntimeDetectionDetail(decision.DetectionID)
		a.writeJSON(w, http.StatusOK, map[string]any{"status": audit.ResponseStatusPlanned, "plan": map[string]any{"enforcement_point": decision.EnforcementPoint, "action_type": actionTypeForEnforcementPoint(decision.EnforcementPoint), "target": strings.Join(runtimeEvidenceHosts(evidence), ", ")}, "decision": decision})
		return
	}
	if idempotencyKey != "" {
		if _, responses, detailErr := a.store.GetRuntimeDecisionDetail(decisionID); detailErr == nil && len(responses) > 0 {
			status := runtimeResponseStatus(responses)
			if status == audit.ResponseStatusExecuted || status == audit.ResponseStatusRolledBack {
				a.writeJSON(w, http.StatusOK, map[string]any{"status": runtimeEnforcementHTTPStatus(status), "decision": decision, "responses": responses, "idempotent_replay": true})
				return
			}
		}
	}
	_, evidence, _ := a.store.GetRuntimeDetectionDetail(decision.DetectionID)
	actionType := actionTypeForEnforcementPoint(decision.EnforcementPoint)
	responses, err := a.executeRuntimeDecisionResponse(decision, actionType, evidence, true)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	responseStatus := runtimeResponseStatus(responses)
	if decision.DetectionID != "" && responseStatus == audit.ResponseStatusExecuted {
		_ = a.store.UpdateRuntimeDetectionStatus(decision.DetectionID, audit.RuntimeDetectionStatusMitigated)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"status":          runtimeEnforcementHTTPStatus(responseStatus),
		"decision":        decision,
		"responses":       responses,
		"idempotency_key": idempotencyKey,
	})
}

// runtimeResponseStatus is the source of truth for the public enforcement
// result. A decision can be recorded and routed without the target module
// actually executing it; only an executed response may close a detection.
func runtimeResponseStatus(responses []audit.ResponseAction) string {
	if len(responses) == 0 {
		return audit.ResponseStatusFailed
	}
	for _, response := range responses {
		if response.Status == audit.ResponseStatusExecuted {
			return audit.ResponseStatusExecuted
		}
	}
	for _, response := range responses {
		if response.Status == audit.ResponseStatusExecuting {
			return audit.ResponseStatusExecuting
		}
	}
	for _, response := range responses {
		if response.Status == audit.ResponseStatusDispatched {
			return audit.ResponseStatusDispatched
		}
	}
	for _, response := range responses {
		if response.Status == audit.ResponseStatusWouldBlock {
			return audit.ResponseStatusWouldBlock
		}
	}
	for _, response := range responses {
		if response.Status == audit.ResponseStatusPlanned {
			return audit.ResponseStatusPlanned
		}
	}
	for _, response := range responses {
		if response.Status == audit.ResponseStatusRolledBack {
			return audit.ResponseStatusRolledBack
		}
	}
	for _, response := range responses {
		if response.Status == audit.ResponseStatusExpired {
			return audit.ResponseStatusExpired
		}
	}
	return audit.ResponseStatusFailed
}

func runtimeEnforcementHTTPStatus(responseStatus string) string {
	switch responseStatus {
	case audit.ResponseStatusExecuted:
		return "blocked"
	case audit.ResponseStatusDispatched:
		return "dispatched"
	case audit.ResponseStatusExecuting:
		return "executing"
	case audit.ResponseStatusWouldBlock:
		return "would_block"
	case audit.ResponseStatusPlanned:
		return "planned"
	case audit.ResponseStatusExpired:
		return "expired"
	case audit.ResponseStatusRolledBack:
		return "rolled_back"
	default:
		return "failed"
	}
}

func (a *APIServer) executeRuntimeDecisionResponse(decision audit.RuntimeDecision, actionType string, evidence []audit.DetectionEvidence, force bool) ([]audit.ResponseAction, error) {
	if decision.DecisionID == "" {
		return nil, fmt.Errorf("decision_id is required")
	}
	if actionType == "" {
		actionType = actionTypeForEnforcementPoint(decision.EnforcementPoint)
	}
	status := audit.ResponseStatusDispatched
	result := "routed to existing " + decision.EnforcementPoint + " enforcement"
	target := ""
	executor := decision.EnforcementPoint
	if !force && decision.Mode == audit.RuntimeSecurityModeObserve {
		status = audit.ResponseStatusWouldBlock
		result = "observe mode: would dispatch to " + decision.EnforcementPoint + " enforcement"
	}
	if decision.EnforcementPoint == audit.EnforcementPointProxy {
		executor = "proxy"
		hosts := runtimeEvidenceHosts(evidence)
		target = strings.Join(hosts, ", ")
		if len(hosts) == 0 {
			status = audit.ResponseStatusFailed
			result = "no network host evidence found for runtime detection"
		} else if blocklist := activeRuntimeBlocklist(); blocklist != nil {
			added := blocklist.AddHosts(hosts, decision.DecisionID)
			status = audit.ResponseStatusExecuted
			if len(added) > 0 {
				target = strings.Join(added, ", ")
				result = "host(s) added to runtime network blocklist; proxy returns 403"
			} else {
				result = "host(s) already present in runtime network blocklist"
			}
		} else {
			status = audit.ResponseStatusFailed
			result = "runtime blocklist unavailable"
		}
	} else if engine := activeDetectionEngine(); engine != nil && engine.Policy() != nil {
		status, target, result = engine.Policy().ExecuteNonProxy(context.Background(), decision, actionType, evidence, force)
	} else {
		status = audit.ResponseStatusFailed
		result = "runtime policy engine unavailable"
	}
	action, err := a.store.RecordResponseAction(audit.ResponseActionInput{
		DecisionID:        decision.DecisionID,
		ActionType:        actionType,
		Executor:          executor,
		Target:            target,
		Status:            status,
		Result:            result,
		RollbackSupported: decision.EnforcementPoint == audit.EnforcementPointProxy,
		ExecutedAt:        time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	return []audit.ResponseAction{action}, nil
}

func manualActionPlan(rawActionType, detectionType string) (string, string, error) {
	actionType := strings.ToUpper(strings.TrimSpace(rawActionType))
	if actionType == "" {
		point, planned := detection.EnforcementPlan(detectionType)
		return point, planned, nil
	}
	actionType = strings.ReplaceAll(actionType, "-", "_")
	switch actionType {
	case "BLOCK_TOOL", "TOOL_BLOCK":
		return audit.EnforcementPointAgentHook, "TOOL_BLOCK", nil
	case "BLOCK_MCP", "MCP_BLOCK":
		return audit.EnforcementPointMCP, "MCP_BLOCK", nil
	case "BLOCK_NETWORK", "NETWORK_BLOCK":
		return audit.EnforcementPointProxy, "BLOCK_NETWORK", nil
	case "BLOCK_PROCESS", "PROCESS_CONTAIN":
		return audit.EnforcementPointProcess, "PROCESS_CONTAIN", nil
	case "DISABLE_RESOURCE":
		return audit.EnforcementPointMCP, "DISABLE_RESOURCE", nil
	case "QUARANTINE_RESOURCE":
		return audit.EnforcementPointFile, "QUARANTINE_RESOURCE", nil
	case "BLOCK":
		// Desktop clients used the generic BLOCK action before the
		// enforcement-point vocabulary was exposed. Resolve it using the
		// same policy plan as automatic decisions.
		point, planned := detection.EnforcementPlan(detectionType)
		return point, planned, nil
	default:
		return "", "", fmt.Errorf("unsupported action_type %q", rawActionType)
	}
}

func actionTypeForEnforcementPoint(point string) string {
	switch point {
	case audit.EnforcementPointAgentHook:
		return "TOOL_BLOCK"
	case audit.EnforcementPointMCP:
		return "MCP_BLOCK"
	case audit.EnforcementPointProxy:
		return "BLOCK_NETWORK"
	case audit.EnforcementPointProcess:
		return "PROCESS_CONTAIN"
	case audit.EnforcementPointFile:
		return "QUARANTINE_RESOURCE"
	case audit.EnforcementPointGuardrail:
		return "PROMPT_BLOCK"
	default:
		return "BLOCK"
	}
}

func runtimeEvidenceHosts(evidence []audit.DetectionEvidence) []string {
	seen := map[string]bool{}
	var hosts []string
	addHost := func(host string) {
		if host != "" && !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	for _, row := range evidence {
		event := row.Event
		if !strings.HasPrefix(event.EventType, "network.") {
			continue
		}
		addHost(hostFromRuntimeTarget(event.Target))
	}
	if len(hosts) > 0 {
		return hosts
	}
	for _, row := range evidence {
		event := row.Event
		for _, value := range []string{event.Target, event.Operation, event.Detail} {
			for _, host := range hostsFromRuntimeText(value) {
				addHost(host)
			}
		}
	}
	return hosts
}

func hostsFromRuntimeText(text string) []string {
	var hosts []string
	for _, token := range strings.Fields(text) {
		token = strings.Trim(token, `"'()[]{}<>,;`)
		if token == "" {
			continue
		}
		if strings.Contains(token, "://") {
			if parsed, err := url.Parse(token); err == nil && parsed.Hostname() != "" {
				hosts = append(hosts, strings.ToLower(parsed.Hostname()))
				continue
			}
		}
		host := hostFromRuntimeTarget(token)
		if host == "" {
			continue
		}
		if host == "localhost" || strings.Contains(host, ".") || net.ParseIP(host) != nil {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func hostFromRuntimeTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}
	if i := strings.IndexAny(target, "/?#"); i > 0 {
		target = target[:i]
	}
	if i := strings.LastIndex(target, ":"); i > 0 {
		target = target[:i]
	}
	if target == "" || strings.ContainsAny(target, " \t") {
		return ""
	}
	return strings.ToLower(target)
}
