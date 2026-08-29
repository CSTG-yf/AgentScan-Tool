// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

type pageAgentSnapshot struct {
	CapturedAt string        `json:"capturedAt"`
	Agents     []pageAgent   `json:"agents"`
	Processes  []pageProcess `json:"processes"`
	Warning    string        `json:"warning,omitempty"`
}

type pageProcess struct {
	PID       uint32  `json:"pid"`
	PPID      uint32  `json:"ppid"`
	Name      string  `json:"name"`
	Product   string  `json:"product"`
	Vendor    string  `json:"vendor"`
	StartedAt *string `json:"startedAt,omitempty"`
	UptimeSec uint64  `json:"uptimeSec"`
	Source    string  `json:"source"`
}

type pageConfigRoot struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Exists bool   `json:"exists"`
}

type pageAgent struct {
	ID                      string              `json:"id"`
	Product                 string              `json:"product"`
	Vendor                  string              `json:"vendor"`
	Kind                    string              `json:"kind"`
	InventoryState          string              `json:"inventoryState,omitempty"`
	Confidence              int                 `json:"confidence,omitempty"`
	Status                  string              `json:"status"`
	RuntimeStatus           string              `json:"runtimeStatus"`
	Running                 bool                `json:"running"`
	ProcessCount            int                 `json:"processCount"`
	PIDs                    []uint32            `json:"pids"`
	PrimaryPID              *uint32             `json:"primaryPid,omitempty"`
	Processes               []pageProcess       `json:"processes,omitempty"`
	ExecutableNames         []string            `json:"executableNames"`
	Version                 string              `json:"version,omitempty"`
	DiscoveryStatus         string              `json:"discoveryStatus,omitempty"`
	PrimaryPath             string              `json:"primaryPath,omitempty"`
	FirstSeenScanAt         *string             `json:"firstSeenScanAt,omitempty"`
	LastSeenScanAt          *string             `json:"lastSeenScanAt,omitempty"`
	StartedAt               *string             `json:"startedAt,omitempty"`
	UptimeSec               *uint64             `json:"uptimeSec,omitempty"`
	Source                  string              `json:"source"`
	InstallPaths            []string            `json:"installPaths,omitempty"`
	ConfigRoots             []pageConfigRoot    `json:"configRoots"`
	Evidence                []pageAgentEvidence `json:"evidence,omitempty"`
	StaticResourceCount     uint64              `json:"staticResourceCount"`
	RiskResourceCount       uint64              `json:"riskResourceCount"`
	CriticalResourceCount   uint64              `json:"criticalResourceCount"`
	LastStaticScanAt        *string             `json:"lastStaticScanAt,omitempty"`
	RuntimeDetectionCount   int                 `json:"runtimeDetectionCount,omitempty"`
	RuntimeAttackCount      int                 `json:"runtimeAttackCount,omitempty"`
	RuntimeBlockedCount     int                 `json:"runtimeBlockedCount,omitempty"`
	RuntimeHighOrAboveCount int                 `json:"runtimeHighOrAboveCount,omitempty"`
	RuntimeLatestAt         *string             `json:"runtimeLatestAt,omitempty"`
	Description             string              `json:"description"`
}

type pageAgentEvidence struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Weight int    `json:"weight"`
}

type pageStaticSnapshot struct {
	CapturedAt string            `json:"capturedAt"`
	Source     string            `json:"source"`
	LastScanAt *string           `json:"lastScanAt,omitempty"`
	Agents     []pageStaticAgent `json:"agents"`
	Warning    string            `json:"warning,omitempty"`
}

type pageStaticAgent struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Runtime     string               `json:"runtime"`
	Source      string               `json:"source"`
	Description string               `json:"description"`
	Resources   []pageStaticResource `json:"resources"`
}

type pageStaticResource struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Type           string               `json:"type"`
	Kind           string               `json:"kind"`
	Path           string               `json:"path"`
	Risk           string               `json:"risk"`
	Status         string               `json:"status"`
	UpdatedAt      string               `json:"updatedAt"`
	Size           string               `json:"size"`
	Permissions    string               `json:"permissions"`
	Hash           string               `json:"hash"`
	Description    string               `json:"description"`
	ContentPreview string               `json:"contentPreview"`
	Findings       []pageStaticFinding  `json:"findings"`
	Relations      []pageStaticRelation `json:"relations"`
}

type pageStaticFinding struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Location       string `json:"location"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

type pageStaticRelation struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Relation string `json:"relation"`
	Risk     string `json:"risk"`
}

type pageEventSnapshot struct {
	CapturedAt      string                    `json:"capturedAt"`
	Source          string                    `json:"source"`
	Summary         pageEventSummary          `json:"summary"`
	SourceBreakdown []pageEventBreakdown      `json:"sourceBreakdown"`
	AgentBreakdown  []pageEventAgentBreakdown `json:"agentBreakdown"`
	Timeline        []pageEventTimelineBucket `json:"timeline"`
	Events          []pageEvent               `json:"events"`
	// Detections are the Phase-2 structured risk findings
	// (runtime_detections): what is actually risky, derived by
	// agent-agnostic rules from the unified runtime events. The page
	// should prefer these over string-matching heuristics for
	// attack/security classification.
	Detections []audit.RuntimeDetection `json:"detections,omitempty"`
	Warning    string                   `json:"warning,omitempty"`
}

type pageEventSummary struct {
	Total       int    `json:"total"`
	Security    int    `json:"security"`
	Attack      int    `json:"attack"`
	Blocked     int    `json:"blocked"`
	Critical    int    `json:"critical"`
	High        int    `json:"high"`
	Correlated  int    `json:"correlated"`
	Agents      int    `json:"agents"`
	Sources     int    `json:"sources"`
	WindowStart string `json:"windowStart,omitempty"`
	WindowEnd   string `json:"windowEnd,omitempty"`
	// Phase-2 detection-backed counters.
	Detections       int `json:"detections"`
	AttackDetections int `json:"attackDetections"`
	OpenDetections   int `json:"openDetections"`
}

type pageEventBreakdown struct {
	Name        string `json:"name"`
	Count       int    `json:"count"`
	Attack      int    `json:"attack"`
	Blocked     int    `json:"blocked"`
	MaxSeverity string `json:"maxSeverity"`
}

type pageEventAgentBreakdown struct {
	Agent       string   `json:"agent"`
	Runtime     string   `json:"runtime"`
	Count       int      `json:"count"`
	Attack      int      `json:"attack"`
	Blocked     int      `json:"blocked"`
	MaxSeverity string   `json:"maxSeverity"`
	LastSeen    string   `json:"lastSeen"`
	Sources     []string `json:"sources"`
}

type pageEventTimelineBucket struct {
	Bucket   string `json:"bucket"`
	Total    int    `json:"total"`
	Attack   int    `json:"attack"`
	Blocked  int    `json:"blocked"`
	HighRisk int    `json:"highRisk"`
}

type pageEvent struct {
	ID             string `json:"id"`
	OccurredAt     string `json:"occurredAt"`
	Kind           string `json:"kind"`
	Agent          string `json:"agent"`
	Runtime        string `json:"runtime"`
	Category       string `json:"category"`
	Subtype        string `json:"subtype"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	RiskScore      int    `json:"riskScore"`
	Status         string `json:"status"`
	Evidence       string `json:"evidence"`
	Action         string `json:"action"`
	TraceID        string `json:"traceId"`
	SessionID      string `json:"sessionId"`
	CorrelationKey string `json:"correlationKey"`
	Source         string `json:"source"`
	RawAction      string `json:"rawAction"`
	Target         string `json:"target"`
	Actor          string `json:"actor"`
	Connector      string `json:"connector"`
	DestinationApp string `json:"destinationApp"`
	ToolName       string `json:"toolName"`
	Model          string `json:"model"`
	MCPServer      string `json:"mcpServer"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	Remediation    string `json:"remediation"`
	// Phase-2 structured detection backing: when this event is
	// evidence of a runtime detection, Kind/Severity come from the
	// detection (category/severity) instead of string matching.
	DetectionID       string `json:"detectionId,omitempty"`
	DetectionType     string `json:"detectionType,omitempty"`
	DetectionSeverity string `json:"detectionSeverity,omitempty"`
}

type pageAttackChainSnapshot struct {
	CapturedAt string            `json:"capturedAt"`
	Source     string            `json:"source"`
	Chains     []pageAttackChain `json:"chains"`
	Items      []pageAttackChain `json:"items,omitempty"`
	Total      int               `json:"total,omitempty"`
	Page       int               `json:"page,omitempty"`
	PageSize   int               `json:"page_size,omitempty"`
	Warning    string            `json:"warning,omitempty"`
}

type pageAttackChain struct {
	ID            string                  `json:"id"`
	TraceID       string                  `json:"traceId"`
	SessionID     string                  `json:"sessionId"`
	Agent         string                  `json:"agent"`
	Runtime       string                  `json:"runtime"`
	Category      string                  `json:"category"`
	Risk          string                  `json:"risk"`
	Status        string                  `json:"status"`
	StartedAt     string                  `json:"startedAt"`
	EndedAt       string                  `json:"endedAt"`
	Summary       string                  `json:"summary"`
	StepCount     int                     `json:"stepCount"`
	EvidenceCount int                     `json:"evidenceCount"`
	Sources       []string                `json:"sources"`
	Steps         []pageAttackChainStep   `json:"steps"`
	Evidence      []pageAttackEvidenceRow `json:"evidence"`
	// Phase 3: links to the detection and the policy decision behind
	// this persisted chain (empty for legacy page-correlated chains).
	DetectionID string `json:"detectionId,omitempty"`
	DecisionID  string `json:"decisionId,omitempty"`
}

type pageAttackChainStep struct {
	ID            string   `json:"id"`
	Order         int      `json:"order"`
	OccurredAt    string   `json:"occurredAt"`
	Title         string   `json:"title"`
	Stage         string   `json:"stage"`
	Kind          string   `json:"kind"`
	Severity      string   `json:"severity"`
	Actor         string   `json:"actor"`
	Prompt        string   `json:"prompt"`
	Tool          string   `json:"tool"`
	Resource      string   `json:"resource"`
	Evidence      string   `json:"evidence"`
	Decision      string   `json:"decision"`
	Stack         []string `json:"stack"`
	SourceEventID string   `json:"sourceEventId"`
	Source        string   `json:"source"`
	TraceID       string   `json:"traceId"`
	SessionID     string   `json:"sessionId"`
}

type pageAttackEvidenceRow struct {
	Key           string `json:"key"`
	Index         int    `json:"index"`
	OccurredAt    string `json:"occurredAt"`
	Stage         string `json:"stage"`
	Agent         string `json:"agent"`
	Tool          string `json:"tool"`
	Resource      string `json:"resource"`
	Decision      string `json:"decision"`
	Evidence      string `json:"evidence"`
	SourceEventID string `json:"sourceEventId"`
	Source        string `json:"source"`
}

type pageGatewayAuditSnapshot struct {
	CapturedAt string                   `json:"capturedAt"`
	Source     string                   `json:"source"`
	Events     []pageGatewayAuditRecord `json:"events"`
	Warning    string                   `json:"warning,omitempty"`
}

type pageGatewayAuditRecord struct {
	Timestamp      string  `json:"timestamp"`
	Action         string  `json:"action"`
	Target         string  `json:"target"`
	Actor          string  `json:"actor"`
	Details        string  `json:"details"`
	Severity       string  `json:"severity"`
	TraceID        string  `json:"traceId"`
	SessionID      string  `json:"sessionId"`
	AgentName      string  `json:"agentName"`
	Connector      string  `json:"connector"`
	DestinationApp string  `json:"destinationApp"`
	ToolName       string  `json:"toolName"`
	Stage          string  `json:"stage"`
	Prompt         string  `json:"prompt"`
	Model          string  `json:"model"`
	MCPServer      string  `json:"mcpServer"`
	Decision       string  `json:"decision"`
	Reason         string  `json:"reason"`
	LatencyMs      *uint64 `json:"latencyMs,omitempty"`
}

type pageAgentDescriptor struct {
	ID          string
	AgentTypeID int64
	Product     string
	Vendor      string
	Kind        string
	Runtime     string
	Source      string
	Description string
	Roots       []pageConfigRoot
}

type pageStaticCandidate struct {
	Agent pageAgentDescriptor
	Type  string
	Path  string
}

type pageAgentDraft struct {
	ID                    string
	Product               string
	Vendor                string
	Kind                  string
	Runtime               string
	Description           string
	Sources               map[string]bool
	ConfigRoots           map[string]pageConfigRoot
	Processes             []pageProcess
	ExecutableNames       map[string]bool
	StaticResourceCount   uint64
	RiskResourceCount     uint64
	CriticalResourceCount uint64
	LastStaticScanAt      string
	RangeServices         []string
}

type pageAgentMetadata struct {
	InventoryState string              `json:"inventory_state,omitempty"`
	Confidence     int                 `json:"confidence,omitempty"`
	Version        string              `json:"version,omitempty"`
	Evidence       []pageAgentEvidence `json:"evidence,omitempty"`
	InstallPaths   []string            `json:"install_paths,omitempty"`
	ConfigPaths    []string            `json:"config_paths,omitempty"`
	Processes      []pageProcess       `json:"processes,omitempty"`
	RangeServices  []string            `json:"range_services,omitempty"`
}

type pageAgentDetection struct {
	AgentTypeID     int64
	RuleID          int64
	Threshold       int
	Desc            pageAgentDescriptor
	Score           int
	CategoryWeights map[string]int
	Evidence        []pageAgentEvidence
	InstallPaths    map[string]string
	ConfigRoots     map[string]pageConfigRoot
	Processes       []pageProcess
	ExecutableNames map[string]bool
	RangeServices   []string
	Running         bool
	RequiredMatched bool
}

func (a *APIServer) handleAttackChains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/attack-chains"), "/")
	if rest != "" {
		if rest == "summary" {
			a.handleAttackChainsSummary(w, r)
			return
		}
		a.handleAttackChainDetail(w, r, strings.Split(rest, "/")[0])
		return
	}
	// Phase 3: persisted attack chains (runtime_attack_chains) are the
	// authoritative backend security objects — the correlation engine
	// wrote them when Detection → Decision completed. The page-level
	// reconstruction below stays as a legacy fallback.
	if a.store != nil {
		if chains := a.backendAttackChains(r); len(chains) > 0 {
			page, pageSize := requestPage(r, 1, 100, 200)
			a.writeJSON(w, http.StatusOK, pageAttackChainSnapshot{
				CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Source:     "runtime-attack-chains",
				Chains:     chains,
				Items:      chains,
				Total:      len(chains),
				Page:       page,
				PageSize:   pageSize,
			})
			return
		}
	}
	events, err := a.buildPageEventDetections(pageLimit(r, 500, 100, 1000))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	chains := pageCorrelateAttackChains(events.Events)
	if len(chains) > 80 {
		chains = chains[:80]
	}
	a.writeJSON(w, http.StatusOK, pageAttackChainSnapshot{
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:     events.Source,
		Chains:     chains,
		Items:      chains,
		Total:      len(chains),
		Page:       1,
		PageSize:   len(chains),
		Warning:    events.Warning,
	})
}

func (a *APIServer) handleAttackChainDetail(w http.ResponseWriter, r *http.Request, chainID string) {
	chainID = strings.TrimSpace(chainID)
	if chainID == "" || strings.ContainsAny(chainID, `/\`) {
		http.NotFound(w, r)
		return
	}
	if a.store != nil {
		chain, events, err := a.store.GetRuntimeAttackChainDetail(chainID)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if chain.AttackChainID != "" {
			pageChain := pageAttackChainFromRuntime(chain)
			pageChain.Steps, pageChain.Evidence, pageChain.Sources = pageChainStepsFromRuntime(events)
			pageChain.StepCount = len(pageChain.Steps)
			pageChain.EvidenceCount = len(pageChain.Evidence)
			detections, decision, responses := a.attackChainSecurityContext(chain)
			a.writeJSON(w, http.StatusOK, map[string]any{
				"attack_chain": chain,
				"events":       events,
				"chain":        pageChain,
				"nodes":        pageChain.Steps,
				"edges":        pageAttackChainEdges(pageChain.Steps),
				"evidence":     pageChain.Evidence,
				"detections":   detections,
				"decision":     decision,
				"response":     firstRuntimeResponse(responses),
				"responses":    responses,
			})
			return
		}
	}
	events, err := a.buildPageEventDetections(pageLimit(r, 500, 100, 1000))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for _, chain := range pageCorrelateAttackChains(events.Events) {
		if chain.ID == chainID {
			a.writeJSON(w, http.StatusOK, map[string]any{
				"chain":    chain,
				"nodes":    chain.Steps,
				"edges":    pageAttackChainEdges(chain.Steps),
				"evidence": chain.Evidence,
				"source":   events.Source,
			})
			return
		}
	}
	a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "attack chain not found"})
}

func (a *APIServer) handleAttackChainsSummary(w http.ResponseWriter, r *http.Request) {
	chains := []pageAttackChain{}
	if a.store != nil {
		q := r.URL.Query()
		rows, err := a.store.ListRuntimeAttackChains(audit.AttackChainFilter{
			AgentID:    strings.TrimSpace(q.Get("agent_id")),
			SessionID:  strings.TrimSpace(q.Get("session_id")),
			TraceID:    strings.TrimSpace(q.Get("trace_id")),
			AttackType: strings.TrimSpace(q.Get("attack_type")),
			Severity:   strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
			Status:     attackChainStatusFilter(q.Get("status")),
			StartTime:  parseAPITime(q.Get("start_time")),
			EndTime:    parseAPITime(q.Get("end_time")),
			Limit:      1000,
		})
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		for _, row := range rows {
			chains = append(chains, pageAttackChainFromRuntime(row))
		}
	}
	if len(chains) == 0 {
		events, err := a.buildPageEventDetections(pageLimit(r, 500, 100, 1000))
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		chains = pageCorrelateAttackChains(events.Events)
	}
	a.writeJSON(w, http.StatusOK, summarizeAttackChains(chains))
}

// backendAttackChains loads persisted attack chains with their event
// sequences and maps them onto the page DTO so the frontend renders
// both sources identically.
func (a *APIServer) backendAttackChains(r *http.Request) []pageAttackChain {
	q := r.URL.Query()
	page, pageSize := requestPage(r, 1, 100, 200)
	limit := pageSize
	if v := strings.TrimSpace(q.Get("limit")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	offset := (page - 1) * pageSize
	if v := strings.TrimSpace(q.Get("offset")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	rows, err := a.store.ListRuntimeAttackChains(audit.AttackChainFilter{
		AgentID:    strings.TrimSpace(q.Get("agent_id")),
		SessionID:  strings.TrimSpace(q.Get("session_id")),
		TraceID:    strings.TrimSpace(q.Get("trace_id")),
		AttackType: strings.TrimSpace(q.Get("attack_type")),
		Severity:   strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		Status:     attackChainStatusFilter(q.Get("status")),
		StartTime:  parseAPITime(q.Get("start_time")),
		EndTime:    parseAPITime(q.Get("end_time")),
		Limit:      limit,
		Offset:     offset,
	})
	if err != nil || len(rows) == 0 {
		return nil
	}
	chains := make([]pageAttackChain, 0, len(rows))
	for _, row := range rows {
		chain := pageAttackChainFromRuntime(row)
		if _, events, err := a.store.GetRuntimeAttackChainDetail(row.AttackChainID); err == nil {
			chain.Steps, chain.Evidence, chain.Sources = pageChainStepsFromRuntime(events)
			chain.StepCount = len(chain.Steps)
			chain.EvidenceCount = len(chain.Evidence)
		}
		chains = append(chains, chain)
	}
	return chains
}

func (a *APIServer) attackChainSecurityContext(chain audit.RuntimeAttackChain) ([]audit.RuntimeDetection, audit.RuntimeDecision, []audit.ResponseAction) {
	detections := []audit.RuntimeDetection{}
	if chain.DetectionID != "" {
		if detection, _, err := a.store.GetRuntimeDetectionDetail(chain.DetectionID); err == nil && detection.DetectionID != "" {
			detections = append(detections, detection)
		}
	}
	var decision audit.RuntimeDecision
	var responses []audit.ResponseAction
	if chain.DecisionID != "" {
		if d, r, err := a.store.GetRuntimeDecisionDetail(chain.DecisionID); err == nil {
			decision = d
			responses = r
		}
	}
	return detections, decision, responses
}

func firstRuntimeResponse(responses []audit.ResponseAction) audit.ResponseAction {
	if len(responses) == 0 {
		return audit.ResponseAction{}
	}
	return responses[0]
}

func pageAttackChainEdges(steps []pageAttackChainStep) []map[string]any {
	if len(steps) < 2 {
		return []map[string]any{}
	}
	edges := make([]map[string]any, 0, len(steps)-1)
	for i := 1; i < len(steps); i++ {
		edges = append(edges, map[string]any{
			"id":     fmt.Sprintf("%s-%s", steps[i-1].ID, steps[i].ID),
			"source": steps[i-1].ID,
			"target": steps[i].ID,
			"order":  i,
		})
	}
	return edges
}

func summarizeAttackChains(chains []pageAttackChain) map[string]any {
	agents := map[string]bool{}
	latest := ""
	summary := map[string]any{
		"total_chains":    len(chains),
		"active_chains":   0,
		"blocked_chains":  0,
		"critical_chains": 0,
		"involved_agents": 0,
		"latest_at":       "",
	}
	active, blocked, critical := 0, 0, 0
	for _, chain := range chains {
		if chain.Agent != "" {
			agents[chain.Agent] = true
		}
		switch strings.ToLower(chain.Status) {
		case "blocked", "contained", "mitigated":
			blocked++
		default:
			active++
		}
		if strings.EqualFold(chain.Risk, "critical") {
			critical++
		}
		if chain.EndedAt > latest {
			latest = chain.EndedAt
		}
	}
	summary["active_chains"] = active
	summary["blocked_chains"] = blocked
	summary["critical_chains"] = critical
	summary["involved_agents"] = len(agents)
	summary["latest_at"] = latest
	return summary
}

func attackChainStatusFilter(raw string) string {
	status := strings.ToLower(strings.TrimSpace(raw))
	switch status {
	case "blocked", "mitigated":
		return audit.AttackChainStatusContained
	default:
		return status
	}
}

func pageAttackChainFromRuntime(c audit.RuntimeAttackChain) pageAttackChain {
	status := c.Status
	if status == audit.AttackChainStatusContained {
		status = "blocked"
	}
	agent := c.AgentName
	if agent == "" {
		agent = c.AgentID
	}
	return pageAttackChain{
		ID:        c.AttackChainID,
		TraceID:   c.TraceID,
		SessionID: c.SessionID,
		Agent:     firstNonEmpty(agent, "Unknown Agent"),
		Runtime:   "",
		Category:  c.AttackType,
		Risk:      strings.ToUpper(c.Severity),
		Status:    status,
		StartedAt: c.StartTime.UTC().Format(time.RFC3339Nano),
		EndedAt:   c.EndTime.UTC().Format(time.RFC3339Nano),
		Summary: fmt.Sprintf("Persisted attack chain %s: %s (%s), correlated by the detection engine.",
			c.AttackChainID, c.AttackType, strings.ToUpper(c.Severity)),
		DetectionID: c.DetectionID,
		DecisionID:  c.DecisionID,
	}
}

func pageChainStepsFromRuntime(events []audit.AttackChainEvent) ([]pageAttackChainStep, []pageAttackEvidenceRow, []string) {
	steps := make([]pageAttackChainStep, 0, len(events))
	sources := map[string]bool{}
	for i, ev := range events {
		e := ev.Event
		source := e.EventSource
		if source == "" {
			source = e.Source
		}
		sources[source] = true
		order := ev.Sequence
		if order == 0 {
			order = i
		}
		step := pageAttackChainStep{
			ID:            strconv.FormatInt(e.ID, 10),
			Order:         order + 1,
			OccurredAt:    e.Timestamp.UTC().Format(time.RFC3339Nano),
			Title:         firstNonEmpty(ev.Relation, e.EventType),
			Stage:         firstNonEmpty(ev.Relation, e.EventType),
			Kind:          "attack",
			Severity:      strings.ToUpper(e.Severity),
			Actor:         firstNonEmpty(e.AgentName, e.CanonicalAgentID),
			Tool:          e.ToolName,
			Resource:      firstNonEmpty(e.MCPServer, e.Target),
			Evidence:      truncate(firstNonEmpty(e.Target, e.Detail), 160),
			Decision:      e.Outcome,
			SourceEventID: strconv.FormatInt(e.ID, 10),
			Source:        source,
			TraceID:       e.TraceID,
			SessionID:     e.SessionID,
		}
		steps = append(steps, step)
	}
	evidence := make([]pageAttackEvidenceRow, 0, len(steps))
	for _, step := range steps {
		evidence = append(evidence, pageAttackEvidenceRow{
			Key:           step.ID,
			Index:         step.Order,
			OccurredAt:    step.OccurredAt,
			Stage:         step.Stage,
			Agent:         step.Actor,
			Tool:          step.Tool,
			Resource:      step.Resource,
			Decision:      step.Decision,
			Evidence:      step.Evidence,
			SourceEventID: step.SourceEventID,
			Source:        step.Source,
		})
	}
	unique := make([]string, 0, len(sources))
	for s := range sources {
		if s != "" {
			unique = append(unique, s)
		}
	}
	sort.Strings(unique)
	return steps, evidence, unique
}

func (a *APIServer) handleGatewayAuditInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snap, err := a.buildPageGatewayAudit(pageLimit(r, 200, 1, 500), r.URL.Query().Get("connector"))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, snap)
}

func pageLimit(r *http.Request, def, min, max int) int {
	limit := def
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	if limit < min {
		return min
	}
	if limit > max {
		return max
	}
	return limit
}

func (a *APIServer) buildPageAgentInventory(limit int) (pageAgentSnapshot, error) {
	var warnings []string
	processes := []pageProcess{}

	if a.store == nil {
		warnings = append(warnings, "audit store is not attached")
		return pageAgentSnapshot{
			CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Agents:     []pageAgent{},
			Processes:  processes,
			Warning:    strings.Join(warnings, "; "),
		}, nil
	}

	warnings = append(warnings, a.refreshAgentInventoryFromScanner()...)

	agentRows, err := a.store.ListAgents(limit)
	if err != nil {
		return pageAgentSnapshot{}, err
	}

	agents := make([]pageAgent, 0, len(agentRows))
	for _, row := range agentRows {
		agent := pageAgentFromCanonical(row)
		agents = append(agents, agent)
		processes = append(processes, agent.ProcessesForSnapshot()...)
	}
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Running != agents[j].Running {
			return agents[i].Running
		}
		if agents[i].Confidence != agents[j].Confidence {
			return agents[i].Confidence > agents[j].Confidence
		}
		if agents[i].RiskResourceCount != agents[j].RiskResourceCount {
			return agents[i].RiskResourceCount > agents[j].RiskResourceCount
		}
		if agents[i].StaticResourceCount != agents[j].StaticResourceCount {
			return agents[i].StaticResourceCount > agents[j].StaticResourceCount
		}
		return agents[i].Product < agents[j].Product
	})
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].Product != processes[j].Product {
			return processes[i].Product < processes[j].Product
		}
		return processes[i].PID < processes[j].PID
	})

	return pageAgentSnapshot{
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Agents:     agents,
		Processes:  processes,
		Warning:    strings.Join(warnings, "; "),
	}, nil
}

func (a pageAgent) ProcessesForSnapshot() []pageProcess {
	if len(a.Processes) == 0 {
		return nil
	}
	out := make([]pageProcess, len(a.Processes))
	copy(out, a.Processes)
	return out
}

func pageRuntimeStatusFromRunning(running bool) string {
	if running {
		return "running"
	}
	return "stopped"
}

func pagePIDsFromProcesses(processes []pageProcess) []uint32 {
	if len(processes) == 0 {
		return []uint32{}
	}
	out := make([]uint32, 0, len(processes))
	for _, proc := range processes {
		out = append(out, proc.PID)
	}
	return pageNormalizePIDs(out)
}

func pageNormalizePIDs(pids []uint32) []uint32 {
	if len(pids) == 0 {
		return []uint32{}
	}
	seen := map[uint32]bool{}
	out := make([]uint32, 0, len(pids))
	for _, pid := range pids {
		if pid == 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if out == nil {
		return []uint32{}
	}
	return out
}

func pageNormalizeRuntimeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return "running"
	case "stopped", "installed", "missing":
		return "stopped"
	case "unknown":
		return "unknown"
	default:
		return ""
	}
}

func pageDiscoveryStatus(status, inventoryState string) string {
	if value := strings.TrimSpace(inventoryState); value != "" {
		return value
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "installed", "observed", "discovered":
		return "discovered"
	case "missing":
		return "missing"
	case "stopped":
		return "installed"
	case "":
		return "unknown"
	default:
		return status
	}
}

func pageStringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func pageAgentPrimaryPath(roots []pageConfigRoot, installPaths []string, source string) string {
	for _, root := range roots {
		if strings.TrimSpace(root.Path) != "" {
			return root.Path
		}
	}
	for _, path := range installPaths {
		if strings.TrimSpace(path) != "" {
			return path
		}
	}
	return strings.TrimSpace(source)
}

func (a *APIServer) refreshAgentInventoryFromScanner() []string {
	if a == nil || a.store == nil {
		return nil
	}
	now := time.Now().UTC()
	var warnings []string

	rules, err := a.store.ListEnabledAgentDiscoveryRules()
	if err != nil {
		return []string{err.Error()}
	}
	activeIDs := []string{}
	for _, rule := range rules {
		d := a.evaluateAgentDiscoveryRule(rule)
		if !pageAgentDetectionTrusted(d) {
			continue
		}
		meta := d.metadata()
		status := "installed"
		if d.Running {
			status = "running"
		}
		id := pageCanonicalAgentID(pageFirstNonEmpty(rule.AgentType.TypeKey, d.Desc.ID, d.Desc.Product))
		if id == "" || pageAgentIDIsVirtual(id) {
			continue
		}
		activeIDs = append(activeIDs, id)
		if _, err := a.store.EnsureAgent(audit.AgentIdentityInput{
			AgentID:         id,
			AgentTypeID:     rule.AgentType.ID,
			DiscoveryRuleID: rule.ID,
			AgentName:       rule.AgentType.Name,
			Vendor:          rule.AgentType.Vendor,
			Kind:            rule.AgentType.Kind,
			Runtime:         rule.AgentType.Runtime,
			Source:          "agent-scanner",
			Status:          status,
			RuntimeStatus:   pageRuntimeStatusFromRunning(d.Running),
			Confidence:      d.Score,
			PIDs:            pagePIDsFromProcesses(d.Processes),
			ObservedAt:      now,
			Metadata:        meta.toMap(),
		}); err != nil {
			warnings = append(warnings, err.Error())
		}
	}
	if err := a.store.MarkMissingAgentDiscoveries(activeIDs, now); err != nil {
		warnings = append(warnings, err.Error())
	}
	return warnings
}

func (a *APIServer) evaluateAgentDiscoveryRule(rule audit.AgentDiscoveryRule) *pageAgentDetection {
	desc := pageDescriptorFromDiscoveryRule(rule)
	d := &pageAgentDetection{
		AgentTypeID:     rule.AgentType.ID,
		RuleID:          rule.ID,
		Threshold:       rule.Threshold,
		Desc:            desc,
		CategoryWeights: map[string]int{},
		InstallPaths:    map[string]string{},
		ConfigRoots:     map[string]pageConfigRoot{},
		ExecutableNames: map[string]bool{},
		RequiredMatched: true,
	}
	if d.Threshold <= 0 {
		d.Threshold = 60
	}
	for _, condition := range rule.Conditions {
		matched := a.matchAgentDiscoveryCondition(d, condition)
		if !matched && condition.Required {
			d.RequiredMatched = false
		}
	}
	return d
}

func (a *APIServer) matchAgentDiscoveryCondition(d *pageAgentDetection, c audit.AgentDiscoveryCondition) bool {
	if d == nil || !c.Enabled {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(c.Type)) {
	case "cli":
		return pageMatchAgentCLICondition(d, c)
	case "file", "directory", "path":
		return pageMatchAgentPathCondition(d, c, a.scannerCfg)
	case "process":
		return a.matchAgentProcessCondition(d, c)
	case "agentrange_root":
		return a.matchAgentRangeCondition(d, c)
	default:
		return false
	}
}

func pageMatchAgentCLICondition(d *pageAgentDetection, c audit.AgentDiscoveryCondition) bool {
	if !pageOperatorAllows(c.Operator, "exists") {
		return false
	}
	path, ok := pageLookPath(c.Value)
	if !ok {
		return false
	}
	pageAddAgentInstallEvidence(d, "cli", c.Value, path, c.Weight)
	return true
}

func pageMatchAgentPathCondition(d *pageAgentDetection, c audit.AgentDiscoveryCondition, cfg *config.Config) bool {
	if !pageOperatorAllows(c.Operator, "exists") {
		return false
	}
	paths := pageExpandDiscoveryPath(c.Value, cfg)
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(c.Type))
		if kind == "directory" && !info.IsDir() {
			continue
		}
		if kind == "file" && info.IsDir() {
			continue
		}
		if pageDiscoveryConditionIsInstallPath(c, path) {
			pageAddAgentInstallEvidence(d, "file", filepath.Base(path), path, c.Weight)
		} else {
			pageAddAgentConfigEvidence(d, pageConfigRoot{Path: path, Kind: pageConfigKind(path), Exists: true}, c.Weight)
		}
		return true
	}
	return false
}

func (a *APIServer) matchAgentProcessCondition(d *pageAgentDetection, c audit.AgentDiscoveryCondition) bool {
	if a == nil || a.aiDiscovery == nil || !pageOperatorAllows(c.Operator, "contains", "equals") {
		return false
	}
	needle := strings.ToLower(strings.TrimSpace(c.Value))
	if needle == "" {
		return false
	}
	matched := false
	for _, sig := range a.aiDiscovery.Snapshot().Signals {
		if sig.State == inventory.AIStateGone || sig.Category != inventory.SignalActiveProcess || sig.Runtime == nil {
			continue
		}
		proc := pageProcessFromSignal(sig)
		haystack := strings.ToLower(strings.Join([]string{
			sig.SignatureID,
			sig.SupportedConnector,
			sig.Name,
			sig.Product,
			sig.Vendor,
			proc.Name,
			proc.Product,
			proc.Vendor,
		}, " "))
		if !pageStringOperatorMatch(haystack, needle, c.Operator) {
			continue
		}
		d.Processes = append(d.Processes, proc)
		if proc.Name != "" {
			d.ExecutableNames[proc.Name] = true
		}
		d.Running = true
		pageAddAgentEvidence(d, "process", pageFirstNonEmpty(proc.Name, sig.Product, sig.Name, c.Value), c.Weight)
		matched = true
	}
	return matched
}

func (a *APIServer) matchAgentRangeCondition(d *pageAgentDetection, c audit.AgentDiscoveryCondition) bool {
	if !pageOperatorAllows(c.Operator, "exists") {
		return false
	}
	desc := pageAgentRangeDescriptor(a.scannerCfg)
	if desc.ID == "" || len(desc.Roots) == 0 {
		return false
	}
	for _, root := range desc.Roots {
		pageAddAgentConfigEvidence(d, root, c.Weight)
	}
	services := pageAgentRangeRunningServices(a.scannerCfg)
	if len(services) > 0 {
		d.RangeServices = append(d.RangeServices, services...)
		d.Running = true
		pageAddAgentEvidence(d, "process", "AgentRange services running", 30)
	}
	return true
}

func pageDescriptorFromDiscoveryRule(rule audit.AgentDiscoveryRule) pageAgentDescriptor {
	id := pageCanonicalAgentID(pageFirstNonEmpty(rule.AgentType.TypeKey, rule.AgentType.Name))
	return pageAgentDescriptor{
		ID:          id,
		AgentTypeID: rule.AgentType.ID,
		Product:     pageFirstNonEmpty(rule.AgentType.Name, id),
		Vendor:      pageFirstNonEmpty(rule.AgentType.Vendor, "Unknown"),
		Kind:        pageFirstNonEmpty(rule.AgentType.Kind, "agent"),
		Runtime:     pageFirstNonEmpty(rule.AgentType.Runtime, pageRuntimeLabel(rule.AgentType.Kind)),
		Source:      "agent-discovery-rule",
		Description: pageFirstNonEmpty(rule.AgentType.Description, pageFirstNonEmpty(rule.AgentType.Name, id)+" discovery rule."),
	}
}

func pageAgentDetectionTrusted(d *pageAgentDetection) bool {
	if d == nil || !d.RequiredMatched {
		return false
	}
	threshold := d.Threshold
	if threshold <= 0 {
		threshold = 60
	}
	return d.Score >= threshold
}

func pageAddAgentEvidence(d *pageAgentDetection, kind, value string, weight int) {
	if d == nil || strings.TrimSpace(kind) == "" || weight <= 0 {
		return
	}
	kind = strings.TrimSpace(kind)
	value = strings.TrimSpace(value)
	if value == "" {
		value = kind
	}
	if d.CategoryWeights == nil {
		d.CategoryWeights = map[string]int{}
	}
	if weight > d.CategoryWeights[kind] {
		d.Score += weight - d.CategoryWeights[kind]
		d.CategoryWeights[kind] = weight
	}
	d.Evidence = append(d.Evidence, pageAgentEvidence{Type: kind, Value: value, Weight: weight})
}

func pageAddAgentInstallEvidence(d *pageAgentDetection, kind, command, path string, weight int) {
	if d == nil {
		return
	}
	path = strings.TrimSpace(path)
	if path != "" {
		d.InstallPaths[pagePathKey(path)] = path
	}
	pageAddAgentEvidence(d, kind, pageFirstNonEmpty(command, path), weight)
}

func pageAddAgentConfigEvidence(d *pageAgentDetection, root pageConfigRoot, weight int) {
	if d == nil || strings.TrimSpace(root.Path) == "" {
		return
	}
	root.Exists = true
	d.ConfigRoots[pagePathKey(root.Path)] = root
	pageAddAgentEvidence(d, "config", root.Path, weight)
}

func (d *pageAgentDetection) metadata() pageAgentMetadata {
	if d == nil {
		return pageAgentMetadata{}
	}
	installPaths := make([]string, 0, len(d.InstallPaths))
	for _, path := range d.InstallPaths {
		installPaths = append(installPaths, path)
	}
	sort.Strings(installPaths)

	configPaths := make([]string, 0, len(d.ConfigRoots))
	for _, root := range d.ConfigRoots {
		configPaths = append(configPaths, root.Path)
	}
	sort.Strings(configPaths)

	state := "installed"
	if d.Running {
		state = "running"
	}
	confidence := d.Score
	if confidence > 100 {
		confidence = 100
	}
	return pageAgentMetadata{
		InventoryState: state,
		Confidence:     confidence,
		Evidence:       append([]pageAgentEvidence(nil), d.Evidence...),
		InstallPaths:   installPaths,
		ConfigPaths:    configPaths,
		Processes:      append([]pageProcess(nil), d.Processes...),
		RangeServices:  append([]string(nil), d.RangeServices...),
	}
}

func (m pageAgentMetadata) toMap() map[string]any {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func pageAgentFromCanonical(row audit.CanonicalAgent) pageAgent {
	meta := pageDecodeAgentMetadata(row.MetadataJSON)
	confidence := meta.Confidence
	if confidence == 0 {
		confidence = row.Confidence
	}
	roots := make([]pageConfigRoot, 0, len(meta.ConfigPaths))
	seenRoots := map[string]bool{}
	for _, path := range meta.ConfigPaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		key := pagePathKey(path)
		if seenRoots[key] {
			continue
		}
		seenRoots[key] = true
		exists := false
		if _, err := os.Stat(path); err == nil {
			exists = true
		}
		roots = append(roots, pageConfigRoot{Path: path, Kind: pageConfigKind(path), Exists: exists})
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Path < roots[j].Path })

	processes := append([]pageProcess(nil), meta.Processes...)
	rangeServices := append([]string(nil), meta.RangeServices...)
	storedRuntimeStatus := pageNormalizeRuntimeStatus(row.RuntimeStatus)
	if storedRuntimeStatus == "stopped" {
		processes = nil
		rangeServices = nil
	}
	pids := make([]uint32, 0, len(processes))
	exes := map[string]bool{}
	var primaryPID *uint32
	var startedAt *string
	var uptime *uint64
	for i, proc := range processes {
		if proc.PID > 0 {
			pids = append(pids, proc.PID)
			if primaryPID == nil {
				pid := proc.PID
				primaryPID = &pid
			}
		}
		if proc.Name != "" {
			exes[proc.Name] = true
		}
		if i == 0 {
			startedAt = proc.StartedAt
			up := proc.UptimeSec
			uptime = &up
		}
	}
	sort.Slice(processes, func(i, j int) bool {
		left, right := "", ""
		if processes[i].StartedAt != nil {
			left = *processes[i].StartedAt
		}
		if processes[j].StartedAt != nil {
			right = *processes[j].StartedAt
		}
		if left != right {
			return left < right
		}
		return processes[i].PID < processes[j].PID
	})
	if len(pids) == 0 && storedRuntimeStatus == "running" {
		pids = append(pids, row.PIDs...)
		if len(pids) > 0 && primaryPID == nil {
			pid := pids[0]
			primaryPID = &pid
		}
	}
	pids = pageNormalizePIDs(pids)
	if len(pids) > 0 && primaryPID == nil {
		pid := pids[0]
		primaryPID = &pid
	}

	installPaths := append([]string(nil), meta.InstallPaths...)
	sort.Strings(installPaths)
	running := storedRuntimeStatus == "running" || len(processes) > 0 || len(rangeServices) > 0 || len(pids) > 0
	runtimeStatus := storedRuntimeStatus
	if runtimeStatus == "" || runtimeStatus == "unknown" {
		switch {
		case running:
			runtimeStatus = "running"
		case len(roots) > 0 || row.StaticResourceCount > 0 || strings.EqualFold(row.Status, "installed") || strings.EqualFold(row.Status, "missing"):
			runtimeStatus = "stopped"
		default:
			runtimeStatus = "unknown"
		}
	}
	var last *string
	if row.LastStaticScanAt != "" {
		last = &row.LastStaticScanAt
	}
	firstSeen := pageStringPtr(row.FirstSeenAt)
	lastSeen := pageStringPtr(row.LastSeenAt)
	description := pageFirstNonEmpty(row.TypeDescription, fmt.Sprintf("%s unified Agent Inventory record from agents table.", pageFirstNonEmpty(row.DisplayName, row.ID)))
	if confidence > 0 {
		description = fmt.Sprintf("%s Confidence %d based on %d evidence item(s).", description, confidence, len(meta.Evidence))
	}
	processCount := len(processes) + len(rangeServices)
	if len(processes) == 0 && len(pids) > 0 {
		processCount += len(pids)
	}
	return pageAgent{
		ID:                    pageCanonicalAgentID(row.ID),
		Product:               pageFirstNonEmpty(row.DisplayName, row.ID),
		Vendor:                pageFirstNonEmpty(row.Vendor, "Unknown"),
		Kind:                  pageFirstNonEmpty(row.Kind, "agent"),
		InventoryState:        meta.InventoryState,
		Confidence:            confidence,
		Status:                runtimeStatus,
		RuntimeStatus:         runtimeStatus,
		Running:               running,
		ProcessCount:          processCount,
		PIDs:                  pids,
		PrimaryPID:            primaryPID,
		Processes:             processes,
		ExecutableNames:       pageSortedKeys(exes),
		Version:               strings.TrimSpace(meta.Version),
		DiscoveryStatus:       pageDiscoveryStatus(row.Status, meta.InventoryState),
		PrimaryPath:           pageAgentPrimaryPath(roots, installPaths, row.Source),
		FirstSeenScanAt:       firstSeen,
		LastSeenScanAt:        lastSeen,
		StartedAt:             startedAt,
		UptimeSec:             uptime,
		Source:                pageFirstNonEmpty(row.Source, "agents"),
		InstallPaths:          installPaths,
		ConfigRoots:           roots,
		Evidence:              append([]pageAgentEvidence(nil), meta.Evidence...),
		StaticResourceCount:   uint64(row.StaticResourceCount),
		RiskResourceCount:     uint64(row.RiskResourceCount),
		CriticalResourceCount: uint64(row.CriticalResourceCount),
		LastStaticScanAt:      last,
		Description:           description,
	}
}

func pageDecodeAgentMetadata(raw string) pageAgentMetadata {
	var meta pageAgentMetadata
	if strings.TrimSpace(raw) == "" {
		return meta
	}
	_ = json.Unmarshal([]byte(raw), &meta)
	return meta
}

func pageAgentInventoryHidden(row audit.CanonicalAgent) bool {
	id := pageCanonicalAgentID(row.ID)
	if pageAgentIDIsVirtual(id) {
		return true
	}
	if strings.EqualFold(row.Status, "missing") {
		return true
	}
	meta := pageDecodeAgentMetadata(row.MetadataJSON)
	return strings.EqualFold(meta.InventoryState, "candidate")
}

func pageAgentIDIsVirtual(id string) bool {
	switch pageCanonicalAgentID(id) {
	case "", "system-environment", "unclassified-agent":
		return true
	default:
		return false
	}
}

func pageAgentIdentityConfigPattern(pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "~/") || pattern == "~" {
		return true
	}
	expanded := os.ExpandEnv(pattern)
	return filepath.IsAbs(expanded)
}

func pageLookPath(command string) (string, bool) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", false
	}
	if path, err := exec.LookPath(command); err == nil && path != "" {
		return path, true
	}
	if filepath.Ext(command) != "" {
		return "", false
	}
	extensions := []string{".exe", ".cmd", ".bat", ".ps1"}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		for _, ext := range extensions {
			path := filepath.Join(dir, command+ext)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path, true
			}
		}
	}
	return "", false
}

func (a *APIServer) buildPageStaticInventory(limit int) (pageStaticSnapshot, error) {
	source := "gateway:/api/v1/static-resources"
	agents := []pageStaticAgent{}
	agentIndex := map[string]int{}
	seen := map[string]bool{}
	var lastScan string
	var warnings []string

	if a.store != nil {
		rows, err := a.store.ListLatestStaticScans(limit)
		if err != nil {
			warnings = append(warnings, err.Error())
		} else {
			for _, row := range rows {
				if row.Timestamp > lastScan {
					lastScan = row.Timestamp
				}
				seen[pagePathKey(row.Target)] = true
				resource := a.pageStaticResourceFromScan(row)
				desc := pageDescriptorFromStaticScan(row, resource.Type)
				pagePushStaticResource(&agents, agentIndex, desc, resource)
			}
		}
	} else {
		warnings = append(warnings, "audit store is not attached")
	}

	for _, candidate := range a.pageDiscoverStaticCandidates(limit) {
		if seen[pagePathKey(candidate.Path)] {
			continue
		}
		seen[pagePathKey(candidate.Path)] = true
		pagePushStaticResource(&agents, agentIndex, candidate.Agent, pageStaticResourceFromCandidate(candidate))
	}

	if inventory, err := a.buildPageAgentInventory(limit); err == nil {
		for _, agent := range inventory.Agents {
			pageEnsureStaticAgentFromInventory(&agents, agentIndex, agent)
		}
	} else {
		warnings = append(warnings, err.Error())
	}

	for i := range agents {
		sort.Slice(agents[i].Resources, func(a, b int) bool {
			left, right := agents[i].Resources[a], agents[i].Resources[b]
			if pageRiskRank(left.Risk) != pageRiskRank(right.Risk) {
				return pageRiskRank(left.Risk) > pageRiskRank(right.Risk)
			}
			if left.UpdatedAt != right.UpdatedAt {
				return left.UpdatedAt > right.UpdatedAt
			}
			return left.Name < right.Name
		})
	}
	sort.Slice(agents, func(i, j int) bool {
		ri, rj := pageAgentMaxRisk(agents[i].Resources), pageAgentMaxRisk(agents[j].Resources)
		if pageRiskRank(ri) != pageRiskRank(rj) {
			return pageRiskRank(ri) > pageRiskRank(rj)
		}
		if len(agents[i].Resources) != len(agents[j].Resources) {
			return len(agents[i].Resources) > len(agents[j].Resources)
		}
		return agents[i].Name < agents[j].Name
	})

	warning := strings.Join(warnings, "; ")
	if warning == "" && pageStaticResourceTotal(agents) == 0 {
		warning = "gateway has no static resource inventory yet"
	}
	var last *string
	if lastScan != "" {
		last = &lastScan
	}
	return pageStaticSnapshot{
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:     source,
		LastScanAt: last,
		Agents:     agents,
		Warning:    warning,
	}, nil
}

func (a *APIServer) pageStaticResourceFromScan(row audit.StaticScanResultRow) pageStaticResource {
	raw := map[string]any{}
	_ = json.Unmarshal([]byte(row.RawJSON), &raw)
	rtype := pageStaticType(pageFirstNonEmpty(row.TargetType, pageMapString(raw, "target_type"), pageMapString(raw, "targetType")), row.Scanner, row.Target)
	findings := []pageStaticFinding{}
	if a.store != nil {
		rows, err := a.store.ListScanFindings(row.ID)
		if err == nil {
			for _, f := range rows {
				findings = append(findings, pageStaticFindingFromRow(f))
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return pageRiskRank(findings[i].Severity) > pageRiskRank(findings[j].Severity)
	})
	hash := pageFirstNonEmpty(row.ContentHash, pageMapString(raw, "content_hash"), pageMapString(raw, "contentHash"), "-")
	risk := pageHighestRisk(row.MaxSeverity, findings)
	size, perms := pageFileMetadata(row.Target)
	updated := row.CapturedAt
	if updated == "" {
		updated = row.Timestamp
	}
	if updated == "" {
		updated = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return pageStaticResource{
		ID:          pageFirstNonEmpty(row.StaticResourceID, row.ID),
		Name:        pageResourceName(row.Target, rtype),
		Type:        rtype,
		Kind:        pageResourceKind(rtype),
		Path:        row.Target,
		Risk:        risk,
		Status:      pageStatusForRisk(risk),
		UpdatedAt:   updated,
		Size:        size,
		Permissions: perms,
		Hash:        hash,
		Description: fmt.Sprintf("Gateway scanner %s reported %d finding(s).", row.Scanner, len(findings)),
		ContentPreview: fmt.Sprintf(
			"scanner: %s\nscan_id: %s\ntarget_type: %s\ntarget: %s\nlast_scan: %s\nfinding_count: %d\nmax_risk: %s\ncontent_hash: %s",
			row.Scanner, row.ID, rtype, row.Target, row.Timestamp, len(findings), risk, hash,
		),
		Findings:  findings,
		Relations: []pageStaticRelation{},
	}
}

func (a *APIServer) buildPageEventDetections(limit int) (pageEventSnapshot, error) {
	if a.store == nil {
		return pageEventSnapshot{}, fmt.Errorf("audit store is not attached")
	}
	events := []pageEvent{}
	var warnings []string
	auditRows, err := a.store.ListEvents(limit)
	if err != nil {
		return pageEventSnapshot{}, err
	}
	for _, row := range auditRows {
		if pageAuditEventRelevant(row) {
			events = append(events, pageEventFromAudit(row))
		}
	}
	findings, err := a.store.ListRecentRuntimeFindings(limit)
	if err == nil {
		for _, row := range findings {
			events = append(events, pageEventFromRuntimeFinding(row))
		}
	} else {
		warnings = append(warnings, err.Error())
	}
	// Phase-2: load structured runtime detections first so behavior
	// events that are detection evidence (a) always appear and (b) get
	// their kind/severity from detection category/severity —
	// structured data instead of pageClassifyEventKind string
	// matching, which remains only as the legacy fallback.
	detections, err := a.store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: limit})
	if err != nil {
		warnings = append(warnings, err.Error())
		detections = nil
	}
	behaviorRows, err := a.store.ListBehaviorEvents(limit)
	if err == nil {
		behaviorIDs := make([]int64, 0, len(behaviorRows))
		for _, row := range behaviorRows {
			behaviorIDs = append(behaviorIDs, row.ID)
		}
		detectionByEvent, mapErr := a.store.DetectionIDsForEvents(behaviorIDs)
		if mapErr != nil {
			warnings = append(warnings, mapErr.Error())
		}
		for _, row := range behaviorRows {
			dets := detectionByEvent[row.ID]
			if pageBehaviorEventRelevant(row) || len(dets) > 0 {
				ev := pageEventFromBehavior(row)
				if len(dets) > 0 {
					ev = pageUpgradeEventFromDetections(ev, dets)
				}
				events = append(events, ev)
			}
		}
	} else {
		warnings = append(warnings, err.Error())
	}
	agentInventory, err := a.buildPageAgentInventory(limit)
	if err != nil {
		warnings = append(warnings, err.Error())
	}
	for i := range events {
		events[i] = pageCanonicalizeEventAgent(events[i], agentInventory.Agents)
	}
	events = pageDedupeEvents(events)
	sort.Slice(events, func(i, j int) bool {
		return events[i].OccurredAt > events[j].OccurredAt
	})
	if len(events) > limit {
		events = events[:limit]
	}
	summary, sources, agents, timeline := pageBuildEventAnalytics(events)
	agents = pageMergeEventAgentsFromInventory(agents, agentInventory.Agents)
	summary.Agents = len(agents)
	summary.Detections = len(detections)
	for _, d := range detections {
		if d.Category == "attack" {
			summary.AttackDetections++
		}
		if d.Status == audit.RuntimeDetectionStatusOpen {
			summary.OpenDetections++
		}
	}
	return pageEventSnapshot{
		CapturedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		Source:          "gateway:audit_events + scan_findings + behavior_events + runtime_detections",
		Summary:         summary,
		SourceBreakdown: sources,
		AgentBreakdown:  agents,
		Timeline:        timeline,
		Events:          events,
		Detections:      detections,
		Warning:         strings.Join(warnings, "; "),
	}, nil
}

// pageUpgradeEventFromDetections promotes a page event to
// detection-backed classification: kind from detection category,
// severity/risk from detection severity. The legacy string-matching
// classification stays only for events without structured detections.
func pageUpgradeEventFromDetections(ev pageEvent, detections []audit.RuntimeDetection) pageEvent {
	for _, d := range detections {
		if strings.EqualFold(d.Category, "attack") {
			ev.Kind = "attack"
		} else if ev.Kind == "behavior" || ev.Kind == "security" {
			ev.Kind = "security"
		}
		if rank := pageRiskRank(d.Severity); rank > ev.RiskScore {
			ev.Severity = strings.ToUpper(d.Severity)
			ev.RiskScore = rank
		}
		if strings.EqualFold(d.Status, audit.RuntimeDetectionStatusMitigated) && ev.Status == "observed" {
			ev.Status = "detected"
		}
		if ev.DetectionID == "" {
			ev.DetectionID = d.DetectionID
			ev.DetectionType = d.DetectionType
			ev.DetectionSeverity = strings.ToUpper(d.Severity)
		}
	}
	return ev
}

func (a *APIServer) buildPageGatewayAudit(limit int, connectorName string) (pageGatewayAuditSnapshot, error) {
	if a.store == nil {
		return pageGatewayAuditSnapshot{}, fmt.Errorf("audit store is not attached")
	}
	connectorName = strings.TrimSpace(strings.ToLower(connectorName))
	if connectorName == "" {
		connectorName = "agentrange"
	}
	rows, err := a.store.ListEvents(limit)
	if err != nil {
		return pageGatewayAuditSnapshot{}, err
	}
	events := []pageGatewayAuditRecord{}
	for _, row := range rows {
		if connectorName != "all" && strings.ToLower(row.Connector) != connectorName {
			continue
		}
		events = append(events, pageGatewayAuditFromEvent(row))
	}
	return pageGatewayAuditSnapshot{
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source:     "gateway:/api/v1/gateway-audit",
		Events:     events,
	}, nil
}

func pageEnsureDraft(drafts map[string]*pageAgentDraft, desc pageAgentDescriptor) *pageAgentDraft {
	id := pageCanonicalAgentID(desc.ID)
	if id == "" {
		id = pageCanonicalAgentID(desc.Product)
	}
	d := drafts[id]
	if d == nil {
		d = &pageAgentDraft{
			ID:              id,
			Product:         pageFirstNonEmpty(desc.Product, id),
			Vendor:          pageFirstNonEmpty(desc.Vendor, "Unknown"),
			Kind:            pageFirstNonEmpty(desc.Kind, "unknown"),
			Runtime:         pageFirstNonEmpty(desc.Runtime, desc.Kind, "Agent Runtime"),
			Description:     desc.Description,
			Sources:         map[string]bool{},
			ConfigRoots:     map[string]pageConfigRoot{},
			ExecutableNames: map[string]bool{},
		}
		drafts[id] = d
	}
	if d.Description == "" && desc.Description != "" {
		d.Description = desc.Description
	}
	if desc.Source != "" {
		d.Sources[desc.Source] = true
	}
	return d
}

func pageFinalizeAgent(d *pageAgentDraft) pageAgent {
	sort.Slice(d.Processes, func(i, j int) bool {
		left, right := "", ""
		if d.Processes[i].StartedAt != nil {
			left = *d.Processes[i].StartedAt
		}
		if d.Processes[j].StartedAt != nil {
			right = *d.Processes[j].StartedAt
		}
		if left != right {
			return left < right
		}
		return d.Processes[i].PID < d.Processes[j].PID
	})
	running := len(d.Processes) > 0 || len(d.RangeServices) > 0
	pids := []uint32{}
	for _, proc := range d.Processes {
		pids = append(pids, proc.PID)
	}
	pids = pageNormalizePIDs(pids)
	var primaryPID *uint32
	var startedAt *string
	var uptime *uint64
	if len(pids) > 0 {
		pid := pids[0]
		primaryPID = &pid
	}
	if len(d.Processes) > 0 {
		startedAt = d.Processes[0].StartedAt
		up := d.Processes[0].UptimeSec
		uptime = &up
	}
	configRoots := make([]pageConfigRoot, 0, len(d.ConfigRoots))
	for _, root := range d.ConfigRoots {
		configRoots = append(configRoots, root)
	}
	sort.Slice(configRoots, func(i, j int) bool { return configRoots[i].Path < configRoots[j].Path })
	exes := pageSortedKeys(d.ExecutableNames)
	sources := pageSortedKeys(d.Sources)
	status := "unknown"
	switch {
	case running:
		status = "running"
	case len(configRoots) > 0 || d.StaticResourceCount > 0:
		status = "stopped"
	}
	var last *string
	if d.LastStaticScanAt != "" {
		last = &d.LastStaticScanAt
	}
	runtimeStatus := pageRuntimeStatusFromRunning(running)
	description := d.Description
	if description == "" {
		if running {
			description = d.Product + " is running; runtime and static signals are available."
		} else {
			description = d.Product + " is installed or configured, but no running process is currently visible."
		}
	}
	return pageAgent{
		ID:                    d.ID,
		Product:               d.Product,
		Vendor:                d.Vendor,
		Kind:                  d.Kind,
		Status:                runtimeStatus,
		RuntimeStatus:         runtimeStatus,
		Running:               running,
		ProcessCount:          len(d.Processes) + len(d.RangeServices),
		PIDs:                  pids,
		PrimaryPID:            primaryPID,
		ExecutableNames:       exes,
		DiscoveryStatus:       pageDiscoveryStatus(status, ""),
		PrimaryPath:           pageAgentPrimaryPath(configRoots, nil, strings.Join(sources, ", ")),
		LastSeenScanAt:        last,
		StartedAt:             startedAt,
		UptimeSec:             uptime,
		Source:                strings.Join(sources, ", "),
		ConfigRoots:           configRoots,
		StaticResourceCount:   d.StaticResourceCount,
		RiskResourceCount:     d.RiskResourceCount,
		CriticalResourceCount: d.CriticalResourceCount,
		LastStaticScanAt:      last,
		Description:           description,
	}
}

func (a *APIServer) pageDiscoverAgentDescriptors() []pageAgentDescriptor {
	if a != nil && a.store != nil {
		rules, err := a.store.ListEnabledAgentDiscoveryRules()
		if err == nil && len(rules) > 0 {
			out := []pageAgentDescriptor{}
			for _, rule := range rules {
				d := a.evaluateAgentDiscoveryRule(rule)
				if !pageAgentDetectionTrusted(d) {
					continue
				}
				desc := d.Desc
				for _, root := range d.ConfigRoots {
					desc.Roots = append(desc.Roots, root)
				}
				if len(desc.Roots) > 0 {
					out = append(out, desc)
				}
			}
			return pageDedupeDescriptors(out)
		}
	}

	var out []pageAgentDescriptor
	if desc := pageAgentRangeDescriptor(a.scannerCfg); desc.ID != "" && len(desc.Roots) > 0 {
		out = append(out, desc)
	}
	cfg := a.scannerCfg
	sigs, err := inventory.LoadAISignaturesForConfig(cfg)
	if err == nil {
		for _, sig := range sigs {
			if sig.SupportedConnector == "" && sig.Category != inventory.SignalSupportedConnector {
				continue
			}
			desc := pageDescriptorFromSignature(sig)
			for _, pattern := range sig.ConfigPaths {
				for _, path := range pageExpandConfigPath(pattern, cfg) {
					if path == "" {
						continue
					}
					if _, err := os.Stat(path); err == nil {
						desc.Roots = append(desc.Roots, pageConfigRoot{Path: path, Kind: pageConfigKind(path), Exists: true})
					}
				}
			}
			if len(desc.Roots) > 0 {
				out = append(out, desc)
			}
		}
	}
	out = append(out, pageHardcodedAgentDescriptors()...)
	return pageDedupeDescriptors(out)
}

func pageDescriptorFromSignature(sig inventory.AISignature) pageAgentDescriptor {
	id := pageCanonicalAgentID(pageFirstNonEmpty(sig.SupportedConnector, sig.ID, pageStableID(sig.Name)))
	return pageAgentDescriptor{
		ID:          id,
		Product:     pageFirstNonEmpty(sig.Name, id),
		Vendor:      pageFirstNonEmpty(sig.Vendor, "Unknown"),
		Kind:        pageFirstNonEmpty(sig.Category, "agent"),
		Runtime:     "Agent",
		Source:      "ai-signature",
		Description: pageFirstNonEmpty(sig.Name, id) + " static configuration and runtime signals.",
	}
}

func pageDescriptorFromCanonicalAgent(row audit.CanonicalAgent) pageAgentDescriptor {
	return pageAgentDescriptor{
		ID:          pageCanonicalAgentID(row.ID),
		Product:     pageFirstNonEmpty(row.DisplayName, row.ID),
		Vendor:      pageFirstNonEmpty(row.Vendor, "Unknown"),
		Kind:        pageFirstNonEmpty(row.Kind, "agent"),
		Runtime:     pageFirstNonEmpty(row.Runtime, pageRuntimeLabel(row.Kind)),
		Source:      pageFirstNonEmpty(row.Source, "agents"),
		Description: pageFirstNonEmpty(row.DisplayName, row.ID) + " unified backend inventory record.",
	}
}

func pageDescriptorFromStaticScan(row audit.StaticScanResultRow, resourceType string) pageAgentDescriptor {
	if row.CanonicalAgentID != "" || row.AgentDisplayName != "" {
		return pageAgentDescriptor{
			ID:          pageCanonicalAgentID(row.CanonicalAgentID),
			Product:     pageFirstNonEmpty(row.AgentDisplayName, row.AgentName, row.AgentID, row.CanonicalAgentID),
			Vendor:      pageFirstNonEmpty(row.AgentVendor, "Unknown"),
			Kind:        pageFirstNonEmpty(row.AgentKind, "agent"),
			Runtime:     pageFirstNonEmpty(row.AgentRuntime, pageRuntimeLabel(row.AgentKind)),
			Source:      "backend-static",
			Description: pageFirstNonEmpty(row.AgentDisplayName, row.AgentName, row.CanonicalAgentID, "Agent") + " static resources discovered by the gateway.",
		}
	}
	return pageInferAgent(row.Target, resourceType)
}

func pageDescriptorFromSignal(sig inventory.AISignal) pageAgentDescriptor {
	id := pageCanonicalAgentID(pageFirstNonEmpty(sig.SupportedConnector, sig.SignatureID, pageStableID(sig.Product), pageStableID(sig.Name)))
	return pageAgentDescriptor{
		ID:          id,
		Product:     pageFirstNonEmpty(sig.Product, sig.Name, id),
		Vendor:      pageFirstNonEmpty(sig.Vendor, "Unknown"),
		Kind:        pageFirstNonEmpty(sig.Category, "agent"),
		Runtime:     "Agent",
		Source:      "ai-discovery",
		Description: pageFirstNonEmpty(sig.Product, sig.Name, id) + " AI discovery signal.",
	}
}

func pageProcessFromSignal(sig inventory.AISignal) pageProcess {
	var started *string
	var uptime uint64
	var pid, ppid uint32
	name := pageFirstNonEmpty(sig.Name, sig.Product, sig.SignatureID)
	if sig.Runtime != nil {
		if !sig.Runtime.StartedAt.IsZero() {
			ts := sig.Runtime.StartedAt.UTC().Format(time.RFC3339Nano)
			started = &ts
		}
		if sig.Runtime.UptimeSec > 0 {
			uptime = uint64(sig.Runtime.UptimeSec)
		}
		if sig.Runtime.PID > 0 {
			pid = uint32(sig.Runtime.PID)
		}
		if sig.Runtime.PPID > 0 {
			ppid = uint32(sig.Runtime.PPID)
		}
		name = pageFirstNonEmpty(sig.Runtime.Comm, name)
	}
	return pageProcess{
		PID:       pid,
		PPID:      ppid,
		Name:      name,
		Product:   pageFirstNonEmpty(sig.Product, sig.Name),
		Vendor:    pageFirstNonEmpty(sig.Vendor, "Unknown"),
		StartedAt: started,
		UptimeSec: uptime,
		Source:    "gateway",
	}
}

func pageAgentRangeDescriptor(cfg *config.Config) pageAgentDescriptor {
	root := ""
	if cfg != nil {
		root = pageFirstNonEmpty(cfg.Claw.WorkspaceDir, cfg.Claw.HomeDir)
	}
	if root == "" || !pageLooksLikeAgentRangeRoot(root) {
		return pageAgentDescriptor{}
	}
	return pageAgentDescriptor{
		ID:          "agentrange-opspilot",
		Product:     "AgentRange / OpsPilot",
		Vendor:      "TraceBastion Lab",
		Kind:        "agent-platform",
		Runtime:     "AgentRange",
		Source:      "agentrange",
		Description: "AgentRange lab platform static configuration and runtime signals.",
		Roots:       []pageConfigRoot{{Path: root, Kind: "AgentRange root", Exists: true}},
	}
}

func pageHardcodedAgentDescriptors() []pageAgentDescriptor {
	home, _ := os.UserHomeDir()
	appData := os.Getenv("APPDATA")
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" && home != "" {
		configHome = filepath.Join(home, ".config")
	}
	type item struct {
		id, product, vendor, kind, runtime, root, label string
	}
	items := []item{}
	if home != "" {
		items = append(items,
			item{"openclaw", "OpenClaw", "DefenseClaw", "agent-platform", "OpenClaw", filepath.Join(home, ".openclaw"), "OpenClaw config"},
			item{"claude-code", "Claude Code", "Anthropic", "terminal-agent", "CLI Agent", filepath.Join(home, ".claude"), "Claude config"},
			item{"codex", "OpenAI Codex", "OpenAI", "terminal-agent", "CLI Agent", filepath.Join(home, ".codex"), "Codex config"},
			item{"gemini", "Gemini CLI", "Google", "terminal-agent", "CLI Agent", filepath.Join(home, ".gemini"), "Gemini config"},
			item{"aider", "Aider", "Aider", "terminal-agent", "CLI Agent", filepath.Join(home, ".aider.conf.yml"), "Aider config"},
			item{"cursor", "Cursor", "Anysphere", "editor-agent", "IDE Agent", filepath.Join(home, ".cursor"), "Cursor config"},
		)
	}
	if configHome != "" {
		items = append(items, item{"opencode", "OpenCode", "OpenCode", "terminal-agent", "CLI Agent", filepath.Join(configHome, "opencode"), "OpenCode config"})
	}
	if appData != "" {
		items = append(items,
			item{"cursor", "Cursor", "Anysphere", "editor-agent", "IDE Agent", filepath.Join(appData, "Cursor", "User"), "Cursor user config"},
			item{"cline", "Cline", "Cline", "editor-agent", "IDE Agent", filepath.Join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev"), "Cline storage"},
			item{"roo-code", "Roo Code", "Roo Code", "editor-agent", "IDE Agent", filepath.Join(appData, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline"), "Roo Code storage"},
			item{"qoder", "Qoder", "Qoder", "ide-agent", "IDE Agent", filepath.Join(appData, "Qoder"), "Qoder config"},
			item{"trae", "Trae", "ByteDance", "desktop-agent", "Desktop Agent", filepath.Join(appData, "Trae"), "Trae config"},
			item{"cherry-studio", "Cherry Studio", "Cherry Studio", "desktop-agent", "Desktop Agent", filepath.Join(appData, "CherryStudio"), "Cherry Studio config"},
			item{"cherry-studio", "Cherry Studio", "Cherry Studio", "desktop-agent", "Desktop Agent", filepath.Join(appData, "Cherry Studio"), "Cherry Studio config"},
		)
	}
	out := []pageAgentDescriptor{}
	for _, it := range items {
		if _, err := os.Stat(it.root); err != nil {
			continue
		}
		out = append(out, pageAgentDescriptor{
			ID:          it.id,
			Product:     it.product,
			Vendor:      it.vendor,
			Kind:        it.kind,
			Runtime:     it.runtime,
			Source:      "filesystem",
			Description: it.product + " static configuration and runtime process signals.",
			Roots:       []pageConfigRoot{{Path: it.root, Kind: it.label, Exists: true}},
		})
	}
	return out
}

func pageDedupeDescriptors(in []pageAgentDescriptor) []pageAgentDescriptor {
	byID := map[string]*pageAgentDescriptor{}
	order := []string{}
	for _, desc := range in {
		desc.ID = pageCanonicalAgentID(desc.ID)
		if desc.ID == "" {
			continue
		}
		existing := byID[desc.ID]
		if existing == nil {
			copyDesc := desc
			copyDesc.Roots = nil
			byID[desc.ID] = &copyDesc
			order = append(order, desc.ID)
			existing = &copyDesc
			byID[desc.ID] = existing
		}
		seen := map[string]bool{}
		for _, root := range existing.Roots {
			seen[pagePathKey(root.Path)] = true
		}
		for _, root := range desc.Roots {
			if !seen[pagePathKey(root.Path)] {
				existing.Roots = append(existing.Roots, root)
				seen[pagePathKey(root.Path)] = true
			}
		}
	}
	out := make([]pageAgentDescriptor, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

func pageExpandConfigPath(pattern string, cfg *config.Config) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	var out []string
	if strings.HasPrefix(pattern, "~/") || pattern == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			out = append(out, filepath.Join(home, strings.TrimPrefix(pattern, "~/")))
		}
		return out
	}
	expanded := os.ExpandEnv(pattern)
	if filepath.IsAbs(expanded) {
		return []string{expanded}
	}
	if cfg != nil && cfg.Claw.WorkspaceDir != "" {
		out = append(out, filepath.Join(cfg.Claw.WorkspaceDir, expanded))
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, filepath.Join(wd, expanded))
	}
	return out
}

func pageExpandDiscoveryPath(pattern string, cfg *config.Config) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	pattern = pageExpandPercentEnv(pattern)
	return pageExpandConfigPath(pattern, cfg)
}

func pageExpandPercentEnv(value string) string {
	for {
		start := strings.Index(value, "%")
		if start < 0 {
			return os.ExpandEnv(value)
		}
		end := strings.Index(value[start+1:], "%")
		if end < 0 {
			return os.ExpandEnv(value)
		}
		end += start + 1
		name := value[start+1 : end]
		if strings.TrimSpace(name) == "" {
			return os.ExpandEnv(value)
		}
		replacement := os.Getenv(name)
		if replacement == "" {
			return ""
		}
		value = value[:start] + replacement + value[end+1:]
	}
}

func pageOperatorAllows(operator string, allowed ...string) bool {
	operator = strings.ToLower(strings.TrimSpace(operator))
	if operator == "" {
		operator = "exists"
	}
	for _, candidate := range allowed {
		if operator == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func pageStringOperatorMatch(haystack, needle, operator string) bool {
	haystack = strings.ToLower(strings.TrimSpace(haystack))
	needle = strings.ToLower(strings.TrimSpace(needle))
	switch strings.ToLower(strings.TrimSpace(operator)) {
	case "equals", "eq":
		return haystack == needle
	case "contains", "":
		return strings.Contains(haystack, needle)
	default:
		return strings.Contains(haystack, needle)
	}
}

func pageDiscoveryConditionIsInstallPath(c audit.AgentDiscoveryCondition, path string) bool {
	field := strings.ToLower(strings.TrimSpace(c.Field))
	if field == "executable_path" || field == "install_path" {
		return true
	}
	return strings.EqualFold(filepath.Ext(path), ".exe")
}

func pageConfigKind(path string) string {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return "config directory"
	}
	return "config file"
}

func pageAgentRangeRunningServices(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	root := pageFirstNonEmpty(cfg.Claw.WorkspaceDir, cfg.Claw.HomeDir)
	compose := filepath.Join(root, "docker-compose.yml")
	if _, err := os.Stat(compose); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", compose, "ps", "--services", "--filter", "status=running")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	var services []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			services = append(services, line)
		}
	}
	return services
}

func (a *APIServer) pageDiscoverStaticCandidates(limit int) []pageStaticCandidate {
	if limit <= 0 {
		limit = 600
	}
	var out []pageStaticCandidate
	for _, desc := range a.pageDiscoverAgentDescriptors() {
		for _, root := range desc.Roots {
			out = append(out, pageStaticCandidatesForRoot(desc, root.Path, limit-len(out))...)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func pageStaticCandidatesForRoot(agent pageAgentDescriptor, root string, remaining int) []pageStaticCandidate {
	if remaining <= 0 {
		return nil
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		if rtype := pageCandidateType(root, false); rtype != "" {
			return []pageStaticCandidate{{Agent: agent, Type: rtype, Path: root}}
		}
		return nil
	}
	var out []pageStaticCandidate
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || len(out) >= remaining {
			return nil
		}
		if path != root && entry.IsDir() {
			name := strings.ToLower(entry.Name())
			if pageSkipDir(name) {
				return filepath.SkipDir
			}
			if pagePathDepth(root, path) > 5 {
				return filepath.SkipDir
			}
			if rtype := pageCandidateType(path, true); rtype == "Skills" || rtype == "Plugin" || rtype == "MCP" {
				out = append(out, pageStaticCandidate{Agent: agent, Type: rtype, Path: path})
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if rtype := pageCandidateType(path, false); rtype != "" {
			out = append(out, pageStaticCandidate{Agent: agent, Type: rtype, Path: path})
		}
		return nil
	})
	return out
}

func pageSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv", "cache", "logs":
		return true
	default:
		return false
	}
}

func pagePathDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return len(strings.Split(rel, string(os.PathSeparator)))
}

func pageCandidateType(path string, isDir bool) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))
	if strings.Contains(lower, "/skills") || base == "skills" || strings.Contains(base, "skill") {
		return "Skills"
	}
	if strings.Contains(lower, "/plugins") || strings.Contains(lower, "/extensions") || strings.Contains(base, "plugin") {
		return "Plugin"
	}
	if strings.Contains(lower, "/mcp") || base == ".mcp.json" || strings.Contains(base, "mcp") {
		return "MCP"
	}
	if isDir {
		return ""
	}
	if base == ".env" || strings.Contains(base, "credential") || strings.Contains(base, "secret") || strings.Contains(base, "token") || strings.Contains(base, "api_key") || strings.Contains(base, "apikey") {
		return "Credential"
	}
	if strings.Contains(base, "prompt") || strings.Contains(base, "rules") || base == "agents.md" || base == "claude.md" || base == ".cursorrules" {
		return "Prompt"
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config":
		return "Config"
	case ".md", ".txt":
		return "Prompt"
	default:
		return ""
	}
}

func pageStaticResourceFromCandidate(candidate pageStaticCandidate) pageStaticResource {
	size, perms := pageFileMetadata(candidate.Path)
	updated := time.Now().UTC().Format(time.RFC3339Nano)
	if st, err := os.Stat(candidate.Path); err == nil {
		updated = st.ModTime().UTC().Format(time.RFC3339Nano)
	}
	hash := "filesystem:" + pagePathKey(candidate.Path)
	return pageStaticResource{
		ID:             "fs-" + pageStableID(candidate.Path),
		Name:           pageResourceName(candidate.Path, candidate.Type),
		Type:           candidate.Type,
		Kind:           pageResourceKind(candidate.Type),
		Path:           candidate.Path,
		Risk:           "info",
		Status:         "discovered",
		UpdatedAt:      updated,
		Size:           size,
		Permissions:    perms,
		Hash:           hash,
		Description:    "Gateway discovered this static resource from the local filesystem; scan findings will attach after the watcher processes it.",
		ContentPreview: fmt.Sprintf("Resource discovered from local filesystem.\nType: %s\nPath: %s\nScan state: pending backend scan\nIdentity: %s", candidate.Type, candidate.Path, hash),
		Findings:       []pageStaticFinding{},
		Relations:      []pageStaticRelation{},
	}
}

func pagePushStaticResource(agents *[]pageStaticAgent, index map[string]int, desc pageAgentDescriptor, resource pageStaticResource) {
	i := pageEnsureStaticAgent(agents, index, desc)
	(*agents)[i].Resources = append((*agents)[i].Resources, resource)
}

func pageStaticResourceTotal(agents []pageStaticAgent) int {
	total := 0
	for _, agent := range agents {
		total += len(agent.Resources)
	}
	return total
}

func pageEnsureStaticAgent(agents *[]pageStaticAgent, index map[string]int, desc pageAgentDescriptor) int {
	id := pageCanonicalAgentID(pageFirstNonEmpty(desc.ID, pageStableID(desc.Product)))
	if id == "" {
		id = "unknown-agent"
	}
	i, ok := index[id]
	if !ok {
		i = len(*agents)
		index[id] = i
		*agents = append(*agents, pageStaticAgent{
			ID:          id,
			Name:        pageFirstNonEmpty(desc.Product, id),
			Runtime:     pageFirstNonEmpty(desc.Runtime, pageRuntimeLabel(desc.Kind), desc.Kind, "Agent"),
			Source:      desc.Source,
			Description: pageFirstNonEmpty(desc.Description, pageFirstNonEmpty(desc.Product, id)+" static resources."),
			Resources:   []pageStaticResource{},
		})
	}
	return i
}

func pageEnsureStaticAgentFromInventory(agents *[]pageStaticAgent, index map[string]int, agent pageAgent) {
	pageEnsureStaticAgent(agents, index, pageAgentDescriptor{
		ID:          agent.ID,
		Product:     agent.Product,
		Vendor:      agent.Vendor,
		Kind:        agent.Kind,
		Runtime:     pageRuntimeLabel(agent.Kind),
		Source:      agent.Source,
		Description: agent.Description,
	})
}

func pageStaticFindingFromRow(row audit.ScanFindingRow) pageStaticFinding {
	severity := pageNormalizeRisk(row.Severity)
	title := pageFirstNonEmpty(row.Title.String, row.RuleID.String, "Gateway static resource finding")
	location := row.Location.String
	if location == "" && row.LineNumber.Valid {
		location = fmt.Sprintf("line %d", row.LineNumber.Int64)
	} else if location != "" && row.LineNumber.Valid {
		location = fmt.Sprintf("%s: line %d", location, row.LineNumber.Int64)
	}
	if location == "" {
		location = "backend scan"
	}
	return pageStaticFinding{
		ID:             row.ID,
		Title:          title,
		Severity:       severity,
		Description:    pageFirstNonEmpty(row.Description.String, "Gateway scanner reported a finding for this static resource."),
		Location:       location,
		Evidence:       pageFirstNonEmpty(row.RuleID.String, row.Location.String, row.ID),
		Recommendation: pageFirstNonEmpty(row.Remediation.String, "Review ownership, reduce permissions, and move sensitive values into a controlled secret store."),
	}
}

func pageAuditEventRelevant(row audit.Event) bool {
	text := strings.ToLower(strings.Join([]string{row.Action, row.Severity, row.Target, row.Details, row.ToolName}, " "))
	return strings.Contains(text, "guardrail") ||
		strings.Contains(text, "inspect") ||
		strings.Contains(text, "network-egress") ||
		strings.Contains(text, "block") ||
		strings.Contains(text, "terminate") ||
		strings.Contains(text, "runtime") ||
		strings.Contains(text, "alert") ||
		pageRiskRank(pageNormalizeRisk(row.Severity)) >= 3
}

func pageEventFromAudit(row audit.Event) pageEvent {
	severity := pageNormalizeRisk(pageFirstNonEmpty(row.Severity, pageStructuredString(row.Structured, "severity")))
	decision := pageFirstNonEmpty(pageStructuredString(row.Structured, "decision"), pageStructuredString(row.Structured, "verdict"), row.Action)
	status := pageStatusFromText(row.Action + " " + row.Details + " " + decision)
	category := pageAuditCategory(row)
	reason := pageStructuredString(row.Structured, "reason")
	prompt := pageStructuredString(row.Structured, "prompt")
	evidence := pageFirstNonEmpty(row.Details, reason, prompt, row.Target, "-")
	agent := pageCanonicalAgentDisplay(row.CanonicalAgentID, row.AgentName, pageStructuredString(row.Structured, "agent_name"), row.Connector, "Gateway")
	runtime := pageCanonicalAgentRuntime(row.CanonicalAgentID, row.Connector, row.DestinationApp, "TraceBastion Gateway")
	trace := pageFirstNonEmpty(row.TraceID, pageStructuredString(row.Structured, "trace_id"))
	session := pageFirstNonEmpty(row.SessionID, pageStructuredString(row.Structured, "session_id"))
	destination := pageFirstNonEmpty(row.DestinationApp, pageStructuredString(row.Structured, "destination_app"))
	tool := pageFirstNonEmpty(row.ToolName, pageStructuredString(row.Structured, "tool_name"))
	text := strings.Join([]string{row.Action, row.Details, row.Target, row.ToolName, category}, " ")
	return pageFinalizeEvent(pageEvent{
		ID:             "audit:" + row.ID,
		OccurredAt:     row.Timestamp.UTC().Format(time.RFC3339Nano),
		Kind:           pageClassifyEventKind(severity, status, text),
		Agent:          agent,
		Runtime:        runtime,
		Category:       category,
		Subtype:        pageFirstNonEmpty(pageStructuredString(row.Structured, "stage"), tool, row.Action, "runtime"),
		Title:          pageAuditTitle(row),
		Severity:       severity,
		Status:         status,
		Evidence:       evidence,
		Action:         pageActionText(status, row.Action),
		TraceID:        trace,
		SessionID:      session,
		Source:         "audit_events",
		RawAction:      row.Action,
		Target:         pageFirstNonEmpty(row.Target, pageStructuredString(row.Structured, "target")),
		Actor:          pageFirstNonEmpty(row.Actor, "defenseclaw"),
		Connector:      row.Connector,
		DestinationApp: destination,
		ToolName:       tool,
		Model:          pageStructuredString(row.Structured, "model"),
		MCPServer:      pageStructuredString(row.Structured, "mcp_server"),
		Decision:       decision,
		Reason:         reason,
		Remediation:    pageStatusAction(status),
	})
}

func pageEventFromRuntimeFinding(row audit.RuntimeScanFindingRow) pageEvent {
	severity := pageNormalizeRisk(row.Severity)
	text := strings.Join([]string{row.Scanner, row.RuleID, row.Category, row.Title, row.Description, row.Location}, " ")
	status := pageStatusFromText(text)
	agent := pageCanonicalAgentDisplay(row.CanonicalAgentID, row.AgentName, row.AgentID, row.AgentInstanceID, "Gateway Runtime")
	runtime := pageCanonicalAgentRuntime(row.CanonicalAgentID, row.Scanner)
	return pageFinalizeEvent(pageEvent{
		ID:             "finding:" + row.ID,
		OccurredAt:     row.Timestamp,
		Kind:           pageClassifyEventKind(severity, status, text),
		Agent:          agent,
		Runtime:        runtime,
		Category:       pageFirstNonEmpty(row.Category, "runtime finding"),
		Subtype:        pageFirstNonEmpty(row.RuleID, row.Scanner, "finding"),
		Title:          pageFirstNonEmpty(row.Title, row.RuleID, row.Scanner, "Runtime finding"),
		Severity:       severity,
		Status:         status,
		Evidence:       pageFirstNonEmpty(row.Location, row.Description, row.Target, "-"),
		Action:         pageFirstNonEmpty(row.Remediation, "record finding and preserve evidence"),
		TraceID:        pageFirstNonEmpty(row.TraceID, row.EvaluationID),
		SessionID:      pageFirstNonEmpty(row.SessionID, row.ScanID),
		Source:         "scan_findings",
		RawAction:      row.Scanner,
		Target:         row.Target,
		Actor:          "runtime scanner",
		Connector:      pageFirstNonEmpty(row.CanonicalAgentID, row.AgentID),
		DestinationApp: row.Scanner,
		ToolName:       row.RuleID,
		Decision:       pageFirstNonEmpty(pageStatusAction(status), status),
		Reason:         pageFirstNonEmpty(row.Description, row.Location),
		Remediation:    row.Remediation,
	})
}

func pageFinalizeEvent(event pageEvent) pageEvent {
	event.Severity = pageNormalizeRisk(event.Severity)
	event.RiskScore = pageRiskRank(event.Severity)
	if event.Kind == "" {
		event.Kind = pageClassifyEventKind(event.Severity, event.Status, pageEventText(event))
	}
	if event.Status == "" {
		event.Status = pageStatusFromText(event.RawAction + " " + event.Action + " " + event.Evidence)
	}
	if event.Title == "" {
		event.Title = pageFirstNonEmpty(event.RawAction, event.Subtype, "Detected event")
	}
	if event.Agent == "" {
		event.Agent = "Unknown Agent"
	}
	if event.Runtime == "" {
		event.Runtime = "Unknown Runtime"
	}
	if event.Source == "" {
		event.Source = "gateway"
	}
	if event.Decision == "" {
		event.Decision = pageFirstNonEmpty(event.Action, pageStatusAction(event.Status))
	}
	if event.Remediation == "" {
		event.Remediation = pageStatusAction(event.Status)
	}
	event.CorrelationKey = pageEventCorrelationKey(event)
	return event
}

func pageEventCorrelationKey(event pageEvent) string {
	if strings.TrimSpace(event.TraceID) != "" {
		return "trace:" + strings.TrimSpace(event.TraceID)
	}
	if strings.TrimSpace(event.SessionID) != "" {
		return "session:" + strings.TrimSpace(event.SessionID)
	}
	return fmt.Sprintf("agent:%s:%d", pageNormalizeKey(event.Agent), pageTimestampKey(event.OccurredAt)/300)
}

func pageBuildEventAnalytics(events []pageEvent) (pageEventSummary, []pageEventBreakdown, []pageEventAgentBreakdown, []pageEventTimelineBucket) {
	summary := pageEventSummary{Total: len(events)}
	sourceStats := map[string]*pageEventBreakdown{}
	agentStats := map[string]*pageEventAgentBreakdown{}
	agentSources := map[string]map[string]bool{}
	sourceNames := map[string]bool{}
	agentNames := map[string]bool{}
	correlationKeys := map[string]bool{}
	timeline := map[string]*pageEventTimelineBucket{}

	for _, event := range events {
		if summary.WindowEnd == "" || event.OccurredAt > summary.WindowEnd {
			summary.WindowEnd = event.OccurredAt
		}
		if summary.WindowStart == "" || event.OccurredAt < summary.WindowStart {
			summary.WindowStart = event.OccurredAt
		}
		switch event.Kind {
		case "attack":
			summary.Attack++
		default:
			summary.Security++
		}
		switch pageNormalizeRisk(event.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		}
		if event.Status == "blocked" {
			summary.Blocked++
		}
		if event.CorrelationKey != "" {
			correlationKeys[event.CorrelationKey] = true
		}
		source := pageFirstNonEmpty(event.Source, "gateway")
		sourceNames[source] = true
		stat := sourceStats[source]
		if stat == nil {
			stat = &pageEventBreakdown{Name: source, MaxSeverity: "info"}
			sourceStats[source] = stat
		}
		pageAccumulateEventBreakdown(stat, event)

		agentKey := pageNormalizeKey(event.Agent + "::" + event.Runtime)
		agentNames[agentKey] = true
		agentStat := agentStats[agentKey]
		if agentStat == nil {
			agentStat = &pageEventAgentBreakdown{
				Agent:       pageFirstNonEmpty(event.Agent, "Unknown Agent"),
				Runtime:     pageFirstNonEmpty(event.Runtime, "Unknown Runtime"),
				MaxSeverity: "info",
			}
			agentStats[agentKey] = agentStat
			agentSources[agentKey] = map[string]bool{}
		}
		agentStat.Count++
		if event.Kind == "attack" {
			agentStat.Attack++
		}
		if event.Status == "blocked" {
			agentStat.Blocked++
		}
		if pageRiskRank(event.Severity) > pageRiskRank(agentStat.MaxSeverity) {
			agentStat.MaxSeverity = pageNormalizeRisk(event.Severity)
		}
		if event.OccurredAt > agentStat.LastSeen {
			agentStat.LastSeen = event.OccurredAt
		}
		agentSources[agentKey][source] = true

		bucket := pageEventTimelineBucketKey(event.OccurredAt)
		if bucket != "" {
			item := timeline[bucket]
			if item == nil {
				item = &pageEventTimelineBucket{Bucket: bucket}
				timeline[bucket] = item
			}
			item.Total++
			if event.Kind == "attack" {
				item.Attack++
			}
			if event.Status == "blocked" {
				item.Blocked++
			}
			if pageRiskRank(event.Severity) >= 4 {
				item.HighRisk++
			}
		}
	}

	summary.Agents = len(agentNames)
	summary.Sources = len(sourceNames)
	summary.Correlated = len(correlationKeys)

	sources := make([]pageEventBreakdown, 0, len(sourceStats))
	for _, stat := range sourceStats {
		sources = append(sources, *stat)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Count != sources[j].Count {
			return sources[i].Count > sources[j].Count
		}
		return sources[i].Name < sources[j].Name
	})

	agents := make([]pageEventAgentBreakdown, 0, len(agentStats))
	for key, stat := range agentStats {
		stat.Sources = pageSortedKeys(agentSources[key])
		agents = append(agents, *stat)
	}
	sort.Slice(agents, func(i, j int) bool {
		if pageRiskRank(agents[i].MaxSeverity) != pageRiskRank(agents[j].MaxSeverity) {
			return pageRiskRank(agents[i].MaxSeverity) > pageRiskRank(agents[j].MaxSeverity)
		}
		if agents[i].Count != agents[j].Count {
			return agents[i].Count > agents[j].Count
		}
		return agents[i].Agent < agents[j].Agent
	})

	buckets := make([]pageEventTimelineBucket, 0, len(timeline))
	for _, bucket := range timeline {
		buckets = append(buckets, *bucket)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Bucket < buckets[j].Bucket })
	if len(buckets) > 24 {
		buckets = buckets[len(buckets)-24:]
	}

	return summary, sources, agents, buckets
}

func pageCanonicalizeEventAgent(event pageEvent, inventory []pageAgent) pageEvent {
	if len(inventory) == 0 {
		return event
	}
	candidates := []string{
		event.Agent,
		event.Connector,
		event.DestinationApp,
		event.Runtime,
		event.Target,
		event.Actor,
	}
	inferred := pageInferAgent(strings.Join(candidates, " "), "")
	if pageCanonicalAgentID(inferred.ID) != "" && inferred.Product != "Unclassified Agent" {
		candidates = append([]string{inferred.ID, inferred.Product}, candidates...)
	}
	for _, candidate := range candidates {
		key := pageCanonicalAgentID(candidate)
		if key == "" {
			continue
		}
		for _, agent := range inventory {
			if pageCanonicalAgentID(agent.ID) == key || pageAgentMatchesCandidate(agent, candidate) {
				event.Agent = agent.Product
				event.Runtime = pageRuntimeLabel(agent.Kind)
				return event
			}
		}
	}
	return event
}

func pageMergeEventAgentsFromInventory(events []pageEventAgentBreakdown, inventory []pageAgent) []pageEventAgentBreakdown {
	seen := map[string]bool{}
	for _, eventAgent := range events {
		seen[pageEventAgentBreakdownKey(eventAgent.Agent, eventAgent.Runtime)] = true
	}
	for _, agent := range inventory {
		key := pageEventAgentBreakdownKey(agent.Product, pageRuntimeLabel(agent.Kind))
		if seen[key] {
			continue
		}
		events = append(events, pageEventAgentBreakdown{
			Agent:       agent.Product,
			Runtime:     pageRuntimeLabel(agent.Kind),
			MaxSeverity: "info",
			Sources:     pageSplitSourceList(agent.Source),
		})
		seen[key] = true
	}
	sort.Slice(events, func(i, j int) bool {
		if pageRiskRank(events[i].MaxSeverity) != pageRiskRank(events[j].MaxSeverity) {
			return pageRiskRank(events[i].MaxSeverity) > pageRiskRank(events[j].MaxSeverity)
		}
		if events[i].Count != events[j].Count {
			return events[i].Count > events[j].Count
		}
		return events[i].Agent < events[j].Agent
	})
	return events
}

func pageEventAgentBreakdownKey(agent, runtime string) string {
	return pageCanonicalAgentID(agent) + "::" + pageNormalizeKey(runtime)
}

func pageCanonicalAgentDisplay(canonicalID string, fallbacks ...string) string {
	if profile, ok := audit.CanonicalAgentProfileForID(canonicalID); ok && profile.DisplayName != "" {
		return profile.DisplayName
	}
	return pageFirstNonEmpty(fallbacks...)
}

func pageCanonicalAgentRuntime(canonicalID string, fallbacks ...string) string {
	if profile, ok := audit.CanonicalAgentProfileForID(canonicalID); ok && profile.Runtime != "" {
		return profile.Runtime
	}
	return pageFirstNonEmpty(fallbacks...)
}

func pageAgentMatchesCandidate(agent pageAgent, candidate string) bool {
	key := pageCanonicalAgentID(candidate)
	if key == "" {
		return false
	}
	values := []string{agent.ID, agent.Product, agent.Source}
	values = append(values, agent.ExecutableNames...)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if pageCanonicalAgentID(part) == key {
				return true
			}
		}
	}
	return false
}

func pageSplitSourceList(source string) []string {
	items := strings.Split(source, ",")
	out := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func pageAccumulateEventBreakdown(stat *pageEventBreakdown, event pageEvent) {
	stat.Count++
	if event.Kind == "attack" {
		stat.Attack++
	}
	if event.Status == "blocked" {
		stat.Blocked++
	}
	if pageRiskRank(event.Severity) > pageRiskRank(stat.MaxSeverity) {
		stat.MaxSeverity = pageNormalizeRisk(event.Severity)
	}
}

func pageEventTimelineBucketKey(value string) string {
	ts, ok := pageParseEventTime(value)
	if !ok {
		return ""
	}
	bucket := ts.UTC().Truncate(5 * time.Minute)
	return bucket.Format(time.RFC3339)
}

func pageParseEventTime(value string) (time.Time, bool) {
	if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return ts, true
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts, true
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006/01/02 15:04:05"} {
		if ts, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

func pageGatewayAuditFromEvent(row audit.Event) pageGatewayAuditRecord {
	latency := pageStructuredUint(row.Structured, "latency_ms")
	return pageGatewayAuditRecord{
		Timestamp:      row.Timestamp.UTC().Format(time.RFC3339Nano),
		Action:         row.Action,
		Target:         row.Target,
		Actor:          row.Actor,
		Details:        row.Details,
		Severity:       row.Severity,
		TraceID:        pageFirstNonEmpty(row.TraceID, pageStructuredString(row.Structured, "trace_id")),
		SessionID:      pageFirstNonEmpty(row.SessionID, pageStructuredString(row.Structured, "session_id")),
		AgentName:      pageFirstNonEmpty(row.AgentName, pageStructuredString(row.Structured, "agent_name")),
		Connector:      row.Connector,
		DestinationApp: pageFirstNonEmpty(row.DestinationApp, pageStructuredString(row.Structured, "destination_app")),
		ToolName:       pageFirstNonEmpty(row.ToolName, pageStructuredString(row.Structured, "tool_name")),
		Stage:          pageStructuredString(row.Structured, "stage"),
		Prompt:         pageStructuredString(row.Structured, "prompt"),
		Model:          pageStructuredString(row.Structured, "model"),
		MCPServer:      pageStructuredString(row.Structured, "mcp_server"),
		Decision:       pageFirstNonEmpty(pageStructuredString(row.Structured, "decision"), pageStructuredString(row.Structured, "verdict")),
		Reason:         pageStructuredString(row.Structured, "reason"),
		LatencyMs:      latency,
	}
}

func pageAuditCategory(row audit.Event) string {
	action := strings.ToLower(row.Action)
	switch {
	case strings.Contains(action, "network-egress"):
		return "network egress"
	case strings.Contains(action, "tool") || row.ToolName != "":
		return "tool inspection"
	case strings.Contains(action, "guardrail") || strings.Contains(action, "prompt"):
		return "prompt/content inspection"
	case strings.Contains(action, "runtime") || strings.Contains(action, "inspect"):
		return "runtime detection"
	default:
		return "security audit"
	}
}

func pageAuditTitle(row audit.Event) string {
	subject := pageFirstNonEmpty(row.ToolName, pageStructuredString(row.Structured, "model"), row.Target)
	action := strings.ToLower(row.Action)
	switch {
	case strings.Contains(action, "network-egress-blocked"):
		return pageFormatTitle("Network egress blocked", subject)
	case strings.Contains(action, "inspect-tool-block"):
		return pageFormatTitle("Tool call blocked", subject)
	case strings.Contains(action, "inspect-tool-alert"):
		return pageFormatTitle("Tool call alert", subject)
	case strings.Contains(action, "guardrail-verdict"):
		return pageFormatTitle("Guardrail verdict", subject)
	case strings.Contains(action, "guardrail-inspection"):
		return pageFormatTitle("Prompt/response inspection", subject)
	default:
		return pageFormatTitle(row.Action, subject)
	}
}

func pageCorrelateAttackChains(events []pageEvent) []pageAttackChain {
	groups := map[string][]pageEvent{}
	for _, event := range events {
		groups[pageChainKey(event)] = append(groups[pageChainKey(event)], event)
	}
	chains := []pageAttackChain{}
	for key, group := range groups {
		if chain, ok := pageBuildAttackChain(key, group); ok {
			chains = append(chains, chain)
		}
	}
	sort.Slice(chains, func(i, j int) bool {
		if pageRiskRank(chains[i].Risk) != pageRiskRank(chains[j].Risk) {
			return pageRiskRank(chains[i].Risk) > pageRiskRank(chains[j].Risk)
		}
		if chains[i].EndedAt != chains[j].EndedAt {
			return chains[i].EndedAt > chains[j].EndedAt
		}
		return chains[i].StepCount > chains[j].StepCount
	})
	return chains
}

func pageBuildAttackChain(key string, events []pageEvent) (pageAttackChain, bool) {
	sort.Slice(events, func(i, j int) bool {
		if pageTimestampKey(events[i].OccurredAt) != pageTimestampKey(events[j].OccurredAt) {
			return pageTimestampKey(events[i].OccurredAt) < pageTimestampKey(events[j].OccurredAt)
		}
		return events[i].ID < events[j].ID
	})
	events = pageDedupeEvents(events)
	if len(events) == 0 || !pageMeaningfulChain(events) {
		return pageAttackChain{}, false
	}
	risk := pageMaxEventRisk(events)
	status := pageChainStatus(events)
	started := events[0].OccurredAt
	ended := events[len(events)-1].OccurredAt
	trace := ""
	session := ""
	agent := ""
	runtime := ""
	for _, event := range events {
		trace = pageFirstNonEmpty(trace, event.TraceID)
		session = pageFirstNonEmpty(session, event.SessionID)
		agent = pageFirstNonEmpty(agent, event.Agent)
		runtime = pageFirstNonEmpty(runtime, event.Runtime)
	}
	steps := make([]pageAttackChainStep, 0, len(events))
	for i, event := range events {
		steps = append(steps, pageStepFromEvent(event, i+1))
	}
	evidence := make([]pageAttackEvidenceRow, 0, len(steps))
	for _, step := range steps {
		evidence = append(evidence, pageAttackEvidenceRow{
			Key:           step.ID,
			Index:         step.Order,
			OccurredAt:    step.OccurredAt,
			Stage:         step.Stage,
			Agent:         step.Actor,
			Tool:          step.Tool,
			Resource:      step.Resource,
			Decision:      step.Decision,
			Evidence:      step.Evidence,
			SourceEventID: step.SourceEventID,
			Source:        step.Source,
		})
	}
	sources := pageUniqueStringsFromEvents(events, func(e pageEvent) string { return e.Source })
	return pageAttackChain{
		ID:            "chain-" + pageStableHash(key),
		TraceID:       trace,
		SessionID:     session,
		Agent:         pageFirstNonEmpty(agent, "Unknown Agent"),
		Runtime:       pageFirstNonEmpty(runtime, "Unknown Runtime"),
		Category:      pageChainCategory(events),
		Risk:          risk,
		Status:        status,
		StartedAt:     started,
		EndedAt:       ended,
		Summary:       fmt.Sprintf("Correlated %d event(s) by %s across %d source(s); max risk is %s.", len(steps), pageKeyLabel(key), len(sources), risk),
		StepCount:     len(steps),
		EvidenceCount: len(evidence),
		Sources:       sources,
		Steps:         steps,
		Evidence:      evidence,
	}, true
}

func pageDedupeEvents(events []pageEvent) []pageEvent {
	seen := map[string]bool{}
	out := []pageEvent{}
	for _, event := range events {
		key := strings.Join([]string{
			pageFirstNonEmpty(event.TraceID, event.SessionID),
			strconv.FormatInt(pageTimestampKey(event.OccurredAt)/10, 10),
			pageNormalizeKey(event.Source),
			pageNormalizeKey(event.Subtype),
			pageNormalizeKey(event.Title),
		}, ":")
		if !seen[key] {
			seen[key] = true
			out = append(out, event)
		}
	}
	return out
}

func pageMeaningfulChain(events []pageEvent) bool {
	if len(events) >= 2 {
		return true
	}
	for _, event := range events {
		if pageRiskRank(event.Severity) >= 4 || event.Status == "blocked" || event.Kind == "attack" {
			return true
		}
	}
	return false
}

func pageStepFromEvent(event pageEvent, order int) pageAttackChainStep {
	kind := pageClassifyChainStep(event)
	stage := event.Category
	if stage == "" {
		stage = kind
	}
	tool := pageFirstNonEmpty(event.Subtype, event.Action, event.Runtime, "-")
	resource := event.Evidence
	if strings.TrimSpace(resource) == "" || resource == "-" {
		resource = pageFirstNonEmpty(event.Category, event.Runtime, event.Source, "-")
	}
	prompt := "-"
	if strings.Contains(pageEventText(event), "prompt") || strings.Contains(pageEventText(event), "injection") {
		prompt = pageFirstNonEmpty(event.Evidence, event.Title, "-")
	}
	return pageAttackChainStep{
		ID:            fmt.Sprintf("step-%d-%s", order, pageStableHash(event.ID)),
		Order:         order,
		OccurredAt:    event.OccurredAt,
		Title:         event.Title,
		Stage:         stage,
		Kind:          kind,
		Severity:      pageNormalizeRisk(event.Severity),
		Actor:         pageFirstNonEmpty(event.Agent, "Unknown Agent"),
		Prompt:        prompt,
		Tool:          tool,
		Resource:      resource,
		Evidence:      pageFirstNonEmpty(event.Evidence, "-"),
		Decision:      pageFirstNonEmpty(event.Action, pageStatusAction(event.Status)),
		Stack:         pageUniqueStrings(event.Source, event.Category, event.Subtype, event.Runtime),
		SourceEventID: event.ID,
		Source:        event.Source,
		TraceID:       event.TraceID,
		SessionID:     event.SessionID,
	}
}

func pageChainKey(event pageEvent) string {
	if strings.TrimSpace(event.CorrelationKey) != "" {
		return strings.TrimSpace(event.CorrelationKey)
	}
	if strings.TrimSpace(event.TraceID) != "" {
		return "trace:" + strings.TrimSpace(event.TraceID)
	}
	if strings.TrimSpace(event.SessionID) != "" {
		return "session:" + strings.TrimSpace(event.SessionID)
	}
	return fmt.Sprintf("agent:%s:%d", pageNormalizeKey(event.Agent), pageTimestampKey(event.OccurredAt)/300)
}

func pageKeyLabel(key string) string {
	if strings.HasPrefix(key, "trace:") {
		return "Trace " + strings.TrimPrefix(key, "trace:")
	}
	if strings.HasPrefix(key, "session:") {
		return "Session " + strings.TrimPrefix(key, "session:")
	}
	return "agent time window"
}

func pageClassifyChainStep(event pageEvent) string {
	text := pageEventText(event)
	switch {
	case strings.Contains(text, "prompt") || strings.Contains(text, "injection") || strings.Contains(text, "jailbreak"):
		return "entry"
	case strings.Contains(text, "mcp"):
		return "mcp"
	case strings.Contains(text, "network") || strings.Contains(text, "egress") || strings.Contains(text, "http") || strings.Contains(text, "curl") || strings.Contains(text, "c2"):
		return "network"
	case strings.Contains(text, "credential") || strings.Contains(text, "secret") || strings.Contains(text, "token") || strings.Contains(text, ".env") || strings.Contains(text, "database") || strings.Contains(text, "file") || strings.Contains(text, "data"):
		return "data"
	case strings.Contains(text, "tool") || strings.Contains(text, "shell") || strings.Contains(text, "command") || strings.Contains(text, "cmd") || strings.Contains(text, "powershell") || strings.Contains(text, "process"):
		return "tool"
	case strings.Contains(text, "llm") || strings.Contains(text, "model") || strings.Contains(text, "guardrail") || strings.Contains(text, "verdict") || strings.Contains(text, "inspection"):
		return "llm"
	case event.Status == "blocked" || strings.Contains(text, "block") || strings.Contains(text, "terminate"):
		return "defense"
	default:
		return "agent"
	}
}

func pageChainCategory(events []pageEvent) string {
	text := ""
	for _, event := range events {
		text += pageEventText(event) + " "
	}
	switch {
	case strings.Contains(text, "network") || strings.Contains(text, "egress") || strings.Contains(text, "c2"):
		return "network / exfiltration chain"
	case strings.Contains(text, "credential") || strings.Contains(text, "secret") || strings.Contains(text, "token"):
		return "credential / sensitive resource chain"
	case strings.Contains(text, "shell") || strings.Contains(text, "command") || strings.Contains(text, "powershell"):
		return "command execution chain"
	case strings.Contains(text, "prompt") || strings.Contains(text, "injection"):
		return "prompt injection chain"
	case strings.Contains(text, "mcp") || strings.Contains(text, "tool"):
		return "tool invocation chain"
	default:
		return "agent behavior chain"
	}
}

func pageChainStatus(events []pageEvent) string {
	out := "audited"
	for _, event := range events {
		switch event.Status {
		case "blocked":
			return "blocked"
		case "pending":
			out = "pending"
		case "detected":
			if out == "audited" {
				out = "detected"
			}
		}
	}
	return out
}

func pageMaxEventRisk(events []pageEvent) string {
	out := "info"
	for _, event := range events {
		risk := pageNormalizeRisk(event.Severity)
		if pageRiskRank(risk) > pageRiskRank(out) {
			out = risk
		}
	}
	return out
}

func pageEventText(event pageEvent) string {
	return strings.ToLower(strings.Join([]string{
		event.Kind,
		event.Agent,
		event.Runtime,
		event.Category,
		event.Subtype,
		event.Title,
		event.Evidence,
		event.Action,
		event.Source,
		event.RawAction,
		event.Target,
		event.Connector,
		event.DestinationApp,
		event.ToolName,
		event.Model,
		event.MCPServer,
		event.Decision,
		event.Reason,
		event.Remediation,
	}, " "))
}

func pageStaticType(sourceType, scannerName, target string) string {
	return audit.StaticResourceType(sourceType, scannerName, target)
}

func pageInferAgent(target, resourceType string) pageAgentDescriptor {
	lower := strings.ToLower(target)
	switch {
	case strings.Contains(lower, "agentrange-player") || strings.Contains(lower, "agentrange") || strings.Contains(lower, "ops-pilot") || strings.Contains(lower, "opspilot"):
		return pageAgentDescriptor{ID: "agentrange-opspilot", Product: "AgentRange / OpsPilot", Vendor: "TraceBastion Lab", Kind: "agent-platform", Runtime: "AgentRange", Source: "task/AgentRange-player", Description: "AgentRange static resources discovered by the gateway."}
	case strings.Contains(lower, "openclaw"):
		return pageAgentDescriptor{ID: "openclaw", Product: "OpenClaw", Vendor: "DefenseClaw", Kind: "agent-platform", Runtime: "OpenClaw", Source: "%USERPROFILE%/.openclaw"}
	case strings.Contains(lower, ".claude") || strings.Contains(lower, "claude"):
		return pageAgentDescriptor{ID: "claude-code", Product: "Claude Code", Vendor: "Anthropic", Kind: "terminal-agent", Runtime: "CLI Agent", Source: "%USERPROFILE%/.claude"}
	case strings.Contains(lower, ".codex") || strings.Contains(lower, "codex"):
		return pageAgentDescriptor{ID: "codex", Product: "OpenAI Codex", Vendor: "OpenAI", Kind: "terminal-agent", Runtime: "CLI Agent", Source: "%USERPROFILE%/.codex"}
	case strings.Contains(lower, "qoder"):
		return pageAgentDescriptor{ID: "qoder", Product: "Qoder", Vendor: "Qoder", Kind: "ide-agent", Runtime: "IDE Agent", Source: "%APPDATA%/Qoder"}
	case strings.Contains(lower, "trae"):
		return pageAgentDescriptor{ID: "trae", Product: "Trae", Vendor: "ByteDance", Kind: "desktop-agent", Runtime: "Desktop Agent", Source: "%APPDATA%/Trae"}
	case strings.Contains(lower, "cherrystudio") || strings.Contains(lower, "cherry-studio") || strings.Contains(lower, "cherry"):
		return pageAgentDescriptor{ID: "cherry-studio", Product: "Cherry Studio", Vendor: "Cherry Studio", Kind: "desktop-agent", Runtime: "Desktop Agent", Source: "%APPDATA%/CherryStudio"}
	case strings.Contains(lower, "cursor"):
		return pageAgentDescriptor{ID: "cursor", Product: "Cursor", Vendor: "Anysphere", Kind: "editor-agent", Runtime: "IDE Agent", Source: "%APPDATA%/Cursor"}
	case strings.Contains(lower, "cline"):
		return pageAgentDescriptor{ID: "cline", Product: "Cline", Vendor: "Cline", Kind: "editor-agent", Runtime: "IDE Agent", Source: "%APPDATA%/Code/User"}
	case strings.Contains(lower, "roo"):
		return pageAgentDescriptor{ID: "roo-code", Product: "Roo Code", Vendor: "Roo Code", Kind: "editor-agent", Runtime: "IDE Agent", Source: "%APPDATA%/Code/User"}
	case resourceType == "Environment":
		return pageAgentDescriptor{ID: "system-environment", Product: "System Environment", Vendor: "Windows", Kind: "runtime", Runtime: "Windows Runtime", Source: "process environment"}
	default:
		id := pageStableID(target)
		return pageAgentDescriptor{ID: id, Product: "Unclassified Agent", Vendor: "Unknown", Kind: "unknown", Runtime: "Backend Static Scanner", Source: target}
	}
}

func pageResourceKind(resourceType string) string {
	switch resourceType {
	case "Config":
		return "configuration file"
	case "Skills":
		return "agent skill"
	case "MCP":
		return "MCP service"
	case "Plugin":
		return "plugin"
	case "Prompt":
		return "prompt / rule"
	case "Credential":
		return "credential / secret reference"
	case "Environment":
		return "environment variable"
	default:
		return "static resource"
	}
}

func pageResourceName(target, resourceType string) string {
	if strings.TrimSpace(target) == "" {
		return resourceType
	}
	if strings.Contains(target, "://") {
		parts := strings.FieldsFunc(target, func(r rune) bool { return r == '/' || r == '#' || r == ':' })
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.TrimSpace(parts[i]) != "" {
				return parts[i]
			}
		}
		return target
	}
	if base := filepath.Base(target); base != "" && base != "." {
		return base
	}
	return target
}

func pageFileMetadata(target string) (string, string) {
	if strings.Contains(target, "://") {
		return "-", "virtual"
	}
	info, err := os.Stat(target)
	if err != nil {
		return "-", "-"
	}
	perms := "read-write"
	if info.Mode().Perm()&0200 == 0 {
		perms = "read-only"
	}
	return pageFormatBytes(info.Size()), perms
}

func pageFormatBytes(bytes int64) string {
	const kb = 1024.0
	const mb = 1024.0 * 1024.0
	if float64(bytes) >= mb {
		return fmt.Sprintf("%.1f MB", float64(bytes)/mb)
	}
	if float64(bytes) >= kb {
		return fmt.Sprintf("%.1f KB", float64(bytes)/kb)
	}
	return fmt.Sprintf("%d B", bytes)
}

func pageHighestRisk(summary string, findings []pageStaticFinding) string {
	out := pageNormalizeRisk(summary)
	for _, finding := range findings {
		risk := pageNormalizeRisk(finding.Severity)
		if pageRiskRank(risk) > pageRiskRank(out) {
			out = risk
		}
	}
	return out
}

func pageStatusForRisk(risk string) string {
	switch pageNormalizeRisk(risk) {
	case "critical", "high":
		return "discovered"
	case "medium":
		return "changed"
	default:
		return "reviewed"
	}
}

func pageAgentMaxRisk(resources []pageStaticResource) string {
	out := "info"
	for _, resource := range resources {
		if pageRiskRank(resource.Risk) > pageRiskRank(out) {
			out = resource.Risk
		}
	}
	return out
}

func pageNormalizeRisk(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "fatal":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "moderate", "warn", "warning":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func pageRiskRank(value string) int {
	switch pageNormalizeRisk(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func pageStatusFromText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "block") || strings.Contains(lower, "terminated") || strings.Contains(lower, "denied"):
		return "blocked"
	case strings.Contains(lower, "pending") || strings.Contains(lower, "confirm"):
		return "pending"
	case strings.Contains(lower, "alert") || strings.Contains(lower, "detect") || strings.Contains(lower, "finding"):
		return "detected"
	default:
		return "audited"
	}
}

func pageClassifyEventKind(severity, status, text string) string {
	lower := strings.ToLower(text)
	if status == "blocked" || pageRiskRank(severity) >= 4 ||
		strings.Contains(lower, "attack") || strings.Contains(lower, "exfil") ||
		strings.Contains(lower, "c2") || strings.Contains(lower, "injection") ||
		strings.Contains(lower, "destructive") || strings.Contains(lower, "malicious") ||
		strings.Contains(lower, "credential") || strings.Contains(lower, "secret") ||
		strings.Contains(lower, "shell") || strings.Contains(lower, "command") {
		return "attack"
	}
	return "security"
}

func pageActionText(status, action string) string {
	switch status {
	case "blocked":
		return "blocked or terminated by runtime policy"
	case "pending":
		return "waiting for confirmation or review"
	case "detected":
		return "recorded risk event and preserved audit evidence"
	default:
		return "audited: " + action
	}
}

func pageStatusAction(status string) string {
	switch status {
	case "blocked":
		return "blocked by backend policy"
	case "pending":
		return "pending human review"
	case "detected":
		return "detection event recorded"
	default:
		return "written to audit log"
	}
}

func pageFormatTitle(prefix, subject string) string {
	if strings.TrimSpace(subject) == "" {
		return prefix
	}
	return prefix + ": " + subject
}

func pageMapString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func pageStructuredString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	if nested, ok := m["structured"].(map[string]any); ok {
		if v, ok := nested[key].(string); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func pageStructuredUint(m map[string]any, key string) *uint64 {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case float64:
		u := uint64(x)
		return &u
	case int:
		u := uint64(x)
		return &u
	case uint64:
		return &x
	default:
		return nil
	}
}

func pageFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func pageSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		if strings.TrimSpace(key) != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func pageUniqueStrings(values ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := pageNormalizeKey(value)
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func pageUniqueStringsFromEvents(events []pageEvent, pick func(pageEvent) string) []string {
	values := []string{}
	for _, event := range events {
		values = append(values, pick(event))
	}
	return pageUniqueStrings(values...)
}

func pageStableID(value string) string {
	var b strings.Builder
	dash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(strings.ToLower(b.String()), "-")
}

func pageCanonicalAgentID(value string) string {
	return audit.CanonicalAgentID(value)
}

func pageRuntimeLabel(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "terminal-agent", "cli-agent":
		return "CLI Agent"
	case "editor-agent", "ide-agent":
		return "IDE Agent"
	case "desktop-agent":
		return "Desktop Agent"
	case "agent-platform":
		return "Agent Platform"
	case "":
		return "Agent"
	default:
		return kind
	}
}

func pageStableHash(value string) string {
	var hash uint64 = 14695981039346656037
	for _, b := range []byte(value) {
		hash ^= uint64(b)
		hash *= 1099511628211
	}
	return fmt.Sprintf("%016x", hash)
}

func pageNormalizeKey(value string) string {
	id := pageStableID(value)
	if id == "" {
		return "unknown"
	}
	return id
}

func pagePathKey(path string) string {
	if strings.Contains(path, "://") {
		return strings.ToLower(strings.TrimSpace(path))
	}
	if abs, err := filepath.Abs(path); err == nil {
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			return strings.ToLower(real)
		}
		return strings.ToLower(abs)
	}
	return strings.ToLower(path)
}

func pageLooksLikeAgentRangeRoot(root string) bool {
	if strings.TrimSpace(root) == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, "docker-compose.yml")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(root, "skills")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, "mcp")); err == nil {
		return true
	}
	return false
}

func pageTimestampKey(value string) int64 {
	if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return ts.Unix()
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts.Unix()
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006/01/02 15:04:05"} {
		if ts, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return ts.Unix()
		}
	}
	return 0
}

func pageSQLString(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return ""
}
