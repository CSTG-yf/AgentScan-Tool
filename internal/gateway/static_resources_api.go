// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// staticResourceMaxContentBytes caps the content tab payload: larger files
// are truncated (truncated=true tells the frontend).
const staticResourceMaxContentBytes = 256 * 1024

// staticScanInFlight guards the on-demand scan/rescan triggers: the scan
// pipeline is expensive, so at most one manually-triggered sweep runs at a
// time; additional requests are rejected with 409.
var staticScanInFlight atomic.Bool

// SetStaticScanTrigger wires the watcher's on-demand scan entry points into
// the API server. The sidecar calls this after creating the watcher; until
// then the POST endpoints answer 503.
func (a *APIServer) SetStaticScanTrigger(scanOne func(resourceID string) error, rescan func(agentID string) error) {
	a.staticScanMu.Lock()
	defer a.staticScanMu.Unlock()
	a.staticScanOne = scanOne
	a.staticRescan = rescan
}

func (a *APIServer) staticScanTriggers() (func(string) error, func(string) error) {
	a.staticScanMu.RLock()
	defer a.staticScanMu.RUnlock()
	return a.staticScanOne, a.staticRescan
}

// handleStaticResourcesAPI dispatches the /api/v1/static-resources/ subtree:
//
//	GET  /{id}                        drawer overview payload
//	GET  /{id}/findings               latest-scan findings (risk tab)
//	GET  /{id}/scans                  full scan history (history tab)
//	GET  /{id}/content                redacted file content / dir listing
//	GET  /{id}/relations              related resources (reserved)
//	PUT  /{id}/status                 manual review status (review loop)
//	POST /{id}/scan                   on-demand single-resource scan
func (a *APIServer) handleStaticResourcesAPI(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/static-resources")
	rest = strings.Trim(rest, "/")

	switch {
	case rest == "" || rest == "/":
		a.handleStaticResourceList(w, r)
	case rest == "agents":
		a.handleStaticResourceAgents(w, r)
	case rest == "summary":
		a.handleStaticResourceSummary(w, r)
	case rest == "rescan":
		a.handleStaticResourceRescan(w, r)
	default:
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		resourceID := parts[0]
		if resourceID == "" || strings.ContainsAny(resourceID, `/\`) {
			http.NotFound(w, r)
			return
		}
		switch {
		case len(parts) == 1:
			a.handleStaticResourceDetail(w, r, resourceID)
		case len(parts) == 2 && parts[1] == "findings":
			a.handleStaticResourceFindings(w, r, resourceID)
		case len(parts) == 2 && parts[1] == "scans":
			a.handleStaticResourceScans(w, r, resourceID)
		case len(parts) == 2 && parts[1] == "content":
			a.handleStaticResourceContent(w, r, resourceID)
		case len(parts) == 2 && parts[1] == "status":
			a.handleStaticResourceStatus(w, r, resourceID)
		case len(parts) == 2 && parts[1] == "relations":
			a.handleStaticResourceRelations(w, r, resourceID)
		case len(parts) == 2 && parts[1] == "scan":
			a.handleStaticResourceScan(w, r, resourceID)
		default:
			http.NotFound(w, r)
		}
	}
}

// handleStaticResourceAgents serves GET /api/v1/static-resources/agents —
// the desktop left-hand agent list with per-agent resource/risk counts.
func (a *APIServer) handleStaticResourceAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items, err := a.store.ListAgentResourceSummaries()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if items == nil {
		items = []audit.AgentResourceSummary{}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleStaticResourceSummary serves GET /api/v1/static-resources/summary?agent_id=
// — the header totals plus the per-type cards.
func (a *APIServer) handleStaticResourceSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if agentID == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id is required"})
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

// handleStaticResourceList serves GET /api/v1/static-resources — the main
// paginated, filterable resource table.
func (a *APIServer) handleStaticResourceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	filter := audit.StaticResourceFilter{
		AgentID:      strings.TrimSpace(q.Get("agent_id")),
		ResourceType: strings.TrimSpace(q.Get("resource_type")),
		RiskLevel:    strings.TrimSpace(q.Get("risk_level")),
		Status:       strings.TrimSpace(q.Get("status")),
		Keyword:      strings.TrimSpace(q.Get("keyword")),
	}
	if v := strings.TrimSpace(q.Get("malicious")); v != "" {
		b := strings.EqualFold(v, "true") || v == "1"
		filter.Malicious = &b
	}
	if v := strings.TrimSpace(q.Get("scan_status")); v != "" {
		b := strings.EqualFold(v, "completed")
		filter.ScanCompleted = &b
	}
	if v := strings.TrimSpace(q.Get("page")); v != "" {
		fmt.Sscanf(v, "%d", &filter.Page)
	}
	if v := strings.TrimSpace(q.Get("page_size")); v != "" {
		fmt.Sscanf(v, "%d", &filter.PageSize)
	}

	page, err := a.store.ListStaticResourcesPage(filter)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, page)
}

// handleStaticResourceDetail serves GET /api/v1/static-resources/{id} — the
// drawer overview tab.
func (a *APIServer) handleStaticResourceDetail(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	detail, err := a.store.GetStaticResourceDetail(resourceID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if detail == nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}
	// File metadata (size / permission) supplements the DB row.
	if info, err := os.Stat(detail.Target); err == nil && !isVirtualTarget(detail.Target) {
		detail.Size = info.Size()
		detail.Permission = staticFilePermission(info.Mode())
	}
	a.writeJSON(w, http.StatusOK, detail)
}

// handleStaticResourceFindings serves GET /api/v1/static-resources/{id}/findings
// — the drawer risk tab: latest-scan findings with a severity summary.
func (a *APIServer) handleStaticResourceFindings(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	findings, err := a.store.ListStaticResourceLatestFindings(resourceID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if findings == nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, findings)
}

// handleStaticResourceScans serves GET /api/v1/static-resources/{id}/scans —
// the drawer history tab: every scan_results record of the resource, newest
// first (first discovery, drift re-scans, manual rescans).
func (a *APIServer) handleStaticResourceScans(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, _, _, _, _, _, _, _, ok, err := a.store.GetStaticResourceTargetPath(resourceID); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}
	history, err := a.store.ListStaticResourceScanHistory(resourceID, pageLimit(r, 50, 1, 200))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, history)
}

// staticResourceManualStatuses are the lifecycle statuses an operator may set
// from the desktop drawer: the review outcomes plus the "undo" reset.
var staticResourceManualStatuses = map[string]bool{
	"discovered":   true,
	"review":       true,
	"needs_review": true,
	"ignored":      true,
}

// handleStaticResourceStatus serves PUT /api/v1/static-resources/{id}/status —
// the manual review loop. The operator marks a resource reviewed / needs
// review / ignored after inspecting it in the file explorer; "discovered"
// undoes the manual mark. Manual statuses survive enumeration and
// disappearance sweeps; a completed scan verdict supersedes them.
func (a *APIServer) handleStaticResourceStatus(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
	}
	status := strings.ToLower(strings.TrimSpace(body.Status))
	if !staticResourceManualStatuses[status] {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of: discovered, review, needs_review, ignored"})
		return
	}
	ok, err := a.store.SetStaticResourceStatus(resourceID, status)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]string{"resource_id": resourceID, "status": status})
}

// handleStaticResourceContent serves GET /api/v1/static-resources/{id}/content
// — the drawer content tab. Single files return redacted text; directory
// resources (skills, MCP dirs) return a file listing.
func (a *APIServer) handleStaticResourceContent(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	detail, err := a.store.GetStaticResourceDetail(resourceID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if detail == nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return
	}
	target := detail.Target
	if isVirtualTarget(target) {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"resource_id":  resourceID,
			"type":         "virtual",
			"content_type": "text/plain",
			"truncated":    false,
			"content":      "该资源是运行时环境快照（非文件），没有可展示的静态内容。",
			"redacted":     false,
		})
		return
	}
	info, err := os.Stat(target)
	if err != nil {
		a.writeJSON(w, http.StatusGone, map[string]string{"error": "resource target no longer exists on disk"})
		return
	}
	if info.IsDir() {
		a.serveStaticDirectoryContent(w, resourceID, target)
		return
	}
	a.serveStaticFileContent(w, resourceID, target)
}

func (a *APIServer) serveStaticFileContent(w http.ResponseWriter, resourceID, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	truncated := len(data) > staticResourceMaxContentBytes
	if truncated {
		data = data[:staticResourceMaxContentBytes]
	}
	// Secrets NEVER leave the backend in cleartext: only the matched
	// secret fragments are rewritten into placeholders so the rest of
	// the file stays previewable.
	content, redactions := scanner.RedactSecretsInContent(string(data))
	a.writeJSON(w, http.StatusOK, map[string]any{
		"resource_id":     resourceID,
		"type":            "file",
		"content_type":    contentContentType(path),
		"language":        contentLanguage(path),
		"truncated":       truncated,
		"content":         content,
		"redacted":        redactions > 0,
		"redaction_count": redactions,
	})
}

func (a *APIServer) serveStaticDirectoryContent(w http.ResponseWriter, resourceID, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	files := []map[string]any{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, map[string]any{
			"name": entry.Name(),
			"path": filepath.Join(dir, entry.Name()),
			"size": info.Size(),
			"type": map[bool]string{true: "directory", false: "file"}[entry.IsDir()],
		})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"resource_id": resourceID,
		"type":        "directory",
		"files":       files,
	})
}

// handleStaticResourceRelations serves GET /api/v1/static-resources/{id}/relations.
// Relationships are derived from persisted canonical ownership/target keys;
// the endpoint always reports supported=true even when the result is empty.
func (a *APIServer) handleStaticResourceRelations(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items, err := a.store.ListStaticResourceRelations(resourceID, pageLimit(r, 50, 1, 200))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if items == nil {
		items = []audit.StaticResourceRelation{}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"resource_id": resourceID, "supported": true, "items": items})
}

// handleStaticResourceScan serves POST /api/v1/static-resources/{id}/scan —
// queue one resource for an immediate re-scan.
func (a *APIServer) handleStaticResourceScan(w http.ResponseWriter, r *http.Request, resourceID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	scanOne, _ := a.staticScanTriggers()
	if scanOne == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "watcher scan pipeline unavailable"})
		return
	}
	if !staticScanInFlight.CompareAndSwap(false, true) {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": "another manual scan is already running"})
		return
	}
	status := a.startAPIScanWithOptions("resource_scan", "resource", "", resourceID, "manual", nil, idempotencyKey, func(ctx context.Context, _ string) error {
		defer staticScanInFlight.Store(false)
		if err := ctx.Err(); err != nil {
			return err
		}
		return scanOne(resourceID)
	})
	if status.Status == "failed" {
		staticScanInFlight.Store(false)
	}
	a.writeJSON(w, http.StatusAccepted, status)
}

// handleStaticResourceRescan serves POST /api/v1/static-resources/rescan —
// re-enumerate and re-scan one agent (body {"agent_id": "..."}) or every
// agent (empty body).
func (a *APIServer) handleStaticResourceRescan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agentID := ""
	idempotencyKey := requestIdempotencyKey(r)
	if r.Body != nil {
		var body struct {
			AgentID        string `json:"agent_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&body); err == nil {
			agentID = strings.TrimSpace(body.AgentID)
			if idempotencyKey == "" {
				idempotencyKey = strings.TrimSpace(body.IdempotencyKey)
			}
		} else if err != io.EOF {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
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
	status := a.startAPIScanWithOptions("resource_scan", "rescan", agentID, "", "manual", map[string]any{"agent_id": agentID}, idempotencyKey, func(ctx context.Context, _ string) error {
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

// isVirtualTarget mirrors the watcher's virtual-resource check for content
// and detail responses.
func isVirtualTarget(target string) bool {
	idx := strings.Index(target, "://")
	if idx <= 0 {
		return false
	}
	for i := 0; i < idx; i++ {
		c := target[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '+' || c == '.') {
			return false
		}
	}
	return true
}

func contentLanguage(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	case ".md":
		return "markdown"
	case ".py":
		return "python"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".go":
		return "go"
	case ".sh", ".bash":
		return "shell"
	case ".env":
		return "dotenv"
	default:
		return "text"
	}
}

func contentContentType(path string) string {
	switch lang := contentLanguage(path); lang {
	case "json":
		return "application/json"
	case "yaml", "toml", "markdown", "dotenv":
		return "text/plain"
	default:
		return "text/plain"
	}
}

func staticFilePermission(mode os.FileMode) string {
	perm := fmt.Sprintf("%o", mode.Perm())
	if mode&0200 != 0 {
		return perm + " read-write"
	}
	return perm + " read-only"
}
