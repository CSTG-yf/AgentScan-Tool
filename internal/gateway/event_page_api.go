package gateway

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func strictTime(raw, name string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if v, err := time.Parse(layout, raw); err == nil {
			return v.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%s must be RFC3339", name)
}
func strictUint(raw, name string) (uint32, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return uint32(v), nil
}
func strictBool(raw, name string) (*bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be true or false", name)
	}
	return &v, nil
}
func strictSort(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "timestamp_desc", nil
	}
	if raw != "timestamp_desc" && raw != "timestamp_asc" {
		return "", fmt.Errorf("sort must be timestamp_desc or timestamp_asc")
	}
	return raw, nil
}

func validatePageQuery(r *http.Request, maxPageSize int) error {
	for _, spec := range []struct {
		name string
		max  int
	}{{"page", 0}, {"page_size", maxPageSize}, {"pageSize", maxPageSize}, {"limit", maxPageSize}} {
		raw := strings.TrimSpace(r.URL.Query().Get(spec.name))
		if raw == "" {
			continue
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return fmt.Errorf("%s must be a positive integer", spec.name)
		}
		if spec.max > 0 && value > spec.max {
			return fmt.Errorf("%s must not exceed %d", spec.name, spec.max)
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		if value, err := strconv.Atoi(raw); err != nil || value < 0 {
			return fmt.Errorf("offset must be a non-negative integer")
		}
	}
	return nil
}

func runtimeEventFilterFromRequest(r *http.Request) (audit.RuntimeEventFilter, error) {
	if err := validatePageQuery(r, 2000); err != nil {
		return audit.RuntimeEventFilter{}, err
	}
	q := r.URL.Query()
	since, err := strictTime(q.Get("start_time"), "start_time")
	if err != nil {
		return audit.RuntimeEventFilter{}, err
	}
	until, err := strictTime(q.Get("end_time"), "end_time")
	if err != nil {
		return audit.RuntimeEventFilter{}, err
	}
	agentPID, err := strictUint(q.Get("agent_pid"), "agent_pid")
	if err != nil {
		return audit.RuntimeEventFilter{}, err
	}
	actorPID, err := strictUint(q.Get("actor_pid"), "actor_pid")
	if err != nil {
		return audit.RuntimeEventFilter{}, err
	}
	pid, err := strictUint(q.Get("pid"), "pid")
	if err != nil {
		return audit.RuntimeEventFilter{}, err
	}
	sort, err := strictSort(q.Get("sort"))
	if err != nil {
		return audit.RuntimeEventFilter{}, err
	}
	include := false
	if raw := q.Get("include_desktop_behavior"); strings.TrimSpace(raw) != "" {
		v, e := strconv.ParseBool(raw)
		if e != nil {
			return audit.RuntimeEventFilter{}, fmt.Errorf("include_desktop_behavior must be true or false")
		}
		include = v
	}
	return audit.RuntimeEventFilter{AgentID: strings.TrimSpace(q.Get("agent_id")), SessionID: strings.TrimSpace(q.Get("session_id")), TraceID: strings.TrimSpace(q.Get("trace_id")), EventType: strings.TrimSpace(q.Get("event_type")), EventCategory: strings.TrimSpace(q.Get("event_category")), EventSource: strings.TrimSpace(q.Get("source")), Severity: strings.ToUpper(strings.TrimSpace(q.Get("severity"))), PID: pid, AgentPID: agentPID, ActorPID: actorPID, Outcome: strings.TrimSpace(q.Get("outcome")), Keyword: strings.TrimSpace(q.Get("keyword")), Since: since, Until: until, IncludeDesktop: include, Sort: sort}, nil
}

func (a *APIServer) handleRuntimeEventsSummary(w http.ResponseWriter, r *http.Request) {
	f, err := runtimeEventFilterFromRequest(r)
	if err != nil {
		a.writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	f.AgentID = ""
	x, err := a.store.RuntimeEventSummary(f)
	if err != nil {
		a.writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, 200, x)
}
func (a *APIServer) handleRuntimeEventsAgents(w http.ResponseWriter, r *http.Request) {
	f, err := runtimeEventFilterFromRequest(r)
	if err != nil {
		a.writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	f.AgentID = ""
	x, err := a.store.RuntimeEventAgents(f)
	if err != nil {
		a.writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, 200, map[string]any{"items": x})
}
func (a *APIServer) handleRuntimeEventsFacets(w http.ResponseWriter, r *http.Request) {
	f, err := runtimeEventFilterFromRequest(r)
	if err != nil {
		a.writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	f.AgentID = ""
	x, err := a.store.RuntimeEventFacetValues(f)
	if err != nil {
		a.writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, 200, x)
}

func auditEventFilterFromRequest(r *http.Request) (audit.AuditEventFilter, error) {
	if err := validatePageQuery(r, 200); err != nil {
		return audit.AuditEventFilter{}, err
	}
	q := r.URL.Query()
	since, err := strictTime(q.Get("start_time"), "start_time")
	if err != nil {
		return audit.AuditEventFilter{}, err
	}
	until, err := strictTime(q.Get("end_time"), "end_time")
	if err != nil {
		return audit.AuditEventFilter{}, err
	}
	sort, err := strictSort(q.Get("sort"))
	if err != nil {
		return audit.AuditEventFilter{}, err
	}
	enforced, err := strictBool(q.Get("enforced"), "enforced")
	if err != nil {
		return audit.AuditEventFilter{}, err
	}
	page, pageSize := requestPage(r, 1, 20, 200)
	return audit.AuditEventFilter{AgentID: strings.TrimSpace(q.Get("agent_id")), Action: strings.TrimSpace(q.Get("action")), Severity: strings.TrimSpace(q.Get("severity")), Connector: strings.TrimSpace(q.Get("connector")), Actor: strings.TrimSpace(q.Get("actor")), ToolName: strings.TrimSpace(q.Get("tool_name")), PolicyID: strings.TrimSpace(q.Get("policy_id")), RequestID: strings.TrimSpace(q.Get("request_id")), SessionID: strings.TrimSpace(q.Get("session_id")), TraceID: strings.TrimSpace(q.Get("trace_id")), Keyword: strings.TrimSpace(q.Get("keyword")), Sort: sort, Enforced: enforced, Since: since, Until: until, Limit: pageSize, Offset: (page - 1) * pageSize}, nil
}

func (a *APIServer) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, 503, map[string]string{"error": "audit store unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/audit-events"), "/")
	f, err := auditEventFilterFromRequest(r)
	if err != nil {
		a.writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	switch rest {
	case "":
		items, total, err := a.store.QueryAuditEvents(f)
		if err != nil {
			a.writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		page := f.Offset/f.Limit + 1
		a.writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": f.Limit})
	case "summary":
		f.AgentID = ""
		x, err := a.store.AuditEventSummary(f)
		if err != nil {
			a.writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, 200, x)
	case "agents":
		f.AgentID = ""
		x, err := a.store.AuditEventAgents(f)
		if err != nil {
			a.writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, 200, map[string]any{"items": x})
	case "facets":
		f.AgentID = ""
		x, err := a.store.AuditEventFacetValues(f)
		if err != nil {
			a.writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, 200, x)
	default:
		if strings.ContainsAny(rest, `/\\`) {
			http.NotFound(w, r)
			return
		}
		x, ok, err := a.store.GetAuditEvent(rest)
		if err != nil {
			a.writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if !ok {
			a.writeJSON(w, 404, map[string]string{"error": "audit event not found"})
			return
		}
		a.writeJSON(w, 200, x)
	}
}
