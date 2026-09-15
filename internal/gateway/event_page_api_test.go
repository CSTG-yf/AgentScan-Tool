package gateway

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestEventPageRoutesAndValidation(t *testing.T) {
	s, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: s}
	for _, path := range []string{"/api/v1/runtime-events/summary", "/api/v1/runtime-events/agents", "/api/v1/runtime-events/facets"} {
		r := httptest.NewRecorder()
		api.handleRuntimeEvents(r, httptest.NewRequest(http.MethodGet, path, nil))
		if r.Code != 200 {
			t.Fatalf("%s status=%d body=%s", path, r.Code, r.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/audit-events", "/api/v1/audit-events/summary", "/api/v1/audit-events/agents", "/api/v1/audit-events/facets"} {
		r := httptest.NewRecorder()
		api.handleAuditEvents(r, httptest.NewRequest(http.MethodGet, path, nil))
		if r.Code != 200 {
			t.Fatalf("%s status=%d body=%s", path, r.Code, r.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/runtime-events?sort=drop_table", "/api/v1/runtime-events?page=0", "/api/v1/runtime-events?include_desktop_behavior=maybe", "/api/v1/runtime-events?start_time=nope", "/api/v1/audit-events?enforced=maybe", "/api/v1/audit-events?page_size=999"} {
		r := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if strings.HasPrefix(path, "/api/v1/audit-events") {
			api.handleAuditEvents(r, req)
		} else {
			api.handleRuntimeEvents(r, req)
		}
		if r.Code != 400 {
			t.Fatalf("%s status=%d body=%s", path, r.Code, r.Body.String())
		}
	}
}
