// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func evaluationAPIArtifact(id, kind, content string) audit.EvaluationArtifact {
	h := sha256.Sum256([]byte(content))
	return audit.EvaluationArtifact{ID: id, Kind: kind, Source: "test fixture", Content: content, SHA256: hex.EncodeToString(h[:])}
}
func TestEvaluationAPIHistoryFiltersArtifactsAndCancel(t *testing.T) {
	s, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: s}
	truth := evaluationAPIArtifact("truth", "ground_truth", `{"runtime":{"one":true}}`)
	proof := evaluationAPIArtifact("proof", "event", `{"action":"block"}`)
	yes := true
	run := audit.EvaluationRun{Name: "run", Mode: "action", Status: "running", DatasetHash: "data", RuntimeTruth: audit.EvaluationTruth{ArtifactID: "truth", DatasetHash: "data"}, Artifacts: []audit.EvaluationArtifact{truth, proof}, Instances: []audit.EvaluationInstance{{ID: "one", Domain: "runtime", Predicted: &yes, Evidence: map[string][]string{"detection": {"proof"}}}}}
	body, _ := json.Marshal(run)
	rec := httptest.NewRecorder()
	api.handleEvaluationsAPI(rec, httptest.NewRequest("POST", evaluationPrefix, bytes.NewReader(body)))
	if rec.Code != 201 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var saved audit.EvaluationRun
	json.Unmarshal(rec.Body.Bytes(), &saved)
	for _, path := range []string{"", "/latest", "/" + saved.ID, "/" + saved.ID + "/comparison", "/" + saved.ID + "/instances?domain=runtime&outcome=tp", "/" + saved.ID + "/artifacts/proof"} {
		rec = httptest.NewRecorder()
		api.handleEvaluationsAPI(rec, httptest.NewRequest("GET", evaluationPrefix+path, nil))
		if rec.Code != 200 {
			t.Fatal(path, rec.Code, rec.Body.String())
		}
	}
	rec = httptest.NewRecorder()
	api.handleEvaluationsAPI(rec, httptest.NewRequest("POST", evaluationPrefix+"/"+saved.ID+"/cancel", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"cancelled"`) {
		t.Fatal("cancel", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	api.handleEvaluationsAPI(rec, httptest.NewRequest("POST", evaluationPrefix, strings.NewReader(string(body)+" {}")))
	if rec.Code != 400 {
		t.Fatal("trailing JSON accepted")
	}
	rec = httptest.NewRecorder()
	api.handleEvaluationsAPI(rec, httptest.NewRequest("GET", evaluationPrefix+"/missing/instances", nil))
	if rec.Code != 404 {
		t.Fatal("missing run", rec.Code)
	}
	rec = httptest.NewRecorder()
	api.handleEvaluationsAPI(rec, httptest.NewRequest("GET", evaluationPrefix+"?limit=201", nil))
	if rec.Code != 400 {
		t.Fatal("unbounded pagination")
	}
}
func TestEvaluationAPIImportLimitIsScoped(t *testing.T) {
	handler := maxBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value map[string]any
		err := json.NewDecoder(r.Body).Decode(&value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(200)
	}), 1<<20)
	body := `{"value":"` + strings.Repeat("a", 2<<20) + `"}`
	for _, test := range []struct {
		path string
		code int
	}{{evaluationPrefix, 200}, {"/api/v1/jobs", 413}} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", test.path, strings.NewReader(body)))
		if rec.Code != test.code {
			t.Fatal(test.path, rec.Code)
		}
	}
}

func TestEvaluationAPIThreeModeComparisonUsesMatchingBaseline(t *testing.T) {
	s, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{store: s}
	truth := evaluationAPIArtifact("truth", "ground_truth", `{"runtime":{"one":true}}`)
	samples := evaluationAPIArtifact("samples", "samples", `[{"at":"2026-10-09T00:00:00Z","value":1},{"at":"2026-10-09T00:00:02Z","value":2}]`)
	ids := map[string]string{}
	for _, mode := range []string{"baseline", "observe", "action"} {
		r := audit.EvaluationRun{Name: mode, Mode: mode, Status: "completed", ComparisonGroup: "same-run", Platform: "test", CodeVersion: "v1", ConfigHash: "known-config", ImageDigest: "sha256:known-image", DatasetHash: "data", StartedAt: "2026-10-09T00:00:00Z", FinishedAt: "2026-10-09T00:00:02Z", RuntimeTruth: audit.EvaluationTruth{ArtifactID: "truth", DatasetHash: "data"}, Artifacts: []audit.EvaluationArtifact{truth, samples}, Series: []audit.EvaluationSeries{{ID: "cpu", Kind: "cpu_pct", Scope: "defense_chain", Basis: "host percent", WindowStart: "2026-10-09T00:00:00Z", WindowEnd: "2026-10-09T00:00:02Z", ExpectedSamples: 2, Complete: true, ArtifactID: "samples", Samples: []audit.EvaluationSample{{At: "2026-10-09T00:00:00Z", Value: 1}, {At: "2026-10-09T00:00:02Z", Value: 2}}}}}
		saved, err := s.CreateEvaluation(r)
		if err != nil {
			t.Fatal(err)
		}
		ids[mode] = saved.ID
	}
	rec := httptest.NewRecorder()
	api.handleEvaluationsAPI(rec, httptest.NewRequest("GET", evaluationPrefix+"/"+ids["action"]+"/comparison", nil))
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var response struct {
		Modes map[string]audit.EvaluationRun `json:"modes"`
	}
	if err = json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Modes) != 3 {
		t.Fatal("missing comparable modes")
	}
	found := false
	for _, m := range response.Modes["action"].Report.Metrics {
		if m.Key == "cpu_increment" {
			found = true
			if m.Value == nil || *m.Value != 0 || m.Status != "passed" {
				t.Fatal("CPU comparison", m)
			}
		}
	}
	if !found {
		t.Fatal("missing CPU metric")
	}
}
