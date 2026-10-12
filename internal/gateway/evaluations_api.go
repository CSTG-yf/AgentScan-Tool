// SPDX-License-Identifier: Apache-2.0
package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const evaluationPrefix = "/api/v1/evaluations"

func evaluationPagination(r *http.Request) (int, int, error) {
	limit, offset := 50, 0
	var err error
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil {
			return 0, 0, err
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil {
			return 0, 0, err
		}
	}
	if limit < 1 || limit > 200 || offset < 0 {
		return 0, 0, errors.New("invalid pagination")
	}
	return limit, offset, nil
}
func (a *APIServer) evaluationError(w http.ResponseWriter, err error) {
	code := 500
	if errors.Is(err, audit.ErrEvaluationNotFound) {
		code = 404
	}
	if errors.Is(err, audit.ErrEvaluationFinished) {
		code = 409
	}
	a.writeJSON(w, code, map[string]string{"error": err.Error()})
}
func (a *APIServer) evaluationWithBaseline(run audit.EvaluationRun) audit.EvaluationRun {
	if run.Mode != "action" || run.Status != "completed" {
		return run
	}
	// Group-filtered history is bounded by the API's durable comparison index.
	baselines, _, err := a.store.ListEvaluationGroup(run.ComparisonGroup, "baseline")
	if err != nil {
		return run
	}
	for _, b := range baselines {
		if b.Status == "completed" && audit.EvaluationComparable(run, b) {
			audit.ApplyEvaluationBaseline(&run, b)
			break
		}
	}
	return run
}
func (a *APIServer) handleEvaluationsAPI(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, 503, map[string]string{"error": "audit store unavailable"})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, evaluationPrefix), "/")
	parts := strings.Split(rest, "/")
	if rest == "" && r.Method == http.MethodPost {
		var run audit.EvaluationRun
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&run); err != nil {
			a.writeJSON(w, 400, map[string]string{"error": "invalid evaluation JSON: " + err.Error()})
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			a.writeJSON(w, 400, map[string]string{"error": "expected one JSON report"})
			return
		}
		if err := audit.ValidateEvaluation(&run); err != nil {
			a.writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		saved, err := a.store.CreateEvaluation(run)
		if err != nil {
			a.evaluationError(w, err)
			return
		}
		a.writeJSON(w, 201, a.evaluationWithBaseline(saved))
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		run, err := a.store.CancelEvaluation(parts[0])
		if err != nil {
			a.evaluationError(w, err)
			return
		}
		a.writeJSON(w, 200, run)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	if rest == "" || rest == "latest" {
		limit, offset, err := evaluationPagination(r)
		if err != nil {
			a.writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if rest == "latest" {
			limit = 1
			offset = 0
		}
		runs, total, err := a.store.ListEvaluations(r.URL.Query().Get("mode"), r.URL.Query().Get("status"), limit, offset)
		if err != nil {
			a.evaluationError(w, err)
			return
		}
		for n := range runs {
			runs[n] = a.evaluationWithBaseline(runs[n])
		}
		if rest == "latest" {
			if len(runs) == 0 {
				a.evaluationError(w, audit.ErrEvaluationNotFound)
			} else {
				a.writeJSON(w, 200, runs[0])
			}
			return
		}
		a.writeJSON(w, 200, map[string]any{"runs": runs, "total": total, "limit": limit, "offset": offset})
		return
	}
	run, err := a.store.GetEvaluation(parts[0])
	if err != nil {
		a.evaluationError(w, err)
		return
	}
	if len(parts) == 1 {
		a.writeJSON(w, 200, a.evaluationWithBaseline(run))
		return
	}
	if len(parts) == 2 && parts[1] == "instances" {
		limit, offset, err := evaluationPagination(r)
		if err != nil {
			a.writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		q := r.URL.Query()
		items, total, err := a.store.ListEvaluationInstances(run.ID, q.Get("domain"), q.Get("outcome"), q.Get("scenario"), q.Get("connector"), limit, offset)
		if err != nil {
			a.evaluationError(w, err)
			return
		}
		a.writeJSON(w, 200, map[string]any{"instances": items, "total": total, "limit": limit, "offset": offset})
		return
	}
	if len(parts) == 3 && parts[1] == "artifacts" {
		artifact, err := a.store.GetEvaluationArtifact(run.ID, parts[2])
		if err != nil {
			a.evaluationError(w, err)
			return
		}
		a.writeJSON(w, 200, artifact)
		return
	}
	if len(parts) == 2 && parts[1] == "comparison" {
		candidates, _, err := a.store.ListEvaluationGroup(run.ComparisonGroup, "")
		if err != nil {
			a.evaluationError(w, err)
			return
		}
		modes := map[string]audit.EvaluationRun{}
		for _, candidate := range candidates {
			if candidate.ID == run.ID || audit.EvaluationComparable(run, candidate) {
				if _, ok := modes[candidate.Mode]; !ok {
					modes[candidate.Mode] = a.evaluationWithBaseline(candidate)
				}
			}
		}
		modes[run.Mode] = a.evaluationWithBaseline(run)
		a.writeJSON(w, 200, map[string]any{"modes": modes, "basis": "同平台、代码、配置、镜像、数据集与运行时真值；缺失元数据不参与比较"})
		return
	}
	http.NotFound(w, r)
}
