// SPDX-License-Identifier: Apache-2.0
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrEvaluationNotFound = errors.New("evaluation not found")
var ErrEvaluationFinished = errors.New("evaluation already finished")

func migrateEvaluations(ex dbExecer) error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS evaluation_runs (id TEXT PRIMARY KEY, mode TEXT NOT NULL, status TEXT NOT NULL, comparison_group TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT NOT NULL, metadata_json TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS idx_evaluation_runs_history ON evaluation_runs(created_at DESC,id)`,
		`CREATE TABLE IF NOT EXISTS evaluation_instances (run_id TEXT NOT NULL REFERENCES evaluation_runs(id), id TEXT NOT NULL, domain TEXT NOT NULL, outcome TEXT NOT NULL, scenario TEXT NOT NULL, connector TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(run_id,domain,id))`,
		`CREATE INDEX IF NOT EXISTS idx_evaluation_instances_filter ON evaluation_instances(run_id,domain,outcome,scenario,connector)`,
		`CREATE TABLE IF NOT EXISTS evaluation_metrics (run_id TEXT NOT NULL REFERENCES evaluation_runs(id), key TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(run_id,key))`,
		`CREATE TABLE IF NOT EXISTS evaluation_artifacts (run_id TEXT NOT NULL REFERENCES evaluation_runs(id), id TEXT NOT NULL, sha256 TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(run_id,id))`,
	} {
		if _, err := ex.Exec(q); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) CreateEvaluation(run EvaluationRun) (EvaluationRun, error) {
	run.Instances = append([]EvaluationInstance(nil), run.Instances...)
	run.Series = append([]EvaluationSeries(nil), run.Series...)
	if err := ValidateEvaluation(&run); err != nil {
		return run, err
	}
	// A new import always gets a new immutable run; callers cannot overwrite history.
	run.ID = uuid.NewString()
	run.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	instances, artifacts := run.Instances, run.Artifacts
	run.Instances = nil
	run.Artifacts = nil
	for n := range run.Series {
		run.Series[n].Samples = nil
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return run, err
	}
	defer tx.Rollback()
	raw, err := json.Marshal(run)
	if err != nil {
		return run, err
	}
	if _, err = tx.Exec(`INSERT INTO evaluation_runs(id,mode,status,comparison_group,created_at,started_at,metadata_json) VALUES(?,?,?,?,?,?,?)`, run.ID, run.Mode, run.Status, run.ComparisonGroup, run.CreatedAt, run.StartedAt, string(raw)); err != nil {
		return run, err
	}
	for _, i := range instances {
		raw, err = json.Marshal(i)
		if err != nil {
			return run, err
		}
		if _, err = tx.Exec(`INSERT INTO evaluation_instances(run_id,id,domain,outcome,scenario,connector,payload_json) VALUES(?,?,?,?,?,?,?)`, run.ID, i.ID, i.Domain, i.Outcome, i.Scenario, i.Connector, string(raw)); err != nil {
			return run, err
		}
	}
	for _, a := range artifacts {
		raw, err = json.Marshal(a)
		if err != nil {
			return run, err
		}
		if _, err = tx.Exec(`INSERT INTO evaluation_artifacts(run_id,id,sha256,payload_json) VALUES(?,?,?,?)`, run.ID, a.ID, a.SHA256, string(raw)); err != nil {
			return run, err
		}
	}
	for _, m := range run.Report.Metrics {
		raw, err = json.Marshal(m)
		if err != nil {
			return run, err
		}
		if _, err = tx.Exec(`INSERT INTO evaluation_metrics(run_id,key,payload_json) VALUES(?,?,?)`, run.ID, m.Key, string(raw)); err != nil {
			return run, err
		}
	}
	return run, tx.Commit()
}
func (s *Store) GetEvaluation(id string) (EvaluationRun, error) {
	var raw string
	var run EvaluationRun
	err := s.db.QueryRow(`SELECT metadata_json FROM evaluation_runs WHERE id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return run, ErrEvaluationNotFound
	}
	if err != nil {
		return run, err
	}
	err = json.Unmarshal([]byte(raw), &run)
	return run, err
}
func (s *Store) ListEvaluations(mode, status string, limit, offset int) ([]EvaluationRun, int, error) {
	where := " WHERE (?='' OR mode=?) AND (?='' OR status=?)"
	args := []any{mode, mode, status, status}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM evaluation_runs`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT metadata_json FROM evaluation_runs`+where+` ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	runs := []EvaluationRun{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		var run EvaluationRun
		if err := json.Unmarshal([]byte(raw), &run); err != nil {
			return nil, 0, err
		}
		runs = append(runs, run)
	}
	return runs, total, rows.Err()
}
func (s *Store) ListEvaluationInstances(id, domain, outcome, scenario, connector string, limit, offset int) ([]EvaluationInstance, int, error) {
	where := ` WHERE run_id=? AND (?='' OR domain=?) AND (?='' OR outcome=?) AND (?='' OR scenario=?) AND (?='' OR connector=?)`
	args := []any{id, domain, domain, outcome, outcome, scenario, scenario, connector, connector}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM evaluation_instances`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT payload_json FROM evaluation_instances`+where+` ORDER BY domain,id LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []EvaluationInstance{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		var i EvaluationInstance
		if err := json.Unmarshal([]byte(raw), &i); err != nil {
			return nil, 0, err
		}
		items = append(items, i)
	}
	return items, total, rows.Err()
}
func (s *Store) GetEvaluationArtifact(runID, id string) (EvaluationArtifact, error) {
	var raw string
	var a EvaluationArtifact
	err := s.db.QueryRow(`SELECT payload_json FROM evaluation_artifacts WHERE run_id=? AND id=?`, runID, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrEvaluationNotFound
	}
	if err != nil {
		return a, err
	}
	err = json.Unmarshal([]byte(raw), &a)
	return a, err
}
func (s *Store) CancelEvaluation(id string) (EvaluationRun, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return EvaluationRun{}, err
	}
	defer tx.Rollback()
	var raw string
	if err = tx.QueryRow(`SELECT metadata_json FROM evaluation_runs WHERE id=?`, id).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return EvaluationRun{}, ErrEvaluationNotFound
	} else if err != nil {
		return EvaluationRun{}, err
	}
	var run EvaluationRun
	if err = json.Unmarshal([]byte(raw), &run); err != nil {
		return run, err
	}
	if run.Status != "running" {
		return run, ErrEvaluationFinished
	}
	run.Status = "cancelled"
	run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	run.Notes = append(run.Notes, "评测记录已取消，已收集证据保留。")
	for n := range run.Report.Metrics {
		run.Report.Metrics[n].Status = "insufficient_evidence"
		run.Report.Metrics[n].Reason = "批次已取消"
		m := run.Report.Metrics[n]
		b, _ := json.Marshal(m)
		if _, err = tx.Exec(`UPDATE evaluation_metrics SET payload_json=? WHERE run_id=? AND key=?`, string(b), id, m.Key); err != nil {
			return run, err
		}
	}
	setEvaluationCapabilityStatus(&run.Report)
	b, err := json.Marshal(run)
	if err != nil {
		return run, err
	}
	result, err := tx.Exec(`UPDATE evaluation_runs SET status=?,metadata_json=? WHERE id=? AND status='running'`, run.Status, string(b), id)
	if err != nil {
		return run, err
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return run, fmt.Errorf("evaluation status changed")
	}
	return run, tx.Commit()
}

func (s *Store) ListEvaluationGroup(group, mode string) ([]EvaluationRun, int, error) {
	if group == "" {
		return []EvaluationRun{}, 0, nil
	}
	rows, err := s.db.Query(`SELECT metadata_json FROM evaluation_runs WHERE comparison_group=? AND (?='' OR mode=?) ORDER BY created_at DESC,id DESC`, group, mode, mode)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	runs := []EvaluationRun{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		var r EvaluationRun
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			return nil, 0, err
		}
		runs = append(runs, r)
	}
	return runs, len(runs), rows.Err()
}
