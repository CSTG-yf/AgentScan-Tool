// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const ScanSchedulesDomain = "scan_schedules"

var ScanScheduleTaskTypes = []string{
	"agent_discovery", "static_assets", "runtime_detections",
	"attack_chains", "behavior_trace", "environment",
}

type ScanSchedule struct {
	TaskType    string         `json:"task_type"`
	Enabled     bool           `json:"enabled"`
	IntervalSec int            `json:"interval_sec"`
	Mode        string         `json:"mode"`
	Scope       map[string]any `json:"scope"`
	UpdatedAt   string         `json:"updated_at"`
	UpdatedBy   string         `json:"updated_by,omitempty"`
}

func DefaultScanSchedules() []ScanSchedule {
	return []ScanSchedule{
		{TaskType: "agent_discovery", Enabled: true, IntervalSec: 900, Mode: "incremental", Scope: map[string]any{}},
		{TaskType: "static_assets", Enabled: false, IntervalSec: 3600, Mode: "incremental", Scope: map[string]any{}},
		{TaskType: "runtime_detections", Enabled: false, IntervalSec: 3600, Mode: "replay", Scope: map[string]any{}},
		{TaskType: "attack_chains", Enabled: false, IntervalSec: 3600, Mode: "rebuild", Scope: map[string]any{}},
		{TaskType: "behavior_trace", Enabled: false, IntervalSec: 900, Mode: "incremental", Scope: map[string]any{}},
		{TaskType: "environment", Enabled: false, IntervalSec: 300, Mode: "incremental", Scope: map[string]any{}},
	}
}

func NormalizeScanTaskType(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", "_"))
	switch value {
	case "agents":
		return "agent_discovery"
	case "resource_scan", "static_resources":
		return "static_assets"
	case "event_replay", "detection_replay":
		return "runtime_detections"
	case "attack_chain_rebuild", "chain_rebuild":
		return "attack_chains"
	}
	return value
}

func ScanJobKind(taskType string) string {
	switch NormalizeScanTaskType(taskType) {
	case "static_assets":
		return "resource_scan"
	case "runtime_detections":
		return "event_replay"
	case "attack_chains":
		return "attack_chain_rebuild"
	default:
		return NormalizeScanTaskType(taskType)
	}
}

func IsScanScheduleTaskType(value string) bool {
	value = NormalizeScanTaskType(value)
	for _, candidate := range ScanScheduleTaskTypes {
		if candidate == value {
			return true
		}
	}
	return false
}

func NormalizeScanTrigger(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "schedule", "scheduled", "scheduler":
		return "scheduler"
	case "watcher":
		return "watcher"
	default:
		return "manual"
	}
}

func NormalizeScanSchedule(in ScanSchedule) (ScanSchedule, error) {
	in.TaskType = NormalizeScanTaskType(in.TaskType)
	if !IsScanScheduleTaskType(in.TaskType) {
		return ScanSchedule{}, fmt.Errorf("unsupported task_type %q", in.TaskType)
	}
	if in.IntervalSec < 3 || in.IntervalSec > 86400 {
		return ScanSchedule{}, fmt.Errorf("interval_sec must be between 3 and 86400")
	}
	in.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	if in.Mode == "scheduled" || in.Mode == "" {
		in.Mode = map[string]string{"runtime_detections": "replay", "attack_chains": "rebuild"}[in.TaskType]
		if in.Mode == "" {
			in.Mode = "incremental"
		}
	}
	allowed := map[string]bool{"full": true, "incremental": true, "single": true, "replay": true, "rebuild": true}
	if !allowed[in.Mode] {
		return ScanSchedule{}, fmt.Errorf("unsupported scan mode %q", in.Mode)
	}
	if in.Scope == nil {
		in.Scope = map[string]any{}
	}
	if in.UpdatedAt == "" {
		in.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return in, nil
}

func migrateScanSchedules(ex dbExecer) error {
	if _, err := ex.Exec(`
CREATE TABLE IF NOT EXISTS scan_schedules (
 task_type TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
 interval_sec INTEGER NOT NULL, mode TEXT NOT NULL DEFAULT 'incremental',
 scope_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL, updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TRIGGER IF NOT EXISTS change_log_scan_schedules_insert AFTER INSERT ON scan_schedules BEGIN INSERT INTO change_log(domain,changed_at) VALUES('scan_schedules',CURRENT_TIMESTAMP); END;
CREATE TRIGGER IF NOT EXISTS change_log_scan_schedules_update AFTER UPDATE ON scan_schedules BEGIN INSERT INTO change_log(domain,changed_at) VALUES('scan_schedules',CURRENT_TIMESTAMP); END;
CREATE TRIGGER IF NOT EXISTS change_log_scan_schedules_delete AFTER DELETE ON scan_schedules BEGIN INSERT INTO change_log(domain,changed_at) VALUES('scan_schedules',CURRENT_TIMESTAMP); END;`); err != nil {
		return err
	}
	for _, schedule := range DefaultScanSchedules() {
		schedule, _ = NormalizeScanSchedule(schedule)
		raw, _ := json.Marshal(schedule.Scope)
		if _, err := ex.Exec(`INSERT INTO scan_schedules(task_type,enabled,interval_sec,mode,scope_json,updated_at,updated_by) VALUES(?,?,?,?,?,?,?) ON CONFLICT(task_type) DO NOTHING`, schedule.TaskType, boolToInt(schedule.Enabled), schedule.IntervalSec, schedule.Mode, string(raw), schedule.UpdatedAt, schedule.UpdatedBy); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListScanSchedules() ([]ScanSchedule, error) {
	if s == nil || s.db == nil {
		return []ScanSchedule{}, nil
	}
	rows, err := s.queryDB(context.Background(), "scan_schedules_list", `SELECT task_type,enabled,interval_sec,mode,scope_json,updated_at,updated_by FROM scan_schedules ORDER BY CASE task_type WHEN 'agent_discovery' THEN 1 WHEN 'static_assets' THEN 2 WHEN 'runtime_detections' THEN 3 WHEN 'attack_chains' THEN 4 WHEN 'behavior_trace' THEN 5 ELSE 6 END`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ScanSchedule{}
	for rows.Next() {
		var item ScanSchedule
		var enabled int
		var raw string
		if err := rows.Scan(&item.TaskType, &enabled, &item.IntervalSec, &item.Mode, &raw, &item.UpdatedAt, &item.UpdatedBy); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		item.Scope = map[string]any{}
		if err := json.Unmarshal([]byte(raw), &item.Scope); err != nil {
			return nil, fmt.Errorf("parse scan schedule %s scope: %w", item.TaskType, err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetScanSchedule(taskType string) (ScanSchedule, bool, error) {
	if s == nil || s.db == nil {
		return ScanSchedule{}, false, nil
	}
	var item ScanSchedule
	var enabled int
	var raw string
	err := s.db.QueryRowContext(context.Background(), `SELECT task_type,enabled,interval_sec,mode,scope_json,updated_at,updated_by FROM scan_schedules WHERE task_type=?`, NormalizeScanTaskType(taskType)).Scan(&item.TaskType, &enabled, &item.IntervalSec, &item.Mode, &raw, &item.UpdatedAt, &item.UpdatedBy)
	if err == sql.ErrNoRows {
		return ScanSchedule{}, false, nil
	}
	if err != nil {
		return ScanSchedule{}, false, err
	}
	item.Enabled = enabled != 0
	item.Scope = map[string]any{}
	if err := json.Unmarshal([]byte(raw), &item.Scope); err != nil {
		return ScanSchedule{}, false, err
	}
	return item, true, nil
}

func (s *Store) SaveScanSchedule(in ScanSchedule) (ScanSchedule, error) {
	if s == nil || s.db == nil {
		return ScanSchedule{}, fmt.Errorf("audit store unavailable")
	}
	in.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	in, err := NormalizeScanSchedule(in)
	if err != nil {
		return ScanSchedule{}, err
	}
	raw, err := json.Marshal(in.Scope)
	if err != nil {
		return ScanSchedule{}, err
	}
	_, err = s.execDB(context.Background(), "scan_schedule_save", `INSERT INTO scan_schedules(task_type,enabled,interval_sec,mode,scope_json,updated_at,updated_by) VALUES(?,?,?,?,?,?,?) ON CONFLICT(task_type) DO UPDATE SET enabled=excluded.enabled,interval_sec=excluded.interval_sec,mode=excluded.mode,scope_json=excluded.scope_json,updated_at=excluded.updated_at,updated_by=excluded.updated_by`, in.TaskType, boolToInt(in.Enabled), in.IntervalSec, in.Mode, string(raw), in.UpdatedAt, in.UpdatedBy)
	return in, err
}
