// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
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

// SaveJSONSetting stores an application-level setting in audit.db. These are
// backend-owned settings used by the desktop UI, not security findings.
func (s *Store) SaveJSONSetting(key string, value any) error {
	if s == nil || s.db == nil {
		return nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("audit: app setting key is required")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("audit: marshal app setting %q: %w", key, err)
	}
	_, err = s.execDB(context.Background(), "app_setting_save", `
INSERT INTO app_settings (key, value_json, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET
  value_json = excluded.value_json,
  updated_at = excluded.updated_at`,
		key,
		string(raw),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("audit: save app setting %q: %w", key, err)
	}
	return nil
}

// LoadJSONSetting loads one application-level setting. It returns false when
// the key has not been written yet.
func (s *Store) LoadJSONSetting(key string, dest any) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false, fmt.Errorf("audit: app setting key is required")
	}
	var raw string
	err := s.scanRow(context.Background(), "app_setting_load",
		s.db.QueryRowContext(context.Background(), `SELECT value_json FROM app_settings WHERE key = ?`, key),
		&raw,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("audit: load app setting %q: %w", key, err)
	}
	if err := json.Unmarshal([]byte(raw), dest); err != nil {
		return false, fmt.Errorf("audit: parse app setting %q: %w", key, err)
	}
	return true, nil
}
