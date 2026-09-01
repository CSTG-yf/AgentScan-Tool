// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"strings"
)

// ChangeCursor is a lightweight invalidation result. It intentionally does
// not contain row data: callers use NextCursor to decide which authoritative
// read model to refresh.
type ChangeCursor struct {
	NextCursor     int64    `json:"next_cursor"`
	ChangedDomains []string `json:"changed_domains"`
	LatestAt       string   `json:"latest_at,omitempty"`
}

// ChangesSince returns domain invalidations after cursor. The revision is a
// SQLite AUTOINCREMENT sequence, so it is monotonic across all writers in the
// local store. Empty domains means all supported domains.
func (s *Store) ChangesSince(cursor int64, domains []string, limit int) (ChangeCursor, error) {
	if s == nil || s.db == nil {
		return ChangeCursor{}, nil
	}
	if cursor < 0 {
		cursor = 0
	}
	if limit <= 0 || limit > 100 {
		limit = 32
	}

	var result ChangeCursor
	var latest sql.NullString
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT COALESCE(MAX(revision), 0), MAX(changed_at) FROM change_log`,
	).Scan(&result.NextCursor, &latest); err != nil {
		return ChangeCursor{}, err
	}
	if latest.Valid {
		result.LatestAt = latest.String
	}
	if cursor >= result.NextCursor {
		return result, nil
	}

	cleanDomains := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		seen := false
		for _, existing := range cleanDomains {
			if existing == domain {
				seen = true
				break
			}
		}
		if !seen {
			cleanDomains = append(cleanDomains, domain)
		}
	}

	where := `revision > ?`
	args := []any{cursor}
	if len(cleanDomains) > 0 {
		placeholders := make([]string, len(cleanDomains))
		for i, domain := range cleanDomains {
			placeholders[i] = "?"
			args = append(args, domain)
		}
		where += " AND domain IN (" + strings.Join(placeholders, ",") + ")"
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT domain FROM change_log WHERE `+where+` GROUP BY domain ORDER BY MIN(revision) LIMIT ?`, args...)
	if err != nil {
		return ChangeCursor{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return ChangeCursor{}, err
		}
		result.ChangedDomains = append(result.ChangedDomains, domain)
	}
	if err := rows.Err(); err != nil {
		return ChangeCursor{}, err
	}
	return result, nil
}
