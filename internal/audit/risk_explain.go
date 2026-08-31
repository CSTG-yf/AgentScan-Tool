package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type GovernanceRiskSeverityMappingPage struct {
	Total    int                                `json:"total"`
	Page     int                                `json:"page"`
	PageSize int                                `json:"page_size"`
	Items    []GovernanceRiskSeverityMappingRow `json:"items"`
}

type GovernanceRiskSeverityMappingRow struct {
	ID             int64  `json:"id"`
	SourceSeverity string `json:"source_severity"`
	RiskLevel      string `json:"risk_level"`
	Description    string `json:"description"`
	Priority       int    `json:"priority"`
	Enabled        bool   `json:"enabled"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type GovernanceRiskRulePrefixMatchPage struct {
	Total    int                                `json:"total"`
	Page     int                                `json:"page"`
	PageSize int                                `json:"page_size"`
	Items    []GovernanceRiskRulePrefixMatchRow `json:"items"`
}

type GovernanceRiskRulePrefixMatchRow struct {
	ID           int64  `json:"id"`
	RuleIDPrefix string `json:"rule_id_prefix"`
	RiskLevel    string `json:"risk_level"`
	Description  string `json:"description"`
	Priority     int    `json:"priority"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type GovernanceRiskCategoryMatchPage struct {
	Total    int                              `json:"total"`
	Page     int                              `json:"page"`
	PageSize int                              `json:"page_size"`
	Items    []GovernanceRiskCategoryMatchRow `json:"items"`
}

type GovernanceRiskCategoryMatchRow struct {
	ID          int64  `json:"id"`
	Category    string `json:"category"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type GovernanceRiskEvaluateInput struct {
	ResourceType string `json:"resource_type"`
	Severity     string `json:"severity"`
	RuleID       string `json:"rule_id"`
	Category     string `json:"category"`
	Tags         string `json:"tags"`
	Title        string `json:"title"`
}

type GovernanceRiskEvaluateResult struct {
	RiskLevel    string   `json:"risk_level"`
	MatchedType  string   `json:"matched_type"`
	MatchedValue string   `json:"matched_value"`
	Reason       string   `json:"reason"`
	Precedence   []string `json:"precedence"`
}

func (s *Store) ListGovernanceRiskSeverityMappings(f GovernancePageFilter) (*GovernanceRiskSeverityMappingPage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE("delete",0) = 0`}
	args := []any{}
	if f.Enabled != nil {
		where = append(where, "COALESCE(enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if strings.TrimSpace(f.RiskLevel) != "" {
		risk := normalizeRiskLevel(f.RiskLevel)
		if !validRiskLevel(risk) {
			return nil, fmt.Errorf("audit: unsupported risk_level %q", f.RiskLevel)
		}
		where = append(where, "LOWER(risk_level) = ?")
		args = append(args, risk)
	}
	if keyword := strings.ToLower(strings.TrimSpace(f.Keyword)); keyword != "" {
		like := "%" + keyword + "%"
		where = append(where, "(LOWER(source_severity) LIKE ? OR LOWER(risk_level) LIKE ? OR LOWER(COALESCE(description,'')) LIKE ?)")
		args = append(args, like, like, like)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_risk_severity_mapping_count", "SELECT COUNT(*) FROM risk_severity_mappings WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_risk_severity_mapping_list", `
SELECT id, source_severity, risk_level, COALESCE(description,''), priority, enabled, created_at, updated_at
FROM risk_severity_mappings
WHERE `+clause+`
ORDER BY priority ASC, id ASC
LIMIT ? OFFSET ?`, append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list risk severity mappings: %w", err)
	}
	defer rows.Close()
	out := &GovernanceRiskSeverityMappingPage{Total: total, Page: page, PageSize: size, Items: []GovernanceRiskSeverityMappingRow{}}
	for rows.Next() {
		item, err := scanGovernanceRiskSeverityMapping(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) ListGovernanceRiskRulePrefixMatches(f GovernancePageFilter) (*GovernanceRiskRulePrefixMatchPage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE("delete",0) = 0`}
	args := []any{}
	if f.Enabled != nil {
		where = append(where, "COALESCE(enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if strings.TrimSpace(f.RiskLevel) != "" {
		risk := normalizeRiskLevel(f.RiskLevel)
		if !validRiskLevel(risk) {
			return nil, fmt.Errorf("audit: unsupported risk_level %q", f.RiskLevel)
		}
		where = append(where, "LOWER(risk_level) = ?")
		args = append(args, risk)
	}
	if keyword := strings.ToLower(strings.TrimSpace(f.Keyword)); keyword != "" {
		like := "%" + keyword + "%"
		where = append(where, "(LOWER(rule_id_prefix) LIKE ? OR LOWER(risk_level) LIKE ? OR LOWER(COALESCE(description,'')) LIKE ?)")
		args = append(args, like, like, like)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_risk_rule_prefix_count", "SELECT COUNT(*) FROM risk_rule_prefix_matches WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_risk_rule_prefix_list", `
SELECT id, rule_id_prefix, risk_level, COALESCE(description,''), priority, enabled, created_at, updated_at
FROM risk_rule_prefix_matches
WHERE `+clause+`
ORDER BY priority ASC, LENGTH(rule_id_prefix) DESC, id ASC
LIMIT ? OFFSET ?`, append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list risk rule prefix matches: %w", err)
	}
	defer rows.Close()
	out := &GovernanceRiskRulePrefixMatchPage{Total: total, Page: page, PageSize: size, Items: []GovernanceRiskRulePrefixMatchRow{}}
	for rows.Next() {
		item, err := scanGovernanceRiskRulePrefixMatch(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) ListGovernanceRiskCategoryMatches(f GovernancePageFilter) (*GovernanceRiskCategoryMatchPage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE("delete",0) = 0`}
	args := []any{}
	if f.Enabled != nil {
		where = append(where, "COALESCE(enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if strings.TrimSpace(f.RiskLevel) != "" {
		risk := normalizeRiskLevel(f.RiskLevel)
		if !validRiskLevel(risk) {
			return nil, fmt.Errorf("audit: unsupported risk_level %q", f.RiskLevel)
		}
		where = append(where, "LOWER(risk_level) = ?")
		args = append(args, risk)
	}
	if keyword := strings.ToLower(strings.TrimSpace(f.Keyword)); keyword != "" {
		like := "%" + keyword + "%"
		where = append(where, "(LOWER(category) LIKE ? OR LOWER(risk_level) LIKE ? OR LOWER(COALESCE(description,'')) LIKE ?)")
		args = append(args, like, like, like)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_risk_category_count", "SELECT COUNT(*) FROM risk_category_matches WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_risk_category_list", `
SELECT id, category, risk_level, COALESCE(description,''), priority, enabled, created_at, updated_at
FROM risk_category_matches
WHERE `+clause+`
ORDER BY priority ASC, category ASC, id ASC
LIMIT ? OFFSET ?`, append(args, size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list risk category matches: %w", err)
	}
	defer rows.Close()
	out := &GovernanceRiskCategoryMatchPage{Total: total, Page: page, PageSize: size, Items: []GovernanceRiskCategoryMatchRow{}}
	for rows.Next() {
		item, err := scanGovernanceRiskCategoryMatch(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) EvaluateGovernanceRisk(in GovernanceRiskEvaluateInput) (GovernanceRiskEvaluateResult, error) {
	precedence := []string{"rule_id_prefix", "category", "severity", "default"}
	if result, ok, err := s.matchGovernanceRiskRulePrefix(strings.TrimSpace(in.RuleID), precedence); err != nil || ok {
		return result, err
	}
	if result, ok, err := s.matchGovernanceRiskCategory(strings.TrimSpace(in.Category), precedence); err != nil || ok {
		return result, err
	}
	if result, ok, err := s.matchGovernanceRiskSeverity(strings.TrimSpace(in.Severity), precedence); err != nil || ok {
		return result, err
	}
	return GovernanceRiskEvaluateResult{
		RiskLevel:    "clean",
		MatchedType:  "default",
		MatchedValue: "",
		Reason:       "No enabled prefix, category, or severity mapping matched; defaulted to clean.",
		Precedence:   precedence,
	}, nil
}

func (s *Store) matchGovernanceRiskRulePrefix(ruleID string, precedence []string) (GovernanceRiskEvaluateResult, bool, error) {
	if ruleID == "" {
		return GovernanceRiskEvaluateResult{}, false, nil
	}
	row := s.db.QueryRowContext(context.Background(), `
SELECT rule_id_prefix, risk_level
FROM risk_rule_prefix_matches
WHERE COALESCE(enabled,0) = 1 AND COALESCE("delete",0) = 0 AND ? LIKE rule_id_prefix || '%'
ORDER BY priority ASC, LENGTH(rule_id_prefix) DESC, id ASC
LIMIT 1`, ruleID)
	var prefix, risk string
	if err := row.Scan(&prefix, &risk); err != nil {
		if err == sql.ErrNoRows {
			return GovernanceRiskEvaluateResult{}, false, nil
		}
		return GovernanceRiskEvaluateResult{}, false, fmt.Errorf("audit: evaluate risk rule prefix: %w", err)
	}
	risk = safeRiskLevel(risk)
	return GovernanceRiskEvaluateResult{
		RiskLevel:    risk,
		MatchedType:  "rule_id_prefix",
		MatchedValue: prefix,
		Reason:       fmt.Sprintf("Rule ID prefix matched %s, mapped to %s.", prefix, risk),
		Precedence:   precedence,
	}, true, nil
}

func (s *Store) matchGovernanceRiskCategory(category string, precedence []string) (GovernanceRiskEvaluateResult, bool, error) {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		return GovernanceRiskEvaluateResult{}, false, nil
	}
	row := s.db.QueryRowContext(context.Background(), `
SELECT category, risk_level
FROM risk_category_matches
WHERE COALESCE(enabled,0) = 1 AND COALESCE("delete",0) = 0 AND LOWER(category) = ?
ORDER BY priority ASC, id ASC
LIMIT 1`, category)
	var matchedCategory, risk string
	if err := row.Scan(&matchedCategory, &risk); err != nil {
		if err == sql.ErrNoRows {
			return GovernanceRiskEvaluateResult{}, false, nil
		}
		return GovernanceRiskEvaluateResult{}, false, fmt.Errorf("audit: evaluate risk category: %w", err)
	}
	risk = safeRiskLevel(risk)
	return GovernanceRiskEvaluateResult{
		RiskLevel:    risk,
		MatchedType:  "category",
		MatchedValue: matchedCategory,
		Reason:       fmt.Sprintf("Category matched %s, mapped to %s.", matchedCategory, risk),
		Precedence:   precedence,
	}, true, nil
}

func (s *Store) matchGovernanceRiskSeverity(severity string, precedence []string) (GovernanceRiskEvaluateResult, bool, error) {
	severity = normalizeSeverity(severity)
	row := s.db.QueryRowContext(context.Background(), `
SELECT source_severity, risk_level
FROM risk_severity_mappings
WHERE COALESCE(enabled,0) = 1 AND COALESCE("delete",0) = 0 AND UPPER(source_severity) = ?
ORDER BY priority ASC, id ASC
LIMIT 1`, severity)
	var matchedSeverity, risk string
	if err := row.Scan(&matchedSeverity, &risk); err != nil {
		if err == sql.ErrNoRows {
			return GovernanceRiskEvaluateResult{}, false, nil
		}
		return GovernanceRiskEvaluateResult{}, false, fmt.Errorf("audit: evaluate risk severity: %w", err)
	}
	risk = safeRiskLevel(risk)
	return GovernanceRiskEvaluateResult{
		RiskLevel:    risk,
		MatchedType:  "severity",
		MatchedValue: matchedSeverity,
		Reason:       fmt.Sprintf("Severity matched %s, mapped to %s.", matchedSeverity, risk),
		Precedence:   precedence,
	}, true, nil
}

func scanGovernanceRiskSeverityMapping(rows *sql.Rows) (GovernanceRiskSeverityMappingRow, error) {
	var item GovernanceRiskSeverityMappingRow
	var enabled int
	if err := rows.Scan(&item.ID, &item.SourceSeverity, &item.RiskLevel, &item.Description, &item.Priority, &enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan risk severity mapping row: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func scanGovernanceRiskRulePrefixMatch(rows *sql.Rows) (GovernanceRiskRulePrefixMatchRow, error) {
	var item GovernanceRiskRulePrefixMatchRow
	var enabled int
	if err := rows.Scan(&item.ID, &item.RuleIDPrefix, &item.RiskLevel, &item.Description, &item.Priority, &enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan risk rule prefix match row: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func scanGovernanceRiskCategoryMatch(rows *sql.Rows) (GovernanceRiskCategoryMatchRow, error) {
	var item GovernanceRiskCategoryMatchRow
	var enabled int
	if err := rows.Scan(&item.ID, &item.Category, &item.RiskLevel, &item.Description, &item.Priority, &enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan risk category match row: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func safeRiskLevel(v string) string {
	v = normalizeRiskLevel(v)
	if !validRiskLevel(v) {
		return "clean"
	}
	return v
}

func seedRiskExplainModel(ex dbExecer) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, item := range []struct {
		severity    string
		risk        string
		description string
		priority    int
	}{
		{"CRITICAL", "critical", "Critical scanner finding maps to critical resource risk.", 30},
		{"HIGH", "high", "High scanner finding maps to high resource risk.", 31},
		{"MEDIUM", "medium", "Medium scanner finding maps to medium resource risk.", 32},
		{"LOW", "low", "Low scanner finding maps to low resource risk.", 33},
		{"INFO", "clean", "Informational scanner finding maps to clean resource risk.", 34},
	} {
		if _, err := ex.Exec(`
INSERT INTO risk_severity_mappings (source_severity, risk_level, description, priority, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, 1, ?, ?)
ON CONFLICT(source_severity) DO UPDATE SET
  risk_level = excluded.risk_level,
  description = excluded.description,
  priority = excluded.priority,
  enabled = 1,
  updated_at = excluded.updated_at,
  "delete" = 0`,
			item.severity, item.risk, item.description, item.priority, now, now); err != nil {
			return fmt.Errorf("seed risk severity mapping %s: %w", item.severity, err)
		}
	}
	if _, err := ex.Exec(`
INSERT INTO risk_rule_prefix_matches (rule_id_prefix, risk_level, description, priority, enabled, created_at, updated_at)
VALUES ('CS-MAL-', 'critical', 'ClawShield malware rule IDs are treated as critical risk before category or severity fallback.', 10, 1, ?, ?)
ON CONFLICT(rule_id_prefix) DO UPDATE SET
  risk_level = excluded.risk_level,
  description = excluded.description,
  priority = excluded.priority,
  enabled = 1,
  updated_at = excluded.updated_at,
  "delete" = 0`, now, now); err != nil {
		return fmt.Errorf("seed risk rule prefix match: %w", err)
	}
	for _, category := range []string{"malware", "reverse_shell", "credential_harvest", "credential_exfiltration", "cryptominer", "c2", "command_execution"} {
		if _, err := ex.Exec(`
INSERT INTO risk_category_matches (category, risk_level, description, priority, enabled, created_at, updated_at)
VALUES (?, 'critical', ?, 20, 1, ?, ?)
ON CONFLICT(category) DO UPDATE SET
  risk_level = excluded.risk_level,
  description = excluded.description,
  priority = excluded.priority,
  enabled = 1,
  updated_at = excluded.updated_at,
  "delete" = 0`,
			category, "Category "+category+" is treated as critical resource risk.", now, now); err != nil {
			return fmt.Errorf("seed risk category match %s: %w", category, err)
		}
	}
	return nil
}
