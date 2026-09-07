// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"strings"
	"time"
)

func migrateRuntimeDetectionSettings(ex dbExecer) error {
	_, err := ex.Exec(`
CREATE TABLE IF NOT EXISTS runtime_detection_rules (
 id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL,
 source TEXT NOT NULL, scope TEXT NOT NULL, agent_type_id INTEGER,
 detection_type TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, confidence REAL NOT NULL,
 matcher_json TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
 priority INTEGER NOT NULL DEFAULT 100, enabled INTEGER NOT NULL DEFAULT 1, system INTEGER NOT NULL DEFAULT 0,
 version INTEGER NOT NULL DEFAULT 1, override_severity INTEGER NOT NULL DEFAULT 0, override_confidence INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "delete" INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(agent_type_id) REFERENCES agent_types(id) ON DELETE CASCADE,
 CHECK((scope='global' AND agent_type_id IS NULL) OR (scope='agent_type' AND agent_type_id IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_detection_rules_unique ON runtime_detection_rules(scope,COALESCE(agent_type_id,0),rule_id) WHERE "delete"=0;
CREATE TABLE IF NOT EXISTS runtime_risk_policies (
 id INTEGER PRIMARY KEY AUTOINCREMENT, policy_key TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 scope TEXT NOT NULL, agent_type_id INTEGER, version INTEGER NOT NULL DEFAULT 1,
 description TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, system INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "delete" INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(agent_type_id) REFERENCES agent_types(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_risk_policy_scope ON runtime_risk_policies(scope,COALESCE(agent_type_id,0)) WHERE "delete"=0;
CREATE TABLE IF NOT EXISTS runtime_risk_policy_rules (
 id INTEGER PRIMARY KEY AUTOINCREMENT, policy_id INTEGER NOT NULL, risk_level TEXT NOT NULL,
 min_score REAL NOT NULL, max_score REAL NOT NULL, decision TEXT NOT NULL,
 priority INTEGER NOT NULL DEFAULT 100, enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "delete" INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(policy_id) REFERENCES runtime_risk_policies(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS runtime_detection_agent_type_settings (
 agent_type_id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1,
 inherit_global_rules INTEGER NOT NULL DEFAULT 1, use_global_risk_policy INTEGER NOT NULL DEFAULT 1,
 custom_risk_policy_id INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 "delete" INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(agent_type_id) REFERENCES agent_types(id) ON DELETE CASCADE,
 FOREIGN KEY(custom_risk_policy_id) REFERENCES runtime_risk_policies(id)
);
CREATE TABLE IF NOT EXISTS runtime_detection_blacklist_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT, agent_type_id INTEGER NOT NULL, target_type TEXT NOT NULL,
 match_type TEXT NOT NULL, value TEXT NOT NULL, detection_type TEXT NOT NULL, category TEXT NOT NULL,
 severity TEXT NOT NULL, confidence REAL NOT NULL, reason TEXT NOT NULL DEFAULT '',
 priority INTEGER NOT NULL DEFAULT 50, enabled INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "delete" INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(agent_type_id) REFERENCES agent_types(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_runtime_blacklist_type ON runtime_detection_blacklist_items(agent_type_id,enabled,"delete");`)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = ex.Exec(`INSERT INTO runtime_risk_policies(policy_key,name,scope,system,created_at,updated_at) VALUES('runtime-risk-policy-default','Default Runtime Risk Policy','global',1,?,?) ON CONFLICT(policy_key) DO NOTHING`, now, now); err != nil {
		return err
	}
	var policyID int64
	if err = ex.QueryRow(`SELECT id FROM runtime_risk_policies WHERE policy_key='runtime-risk-policy-default'`).Scan(&policyID); err != nil {
		return err
	}
	var count int
	if err = ex.QueryRow(`SELECT COUNT(*) FROM runtime_risk_policy_rules WHERE policy_id=?`, policyID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		for _, r := range DefaultRuntimeRiskPolicyRules() {
			if _, err = ex.Exec(`INSERT INTO runtime_risk_policy_rules(policy_id,risk_level,min_score,max_score,decision,priority,enabled,created_at,updated_at) VALUES(?,?,?,?,?,100,1,?,?)`, policyID, r.RiskLevel, r.MinScore, r.MaxScore, r.Decision, now, now); err != nil {
				return err
			}
		}
	}
	for _, table := range []string{"runtime_detection_rules", "runtime_risk_policies", "runtime_risk_policy_rules", "runtime_detection_agent_type_settings", "runtime_detection_blacklist_items"} {
		for _, op := range []string{"insert", "update", "delete"} {
			q := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS change_log_%s_%s AFTER %s ON %s BEGIN INSERT INTO change_log(domain,changed_at) VALUES('%s',CURRENT_TIMESTAMP); END;`, table, op, strings.ToUpper(op), table, RuntimeDetectionSettingsDomain)
			if _, err = ex.Exec(q); err != nil {
				return err
			}
		}
	}
	return nil
}
