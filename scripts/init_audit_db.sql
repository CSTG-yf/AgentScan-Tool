-- DefenseClaw audit database initializer.
-- Run manually with:
--   sqlite3 audit.db ".read scripts/init_audit_db.sql"
-- This file is generated from the current application migrations and contains
-- schema plus default seed data only. It does not contain local user data.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL,
		"delete" INTEGER NOT NULL DEFAULT 0
	);
INSERT INTO schema_version VALUES(1,'2026-08-31 03:19:24.5337907 +0000 UTC',0);
INSERT INTO schema_version VALUES(2,'2026-08-31 03:19:24.534824 +0000 UTC',0);
INSERT INTO schema_version VALUES(3,'2026-08-31 03:19:24.5353554 +0000 UTC',0);
INSERT INTO schema_version VALUES(4,'2026-08-31 03:19:24.5386033 +0000 UTC',0);
INSERT INTO schema_version VALUES(5,'2026-08-31 03:19:24.5414585 +0000 UTC',0);
INSERT INTO schema_version VALUES(6,'2026-08-31 03:19:24.5452477 +0000 UTC',0);
INSERT INTO schema_version VALUES(7,'2026-08-31 03:19:24.5473308 +0000 UTC',0);
INSERT INTO schema_version VALUES(8,'2026-08-31 03:19:24.5478497 +0000 UTC',0);
INSERT INTO schema_version VALUES(9,'2026-08-31 03:19:24.5483692 +0000 UTC',0);
INSERT INTO schema_version VALUES(10,'2026-08-31 03:19:24.5525206 +0000 UTC',0);
INSERT INTO schema_version VALUES(11,'2026-08-31 03:19:24.5585803 +0000 UTC',0);
INSERT INTO schema_version VALUES(12,'2026-08-31 03:19:24.5608954 +0000 UTC',0);
INSERT INTO schema_version VALUES(13,'2026-08-31 03:19:24.5629772 +0000 UTC',0);
INSERT INTO schema_version VALUES(14,'2026-08-31 03:19:24.5629772 +0000 UTC',0);
INSERT INTO schema_version VALUES(15,'2026-08-31 03:19:24.5645683 +0000 UTC',0);
INSERT INTO schema_version VALUES(16,'2026-08-31 03:19:24.5650876 +0000 UTC',0);
INSERT INTO schema_version VALUES(17,'2026-08-31 03:19:24.5666604 +0000 UTC',0);
INSERT INTO schema_version VALUES(18,'2026-08-31 03:19:24.5671855 +0000 UTC',0);
INSERT INTO schema_version VALUES(19,'2026-08-31 03:19:24.5698743 +0000 UTC',0);
INSERT INTO schema_version VALUES(20,'2026-08-31 03:19:24.5709106 +0000 UTC',0);
INSERT INTO schema_version VALUES(21,'2026-08-31 03:19:24.5764791 +0000 UTC',0);
INSERT INTO schema_version VALUES(22,'2026-08-31 03:19:24.5764791 +0000 UTC',0);
INSERT INTO schema_version VALUES(23,'2026-08-31 03:19:24.577782 +0000 UTC',0);
INSERT INTO schema_version VALUES(24,'2026-08-31 03:19:24.577782 +0000 UTC',0);
INSERT INTO schema_version VALUES(25,'2026-08-31 03:19:24.577782 +0000 UTC',0);
INSERT INTO schema_version VALUES(26,'2026-08-31 03:19:24.5813069 +0000 UTC',0);
INSERT INTO schema_version VALUES(27,'2026-08-31 03:19:24.5813069 +0000 UTC',0);
INSERT INTO schema_version VALUES(28,'2026-08-31 03:19:24.5813069 +0000 UTC',0);
INSERT INTO schema_version VALUES(29,'2026-08-31 03:19:24.5914588 +0000 UTC',0);
INSERT INTO schema_version VALUES(30,'2026-08-31 03:19:24.5953034 +0000 UTC',0);
INSERT INTO schema_version VALUES(31,'2026-08-31 03:19:24.5953034 +0000 UTC',0);
INSERT INTO schema_version VALUES(32,'2026-08-31 03:19:24.5953034 +0000 UTC',0);
INSERT INTO schema_version VALUES(33,'2026-08-31 03:19:24.6018133 +0000 UTC',0);
INSERT INTO schema_version VALUES(34,'2026-08-31 03:19:24.6018133 +0000 UTC',0);
INSERT INTO schema_version VALUES(35,'2026-08-31 03:19:24.6018133 +0000 UTC',0);
INSERT INTO schema_version VALUES(36,'2026-08-31 03:19:24.6018133 +0000 UTC',0);
INSERT INTO schema_version VALUES(37,'2026-08-31 03:19:24.608942 +0000 UTC',0);
INSERT INTO schema_version VALUES(38,'2026-08-31 03:19:24.6099544 +0000 UTC',0);
CREATE TABLE audit_events (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				action TEXT NOT NULL,
				target TEXT,
				actor TEXT NOT NULL DEFAULT 'defenseclaw',
				details TEXT,
				structured_json TEXT,
				severity TEXT,
				run_id TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			, trace_id TEXT, request_id TEXT, session_id TEXT, agent_name TEXT, agent_instance_id TEXT, policy_id TEXT, destination_app TEXT, tool_name TEXT, tool_id TEXT, schema_version INTEGER, content_hash TEXT, generation INTEGER, binary_version TEXT, agent_id TEXT, sidecar_instance_id TEXT, connector TEXT, step_idx INTEGER, enforced INTEGER, rule_pack_dir TEXT, canonical_agent_id TEXT);
CREATE TABLE scan_results (
				id TEXT PRIMARY KEY,
				scanner TEXT NOT NULL,
				target TEXT NOT NULL,
				timestamp DATETIME NOT NULL,
				duration_ms INTEGER,
				finding_count INTEGER,
				max_severity TEXT,
				raw_json TEXT,
				run_id TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			, verdict TEXT, exit_code INTEGER, error TEXT, schema_version INTEGER, content_hash TEXT, generation INTEGER, binary_version TEXT, agent_id TEXT, agent_instance_id TEXT, sidecar_instance_id TEXT, session_id TEXT, request_id TEXT, trace_id TEXT, evaluation_id TEXT, agent_name TEXT, canonical_agent_id TEXT, static_resource_id TEXT, scan_profile_id INTEGER, resource_rule_id INTEGER);
CREATE TABLE findings (
				id TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL,
				severity TEXT NOT NULL,
				title TEXT NOT NULL,
				description TEXT,
				location TEXT,
				remediation TEXT,
				scanner TEXT NOT NULL,
				tags TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0, rule_id TEXT, line_number INTEGER, schema_version INTEGER, content_hash TEXT, generation INTEGER, binary_version TEXT, agent_id TEXT, sidecar_instance_id TEXT,
				FOREIGN KEY (scan_id) REFERENCES scan_results(id)
			);
CREATE TABLE actions (
				id TEXT PRIMARY KEY,
				target_type TEXT NOT NULL,
				target_name TEXT NOT NULL,
				source_path TEXT,
				actions_json TEXT NOT NULL DEFAULT '{}',
				reason TEXT,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			, schema_version INTEGER, content_hash TEXT, generation INTEGER, binary_version TEXT, sidecar_instance_id TEXT, connector TEXT NOT NULL DEFAULT '');
CREATE TABLE network_egress_events (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				session_id TEXT,
				hostname TEXT NOT NULL,
				url TEXT,
				http_method TEXT,
				protocol TEXT,
				policy_outcome TEXT NOT NULL,
				decision_code TEXT,
				blocked INTEGER NOT NULL DEFAULT 0,
				severity TEXT NOT NULL DEFAULT 'INFO',
				details TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			, schema_version INTEGER, content_hash TEXT, generation INTEGER, binary_version TEXT, sidecar_instance_id TEXT, connector TEXT, agent_id TEXT, agent_lifecycle_id TEXT, agent_execution_id TEXT, user_id TEXT, tool_id TEXT, root_agent_id TEXT, parent_agent_id TEXT, root_session_id TEXT, canonical_agent_id TEXT);
CREATE TABLE target_snapshots (
				id TEXT PRIMARY KEY,
				target_type TEXT NOT NULL,
				target_path TEXT NOT NULL,
				content_hash TEXT NOT NULL,
				dependency_hashes TEXT,
				config_hashes TEXT,
				network_endpoints TEXT,
				scan_id TEXT,
				captured_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0, schema_version INTEGER, generation INTEGER, binary_version TEXT, sidecar_instance_id TEXT, scanner_fingerprint TEXT NOT NULL DEFAULT '',
				UNIQUE(target_type, target_path)
			);
CREATE TABLE judge_responses (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				kind TEXT NOT NULL,
				direction TEXT,
				model TEXT,
				action TEXT,
				severity TEXT,
				latency_ms INTEGER,
				parse_error TEXT,
				raw_response TEXT NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			, request_id TEXT, trace_id TEXT, run_id TEXT, input_hash TEXT, confidence REAL, fail_closed_applied INTEGER NOT NULL DEFAULT 0, inspected_model TEXT, prompt_template_id TEXT, schema_version INTEGER, content_hash TEXT, generation INTEGER, binary_version TEXT, agent_id TEXT, sidecar_instance_id TEXT, session_id TEXT, agent_instance_id TEXT, policy_id TEXT, destination_app TEXT, tool_name TEXT, tool_id TEXT, canonical_agent_id TEXT);
CREATE TABLE scan_findings (
				id TEXT PRIMARY KEY,
				scan_id TEXT NOT NULL,
				scanner TEXT NOT NULL,
				target TEXT NOT NULL,
				rule_id TEXT,
				category TEXT,
				severity TEXT NOT NULL,
				title TEXT,
				description TEXT,
				location TEXT,
				line_number INTEGER,
				remediation TEXT,
				tags TEXT,
				timestamp DATETIME NOT NULL,
				run_id TEXT,
				request_id TEXT,
				session_id TEXT,
				agent_id TEXT,
				agent_instance_id TEXT,
				sidecar_instance_id TEXT,
				schema_version INTEGER,
				content_hash TEXT,
				generation INTEGER,
				binary_version TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			, data_axis TEXT, tool_capability_class TEXT, content_fingerprint TEXT, external_endpoint TEXT, turn_id INTEGER, decision_path TEXT, confidence REAL, evaluation_id TEXT, agent_name TEXT, trace_id TEXT, canonical_agent_id TEXT, static_resource_id TEXT);
CREATE TABLE activity_events (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				actor TEXT NOT NULL,
				action TEXT NOT NULL,
				target_type TEXT NOT NULL,
				target_id TEXT NOT NULL,
				reason TEXT,
				before_json TEXT,
				after_json TEXT,
				diff_json TEXT,
				version_from TEXT,
				version_to TEXT,
				request_id TEXT,
				trace_id TEXT,
				run_id TEXT,
				schema_version INTEGER,
				content_hash TEXT,
				generation INTEGER,
				binary_version TEXT,
				agent_id TEXT,
				sidecar_instance_id TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			, canonical_agent_id TEXT);
CREATE TABLE sink_health (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL,
				sink_name TEXT NOT NULL,
				sink_kind TEXT NOT NULL,
				outcome TEXT NOT NULL,
				status_code INTEGER,
				latency_ms INTEGER,
				batch_size INTEGER,
				error TEXT,
				queue_depth INTEGER,
				dropped_count INTEGER,
				schema_version INTEGER,
				content_hash TEXT,
				generation INTEGER,
				binary_version TEXT,
				sidecar_instance_id TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE agents (
				id TEXT PRIMARY KEY,
				display_name TEXT NOT NULL,
				vendor TEXT NOT NULL DEFAULT '',
				kind TEXT NOT NULL DEFAULT '',
				runtime TEXT NOT NULL DEFAULT '',
				source TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'observed',
				first_seen_at DATETIME NOT NULL,
				last_seen_at DATETIME NOT NULL,
				last_static_scan_at DATETIME,
				metadata_json TEXT NOT NULL DEFAULT '{}',
				"delete" INTEGER NOT NULL DEFAULT 0
			, agent_type_id INTEGER, matched_rule_id INTEGER, confidence INTEGER NOT NULL DEFAULT 0, runtime_status TEXT NOT NULL DEFAULT 'unknown', pids_json TEXT NOT NULL DEFAULT '[]');
CREATE TABLE agent_aliases (
				alias TEXT PRIMARY KEY,
				agent_id TEXT NOT NULL,
				raw_alias TEXT NOT NULL,
				alias_type TEXT NOT NULL DEFAULT '',
				source TEXT NOT NULL DEFAULT '',
				created_at DATETIME NOT NULL,
				last_seen_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0,
				FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
			);
CREATE TABLE static_resources (
				id TEXT PRIMARY KEY,
				canonical_agent_id TEXT NOT NULL,
				resource_type TEXT NOT NULL,
				name TEXT NOT NULL,
				target TEXT NOT NULL,
				scanner TEXT NOT NULL DEFAULT '',
				target_type TEXT NOT NULL DEFAULT '',
				last_scan_id TEXT,
				last_seen_at DATETIME NOT NULL,
				max_severity TEXT NOT NULL DEFAULT 'INFO',
				finding_count INTEGER NOT NULL DEFAULT 0,
				content_hash TEXT,
				status TEXT NOT NULL DEFAULT 'discovered',
				source TEXT NOT NULL DEFAULT '',
				"delete" INTEGER NOT NULL DEFAULT 0, resource_rule_id INTEGER, scan_profile_id INTEGER, risk_level TEXT NOT NULL DEFAULT 'clean', malicious INTEGER NOT NULL DEFAULT 0,
				FOREIGN KEY (canonical_agent_id) REFERENCES agents(id) ON DELETE CASCADE
			);
CREATE TABLE behavior_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp DATETIME NOT NULL,
				event_type TEXT NOT NULL,
				source TEXT NOT NULL,
				agent_pid INTEGER NOT NULL DEFAULT 0,
				agent_executable TEXT NOT NULL DEFAULT '',
				actor_pid INTEGER NOT NULL DEFAULT 0,
				actor_executable TEXT NOT NULL DEFAULT '',
				path TEXT,
				action TEXT,
				outcome TEXT NOT NULL DEFAULT 'observed',
				detail TEXT NOT NULL DEFAULT '',
				agent_name TEXT,
				canonical_agent_id TEXT,
				agent_instance_id TEXT,
				session_id TEXT,
				trace_id TEXT,
				sidecar_instance_id TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0, event_id TEXT, event_source TEXT, event_category TEXT, span_id TEXT, parent_span_id TEXT, ppid INTEGER, operation TEXT, target TEXT, tool_name TEXT, mcp_server TEXT, severity TEXT, confidence REAL, attributes_json TEXT, raw_data_json TEXT,
				FOREIGN KEY (canonical_agent_id) REFERENCES agents(id) ON DELETE SET NULL
			);
CREATE TABLE app_settings (
				key TEXT PRIMARY KEY,
				value_json TEXT NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE agent_types (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				type_key TEXT NOT NULL UNIQUE,
				name TEXT NOT NULL,
				vendor TEXT NOT NULL DEFAULT '',
				kind TEXT NOT NULL DEFAULT '',
				runtime TEXT NOT NULL DEFAULT '',
				description TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL DEFAULT 1,
				"delete" INTEGER NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL
			);
INSERT INTO agent_types VALUES(1,'agentrange-opspilot','AgentRange / OpsPilot','TraceBastion Lab','agent-platform','Agent Platform','Local AgentRange target platform used for TraceBastion lab scenarios.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(2,'openclaw','OpenClaw','DefenseClaw','agent-platform','Agent Platform','OpenClaw local agent platform configuration and runtime signals.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(3,'claude-code','Claude Code','Anthropic','terminal-agent','CLI Agent','Anthropic Claude Code CLI agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(4,'codex','OpenAI Codex','OpenAI','terminal-agent','CLI Agent','OpenAI Codex CLI coding agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(5,'gemini-cli','Gemini CLI','Google','terminal-agent','CLI Agent','Google Gemini CLI agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(6,'aider','Aider','Aider','terminal-agent','CLI Agent','Aider CLI coding agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(7,'opencode','OpenCode','OpenCode','terminal-agent','CLI Agent','OpenCode CLI coding agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(8,'cursor','Cursor','Anysphere','editor-agent','IDE Agent','Cursor AI editor agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(9,'cline','Cline','Cline','editor-agent','IDE Agent','Cline VS Code agent extension.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(10,'roo-code','Roo Code','Roo Code','editor-agent','IDE Agent','Roo Code VS Code agent extension.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(11,'qoder','Qoder','Qoder','ide-agent','IDE Agent','Qoder IDE agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(12,'trae','Trae','ByteDance','desktop-agent','Desktop Agent','Trae AI desktop agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
INSERT INTO agent_types VALUES(13,'cherry-studio','Cherry Studio','Cherry Studio','desktop-agent','Desktop Agent','Cherry Studio desktop agent.',1,0,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z');
CREATE TABLE agent_discovery_rules (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				agent_type_id INTEGER NOT NULL,
				rule_name TEXT NOT NULL,
				threshold INTEGER NOT NULL DEFAULT 60,
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0,
				FOREIGN KEY (agent_type_id) REFERENCES agent_types(id) ON DELETE CASCADE,
				UNIQUE(agent_type_id, rule_name)
			);
INSERT INTO agent_discovery_rules VALUES(1,1,'AgentRange configured workspace',70,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(2,2,'OpenClaw local installation',60,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(3,3,'Claude Code CLI and config',40,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(4,4,'Codex CLI and config',40,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(5,5,'Gemini CLI and config',40,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(6,6,'Aider CLI and config',40,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(7,7,'OpenCode CLI and config',40,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(8,8,'Cursor installation and config',60,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(9,9,'Cline extension storage',60,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(10,10,'Roo Code extension storage',60,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(11,11,'Qoder installation and config',60,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(12,12,'Trae installation and config',60,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_rules VALUES(13,13,'Cherry Studio installation and config',60,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
CREATE TABLE agent_discovery_conditions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				rule_id INTEGER NOT NULL,
				condition_type TEXT NOT NULL,
				field TEXT NOT NULL DEFAULT '',
				operator TEXT NOT NULL,
				value TEXT NOT NULL,
				weight INTEGER NOT NULL DEFAULT 0,
				required INTEGER NOT NULL DEFAULT 0,
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0,
				FOREIGN KEY (rule_id) REFERENCES agent_discovery_rules(id) ON DELETE CASCADE,
				UNIQUE(rule_id, condition_type, field, operator, value)
			);
INSERT INTO agent_discovery_conditions VALUES(1,1,'agentrange_root','path','exists','configured-workspace',70,1,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(2,1,'process','command_line','contains','agentrange',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(3,1,'process','command_line','contains','opspilot',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(4,2,'cli','name','exists','openclaw',40,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(5,2,'directory','path','exists','~/.openclaw',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(6,2,'process','command_line','contains','openclaw',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(7,3,'cli','name','exists','claude',40,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(8,3,'directory','path','exists','~/.claude',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(9,3,'process','command_line','contains','claude',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(10,4,'cli','name','exists','codex',40,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(11,4,'directory','path','exists','~/.codex',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(12,4,'process','command_line','contains','codex',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(13,5,'cli','name','exists','gemini',40,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(14,5,'directory','path','exists','~/.gemini',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(15,5,'process','command_line','contains','gemini',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(16,6,'cli','name','exists','aider',40,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(17,6,'file','path','exists','~/.aider.conf.yml',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(18,6,'directory','path','exists','~/.aider',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(19,6,'process','command_line','contains','aider',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(20,7,'cli','name','exists','opencode',40,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(21,7,'directory','path','exists','${XDG_CONFIG_HOME}/opencode',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(22,7,'directory','path','exists','~/.config/opencode',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(23,7,'process','command_line','contains','opencode',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(24,8,'file','executable_path','exists','%LOCALAPPDATA%\Programs\Cursor\Cursor.exe',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(25,8,'file','executable_path','exists','%ProgramFiles%\Cursor\Cursor.exe',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(26,8,'directory','path','exists','%APPDATA%\Cursor\User',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(27,8,'directory','path','exists','~/.cursor',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(28,8,'process','command_line','contains','cursor',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(29,9,'directory','path','exists','%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(30,9,'process','command_line','contains','cline',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(31,10,'directory','path','exists','%APPDATA%\Code\User\globalStorage\rooveterinaryinc.roo-cline',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(32,10,'process','command_line','contains','roo',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(33,11,'file','executable_path','exists','%LOCALAPPDATA%\Programs\Qoder\Qoder.exe',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(34,11,'directory','path','exists','%APPDATA%\Qoder',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(35,11,'process','command_line','contains','qoder',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(36,12,'file','executable_path','exists','%LOCALAPPDATA%\Programs\Trae\Trae.exe',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(37,12,'directory','path','exists','%APPDATA%\Trae',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(38,12,'process','command_line','contains','trae',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(39,13,'file','executable_path','exists','%LOCALAPPDATA%\Programs\Cherry Studio\Cherry Studio.exe',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(40,13,'directory','path','exists','%APPDATA%\CherryStudio',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(41,13,'directory','path','exists','%APPDATA%\Cherry Studio',25,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO agent_discovery_conditions VALUES(42,13,'process','command_line','contains','cherry',60,0,1,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
CREATE TABLE resource_scan_profiles (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				resource_type TEXT NOT NULL,
				enabled INTEGER NOT NULL DEFAULT 1,
				description TEXT,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
INSERT INTO resource_scan_profiles VALUES(1,'skill-full','skill',1,'Skill 全量安全检测：SkillScanner + Malware + Injection + Secrets + PII + Vuln','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profiles VALUES(2,'mcp-full','mcp',1,'MCP 全量安全检测：MCPScanner + Secrets + Malware + Injection','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profiles VALUES(3,'plugin-full','plugin',1,'Plugin 安全检测：PluginScanner + Secrets + Malware','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profiles VALUES(4,'config-basic','config',1,'Config 安全检测：Secrets + Injection','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profiles VALUES(5,'prompt-basic','prompt',1,'Prompt 安全检测：Injection + Secrets','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profiles VALUES(6,'credential-basic','credential',1,'Credential 安全检测：Secrets + PII','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
CREATE TABLE security_scan_capabilities (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				capability_key TEXT NOT NULL UNIQUE,
				name TEXT NOT NULL,
				scanner_name TEXT NOT NULL,
				enabled INTEGER NOT NULL DEFAULT 1,
				description TEXT,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
INSERT INTO security_scan_capabilities VALUES(1,'skill_security','Skill 安全检测','skill-scanner',1,'Python skill-scanner CLI（含可选 LLM 分析）','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO security_scan_capabilities VALUES(2,'mcp_security','MCP 安全检测','mcp-scanner',1,'Python defenseclaw mcp scan CLI（含可选 LLM 分析）','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO security_scan_capabilities VALUES(3,'plugin_security','Plugin 安全检测','plugin-scanner',1,'Plugin 扫描器','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO security_scan_capabilities VALUES(4,'secret_detection','密钥泄露检测','clawshield-secrets',1,'ClawShield 内置密钥/凭据正则检测','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO security_scan_capabilities VALUES(5,'pii_detection','PII 检测','clawshield-pii',1,'ClawShield 内置个人敏感信息检测','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO security_scan_capabilities VALUES(6,'malware_detection','恶意代码检测','clawshield-malware',1,'ClawShield 内置恶意特征/脚本/高熵负载检测','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO security_scan_capabilities VALUES(7,'vulnerability_detection','漏洞检测','clawshield-vuln',1,'ClawShield 内置危险 API/漏洞模式检测','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO security_scan_capabilities VALUES(8,'prompt_injection','提示注入检测','clawshield-injection',1,'ClawShield 内置提示注入/指令覆盖检测','2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
CREATE TABLE resource_scan_profile_capabilities (
				profile_id INTEGER NOT NULL,
				capability_id INTEGER NOT NULL,
				priority INTEGER NOT NULL DEFAULT 100,
				enabled INTEGER NOT NULL DEFAULT 1,
				config_json TEXT,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (profile_id, capability_id),
				FOREIGN KEY (profile_id) REFERENCES resource_scan_profiles(id) ON DELETE CASCADE,
				FOREIGN KEY (capability_id) REFERENCES security_scan_capabilities(id) ON DELETE CASCADE
			);
INSERT INTO resource_scan_profile_capabilities VALUES(1,1,100,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(1,6,101,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(1,8,102,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(1,4,103,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(1,5,104,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(1,7,105,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(2,2,100,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(2,4,101,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(2,6,102,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(2,8,103,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(3,3,100,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(3,4,101,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(3,6,102,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(4,4,100,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(4,8,101,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(5,8,100,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(5,4,101,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(6,4,100,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
INSERT INTO resource_scan_profile_capabilities VALUES(6,5,101,1,NULL,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0);
CREATE TABLE agent_resource_rules (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				agent_type_id INTEGER NOT NULL,
				name TEXT NOT NULL,
				resource_type TEXT NOT NULL,
				path_pattern TEXT NOT NULL,
				enumeration_mode TEXT NOT NULL DEFAULT 'children',
				scan_profile_id INTEGER,
				enabled INTEGER NOT NULL DEFAULT 1,
				priority INTEGER NOT NULL DEFAULT 100,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0, pre_scan_profile_id INTEGER, post_scan_profile_id INTEGER,
				FOREIGN KEY (agent_type_id) REFERENCES agent_types(id) ON DELETE CASCADE,
				FOREIGN KEY (scan_profile_id) REFERENCES resource_scan_profiles(id) ON DELETE SET NULL,
				UNIQUE(agent_type_id, name)
			);
INSERT INTO agent_resource_rules VALUES(1,1,'agentrange-skills','skill','${WORKSPACE_ROOT}/skills','children',1,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(2,1,'agentrange-mcp','mcp','${WORKSPACE_ROOT}/mcp','children',2,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(3,1,'agentrange-compose','config','${WORKSPACE_ROOT}/docker-compose.yml','exact',4,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(4,2,'openclaw-skills','skill','${CONFIG_ROOT}/skills','children',1,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(5,2,'openclaw-config','config','${CONFIG_ROOT}/openclaw.json','exact',4,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(6,3,'claude-skills','skill','${CONFIG_ROOT}/skills','children',1,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(7,3,'claude-settings','config','${CONFIG_ROOT}/settings.json','exact',4,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(8,3,'claude-prompt','prompt','${CONFIG_ROOT}/CLAUDE.md','exact',5,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(9,4,'codex-skills','skill','${CONFIG_ROOT}/skills','children',1,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(10,4,'codex-config','config','${CONFIG_ROOT}/config.toml','exact',4,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(11,5,'gemini-settings','config','${CONFIG_ROOT}/settings.json','exact',4,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
INSERT INTO agent_resource_rules VALUES(12,5,'gemini-prompt','prompt','${CONFIG_ROOT}/GEMINI.md','exact',5,1,100,'2026-08-31T03:19:24.5813069Z','2026-08-31T03:19:24.5813069Z',0,1,1);
CREATE TABLE agent_runtime_sessions (
				session_id TEXT PRIMARY KEY,
				agent_id TEXT NOT NULL,
				root_pid INTEGER NOT NULL DEFAULT 0,
				started_at DATETIME NOT NULL,
				ended_at DATETIME,
				working_directory TEXT,
				user TEXT,
				status TEXT NOT NULL DEFAULT 'active',
				metadata_json TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0,
				FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
			);
CREATE TABLE runtime_detections (
				detection_id TEXT PRIMARY KEY,
				agent_id TEXT NOT NULL DEFAULT '',
				session_id TEXT,
				trace_id TEXT,
				detection_type TEXT NOT NULL,
				category TEXT NOT NULL DEFAULT 'suspicious',
				severity TEXT NOT NULL DEFAULT 'medium',
				confidence REAL NOT NULL DEFAULT 0,
				rule_id TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'open',
				title TEXT NOT NULL DEFAULT '',
				detail TEXT,
				remediation TEXT,
				attributes_json TEXT,
				first_seen_at DATETIME NOT NULL,
				last_seen_at DATETIME NOT NULL,
				event_count INTEGER NOT NULL DEFAULT 0,
				agent_name TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE runtime_detection_events (
				detection_id TEXT NOT NULL,
				event_id INTEGER NOT NULL,
				role TEXT NOT NULL DEFAULT 'evidence',
				sequence INTEGER NOT NULL DEFAULT 0,
				linked_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (detection_id, event_id)
			);
CREATE TABLE runtime_decisions (
				decision_id TEXT PRIMARY KEY,
				detection_id TEXT NOT NULL,
				agent_id TEXT NOT NULL DEFAULT '',
				session_id TEXT,
				trace_id TEXT,
				decision TEXT NOT NULL,
				risk_score REAL NOT NULL DEFAULT 0,
				confidence REAL NOT NULL DEFAULT 0,
				policy_id TEXT NOT NULL DEFAULT '',
				reason TEXT,
				enforcement_point TEXT NOT NULL DEFAULT '',
				mode TEXT NOT NULL DEFAULT 'observe',
				would_block INTEGER NOT NULL DEFAULT 0,
				agent_name TEXT,
				created_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE runtime_response_actions (
				response_id TEXT PRIMARY KEY,
				decision_id TEXT NOT NULL,
				action_type TEXT NOT NULL,
				executor TEXT NOT NULL DEFAULT '',
				target TEXT,
				status TEXT NOT NULL DEFAULT 'pending',
				result TEXT,
				executed_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE runtime_attack_chains (
				attack_chain_id TEXT PRIMARY KEY,
				agent_id TEXT NOT NULL DEFAULT '',
				session_id TEXT,
				trace_id TEXT,
				attack_type TEXT NOT NULL,
				severity TEXT NOT NULL DEFAULT 'high',
				status TEXT NOT NULL DEFAULT 'active',
				start_time DATETIME NOT NULL,
				end_time DATETIME NOT NULL,
				detection_id TEXT NOT NULL DEFAULT '',
				decision_id TEXT NOT NULL DEFAULT '',
				agent_name TEXT,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
CREATE TABLE runtime_attack_chain_events (
				attack_chain_id TEXT NOT NULL,
				event_id INTEGER NOT NULL,
				sequence INTEGER NOT NULL DEFAULT 0,
				relation TEXT NOT NULL DEFAULT '',
				"delete" INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (attack_chain_id, event_id)
			);
CREATE TABLE resource_pre_scan_profiles (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				profile_key TEXT NOT NULL UNIQUE,
				name TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL DEFAULT 1,
				is_default INTEGER NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
INSERT INTO resource_pre_scan_profiles VALUES(1,'default-pre-scan','默认 Pre-scan 方案','资源发现后、扫描前的默认准入决策方案。',1,1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
CREATE TABLE resource_pre_scan_rules (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				profile_id INTEGER NOT NULL,
				rule_name TEXT NOT NULL,
				priority INTEGER NOT NULL DEFAULT 100,
				agent_type_id INTEGER,
				resource_type TEXT NOT NULL DEFAULT 'all',
				path_pattern TEXT NOT NULL DEFAULT '',
				source_trust TEXT NOT NULL DEFAULT '',
				decision TEXT NOT NULL DEFAULT 'scan',
				install_action TEXT NOT NULL DEFAULT 'none',
				file_action TEXT NOT NULL DEFAULT 'none',
				runtime_action TEXT NOT NULL DEFAULT 'allow',
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0,
				FOREIGN KEY (profile_id) REFERENCES resource_pre_scan_profiles(id) ON DELETE CASCADE,
				FOREIGN KEY (agent_type_id) REFERENCES agent_types(id) ON DELETE SET NULL,
				UNIQUE(profile_id, rule_name)
			);
INSERT INTO resource_pre_scan_rules VALUES(1,1,'默认扫描',100,NULL,'all','','','scan','none','none','allow',1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
CREATE TABLE resource_post_scan_profiles (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				profile_key TEXT NOT NULL UNIQUE,
				name TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL DEFAULT 1,
				is_default INTEGER NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
INSERT INTO resource_post_scan_profiles VALUES(1,'default-post-scan','默认 Post-scan 方案','扫描完成后按严重级别和风险结论执行默认处置。',1,1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
CREATE TABLE resource_post_scan_rules (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				profile_id INTEGER NOT NULL,
				rule_name TEXT NOT NULL,
				priority INTEGER NOT NULL DEFAULT 100,
				resource_type TEXT NOT NULL DEFAULT 'all',
				severity TEXT NOT NULL DEFAULT 'INFO',
				risk_level TEXT NOT NULL DEFAULT 'clean',
				malicious INTEGER NOT NULL DEFAULT 0,
				finding_category TEXT NOT NULL DEFAULT '',
				scanner TEXT NOT NULL DEFAULT '',
				decision TEXT NOT NULL DEFAULT 'alert',
				install_action TEXT NOT NULL DEFAULT 'none',
				file_action TEXT NOT NULL DEFAULT 'none',
				runtime_action TEXT NOT NULL DEFAULT 'allow',
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0,
				FOREIGN KEY (profile_id) REFERENCES resource_post_scan_profiles(id) ON DELETE CASCADE,
				UNIQUE(profile_id, rule_name)
			);
INSERT INTO resource_post_scan_rules VALUES(1,1,'严重风险阻断',10,'all','CRITICAL','critical',0,'','','block','block','quarantine','block',1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
INSERT INTO resource_post_scan_rules VALUES(2,1,'高风险阻断',20,'all','HIGH','high',0,'','','block','block','quarantine','block',1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
INSERT INTO resource_post_scan_rules VALUES(3,1,'中风险告警',30,'all','MEDIUM','medium',0,'','','alert','none','none','allow',1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
INSERT INTO resource_post_scan_rules VALUES(4,1,'低风险告警',40,'all','LOW','low',0,'','','alert','none','none','allow',1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
INSERT INTO resource_post_scan_rules VALUES(5,1,'无风险放行',50,'all','INFO','clean',0,'','','allow','none','none','allow',1,'2026-08-31T03:19:24.607571Z','2026-08-31T03:19:24.607571Z',0);
CREATE TABLE risk_severity_mappings (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				source_severity TEXT NOT NULL UNIQUE,
				risk_level TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				priority INTEGER NOT NULL DEFAULT 100,
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
INSERT INTO risk_severity_mappings VALUES(1,'CRITICAL','critical','Critical scanner finding maps to critical resource risk.',30,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_severity_mappings VALUES(2,'HIGH','high','High scanner finding maps to high resource risk.',31,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_severity_mappings VALUES(3,'MEDIUM','medium','Medium scanner finding maps to medium resource risk.',32,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_severity_mappings VALUES(4,'LOW','low','Low scanner finding maps to low resource risk.',33,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_severity_mappings VALUES(5,'INFO','clean','Informational scanner finding maps to clean resource risk.',34,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
CREATE TABLE risk_rule_prefix_matches (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				rule_id_prefix TEXT NOT NULL UNIQUE,
				risk_level TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				priority INTEGER NOT NULL DEFAULT 100,
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
INSERT INTO risk_rule_prefix_matches VALUES(1,'CS-MAL-','critical','ClawShield malware rule IDs are treated as critical risk before category or severity fallback.',10,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
CREATE TABLE risk_category_matches (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				category TEXT NOT NULL UNIQUE,
				risk_level TEXT NOT NULL,
				description TEXT NOT NULL DEFAULT '',
				priority INTEGER NOT NULL DEFAULT 100,
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL,
				updated_at DATETIME NOT NULL,
				"delete" INTEGER NOT NULL DEFAULT 0
			);
INSERT INTO risk_category_matches VALUES(1,'malware','critical','Category malware is treated as critical resource risk.',20,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_category_matches VALUES(2,'reverse_shell','critical','Category reverse_shell is treated as critical resource risk.',20,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_category_matches VALUES(3,'credential_harvest','critical','Category credential_harvest is treated as critical resource risk.',20,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_category_matches VALUES(4,'credential_exfiltration','critical','Category credential_exfiltration is treated as critical resource risk.',20,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_category_matches VALUES(5,'cryptominer','critical','Category cryptominer is treated as critical resource risk.',20,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_category_matches VALUES(6,'c2','critical','Category c2 is treated as critical resource risk.',20,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
INSERT INTO risk_category_matches VALUES(7,'command_execution','critical','Category command_execution is treated as critical resource risk.',20,1,'2026-08-31T03:19:24.6099544Z','2026-08-31T03:19:24.6099544Z',0);
PRAGMA writable_schema=ON;
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('agent_types',13);
INSERT INTO sqlite_sequence VALUES('agent_discovery_rules',13);
INSERT INTO sqlite_sequence VALUES('agent_discovery_conditions',42);
INSERT INTO sqlite_sequence VALUES('security_scan_capabilities',8);
INSERT INTO sqlite_sequence VALUES('resource_scan_profiles',6);
INSERT INTO sqlite_sequence VALUES('agent_resource_rules',12);
INSERT INTO sqlite_sequence VALUES('resource_pre_scan_profiles',1);
INSERT INTO sqlite_sequence VALUES('resource_post_scan_profiles',1);
INSERT INTO sqlite_sequence VALUES('resource_pre_scan_rules',1);
INSERT INTO sqlite_sequence VALUES('resource_post_scan_rules',5);
INSERT INTO sqlite_sequence VALUES('risk_severity_mappings',5);
INSERT INTO sqlite_sequence VALUES('risk_rule_prefix_matches',1);
INSERT INTO sqlite_sequence VALUES('risk_category_matches',7);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_action ON audit_events(action);
CREATE INDEX idx_audit_severity_timestamp ON audit_events(severity, timestamp);
CREATE INDEX idx_scan_scanner ON scan_results(scanner);
CREATE INDEX idx_finding_severity ON findings(severity);
CREATE INDEX idx_finding_scan ON findings(scan_id);
CREATE INDEX idx_egress_timestamp ON network_egress_events(timestamp);
CREATE INDEX idx_egress_hostname ON network_egress_events(hostname);
CREATE INDEX idx_egress_blocked ON network_egress_events(blocked);
CREATE INDEX idx_egress_session ON network_egress_events(session_id);
CREATE INDEX idx_snapshots_target ON target_snapshots(target_type, target_path);
CREATE INDEX idx_audit_run_id ON audit_events(run_id);
CREATE INDEX idx_scan_run_id ON scan_results(run_id);
CREATE INDEX idx_judge_timestamp ON judge_responses(timestamp);
CREATE INDEX idx_judge_kind ON judge_responses(kind);
CREATE INDEX idx_judge_severity ON judge_responses(severity);
CREATE INDEX idx_audit_trace_id ON audit_events(trace_id);
CREATE INDEX idx_audit_request_id ON audit_events(request_id);
CREATE INDEX idx_judge_request_id ON judge_responses(request_id);
CREATE INDEX idx_judge_trace_id ON judge_responses(trace_id);
CREATE INDEX idx_judge_run_id ON judge_responses(run_id);
CREATE INDEX idx_audit_session_id ON audit_events(session_id);
CREATE INDEX idx_audit_agent_instance_id ON audit_events(agent_instance_id);
CREATE INDEX idx_audit_policy_id ON audit_events(policy_id);
CREATE INDEX idx_audit_tool_name ON audit_events(tool_name);
CREATE INDEX idx_audit_agent_id ON audit_events(agent_id);
CREATE INDEX idx_audit_generation ON audit_events(generation);
CREATE INDEX idx_audit_sidecar_instance_id ON audit_events(sidecar_instance_id);
CREATE INDEX idx_scan_findings_scan_id ON scan_findings(scan_id);
CREATE INDEX idx_scan_findings_scanner ON scan_findings(scanner);
CREATE INDEX idx_scan_findings_severity ON scan_findings(severity);
CREATE INDEX idx_scan_findings_rule_id ON scan_findings(rule_id);
CREATE INDEX idx_scan_findings_timestamp ON scan_findings(timestamp);
CREATE INDEX idx_scan_findings_agent_id ON scan_findings(agent_id);
CREATE INDEX idx_activity_timestamp ON activity_events(timestamp);
CREATE INDEX idx_activity_actor ON activity_events(actor);
CREATE INDEX idx_activity_action ON activity_events(action);
CREATE INDEX idx_activity_target ON activity_events(target_type, target_id);
CREATE INDEX idx_activity_generation ON activity_events(generation);
CREATE INDEX idx_sink_health_timestamp ON sink_health(timestamp);
CREATE INDEX idx_sink_health_sink ON sink_health(sink_name);
CREATE INDEX idx_sink_health_outcome ON sink_health(outcome);
CREATE INDEX idx_scan_agent_id ON scan_results(agent_id);
CREATE INDEX idx_scan_generation ON scan_results(generation);
CREATE INDEX idx_findings_agent_id ON findings(agent_id);
CREATE INDEX idx_scan_findings_session_turn ON scan_findings(session_id, agent_instance_id, turn_id);
CREATE INDEX idx_scan_findings_evaluation_id ON scan_findings(evaluation_id);
CREATE INDEX idx_scan_results_evaluation_id ON scan_results(evaluation_id);
CREATE INDEX idx_audit_connector ON audit_events(connector);
CREATE UNIQUE INDEX idx_actions_type_name_conn ON actions(target_type, target_name, connector);
CREATE INDEX idx_egress_agent ON network_egress_events(agent_id);
CREATE INDEX idx_egress_lifecycle ON network_egress_events(agent_lifecycle_id);
CREATE INDEX idx_egress_user ON network_egress_events(user_id);
CREATE INDEX idx_egress_root_agent ON network_egress_events(root_agent_id);
CREATE INDEX idx_agents_last_seen ON agents(last_seen_at);
CREATE INDEX idx_agent_aliases_agent_id ON agent_aliases(agent_id);
CREATE INDEX idx_static_resources_agent ON static_resources(canonical_agent_id);
CREATE INDEX idx_static_resources_target ON static_resources(target);
CREATE UNIQUE INDEX idx_static_resources_agent_target ON static_resources(canonical_agent_id, target);
CREATE INDEX idx_audit_canonical_agent ON audit_events(canonical_agent_id);
CREATE INDEX idx_scan_results_canonical_agent ON scan_results(canonical_agent_id);
CREATE INDEX idx_scan_results_static_resource ON scan_results(static_resource_id);
CREATE INDEX idx_scan_findings_canonical_agent ON scan_findings(canonical_agent_id);
CREATE INDEX idx_scan_findings_static_resource ON scan_findings(static_resource_id);
CREATE INDEX idx_scan_findings_trace_id ON scan_findings(trace_id);
CREATE INDEX idx_egress_canonical_agent ON network_egress_events(canonical_agent_id);
CREATE INDEX idx_behavior_events_timestamp ON behavior_events(timestamp DESC);
CREATE INDEX idx_behavior_events_agent ON behavior_events(canonical_agent_id, timestamp DESC);
CREATE INDEX idx_behavior_events_agent_pid ON behavior_events(agent_pid, timestamp DESC);
CREATE INDEX idx_behavior_events_path ON behavior_events(path);
CREATE INDEX idx_behavior_events_type ON behavior_events(event_type, timestamp DESC);
CREATE INDEX idx_app_settings_updated_at ON app_settings(updated_at DESC);
CREATE INDEX idx_activity_canonical_agent ON activity_events(canonical_agent_id);
CREATE INDEX idx_judge_canonical_agent ON judge_responses(canonical_agent_id);
CREATE INDEX idx_agent_types_type_key ON agent_types(type_key);
CREATE INDEX idx_agent_discovery_rules_type ON agent_discovery_rules(agent_type_id);
CREATE INDEX idx_agent_discovery_conditions_rule ON agent_discovery_conditions(rule_id);
CREATE INDEX idx_agents_type ON agents(agent_type_id);
CREATE INDEX idx_agents_matched_rule ON agents(matched_rule_id);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agent_resource_rules_type ON agent_resource_rules(agent_type_id);
CREATE INDEX idx_resource_scan_profiles_type ON resource_scan_profiles(resource_type);
CREATE INDEX idx_profile_capabilities_profile ON resource_scan_profile_capabilities(profile_id);
CREATE INDEX idx_static_resources_rule ON static_resources(resource_rule_id);
CREATE INDEX idx_static_resources_profile ON static_resources(scan_profile_id);
CREATE UNIQUE INDEX idx_static_resource_identity ON static_resources(canonical_agent_id, resource_type, target);
CREATE INDEX idx_scan_results_profile ON scan_results(scan_profile_id);
CREATE INDEX idx_scan_results_rule ON scan_results(resource_rule_id);
CREATE INDEX idx_agent_runtime_sessions_agent ON agent_runtime_sessions(agent_id, started_at DESC);
CREATE INDEX idx_agent_runtime_sessions_status ON agent_runtime_sessions(status, started_at DESC);
CREATE INDEX idx_behavior_events_session ON behavior_events(session_id, timestamp ASC);
CREATE INDEX idx_behavior_events_trace ON behavior_events(trace_id, timestamp ASC);
CREATE INDEX idx_behavior_events_source ON behavior_events(event_source, timestamp DESC);
CREATE INDEX idx_behavior_events_severity ON behavior_events(severity, timestamp DESC);
CREATE INDEX idx_runtime_detections_agent ON runtime_detections(agent_id, last_seen_at DESC);
CREATE INDEX idx_runtime_detections_session ON runtime_detections(session_id, last_seen_at DESC);
CREATE INDEX idx_runtime_detections_rule ON runtime_detections(rule_id, agent_id, session_id, status, last_seen_at DESC);
CREATE INDEX idx_runtime_detections_severity ON runtime_detections(severity, last_seen_at DESC);
CREATE INDEX idx_runtime_detections_type ON runtime_detections(detection_type, last_seen_at DESC);
CREATE INDEX idx_runtime_detection_events_event ON runtime_detection_events(event_id);
CREATE INDEX idx_runtime_decisions_detection ON runtime_decisions(detection_id, created_at DESC);
CREATE INDEX idx_runtime_decisions_agent ON runtime_decisions(agent_id, created_at DESC);
CREATE INDEX idx_runtime_decisions_session ON runtime_decisions(session_id, created_at DESC);
CREATE INDEX idx_runtime_decisions_verdict ON runtime_decisions(decision, created_at DESC);
CREATE INDEX idx_runtime_response_actions_decision ON runtime_response_actions(decision_id, executed_at DESC);
CREATE INDEX idx_runtime_attack_chains_agent ON runtime_attack_chains(agent_id, start_time DESC);
CREATE INDEX idx_runtime_attack_chains_session ON runtime_attack_chains(session_id, start_time DESC);
CREATE INDEX idx_runtime_attack_chains_detection ON runtime_attack_chains(detection_id);
CREATE INDEX idx_runtime_attack_chain_events_event ON runtime_attack_chain_events(event_id);
CREATE INDEX idx_agents_runtime_status ON agents(runtime_status);
CREATE INDEX idx_agent_types_delete ON agent_types("delete");
CREATE INDEX idx_resource_pre_scan_profiles_enabled ON resource_pre_scan_profiles(enabled, "delete");
CREATE INDEX idx_resource_pre_scan_rules_profile ON resource_pre_scan_rules(profile_id, priority);
CREATE INDEX idx_resource_pre_scan_rules_agent_type ON resource_pre_scan_rules(agent_type_id);
CREATE INDEX idx_resource_post_scan_profiles_enabled ON resource_post_scan_profiles(enabled, "delete");
CREATE INDEX idx_resource_post_scan_rules_profile ON resource_post_scan_rules(profile_id, priority);
CREATE INDEX idx_agent_resource_rules_pre_scan_profile ON agent_resource_rules(pre_scan_profile_id);
CREATE INDEX idx_agent_resource_rules_post_scan_profile ON agent_resource_rules(post_scan_profile_id);
CREATE INDEX idx_risk_severity_mappings_filter ON risk_severity_mappings(risk_level, enabled, "delete");
CREATE INDEX idx_risk_rule_prefix_matches_filter ON risk_rule_prefix_matches(risk_level, enabled, "delete");
CREATE INDEX idx_risk_category_matches_filter ON risk_category_matches(risk_level, enabled, "delete");
PRAGMA writable_schema=OFF;
COMMIT;
