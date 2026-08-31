// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

const processEnvironmentTarget = "environment://process"

var promptResourceNames = map[string]bool{
	"agents.md":         true,
	"claude.md":         true,
	"gemini.md":         true,
	"instructions.md":   true,
	"prompt.md":         true,
	"prompts.md":        true,
	"rules.md":          true,
	"system-prompt.md":  true,
	"system_prompt.md":  true,
	"system_prompt.txt": true,
	".cursorrules":      true,
	".windsurfrules":    true,
}

var configResourceNames = map[string]bool{
	"config.json":                 true,
	"config.yaml":                 true,
	"config.yml":                  true,
	"docker-compose.override.yml": true,
	"docker-compose.yaml":         true,
	"docker-compose.yml":          true,
	"settings.json":               true,
	"settings.yaml":               true,
	"settings.yml":                true,
}

var credentialResourceNames = map[string]bool{
	".env":             true,
	".env.example":     true,
	".env.local":       true,
	".env.production":  true,
	"credentials.json": true,
	"credentials.yaml": true,
	"credentials.yml":  true,
	"secrets.json":     true,
	"secrets.yaml":     true,
	"secrets.yml":      true,
}

func (w *InstallWatcher) enumerateAuxiliaryStaticTargets() []InstallEvent {
	var targets []InstallEvent
	seen := map[string]bool{}

	addFile := func(targetType InstallType, path string) {
		path = expandUserPath(strings.TrimSpace(path))
		if path == "" {
			return
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return
		}
		abs, _ := filepath.Abs(path)
		key := string(targetType) + "\x00" + abs
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, InstallEvent{
			Type:      targetType,
			Name:      filepath.Base(abs),
			Path:      abs,
			Connector: watcherConnectorName(w.cfg),
			Timestamp: time.Now().UTC(),
		})
	}

	for _, path := range w.configCandidatePaths() {
		addFile(InstallConfig, path)
	}
	for _, path := range w.promptCandidatePaths() {
		addFile(InstallPrompt, path)
	}
	for _, path := range w.credentialCandidatePaths() {
		addFile(InstallCredential, path)
	}

	targets = append(targets, InstallEvent{
		Type:      InstallEnvironment,
		Name:      "process-environment",
		Path:      processEnvironmentTarget,
		Connector: watcherConnectorName(w.cfg),
		Timestamp: time.Now().UTC(),
	})

	return targets
}

func (w *InstallWatcher) enumerateAgentRangeStaticTargets() []InstallEvent {
	root := w.agentRangeRoot()
	if root == "" {
		return nil
	}

	var targets []InstallEvent
	addChildDirs := func(targetType InstallType, parent string) {
		entries, err := os.ReadDir(parent)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			if targetType == InstallMCP && strings.HasPrefix(entry.Name(), "_") {
				continue
			}
			targets = append(targets, InstallEvent{
				Type:      targetType,
				Name:      entry.Name(),
				Path:      filepath.Join(parent, entry.Name()),
				Connector: "agentrange",
				Timestamp: time.Now().UTC(),
			})
		}
	}

	addChildDirs(InstallSkill, filepath.Join(root, "skills"))
	addChildDirs(InstallMCP, filepath.Join(root, "mcp"))
	return targets
}

func (w *InstallWatcher) configCandidatePaths() []string {
	var paths []string
	if w.cfg != nil {
		paths = append(paths, w.cfg.ConfigFilePath, w.cfg.Claw.ConfigFile)
	}
	for _, root := range w.staticResourceRoots() {
		for name := range configResourceNames {
			paths = append(paths, filepath.Join(root, name))
		}
	}
	return dedupStrings(paths)
}

func (w *InstallWatcher) promptCandidatePaths() []string {
	var paths []string
	paths = append(paths, w.policyWatchPaths()...)

	for _, root := range w.staticResourceRoots() {
		for name := range promptResourceNames {
			paths = append(paths, filepath.Join(root, name))
		}
	}

	if w.cfg != nil {
		paths = append(paths, w.cfg.Claw.ConfigFile, w.cfg.ConfigFilePath)
	}
	return dedupStrings(paths)
}

func (w *InstallWatcher) credentialCandidatePaths() []string {
	var paths []string
	if w.cfg != nil {
		paths = append(paths, w.cfg.ConfigFilePath, w.cfg.Claw.ConfigFile)
		if w.cfg.DataDir != "" {
			for name := range credentialResourceNames {
				paths = append(paths, filepath.Join(w.cfg.DataDir, name))
			}
		}
	}
	for _, root := range w.staticResourceRoots() {
		for name := range credentialResourceNames {
			paths = append(paths, filepath.Join(root, name))
		}
	}
	return dedupStrings(paths)
}

func (w *InstallWatcher) staticResourceRoots() []string {
	if w == nil || w.cfg == nil {
		return nil
	}
	var roots []string
	if workspace := w.cfg.ConnectorWorkspaceDir(); workspace != "" {
		roots = append(roots, workspace)
	}
	if home := w.cfg.ConnectorHomeDir(watcherConnectorName(w.cfg)); home != "" {
		roots = append(roots, home)
	}
	return dedupStrings(roots)
}

func (w *InstallWatcher) staticRealtimeDirs() []string {
	if w == nil || w.cfg == nil {
		return nil
	}

	var dirs []string
	for _, path := range w.configCandidatePaths() {
		path = expandUserPath(strings.TrimSpace(path))
		if path != "" {
			dirs = append(dirs, filepath.Dir(path))
		}
	}
	for _, path := range append(w.promptCandidatePaths(), w.credentialCandidatePaths()...) {
		path = expandUserPath(strings.TrimSpace(path))
		if path == "" || path == processEnvironmentTarget {
			continue
		}
		dirs = append(dirs, filepath.Dir(path))
	}
	dirs = append(dirs, w.agentRangeMCPDirs()...)
	if w.cfg.PolicyDir != "" {
		dirs = append(dirs, expandUserPath(w.cfg.PolicyDir))
	}
	if w.cfg.DataDir != "" {
		dirs = append(dirs, expandUserPath(w.cfg.DataDir))
	}
	return existingDirs(dirs)
}

func (w *InstallWatcher) staticRescanTypesForPath(path string) []InstallType {
	if w == nil || w.cfg == nil {
		return nil
	}
	path = cleanAbsPath(path)
	if path == "" {
		return nil
	}

	var types []InstallType
	add := func(targetType InstallType) {
		for _, existing := range types {
			if existing == targetType {
				return
			}
		}
		types = append(types, targetType)
	}

	base := strings.ToLower(filepath.Base(path))
	if configResourceNames[base] {
		add(InstallConfig)
	}
	if promptResourceNames[base] {
		add(InstallPrompt)
	}
	if credentialResourceNames[base] || credentialNameLooksSensitive(base) {
		add(InstallCredential)
	}

	for _, cfgPath := range []string{w.cfg.ConfigFilePath, w.cfg.Claw.ConfigFile} {
		if cleanAbsPath(cfgPath) == path {
			add(InstallMCP)
			add(InstallPrompt)
			add(InstallCredential)
		}
	}
	if w.cfg.PolicyDir != "" && isPathWithin(path, expandUserPath(w.cfg.PolicyDir)) && isPolicyLikeFile(path) {
		add(InstallPrompt)
	}
	if w.cfg.DataDir != "" && isPathWithin(path, expandUserPath(w.cfg.DataDir)) && credentialResourceNames[base] {
		add(InstallCredential)
		add(InstallEnvironment)
	}
	if root := w.agentRangeRoot(); root != "" {
		if isPathWithin(path, filepath.Join(root, "mcp")) {
			add(InstallMCP)
		}
		if cleanAbsPath(path) == cleanAbsPath(filepath.Join(root, "docker-compose.yml")) {
			add(InstallConfig)
		}
	}

	return types
}

func (w *InstallWatcher) agentRangeRoot() string {
	if w == nil || w.cfg == nil {
		return ""
	}
	root := w.cfg.ConnectorWorkspaceDir()
	if root == "" || !looksLikeAgentRangeRoot(root) {
		return ""
	}
	return cleanAbsPath(root)
}

func (w *InstallWatcher) agentRangeMCPDirs() []string {
	root := w.agentRangeRoot()
	if root == "" {
		return nil
	}
	return existingDirs([]string{filepath.Join(root, "mcp")})
}

func (w *InstallWatcher) isAgentRangePath(path string) bool {
	root := w.agentRangeRoot()
	return root != "" && isPathWithin(path, root)
}

func looksLikeAgentRangeRoot(root string) bool {
	root = cleanAbsPath(root)
	if root == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(root, "docker-compose.yml"))
	if err != nil || info.IsDir() {
		return false
	}
	for _, dir := range []string{"skills", "mcp"} {
		if info, err := os.Stat(filepath.Join(root, dir)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

func localTargetExists(path string) bool {
	path = cleanAbsPath(path)
	if path == "" || strings.Contains(path, "://") {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func snapshotProcessEnvironment() (*TargetSnapshot, error) {
	var entries []string
	for _, raw := range os.Environ() {
		key, value, _ := strings.Cut(raw, "=")
		valueHash := sha256.Sum256([]byte(value))
		entries = append(entries, key+"="+hex.EncodeToString(valueHash[:]))
	}
	sort.Strings(entries)

	overall := sha256.New()
	for _, entry := range entries {
		overall.Write([]byte(entry + "\n"))
	}
	contentHash := hex.EncodeToString(overall.Sum(nil))

	return &TargetSnapshot{
		ContentHash:      contentHash,
		DependencyHashes: map[string]string{},
		ConfigHashes: map[string]string{
			"process.environment": contentHash,
		},
		Timestamp: time.Now().UTC(),
	}, nil
}

type staticResourceScanner struct {
	kind InstallType
	cfg  *config.Config
}

func (s *staticResourceScanner) Name() string {
	return "static-resource-scanner"
}

func (s *staticResourceScanner) Version() string {
	return "1.0.0"
}

func (s *staticResourceScanner) SupportedTargets() []string {
	return []string{string(s.kind)}
}

func (s *staticResourceScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	start := time.Now()
	result := &scanner.ScanResult{
		Scanner:    s.Name(),
		Target:     target,
		Timestamp:  start,
		TargetType: string(s.kind),
	}

	if s.kind == InstallEnvironment || target == processEnvironmentTarget {
		result.Duration = time.Since(start)
		return result, nil
	}

	var scanners []scanner.Scanner
	switch s.kind {
	case InstallCredential:
		scanners = []scanner.Scanner{
			scanner.NewClawShieldSecretsScanner(),
			scanner.NewClawShieldPIIScanner(),
		}
	case InstallPrompt:
		scanners = []scanner.Scanner{
			scanner.NewClawShieldInjectionScanner(),
			scanner.NewClawShieldSecretsScanner(),
		}
	default:
		scanners = []scanner.Scanner{
			scanner.NewClawShieldSecretsScanner(),
			scanner.NewClawShieldInjectionScanner(),
		}
	}

	for _, sc := range scanners {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sub, err := sc.Scan(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sc.Name(), err)
		}
		for _, finding := range sub.Findings {
			if strings.TrimSpace(finding.Scanner) == "" {
				finding.Scanner = sc.Name()
			}
			result.Findings = append(result.Findings, finding)
		}
	}
	result.Duration = time.Since(start)
	return result, nil
}

func expandUserPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func cleanAbsPath(path string) string {
	path = expandUserPath(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	// Strip the Windows extended-length prefix ("\\?\C:\…") that some
	// discovery sources record verbatim: Go's filepath helpers and the
	// scanners expect plain drive paths.
	path = strings.TrimPrefix(path, `\\?\`)
	path = strings.TrimPrefix(path, `\\.\`)
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(abs)
}

func isPathWithin(path, root string) bool {
	path = cleanAbsPath(path)
	root = cleanAbsPath(root)
	if path == "" || root == "" {
		return false
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

func isPolicyLikeFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json", ".rego", ".md", ".txt":
		return true
	default:
		return false
	}
}

func credentialNameLooksSensitive(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "secret") ||
		strings.Contains(name, "token") ||
		strings.Contains(name, "credential") ||
		strings.Contains(name, "apikey") ||
		strings.Contains(name, "api_key")
}

func existingDirs(paths []string) []string {
	var out []string
	for _, path := range dedupStrings(paths) {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			out = append(out, path)
		}
	}
	return out
}

func dedupStrings(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	var out []string
	for _, path := range paths {
		path = expandUserPath(strings.TrimSpace(path))
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// enumerateResourcesForAgent is the rule-driven replacement for the legacy
// fixed-filename/fixed-directory resource discovery: it takes one discovered
// agent, looks up the enabled agent_resource_rules rows for the agent's type,
// expands each rule's path_pattern against the agent's recorded roots, and
// enumerates the concrete resource targets (exact file / child dirs / glob /
// recursive). Every target is ensured into static_resources (carrying the
// agent + rule + scan-profile lineage) and returned as an InstallEvent for
// the admission and rescan pipelines.
func (w *InstallWatcher) enumerateResourcesForAgent(agent audit.AgentResourceRecord) []InstallEvent {
	if w == nil || w.store == nil || agent.ID == "" || agent.AgentTypeID <= 0 {
		return nil
	}
	rules, err := w.store.ListResourceRulesByAgentType(agent.AgentTypeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] list resource rules for agent %s: %v\n", agent.ID, err)
		return nil
	}
	if len(rules) == 0 {
		return nil
	}

	// observedAt is this enumeration's generation timestamp: every resource
	// still on disk gets last_seen_at = observedAt, and after the sweep
	// anything older is marked missing (resource disappeared — rows are
	// kept, never deleted, so the asset history stays complete).
	observedAt := time.Now().UTC()
	connector := watcherConnectorName(w.cfg)
	var events []InstallEvent
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, path := range w.expandResourceRulePath(agent, rule.PathPattern) {
			for _, target := range enumerateResourceTargets(path, rule.EnumerationMode) {
				resourceID, err := w.store.EnsureStaticResource(audit.StaticResourceInput{
					CanonicalAgentID: agent.ID,
					ResourceType:     rule.ResourceType,
					Name:             filepath.Base(target),
					Target:           target,
					ScanProfileID:    rule.ScanProfileID,
					ResourceRuleID:   rule.ID,
					Source:           "agent-resource-rule",
					ObservedAt:       observedAt,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "[watch] ensure static resource %s: %v\n", target, err)
					continue
				}
				events = append(events, InstallEvent{
					Type:              InstallType(rule.ResourceType),
					Name:              filepath.Base(target),
					Path:              target,
					AgentID:           agent.ID,
					AgentTypeID:       agent.AgentTypeID,
					ResourceID:        resourceID,
					ResourceRuleID:    rule.ID,
					ScanProfileID:     rule.ScanProfileID,
					PreScanProfileID:  rule.PreScanProfileID,
					PostScanProfileID: rule.PostScanProfileID,
					Connector:         connector,
					Timestamp:         observedAt,
				})
			}
		}
	}
	if missing, err := w.store.MarkMissingResources(agent.ID, observedAt); err != nil {
		fmt.Fprintf(os.Stderr, "[watch] mark missing resources for agent %s: %v\n", agent.ID, err)
	} else if missing > 0 {
		fmt.Fprintf(os.Stderr, "[watch] agent %s: %d resource(s) no longer present (marked missing)\n", agent.ID, missing)
	}
	return events
}

// expandResourceRulePath resolves the ${INSTALL_ROOT} / ${CONFIG_ROOT} /
// ${WORKSPACE_ROOT} / ${HOME} placeholders in an agent_resource_rules
// path_pattern against one agent's recorded roots. Patterns referencing a
// root this agent cannot resolve yield no paths (the rule simply doesn't
// apply), and ~/ prefixes expand like everywhere else in the watcher.
func (w *InstallWatcher) expandResourceRulePath(agent audit.AgentResourceRecord, pattern string) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == processEnvironmentTarget {
		return nil
	}

	path := pattern
	if strings.Contains(path, "${INSTALL_ROOT}") {
		if agent.InstallRoot == "" {
			return nil
		}
		path = strings.ReplaceAll(path, "${INSTALL_ROOT}", agent.InstallRoot)
	}
	if strings.Contains(path, "${CONFIG_ROOT}") {
		if agent.ConfigRoot == "" {
			return nil
		}
		path = strings.ReplaceAll(path, "${CONFIG_ROOT}", agent.ConfigRoot)
	}
	if strings.Contains(path, "${WORKSPACE_ROOT}") {
		workspace := cleanAbsPath(agent.WorkspaceRoot)
		if workspace == "" {
			// Agents discovered before the workspace_root metadata key
			// existed (notably AgentRange) record the workspace root as
			// their first config path — reuse it when it actually looks
			// like a range root, before falling back to the watcher's
			// own connector workspace.
			if candidate := cleanAbsPath(agent.ConfigRoot); candidate != "" && looksLikeAgentRangeRoot(candidate) {
				workspace = candidate
			} else if w != nil {
				workspace = w.agentRangeRoot()
			}
		}
		if workspace == "" {
			return nil
		}
		path = strings.ReplaceAll(path, "${WORKSPACE_ROOT}", workspace)
	}
	if home, err := os.UserHomeDir(); err == nil {
		path = strings.ReplaceAll(path, "${HOME}", home)
	}
	if strings.Contains(path, "${") {
		// Unknown placeholder: the rule is ahead of this build's expansion
		// table; skip rather than scan a literal "${...}" path.
		return nil
	}

	abs := cleanAbsPath(path)
	if abs == "" {
		return nil
	}
	return []string{abs}
}

// enumerateResourceTargets turns one expanded rule path into concrete
// resource targets according to the rule's enumeration_mode:
//
//	exact      — the path itself is the resource (config.toml, CLAUDE.md, …)
//	children   — every first-level child directory (skills/shell_runner, …)
//	glob       — filepath.Glob matches (e.g. ${CONFIG_ROOT}/*.json)
//	recursive  — every non-hidden file under the path (WalkDir)
//
// Hidden entries (dot-prefixed) are skipped in every mode; a missing path
// yields no targets.
func enumerateResourceTargets(path, mode string) []string {
	if path == "" || path == processEnvironmentTarget {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "glob":
		matches, err := filepath.Glob(path)
		if err != nil || len(matches) == 0 {
			return nil
		}
		sort.Strings(matches)
		var out []string
		for _, match := range matches {
			if strings.HasPrefix(filepath.Base(match), ".") {
				continue
			}
			out = append(out, match)
		}
		return out
	case "recursive":
		var out []string
		_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // tolerate unreadable subtrees
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") && p != path {
					return fs.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") {
				return nil
			}
			out = append(out, p)
			return nil
		})
		return out
	case "exact":
		if _, err := os.Stat(path); err != nil {
			return nil
		}
		return []string{path}
	default: // "children" (also the DB default)
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil
		}
		var out []string
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				continue
			}
			out = append(out, filepath.Join(path, name))
		}
		return out
	}
}

// compositeScanner runs every capability scanner resolved for one resource
// target and merges their findings into a single ScanResult, so a Skill can
// be checked by SkillScanner + Malware + Injection + Secrets in one pass
// instead of only one type-driven scanner.
type compositeScanner struct {
	kind InstallType
	subs []scanner.Scanner
}

func (s *compositeScanner) Name() string               { return "composite-scanner" }
func (s *compositeScanner) Version() string            { return "1.0.0" }
func (s *compositeScanner) SupportedTargets() []string { return []string{string(s.kind)} }

func (s *compositeScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	start := time.Now()
	result := &scanner.ScanResult{
		Scanner:    s.Name(),
		Target:     target,
		Timestamp:  start,
		TargetType: string(s.kind),
	}

	var lastErr error
	for _, sub := range s.subs {
		if err := ctx.Err(); err != nil {
			break
		}
		subResult, err := sub.Scan(ctx, target)
		if err != nil {
			// One capability failing must not discard the findings the
			// other capabilities already produced.
			lastErr = err
			continue
		}
		if subResult == nil {
			continue
		}
		for _, finding := range subResult.Findings {
			if strings.TrimSpace(finding.Scanner) == "" {
				finding.Scanner = sub.Name()
			}
			result.Findings = append(result.Findings, finding)
		}
	}
	result.Duration = time.Since(start)

	// Only surface an error when every capability failed and nothing was
	// collected — partial results still feed the admission gate.
	if len(result.Findings) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return result, nil
}

// maliciousCategories lists the structured finding categories that mark a
// resource as malicious (a real attack payload) rather than merely risky
// configuration — "risk" and "malicious" stay independent metrics.
var maliciousCategories = map[string]bool{
	"malware":                 true,
	"reverse_shell":           true,
	"credential_harvest":      true,
	"credential_exfiltration": true,
	"cryptominer":             true,
	"c2":                      true,
	"command_execution":       true,
	"prompt_injection":        true,
	"malicious_mcp_tool":      true,
	"data_exfiltration":       true,
}

// maliciousRuleIDPrefixes are structured detection-id prefixes whose
// findings are malicious by construction — the ClawShield malware signature
// family (reverse shells, credential harvesters, cryptominers, C2 beacons,
// zip-slip archives).
var maliciousRuleIDPrefixes = []string{"CS-MAL-"}

// maliciousTags are structured finding tags emitted by the ClawShield
// detectors. Only unambiguous attack tags participate — the generic
// "injection" tag is deliberately excluded because weak heuristic findings
// (verb density, entropy) carry it too.
var maliciousTags = map[string]bool{
	"malware":               true,
	"reverse_shell":         true,
	"credential_harvest":    true,
	"cryptominer":           true,
	"c2":                    true,
	"zip_slip":              true,
	"role_override":         true,
	"instruction_injection": true,
	"delimiter_injection":   true,
}

// maliciousTitleKeywords is the last-resort fallback for scanners that emit
// no structured semantics at all. Title wording changes over time, so this
// path must never be the primary signal.
var maliciousTitleKeywords = []string{
	"malware",
	"reverse shell",
	"credential harvest",
	"credential exfiltration",
	"cryptominer",
	"command execution",
	"prompt injection",
	"malicious mcp",
	"data exfiltration",
	"zip slip",
}

// isMaliciousFinding applies the structured-field priority: RuleID →
// Category → Tags / finding ID (structured ClawShield fields) → Title
// (legacy fallback only). The malicious verdict must never hinge on display
// text: rewording "Possible command execution risk" to "Dangerous shell
// invocation" must not change the outcome.
func isMaliciousFinding(f scanner.Finding) bool {
	ruleID := strings.TrimSpace(f.RuleID)
	if ruleID != "" {
		for _, prefix := range maliciousRuleIDPrefixes {
			if strings.HasPrefix(ruleID, prefix) {
				return true
			}
		}
	}
	if maliciousCategories[strings.ToLower(strings.TrimSpace(f.Category))] {
		return true
	}
	for _, tag := range f.Tags {
		if maliciousTags[strings.ToLower(strings.TrimSpace(tag))] {
			return true
		}
	}
	if strings.HasPrefix(strings.TrimSpace(f.ID), "CS-MAL-") {
		return true
	}
	return maliciousTitleFallback(f.Title)
}

// maliciousTitleFallback is the display-text heuristic of last resort.
func maliciousTitleFallback(title string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	if title == "" {
		return false
	}
	for _, keyword := range maliciousTitleKeywords {
		if strings.Contains(title, keyword) {
			return true
		}
	}
	return false
}

// containsMaliciousFinding reports whether any finding marks the resource
// as malicious (structured fields first, title only as fallback).
func containsMaliciousFinding(findings []scanner.Finding) bool {
	for i := range findings {
		if isMaliciousFinding(findings[i]) {
			return true
		}
	}
	return false
}

// updateResourceRisk writes the post-scan verdict back onto the
// rule-produced static_resources row. Risk is derived from the configurable
// governance risk tables first, with legacy heuristics only as compatibility
// fallback when those tables cannot evaluate a finding.
func (w *InstallWatcher) updateResourceRisk(evt InstallEvent, result *scanner.ScanResult, scanID string) {
	if w == nil || w.store == nil || evt.ResourceID == "" || result == nil {
		return
	}
	risk := w.resourceRiskSummary(result)
	if err := w.store.UpdateStaticResourceRisk(evt.ResourceID, audit.ResourceRiskUpdate{
		RiskLevel:    risk.RiskLevel,
		Malicious:    risk.Malicious,
		MaxSeverity:  risk.MaxSeverity,
		FindingCount: len(result.Findings),
		LastScanID:   scanID,
		LastSeenAt:   time.Now().UTC(),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[watch] update resource risk %s: %v\n", evt.ResourceID, err)
	}
}

// buildResourceWatchContexts derives one resourceWatchContext per expanded
// rule path across all discovered agents: the realtime watcher registers
// ctx.Root with fsnotify and classifies subsequent events against the
// context, so filesystem activity under a rule path maps back to its agent,
// rule, resource type, and scan profile. Exact-mode rules watch the file's
// parent directory and match the basename; glob rules watch the pattern's
// directory and match the pattern; children/recursive rules watch the root
// itself.
func (w *InstallWatcher) buildResourceWatchContexts() []resourceWatchContext {
	if w == nil || w.store == nil {
		return nil
	}
	agents, err := w.store.ListActiveAgents()
	if err != nil || len(agents) == 0 {
		return nil
	}
	var contexts []resourceWatchContext
	for _, agent := range agents {
		if agent.AgentTypeID <= 0 {
			continue
		}
		rules, err := w.store.ListResourceRulesByAgentType(agent.AgentTypeID)
		if err != nil || len(rules) == 0 {
			continue
		}
		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}
			for _, path := range w.expandResourceRulePath(agent, rule.PathPattern) {
				ctx := resourceWatchContext{
					AgentID:           agent.ID,
					AgentTypeID:       agent.AgentTypeID,
					RuleID:            rule.ID,
					ProfileID:         rule.ScanProfileID,
					PreScanProfileID:  rule.PreScanProfileID,
					PostScanProfileID: rule.PostScanProfileID,
					Type:              InstallType(rule.ResourceType),
					ResourceType:      rule.ResourceType,
					Mode:              strings.ToLower(strings.TrimSpace(rule.EnumerationMode)),
				}
				switch ctx.Mode {
				case "exact":
					ctx.Root = filepath.Dir(path)
					ctx.FileName = filepath.Base(path)
				case "glob":
					ctx.Pattern = path
					ctx.Root = filepath.Dir(path)
				default: // children / recursive
					ctx.Root = path
				}
				contexts = append(contexts, ctx)
			}
		}
	}
	return contexts
}

// resourceWatchDirs extracts the unique existing directories to register
// with fsnotify from the rule watch contexts.
func resourceWatchDirs(contexts []resourceWatchContext) []string {
	var dirs []string
	for _, ctx := range contexts {
		dirs = append(dirs, ctx.Root)
	}
	return existingDirs(dirs)
}

// ruleEventForPath classifies a realtime fsnotify path against the rule
// watch contexts: when the path is a resource target of some rule (child
// directory under a children-mode root, any file under a recursive root,
// the exact-mode file, or a glob match), an InstallEvent carrying the full
// agent/rule/profile lineage is returned. The static_resources row is
// ensured so admission and the post-scan risk update act on the same row
// the enumeration pipeline produced.
func (w *InstallWatcher) ruleEventForPath(path string) (InstallEvent, bool) {
	if len(w.ruleWatchContexts) == 0 {
		return InstallEvent{}, false
	}
	abs := cleanAbsPath(path)
	if abs == "" {
		return InstallEvent{}, false
	}
	for _, ctx := range w.ruleWatchContexts {
		target := ""
		switch ctx.Mode {
		case "children":
			// A children-mode resource is a first-level child DIRECTORY of
			// the rule root; events deeper inside belong to the child's own
			// tree, and loose files directly under the root are not
			// resources (enumeration skips them too).
			if filepath.Dir(abs) == ctx.Root {
				if info, err := os.Stat(abs); err == nil && info.IsDir() {
					target = abs
				}
			}
		case "recursive":
			if abs == ctx.Root || strings.HasPrefix(abs, ctx.Root+string(os.PathSeparator)) {
				target = abs
			}
		case "exact":
			if abs == filepath.Join(ctx.Root, ctx.FileName) {
				target = abs
			}
		case "glob":
			if ok, _ := filepath.Match(ctx.Pattern, abs); ok {
				target = abs
			}
		}
		if target == "" {
			continue
		}
		evt := InstallEvent{
			Type:              ctx.Type,
			Name:              filepath.Base(target),
			Path:              target,
			AgentID:           ctx.AgentID,
			AgentTypeID:       ctx.AgentTypeID,
			ResourceRuleID:    ctx.RuleID,
			ScanProfileID:     ctx.ProfileID,
			PreScanProfileID:  ctx.PreScanProfileID,
			PostScanProfileID: ctx.PostScanProfileID,
			Connector:         watcherConnectorName(w.cfg),
			Timestamp:         time.Now().UTC(),
		}
		if w.store != nil {
			resourceID, err := w.store.EnsureStaticResource(audit.StaticResourceInput{
				CanonicalAgentID: ctx.AgentID,
				ResourceType:     ctx.ResourceType,
				Name:             filepath.Base(target),
				Target:           target,
				ScanProfileID:    ctx.ProfileID,
				ResourceRuleID:   ctx.RuleID,
				Source:           "agent-resource-rule",
			})
			if err == nil {
				evt.ResourceID = resourceID
			}
		}
		return evt, true
	}
	return InstallEvent{}, false
}

// markRemovedRuleResource flags the rule-produced static resource behind a
// Remove fsnotify event as missing (near-realtime disappearance detection;
// the periodic enumeration sweep catches anything the event missed).
// Returns true when the path mapped onto a rule watch context, consuming
// the event.
func (w *InstallWatcher) markRemovedRuleResource(path string) bool {
	if len(w.ruleWatchContexts) == 0 || w.store == nil {
		return false
	}
	abs := cleanAbsPath(path)
	if abs == "" {
		return false
	}
	for _, ctx := range w.ruleWatchContexts {
		match := false
		switch ctx.Mode {
		case "children":
			match = filepath.Dir(abs) == ctx.Root
		case "recursive":
			match = abs == ctx.Root || strings.HasPrefix(abs, ctx.Root+string(os.PathSeparator))
		case "exact":
			match = abs == filepath.Join(ctx.Root, ctx.FileName)
		case "glob":
			if ok, _ := filepath.Match(ctx.Pattern, abs); ok {
				match = true
			}
		}
		if !match {
			continue
		}
		if err := w.store.MarkResourceMissingByPath(ctx.AgentID, abs); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] mark resource missing %s: %v\n", abs, err)
		}
		return true
	}
	return false
}
