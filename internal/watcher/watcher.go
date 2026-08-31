// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// InstallType distinguishes between static-resource scan targets.
type InstallType string

const (
	InstallConfig      InstallType = "config"
	InstallSkill       InstallType = "skill"
	InstallMCP         InstallType = "mcp"
	InstallPlugin      InstallType = "plugin"
	InstallPrompt      InstallType = "prompt"
	InstallCredential  InstallType = "credential"
	InstallEnvironment InstallType = "environment"
)

// String returns the string representation of the InstallType.
func (t InstallType) String() string { return string(t) }

// InstallEvent is emitted when the watcher detects a new skill or MCP server.
type InstallEvent struct {
	Type InstallType
	Name string
	Path string
	// AgentID / ResourceID / ResourceRuleID / ScanProfileID carry the
	// rule-driven lineage: which agent owns the resource, which
	// static_resources row it maps to, which agent_resource_rules row
	// produced it, and which resource_scan_profiles detection plan
	// applies. Empty/zero for legacy events (skill dirs, MCP config).
	AgentID           string
	AgentTypeID       int64
	ResourceID        string
	ResourceRuleID    int64
	ScanProfileID     int64
	PreScanProfileID  int64
	PostScanProfileID int64
	// Connector is the owning connector for this install, used to scope
	// per-connector enforcement on the admit path (most-specific-wins:
	// connector-scoped state, then the bare global state). Empty ⇒ resolve the
	// connector from the watcher config (watcherConnectorName) — preserves the
	// pre-existing global behavior for events that do not tag a connector.
	Connector string
	Timestamp time.Time
}

// Verdict is the outcome of running the admission gate on an install.
type Verdict string

const (
	VerdictBlocked   Verdict = "blocked"
	VerdictAllowed   Verdict = "allowed"
	VerdictClean     Verdict = "clean"
	VerdictRejected  Verdict = "rejected"
	VerdictWarning   Verdict = "warning"
	VerdictScanError Verdict = "scan-error"
)

// AdmissionResult captures the outcome for a single install event.
type AdmissionResult struct {
	Event         InstallEvent
	Verdict       Verdict
	Reason        string
	MaxSeverity   string
	FindingCount  int
	InstallAction string
	FileAction    string
	RuntimeAction string
}

// OnAdmission is called after each install event is processed.
type OnAdmission func(AdmissionResult)

type pendingWork struct {
	FirstSeen   time.Time
	Event       InstallEvent
	RescanTypes []InstallType
}

// InstallWatcher monitors OpenClaw skill directories for new installs
// and runs the admission gate (block → allow → scan) on each detection.
// MCP servers are managed via “defenseclaw mcp set/unset“ rather than
// filesystem watching.
// WebhookDispatcher is implemented by gateway.WebhookDispatcher. Declared as
// an interface here to avoid an import cycle (watcher → gateway).
type WebhookDispatcher interface {
	Dispatch(event audit.Event)
}

type InstallWatcher struct {
	cfg        *config.Config
	skillDirs  []string
	pluginDirs []string
	store      *audit.Store
	logger     *audit.Logger
	shell      *sandbox.OpenShell
	opa        *policy.Engine
	otel       *telemetry.Provider
	webhooks   WebhookDispatcher
	debounce   time.Duration
	onAdmit    OnAdmission

	mu       sync.Mutex
	pending  map[string]pendingWork
	rescanMu sync.Mutex

	policyFileMu     sync.Mutex
	policyFileHashes map[string]string   // path → sha256 hex of file contents (policy / list YAML watch)
	policyListSnap   map[string][]string // path → sorted rule keys for list YAML diffs

	// ruleWatchContexts maps realtime fsnotify events back onto the
	// agent_resource_rules row that put the watched directory under
	// surveillance: which agent, rule, resource type, and scan profile a
	// changed path belongs to. Built once per Run() from the discovered
	// agents + their enabled rules.
	ruleWatchContexts []resourceWatchContext

	// scannerFactory resolves the scanner for an event. Defaults to
	// scannerFor; tests inject a fake to observe scan invocations without
	// shelling out to the real scanner binaries.
	scannerFactory func(InstallEvent) scanner.Scanner
}

// resourceWatchContext ties one watched directory back to the
// agent_resource_rules row that produced it, so a filesystem event can be
// classified with full lineage (agent / rule / profile / resource type)
// instead of guessing from fixed skill/plugin directories.
type resourceWatchContext struct {
	AgentID           string
	AgentTypeID       int64
	RuleID            int64
	ProfileID         int64
	PreScanProfileID  int64
	PostScanProfileID int64
	Type              InstallType
	ResourceType      string
	// Root is the directory registered with fsnotify.
	Root string
	// Mode is the rule's enumeration_mode (children / recursive / exact /
	// glob) and decides how an event path maps onto a resource target.
	Mode string
	// FileName is the exact-mode target file (events for other files in
	// Root are ignored).
	FileName string
	// Pattern is the glob-mode pattern (events are matched against it).
	Pattern string
}

// newScanner resolves the scanner for evt via the injectable factory, falling
// back to the capability-driven scannersFor (which itself falls back to the
// config-driven scannerFor) when no factory is installed. When the event's
// scan profile maps to multiple capabilities, a compositeScanner running all
// of them is returned.
func (w *InstallWatcher) newScanner(evt InstallEvent) scanner.Scanner {
	if w.scannerFactory != nil {
		return w.scannerFactory(evt)
	}
	return w.scannerCompositeFor(evt)
}

// scannerCompositeFor turns the capability list for evt's scan profile into
// one runnable scanner.Scanner: a single scanner when one capability (or the
// legacy fallback) applies, or a compositeScanner merging findings from all
// capabilities.
func (w *InstallWatcher) scannerCompositeFor(evt InstallEvent) scanner.Scanner {
	scanners := w.scannersFor(evt)
	if len(scanners) == 0 {
		return nil
	}
	if len(scanners) == 1 {
		return scanners[0]
	}
	return &compositeScanner{kind: evt.Type, subs: scanners}
}

// scannersFor resolves the security detection capabilities for evt. When the
// event carries a ScanProfileID, the enabled profile capabilities (DB) decide
// which scanners run — the database drives "what checks apply to this
// resource". Events without a profile (or with an empty capability list) fall
// back to the legacy type-driven scannerFor.
func (w *InstallWatcher) scannersFor(evt InstallEvent) []scanner.Scanner {
	if evt.ScanProfileID > 0 && w.store != nil {
		capabilities, err := w.store.ListScanCapabilities(evt.ScanProfileID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watch] list capabilities for profile %d: %v\n", evt.ScanProfileID, err)
		}
		var scanners []scanner.Scanner
		for _, capability := range capabilities {
			if sc := w.resolveSecurityScanner(capability.CapabilityKey, evt); sc != nil {
				scanners = append(scanners, sc)
			}
		}
		if len(scanners) > 0 {
			return scanners
		}
	}
	if s := w.scannerFor(evt); s != nil {
		return []scanner.Scanner{s}
	}
	return nil
}

// resolveSecurityScanner maps a security_scan_capabilities capability_key to
// the concrete scanner.Scanner implementation. Local-path special cases
// (AgentRange skills, local MCP targets) keep the in-process static resource
// scanner instead of shelling out to the Python CLIs.
func (w *InstallWatcher) resolveSecurityScanner(capability string, evt InstallEvent) scanner.Scanner {
	switch capability {
	case "skill_security":
		if w.isAgentRangePath(evt.Path) {
			return &staticResourceScanner{kind: evt.Type, cfg: w.cfg}
		}
		return scanner.NewSkillScannerFromLLM(
			w.cfg.Scanners.SkillScanner,
			w.cfg.ResolveLLM("scanners.skill"),
			w.cfg.CiscoAIDefense,
		)
	case "mcp_security":
		if localTargetExists(evt.Path) {
			return &staticResourceScanner{kind: evt.Type, cfg: w.cfg}
		}
		return scanner.NewMCPScannerFromLLM(
			w.cfg.Scanners.MCPScanner,
			w.cfg.ResolveLLM("scanners.mcp"),
			w.cfg.CiscoAIDefense,
		)
	case "plugin_security":
		return scanner.NewPluginScanner(w.cfg.Scanners.PluginScanner)
	case "secret_detection":
		return scanner.NewClawShieldSecretsScanner()
	case "pii_detection":
		return scanner.NewClawShieldPIIScanner()
	case "prompt_injection":
		return scanner.NewClawShieldInjectionScanner()
	case "malware_detection":
		return scanner.NewClawShieldMalwareScanner()
	case "vulnerability_detection":
		return scanner.NewClawShieldVulnScanner()
	default:
		return nil
	}
}

// New creates an InstallWatcher. The opa parameter may be nil to fall back
// to the built-in Go admission logic. The otel parameter may be nil when
// telemetry is disabled.
func New(cfg *config.Config, skillDirs, pluginDirs []string, store *audit.Store, logger *audit.Logger, shell *sandbox.OpenShell, opa *policy.Engine, otel *telemetry.Provider, onAdmit OnAdmission) *InstallWatcher {
	debounce := time.Duration(cfg.Watch.DebounceMs) * time.Millisecond
	if debounce <= 0 {
		debounce = 500 * time.Millisecond
	}
	return &InstallWatcher{
		cfg:              cfg,
		skillDirs:        skillDirs,
		pluginDirs:       pluginDirs,
		store:            store,
		logger:           logger,
		shell:            shell,
		opa:              opa,
		otel:             otel,
		debounce:         debounce,
		onAdmit:          onAdmit,
		pending:          make(map[string]pendingWork),
		policyFileHashes: make(map[string]string),
		policyListSnap:   make(map[string][]string),
	}
}

// SetOTelProvider attaches the OTel provider for watcher metrics.
func (w *InstallWatcher) SetOTelProvider(p *telemetry.Provider) {
	w.otel = p
}

// SetWebhookDispatcher attaches a webhook dispatcher for outbound notifications.
func (w *InstallWatcher) SetWebhookDispatcher(d WebhookDispatcher) {
	w.webhooks = d
}

// Run starts watching configured directories. It blocks until ctx is cancelled.
func (w *InstallWatcher) Run(ctx context.Context) error {
	if w.cfg.Watch.RescanEnabled {
		go w.rescanLoop(ctx)
	}

	if !w.cfg.Watch.RealtimeEnabled {
		fmt.Fprintf(os.Stderr, "[watch] realtime scanning disabled; periodic rescan enabled=%v\n", w.cfg.Watch.RescanEnabled)
		<-ctx.Done()
		_ = w.logger.LogAction(string(audit.ActionWatchStop), "", "context cancelled")
		return ctx.Err()
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watcher: create fsnotify watcher: %w", err)
	}
	defer fsw.Close()

	watched := 0
	// Rule-driven mode: when any discovered agent has enabled resource
	// rules, the rules are the single source of truth for which directories
	// are watched — the legacy skill/plugin/AgentRange registrations stay
	// off so deleting or disabling a rule truly stops coverage of its
	// directory (no hardcoded path keeps scanning behind the database's
	// back). With no rules anywhere, the legacy fixed directories apply.
	// This mirrors the enumeration fallback in enumerateTargets exactly.
	ruleContexts := w.buildResourceWatchContexts()
	ruleDriven := len(ruleContexts) > 0
	w.ruleWatchContexts = ruleContexts

	if !ruleDriven {
		for _, dir := range w.skillDirs {
			count, err := ensureAndWatchTree(fsw, dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[watch] skill dir %s: %v (skipping)\n", dir, err)
				continue
			}
			watched += count
			fmt.Printf("[watch] monitoring skill dir: %s (%d dirs)\n", dir, count)
		}
		for _, dir := range w.pluginDirs {
			count, err := ensureAndWatchTree(fsw, dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[watch] plugin dir %s: %v (skipping)\n", dir, err)
				continue
			}
			watched += count
			fmt.Printf("[watch] monitoring plugin dir: %s (%d dirs)\n", dir, count)
		}
		for _, dir := range w.agentRangeMCPDirs() {
			count, err := ensureAndWatchTree(fsw, dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[watch] AgentRange mcp dir %s: %v (skipping)\n", dir, err)
				continue
			}
			watched += count
			fmt.Printf("[watch] monitoring AgentRange mcp dir: %s (%d dirs)\n", dir, count)
		}
	} else {
		fmt.Printf("[watch] rule-driven mode: %d agent resource rule watch dir(s) active; legacy fixed dirs off\n", len(ruleContexts))
	}
	// Rule-driven watch roots: every enabled agent_resource_rules row across
	// the discovered agents contributes its expanded root directory, so new
	// resources landing under a rule path trigger the admission gate even
	// when the path sits outside the configured skill/plugin dirs.
	for _, dir := range resourceWatchDirs(ruleContexts) {
		if err := ensureAndWatch(fsw, dir); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] agent resource rule dir %s: %v (skipping)\n", dir, err)
			continue
		}
		watched++
	}
	for _, dir := range w.staticRealtimeDirs() {
		if err := ensureAndWatch(fsw, dir); err != nil {
			fmt.Fprintf(os.Stderr, "[watch] static resource dir %s: %v (skipping)\n", dir, err)
			continue
		}
		watched++
		fmt.Printf("[watch] monitoring static resource dir: %s\n", dir)
	}

	if watched == 0 {
		if w.cfg.Watch.RescanEnabled {
			fmt.Fprintf(os.Stderr, "[watch] no realtime directories; periodic rescan remains enabled\n")
			<-ctx.Done()
			_ = w.logger.LogAction(string(audit.ActionWatchStop), "", "context cancelled")
			return ctx.Err()
		}
		return fmt.Errorf("watcher: no directories to watch — check claw.mode and claw.home_dir")
	}

	_ = w.logger.LogAction(string(audit.ActionWatchStart), "", fmt.Sprintf("dirs=%d debounce=%s", watched, w.debounce))

	if w.opa != nil && w.otel != nil {
		w.opa.SetOTelProvider(w.otel)
	}
	go w.watchPolicyListsAndYAML(ctx)

	ticker := time.NewTicker(w.debounce)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = w.logger.LogAction(string(audit.ActionWatchStop), "", "context cancelled")
			return ctx.Err()

		case event, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename|fsnotify.Write|fsnotify.Remove) == 0 {
				continue
			}
			if event.Op&fsnotify.Create != 0 {
				_ = watchTreeIfDir(fsw, event.Name)
			}

			// Rule-produced resources disappearing from disk are flagged
			// missing immediately (rows kept, never deleted) instead of
			// waiting for the next enumeration sweep.
			if event.Op&fsnotify.Remove != 0 {
				if w.markRemovedRuleResource(event.Name) {
					continue
				}
			}

			// Rule-driven classification first: the event path is matched
			// against the rule watch contexts, so the admission event
			// carries the agent/rule/profile lineage.
			if evt, ok := w.ruleEventForPath(event.Name); ok {
				if w.otel != nil {
					w.otel.RecordWatcherEvent(ctx, watcherEventOp(event.Op), evt.Type.String(), "")
				}
				w.queueAdmission(evt)
				continue
			}

			if evt, ok := w.targetEventForPath(event.Name); ok {
				if w.otel != nil {
					w.otel.RecordWatcherEvent(ctx, watcherEventOp(event.Op), evt.Type.String(), "")
				}
				w.queueAdmission(evt)
				continue
			}

			if rescanTypes := w.staticRescanTypesForPath(event.Name); len(rescanTypes) > 0 {
				if w.otel != nil {
					w.otel.RecordWatcherEvent(ctx, watcherEventOp(event.Op), installTypesLabel(rescanTypes), "")
				}
				w.queueTypeRescan(rescanTypes)
			}

		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			if w.otel != nil {
				w.otel.RecordWatcherError(ctx)
			}
			fmt.Fprintf(os.Stderr, "[watch] fsnotify error: %v\n", err)

		case <-ticker.C:
			w.processPending(ctx)
		}
	}
}

func (w *InstallWatcher) queueAdmission(evt InstallEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if existing, exists := w.pending[evt.Path]; exists {
		existing.Event = evt
		w.pending[evt.Path] = existing
		return
	}
	w.pending[evt.Path] = pendingWork{FirstSeen: time.Now(), Event: evt}
}

func (w *InstallWatcher) queueTypeRescan(targetTypes []InstallType) {
	if len(targetTypes) == 0 {
		return
	}
	key := "rescan:" + installTypesLabel(targetTypes)
	w.mu.Lock()
	defer w.mu.Unlock()
	if existing, exists := w.pending[key]; exists {
		existing.RescanTypes = append([]InstallType(nil), targetTypes...)
		w.pending[key] = existing
		return
	}
	w.pending[key] = pendingWork{
		FirstSeen:   time.Now(),
		RescanTypes: append([]InstallType(nil), targetTypes...),
	}
}

func (w *InstallWatcher) processPending(ctx context.Context) {
	w.mu.Lock()
	now := time.Now()
	var ready []pendingWork
	for key, work := range w.pending {
		if now.Sub(work.FirstSeen) >= w.debounce {
			ready = append(ready, work)
			delete(w.pending, key)
		}
	}
	w.mu.Unlock()

	for _, work := range ready {
		if len(work.RescanTypes) > 0 {
			w.runRescanCycleForTypes(ctx, work.RescanTypes...)
			continue
		}
		evt := work.Event
		if evt.Path == "" {
			continue
		}
		if _, err := os.Stat(evt.Path); err != nil {
			continue
		}
		result := w.runAdmission(ctx, evt)
		if w.onAdmit != nil {
			w.onAdmit(result)
		}
	}
}

func (w *InstallWatcher) classifyEvent(path string) InstallEvent {
	if evt, ok := w.targetEventForPath(path); ok {
		return evt
	}
	return InstallEvent{
		Type:      InstallSkill,
		Name:      filepath.Base(path),
		Path:      path,
		Connector: watcherConnectorName(w.cfg),
		Timestamp: time.Now().UTC(),
	}
}

func (w *InstallWatcher) targetEventForPath(path string) (InstallEvent, bool) {
	for _, dir := range w.skillDirs {
		if targetPath, ok := topLevelChildPath(dir, path); ok {
			return InstallEvent{
				Type:      InstallSkill,
				Name:      filepath.Base(targetPath),
				Path:      targetPath,
				Connector: watcherConnectorName(w.cfg),
				Timestamp: time.Now().UTC(),
			}, true
		}
	}
	for _, dir := range w.pluginDirs {
		if targetPath, ok := topLevelChildPath(dir, path); ok {
			return InstallEvent{
				Type:      InstallPlugin,
				Name:      filepath.Base(targetPath),
				Path:      targetPath,
				Connector: watcherConnectorName(w.cfg),
				Timestamp: time.Now().UTC(),
			}, true
		}
	}
	return InstallEvent{}, false
}

func topLevelChildPath(root, path string) (string, bool) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", false
	}
	first := strings.Split(rel, string(filepath.Separator))[0]
	if first == "" || first == "." || first == ".." {
		return "", false
	}
	return filepath.Join(rootAbs, first), true
}

// eventConnector resolves the connector that owns an install event: the
// connector tagged on the event when present, otherwise the watcher's own
// connector (watcherConnectorName). This keeps the admit path correct for
// events that do not carry a Connector (e.g. the rescan enumerator), which
// previously always resolved via watcherConnectorName.
func (w *InstallWatcher) eventConnector(evt InstallEvent) string {
	if c := strings.TrimSpace(evt.Connector); c != "" {
		return c
	}
	return watcherConnectorName(w.cfg)
}

func (w *InstallWatcher) logAdmissionScan(ctx context.Context, result *scanner.ScanResult, verdict string, evt InstallEvent) {
	if w == nil || result == nil {
		return
	}
	if w.logger == nil {
		w.updateResourceRisk(evt, result, "")
		return
	}
	scanID, err := w.logger.LogScanWithCorrelationID(ctx, result, verdict, audit.ScanCorrelation{
		AgentID:          evt.AgentID,
		Connector:        w.eventConnector(evt),
		StaticResourceID: evt.ResourceID,
		ResourceRuleID:   evt.ResourceRuleID,
		ScanProfileID:    evt.ScanProfileID,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] log admission scan %s: %v\n", evt.Path, err)
		w.updateResourceRisk(evt, result, "")
		return
	}
	w.updateResourceRisk(evt, result, scanID)
}

// runAdmission applies the full admission gate: block → allow → scan.
// When the OPA engine is available it delegates the verdict decision to
// Rego policy; otherwise it falls back to the built-in Go logic.
func (w *InstallWatcher) runAdmission(ctx context.Context, evt InstallEvent) (res AdmissionResult) {
	pe := enforce.NewPolicyEngine(w.store)
	targetType := string(evt.Type)
	policyID := enforce.PolicyStableID(w.cfg.PolicyDir)
	ctx, admSpan := enforce.StartAdmissionDecideSpan(ctx, targetType, evt.Name, policyID)
	// SLO timer: measure watcher-detection → admission-decision wall
	// time so every run feeds defenseclaw.slo.block.latency. Blocked
	// verdicts drive the <2000ms SLO dashboard; allowed/clean still
	// populate the histogram so operators can compare distributions.
	admissionStart := time.Now()
	defer func() {
		enforce.EndAdmissionDecideSpan(admSpan, string(res.Verdict), res.Reason, policyID, nil)
		if w.otel != nil {
			w.otel.RecordBlockSLO(ctx, targetType, float64(time.Since(admissionStart).Milliseconds()))
		}
	}()

	_ = w.logger.LogAction(string(audit.ActionInstallDetected), evt.Path,
		fmt.Sprintf("type=%s name=%s", targetType, evt.Name))

	// Avarice F-2867: an explicit operator allow that recorded a
	// source_path MUST NOT auto-allow a different on-disk asset
	// just because it presents the same target name. We consult
	// the stored entry first; if its source_path differs from
	// evt.Path we drop the allow and force a fresh scan/decision.
	if existing, _ := pe.GetAction(targetType, evt.Name); existing != nil {
		if existing.Actions.Install == "allow" && existing.SourcePath != "" && existing.SourcePath != evt.Path {
			_ = w.logger.LogAction("install-allow-path-mismatch", evt.Path,
				fmt.Sprintf("type=%s name=%s allowed_path=%q presented_path=%q (F-2867)",
					targetType, evt.Name, existing.SourcePath, evt.Path))
			if w.otel != nil {
				w.otel.EmitPolicyDecision("admission", "allow-path-mismatch", evt.Name, targetType,
					"allow entry pinned to different source_path; failing closed (F-2867)",
					map[string]string{
						"allowed_path":   existing.SourcePath,
						"presented_path": evt.Path,
					})
			}
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{
				Event:   evt,
				Verdict: VerdictBlocked,
				Reason:  "allow entry pinned to different source_path; failing closed (F-2867)",
			}
			return res
		}
	}

	// Build block/allow lists from the SQLite store for the OPA input.
	blockList := w.buildListEntries(pe, "block")
	allowList := w.buildListEntries(pe, "allow")
	fallbackProfile := policy.LoadFallbackProfile(w.cfg.PolicyDir)

	assetDecision := w.cfg.EvaluateAssetPolicy(config.AssetPolicyInput{
		TargetType:     targetType,
		Name:           evt.Name,
		Connector:      w.eventConnector(evt),
		SourcePath:     evt.Path,
		RuntimeSurface: "watcher",
	})
	if assetDecision.Enabled && assetDecision.RawAction == "block" {
		if w.otel != nil {
			w.otel.EmitPolicyDecision("asset-policy", assetDecision.Action, evt.Name, targetType, assetDecision.Reason, map[string]string{
				"source":          assetDecision.Source,
				"registry_status": assetDecision.RegistryStatus,
				"runtime_surface": "watcher",
				"would_block":     fmt.Sprintf("%t", assetDecision.WouldBlock),
			})
		}
		if assetDecision.Action == "block" {
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=%s source=%s", targetType, assetDecision.Reason, assetDecision.Source))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: assetDecision.Reason}
			return res
		}
	}

	if blocked, bErr := pe.IsBlocked(targetType, evt.Name); bErr == nil && blocked {
		reason := fmt.Sprintf("%s %q is on the block list - rejected", targetType, evt.Name)
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s reason=blocked", targetType))
		if w.otel != nil {
			w.otel.EmitPolicyDecision("admission", "blocked", evt.Name, targetType, reason, nil)
		}
		w.enforceBlock(ctx, evt)
		w.recordAdmission(ctx, "blocked", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: reason, InstallAction: "block"}
		return res
	}

	skipLegacyPreScan := false
	if dbPre, matched, err := w.evaluateResourcePreScanDecision(evt); err != nil {
		fmt.Fprintf(os.Stderr, "[watch] evaluate pre-scan profile %d: %v\n", evt.PreScanProfileID, err)
	} else if matched {
		switch dbPre.Decision {
		case "block", "reject", "rejected":
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=%s", targetType, dbPre.Reason))
			if w.otel != nil {
				w.otel.EmitPolicyDecision("resource-pre-scan", "blocked", evt.Name, targetType, dbPre.Reason, nil)
			}
			w.applyResourcePreScanAction(ctx, pe, dbPre, evt, targetType)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{
				Event: evt, Verdict: VerdictBlocked, Reason: dbPre.Reason,
				InstallAction: dbPre.InstallAction,
				FileAction:    dbPre.FileAction,
				RuntimeAction: dbPre.RuntimeAction,
			}
			return res
		case "allow", "skip":
			_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
				fmt.Sprintf("type=%s reason=%s", targetType, dbPre.Reason))
			if w.otel != nil {
				w.otel.EmitPolicyDecision("resource-pre-scan", "allowed", evt.Name, targetType, dbPre.Reason, nil)
			}
			w.applyResourcePreScanAction(ctx, pe, dbPre, evt, targetType)
			w.recordAdmission(ctx, "allowed", targetType)
			res = AdmissionResult{
				Event: evt, Verdict: VerdictAllowed, Reason: dbPre.Reason,
				InstallAction: dbPre.InstallAction,
				FileAction:    dbPre.FileAction,
				RuntimeAction: dbPre.RuntimeAction,
			}
			return res
		case "alert", "review":
			_ = w.logger.LogAction(string(audit.ActionInstallWarning), evt.Path,
				fmt.Sprintf("type=%s phase=pre-scan reason=%s", targetType, dbPre.Reason))
			if w.otel != nil {
				w.otel.EmitPolicyDecision("resource-pre-scan", "warning", evt.Name, targetType, dbPre.Reason, nil)
			}
			skipLegacyPreScan = true
		case "scan":
			_ = w.logger.LogAction("resource-pre-scan-scan", evt.Path,
				fmt.Sprintf("type=%s reason=%s", targetType, dbPre.Reason))
			skipLegacyPreScan = true
		}
	}

	// Phase 1: pre-scan OPA evaluation (no scan_result yet).
	if !skipLegacyPreScan && w.opa != nil {
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: evt.Name,
			Path:       evt.Path,
			BlockList:  blockList,
			AllowList:  allowList,
		}
		out, err := w.opa.Evaluate(ctx, input)
		if err == nil {
			switch out.Verdict {
			case "blocked":
				_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
					fmt.Sprintf("type=%s reason=blocked", targetType))
				if w.otel != nil {
					w.otel.EmitPolicyDecision("admission", "blocked", evt.Name, targetType, out.Reason, nil)
				}
				w.enforceBlock(ctx, evt)
				w.recordAdmission(ctx, "blocked", targetType)
				res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
				return res
			case "rejected":
				_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
					fmt.Sprintf("type=%s reason=policy-rejected", targetType))
				if w.otel != nil {
					w.otel.EmitPolicyDecision("admission", "rejected", evt.Name, targetType, out.Reason, nil)
				}
				w.enforceBlock(ctx, evt)
				w.recordAdmission(ctx, "rejected", targetType)
				res = AdmissionResult{Event: evt, Verdict: VerdictRejected, Reason: out.Reason}
				return res
			case "allowed":
				_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
					fmt.Sprintf("type=%s reason=allow-listed", targetType))
				if w.otel != nil {
					w.otel.EmitPolicyDecision("admission", "allowed", evt.Name, targetType, out.Reason, nil)
				}
				w.recordAdmission(ctx, "allowed", targetType)
				res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
				return res
			}
			// verdict == "scan" → proceed to scanning below
		}
		// On OPA error, fall back to the built-in pre-scan gate so explicit
		// block/allow semantics still hold even when Rego is unavailable.
		fallbackOut := policy.EvaluateAdmissionFallback(input, fallbackProfile)
		switch fallbackOut.Verdict {
		case "blocked":
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=blocked", targetType))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: fallbackOut.Reason}
			return res
		case "allowed":
			_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
				fmt.Sprintf("type=%s reason=allow-listed", targetType))
			w.recordAdmission(ctx, "allowed", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: fallbackOut.Reason}
			return res
		}
	} else if !skipLegacyPreScan {
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: evt.Name,
			Path:       evt.Path,
			BlockList:  blockList,
			AllowList:  allowList,
		}
		out := policy.EvaluateAdmissionFallback(input, fallbackProfile)
		switch out.Verdict {
		case "blocked":
			_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
				fmt.Sprintf("type=%s reason=blocked", targetType))
			w.enforceBlock(ctx, evt)
			w.recordAdmission(ctx, "blocked", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: out.Reason}
			return res
		case "allowed":
			_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
				fmt.Sprintf("type=%s reason=allow-listed", targetType))
			w.recordAdmission(ctx, "allowed", targetType)
			res = AdmissionResult{Event: evt, Verdict: VerdictAllowed, Reason: out.Reason}
			return res
		}
	}

	// Phase 2: Scan.
	s := w.newScanner(evt)
	if s == nil {
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictScanError, Reason: "no scanner available"}
		return res
	}

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := s.Scan(scanCtx, evt.Path)
	if err != nil {
		_ = w.logger.LogAction(string(audit.ActionInstallScanError), evt.Path,
			fmt.Sprintf("type=%s scanner=%s error=%v", targetType, s.Name(), err))
		if w.otel != nil {
			w.otel.RecordScanError(ctx, s.Name(), targetType, classifyWatcherScanError(err))
		}
		// Avarice F-3187: a scanner error must NOT leave the
		// freshly-detected install in place. The legacy code
		// recorded `scan-error` and returned without quarantine,
		// blocking, or disabling the artifact, so a malicious
		// skill/plugin that crashed its scanner stayed installed.
		// Treat scanner failures as fail-closed: enforce a block
		// (which quarantines + disables per fallback policy) before
		// surfacing the verdict to the sidecar.
		w.enforceBlock(ctx, evt)
		_ = w.logger.LogAction("install-blocked", evt.Path,
			fmt.Sprintf("type=%s reason=scanner-error scanner=%s (F-3187)",
				targetType, s.Name()))
		w.recordAdmission(ctx, "scan-error", targetType)
		res = AdmissionResult{Event: evt, Verdict: VerdictBlocked,
			Reason:        fmt.Sprintf("scanner failure (fail-closed): %v", err),
			InstallAction: "block",
		}
		return res
	}

	// Manual block/allow entries should win even if they were added while the
	// scan was running.
	if blocked, bErr := pe.IsBlocked(targetType, evt.Name); bErr == nil && blocked {
		reason := fmt.Sprintf("%s %q is on the block list — rejected", targetType, evt.Name)
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s reason=blocked-post-scan", targetType))
		w.logAdmissionScan(ctx, result, "blocked", evt)
		w.enforceBlock(ctx, evt)
		w.recordAdmission(ctx, "blocked", targetType)
		res = AdmissionResult{
			Event: evt, Verdict: VerdictBlocked, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "block",
		}
		return res
	}
	if allowed, aErr := pe.IsAllowed(targetType, evt.Name); aErr == nil && allowed {
		reason := fmt.Sprintf("scan found findings but %s %q is allow-listed — skipping enforcement", targetType, evt.Name)
		_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
			fmt.Sprintf("type=%s reason=allow-listed-post-scan", targetType))
		w.logAdmissionScan(ctx, result, "allowed", evt)
		if w.otel != nil {
			w.otel.EmitPolicyDecision("admission", "allowed", evt.Name, targetType, reason, map[string]string{
				"scanner": s.Name(),
			})
		}
		w.recordAdmission(ctx, "allowed", targetType)
		res = AdmissionResult{
			Event: evt, Verdict: VerdictAllowed, Reason: reason,
			MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
			InstallAction: "allow",
		}
		return res
	}

	riskSummary := w.resourceRiskSummary(result)
	if dbPost, matched, err := w.evaluateResourcePostScanDecision(evt, result, s.Name(), riskSummary); err != nil {
		fmt.Fprintf(os.Stderr, "[watch] evaluate post-scan profile %d: %v\n", evt.PostScanProfileID, err)
	} else if matched {
		if w.otel != nil {
			w.otel.EmitPolicyDecision("resource-post-scan", dbPost.Verdict, evt.Name, targetType, dbPost.Reason, map[string]string{
				"scanner":      s.Name(),
				"max_severity": riskSummary.MaxSeverity,
				"risk_level":   riskSummary.RiskLevel,
			})
		}
		w.applyResourcePostScanAction(ctx, pe, dbPost, evt, targetType, result, s.Name())
		w.logAdmissionScan(ctx, result, dbPost.Verdict, evt)
		w.recordAdmission(ctx, dbPost.Verdict, targetType)
		res = AdmissionResult{
			Event: evt, Verdict: toVerdict(dbPost.Verdict), Reason: dbPost.Reason,
			MaxSeverity: riskSummary.MaxSeverity, FindingCount: len(result.Findings),
			InstallAction: dbPost.InstallAction,
			FileAction:    dbPost.FileAction,
			RuntimeAction: dbPost.RuntimeAction,
		}
		return res
	}

	// Phase 3: post-scan OPA evaluation with scan_result.
	if w.opa != nil {
		scanInput := &policy.ScanResultInput{
			MaxSeverity:   string(result.MaxSeverity()),
			TotalFindings: len(result.Findings),
			ScannerName:   s.Name(),
			Findings:      toFindingInputs(result.Findings),
		}
		input := policy.AdmissionInput{
			TargetType: targetType,
			TargetName: evt.Name,
			Path:       evt.Path,
			BlockList:  blockList,
			AllowList:  allowList,
			ScanResult: scanInput,
		}
		out, evalErr := w.opa.Evaluate(ctx, input)
		if evalErr == nil {
			if w.otel != nil {
				if out.Verdict == "rejected" || out.Verdict == "blocked" {
					w.otel.EmitPolicyDecision("admission", out.Verdict, evt.Name, targetType, out.Reason, map[string]string{
						"scanner":      s.Name(),
						"max_severity": string(result.MaxSeverity()),
					})
				}
				if out.Verdict == "clean" || out.Verdict == "warning" {
					w.otel.EmitPolicyDecision("admission", out.Verdict, evt.Name, targetType, out.Reason, map[string]string{
						"scanner":      s.Name(),
						"max_severity": string(result.MaxSeverity()),
					})
				}
			}
			w.applyPostScanEnforcement(ctx, pe, out, evt, targetType, result, s.Name())
			w.logAdmissionScan(ctx, result, out.Verdict, evt)
			w.recordAdmission(ctx, out.Verdict, targetType)
			res = AdmissionResult{
				Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
				MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
				InstallAction: out.InstallAction,
				FileAction:    out.FileAction,
				RuntimeAction: out.RuntimeAction,
			}
			return res
		}
		// On OPA error, fall through to built-in logic.
	}

	scanInput := &policy.ScanResultInput{
		MaxSeverity:   string(result.MaxSeverity()),
		TotalFindings: len(result.Findings),
		ScannerName:   s.Name(),
		Findings:      toFindingInputs(result.Findings),
	}
	out := policy.EvaluateAdmissionFallback(policy.AdmissionInput{
		TargetType: targetType,
		TargetName: evt.Name,
		Path:       evt.Path,
		BlockList:  blockList,
		AllowList:  allowList,
		ScanResult: scanInput,
	}, fallbackProfile)
	w.applyPostScanEnforcement(ctx, pe, out, evt, targetType, result, s.Name())
	w.logAdmissionScan(ctx, result, out.Verdict, evt)
	w.recordAdmission(ctx, out.Verdict, targetType)
	res = AdmissionResult{
		Event: evt, Verdict: toVerdict(out.Verdict), Reason: out.Reason,
		MaxSeverity: string(result.MaxSeverity()), FindingCount: len(result.Findings),
		InstallAction: out.InstallAction,
		FileAction:    out.FileAction,
		RuntimeAction: out.RuntimeAction,
	}
	return res
}

// applyPostScanEnforcement takes the OPA verdict after scanning and executes
// the enforcement side-effects (block, quarantine, disable) that OPA cannot
// perform itself. It respects file_action and install_action from OPA output.
//
// Allow-listed items are exempt from auto-enforcement; only a manual block
// can override an allow entry.
func (w *InstallWatcher) applyPostScanEnforcement(ctx context.Context, pe *enforce.PolicyEngine, out *policy.AdmissionOutput, evt InstallEvent, targetType string, result *scanner.ScanResult, scannerName string) {
	// Re-check allow list to guard against races where the item became
	// allowed between the pre-scan check and post-scan enforcement.
	if allowed, err := pe.IsAllowed(targetType, evt.Name); err == nil && allowed {
		_ = w.logger.LogAction(string(audit.ActionInstallAllowedSkipEnforce), evt.Path,
			fmt.Sprintf("type=%s %s is allow-listed — skipping auto-enforcement", targetType, evt.Name))
		return
	}

	switch out.Verdict {
	case "clean":
		_ = w.logger.LogAction(string(audit.ActionInstallClean), evt.Path,
			fmt.Sprintf("type=%s scanner=%s", targetType, scannerName))
	case "rejected":
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s install_action=%s file_action=%s",
				targetType, result.MaxSeverity(), scannerName, out.InstallAction, out.FileAction))

		if w.takeActionFor(evt) {
			blockReason := fmt.Sprintf("auto-block: watch detected %s findings (scanner=%s)", result.MaxSeverity(), scannerName)

			installAction := coalesce(out.InstallAction, "block")
			runtimeAction := coalesce(out.RuntimeAction, "allow")
			fileAction := coalesce(out.FileAction, "none")

			if installAction == "block" {
				_ = pe.Block(targetType, evt.Name, blockReason)
			}
			pe.SetSourcePath(targetType, evt.Name, evt.Path)

			enforcement := map[string]string{
				"source_path": evt.Path,
				"install":     installAction,
				"runtime":     runtimeAction,
				"file":        fileAction,
			}

			if fileAction == "quarantine" {
				_ = pe.Quarantine(targetType, evt.Name, blockReason)
			}
			if runtimeAction == "block" {
				_ = pe.Disable(targetType, evt.Name, blockReason)
			}

			_ = w.logger.LogActionWithEnforcement(string(audit.ActionWatcherBlock), evt.Name,
				fmt.Sprintf("type=%s reason=%s", targetType, blockReason), enforcement)

			if fileAction == "quarantine" || runtimeAction == "block" {
				w.enforceBlock(ctx, evt)
			}
		}
	case "warning":
		_ = w.logger.LogAction(string(audit.ActionInstallWarning), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s", targetType, result.MaxSeverity(), scannerName))
	}
}

func coalesce(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// buildListEntries queries the SQLite store for block or allow entries.
func (w *InstallWatcher) buildListEntries(pe *enforce.PolicyEngine, action string) []policy.ListEntry {
	var entries []audit.ActionEntry
	var err error
	switch action {
	case "block":
		entries, err = pe.ListBlocked()
	case "allow":
		entries, err = pe.ListAllowed()
	}
	if err != nil || entries == nil {
		return nil
	}
	out := make([]policy.ListEntry, len(entries))
	for i, e := range entries {
		out[i] = policy.ListEntry{
			TargetType: e.TargetType,
			TargetName: e.TargetName,
			Reason:     e.Reason,
		}
	}
	return out
}

func toVerdict(s string) Verdict {
	switch s {
	case "blocked":
		return VerdictBlocked
	case "allowed":
		return VerdictAllowed
	case "clean":
		return VerdictClean
	case "rejected":
		return VerdictRejected
	case "warning":
		return VerdictWarning
	default:
		return VerdictScanError
	}
}

func (w *InstallWatcher) scannerFor(evt InstallEvent) scanner.Scanner {
	// Each scanner kind gets its own resolved LLMConfig so
	// ``scanners.{skill,mcp}.llm`` overrides layered on top of the
	// global ``llm:`` block take effect. Resolving per-event (rather
	// than caching once at watcher startup) means a config reload is
	// picked up automatically on the next install.
	switch evt.Type {
	case InstallConfig:
		return &staticResourceScanner{kind: evt.Type, cfg: w.cfg}
	case InstallSkill:
		if w.isAgentRangePath(evt.Path) {
			return &staticResourceScanner{kind: evt.Type, cfg: w.cfg}
		}
		return scanner.NewSkillScannerFromLLM(
			w.cfg.Scanners.SkillScanner,
			w.cfg.ResolveLLM("scanners.skill"),
			w.cfg.CiscoAIDefense,
		)
	case InstallMCP:
		if localTargetExists(evt.Path) {
			return &staticResourceScanner{kind: evt.Type, cfg: w.cfg}
		}
		return scanner.NewMCPScannerFromLLM(
			w.cfg.Scanners.MCPScanner,
			w.cfg.ResolveLLM("scanners.mcp"),
			w.cfg.CiscoAIDefense,
		)

	case InstallPlugin:
		return scanner.NewPluginScanner(w.cfg.Scanners.PluginScanner)
	case InstallPrompt, InstallCredential, InstallEnvironment:
		return &staticResourceScanner{kind: evt.Type, cfg: w.cfg}
	default:
		return nil
	}
}

// takeActionFor returns whether enforcement actions should be applied for the
// given event type, using the per-type gateway watcher config with a fallback
// to the legacy watch.auto_block flag.
func (w *InstallWatcher) takeActionFor(evt InstallEvent) bool {
	switch evt.Type {
	case InstallSkill:
		return w.cfg.Gateway.Watcher.Skill.TakeAction
	case InstallPlugin:
		return w.cfg.Gateway.Watcher.Plugin.TakeAction
	case InstallMCP:
		return w.cfg.Gateway.Watcher.MCP.TakeAction
	case InstallConfig, InstallPrompt, InstallCredential, InstallEnvironment:
		return false
	default:
		return w.cfg.Watch.AutoBlock
	}
}

func (w *InstallWatcher) enforceBlock(ctx context.Context, evt InstallEvent) {
	switch evt.Type {
	case InstallSkill:
		se := enforce.NewSkillEnforcer(w.cfg.QuarantineDir)
		dest, err := se.Quarantine(evt.Path)
		if err != nil {
			w.emitQuarantineFailure(ctx, gatewaylog.ErrCodeFSMoveFailed, evt.Path, err)
			return
		}
		w.recordQuarantineAudit(ctx, audit.ActionQuarantine, evt.Path, dest)
	case InstallMCP:
		me := enforce.NewMCPEnforcer(w.shell)
		_ = me.BlockEndpoint(evt.Name)
	case InstallPlugin:
		pe := enforce.NewPluginEnforcer(w.cfg.QuarantineDir, w.shell)
		dest, err := pe.Quarantine(evt.Path)
		if err != nil {
			w.emitQuarantineFailure(ctx, gatewaylog.ErrCodeFSMoveFailed, evt.Path, err)
			return
		}
		w.recordQuarantineAudit(ctx, audit.ActionQuarantine, evt.Path, dest)
	}
}

func (w *InstallWatcher) emitQuarantineFailure(ctx context.Context, code gatewaylog.ErrorCode, path string, err error) {
	if w.otel != nil {
		w.otel.EmitGatewayEvent(gatewaylog.Event{
			Timestamp: time.Now().UTC(),
			EventType: gatewaylog.EventError,
			Severity:  gatewaylog.SeverityHigh,
			Error: &gatewaylog.ErrorPayload{
				Subsystem: string(gatewaylog.SubsystemQuarantine),
				Code:      string(code),
				Message:   "quarantine filesystem move failed",
				Cause:     err.Error(),
			},
		})
		w.otel.RecordQuarantineAction(ctx, "move_in", "error")
	} else {
		fmt.Fprintf(os.Stderr, "[watch] quarantine %s: %v\n", path, err)
	}
}

func (w *InstallWatcher) recordQuarantineAudit(ctx context.Context, action audit.Action, srcPath, destPath string) {
	if w.otel != nil {
		w.otel.RecordQuarantineAction(ctx, "move_in", "ok")
	}
	_ = w.logger.LogEvent(audit.Event{
		Action:   string(action),
		Target:   srcPath,
		Actor:    "defenseclaw",
		Details:  fmt.Sprintf("dest=%s", destPath),
		Severity: "INFO",
	})
}

// isDirectChildDir returns true if path is a directory and a direct child
// of one of the watched skill or MCP directories. Files and nested
// subdirectories inside a skill are ignored — a skill is always a top-level
// directory under a skill dir.
func (w *InstallWatcher) isDirectChildDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}

	parent := filepath.Dir(path)
	parentAbs, _ := filepath.Abs(parent)

	for _, dir := range w.skillDirs {
		dirAbs, _ := filepath.Abs(dir)
		if parentAbs == dirAbs {
			return true
		}
	}
	for _, dir := range w.pluginDirs {
		dirAbs, _ := filepath.Abs(dir)
		if parentAbs == dirAbs {
			return true
		}
	}
	return false
}

func (w *InstallWatcher) recordAdmission(ctx context.Context, decision, targetType string) {
	if w.otel != nil {
		w.otel.RecordAdmissionDecision(ctx, decision, targetType, "watcher")
	}
}

func watcherConnectorName(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if strings.TrimSpace(cfg.Guardrail.Connector) != "" {
		return strings.ToLower(strings.TrimSpace(cfg.Guardrail.Connector))
	}
	return strings.ToLower(strings.TrimSpace(string(cfg.Claw.Mode)))
}

func classifyWatcherScanError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "executable file not found"):
		return "not_found"
	case strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "timeout"):
		return "timeout"
	case strings.Contains(msg, "parse") || strings.Contains(msg, "unmarshal") || strings.Contains(msg, "json"):
		return "parse"
	default:
		return "crash"
	}
}

func toFindingInputs(findings []scanner.Finding) []policy.FindingInput {
	if len(findings) == 0 {
		return nil
	}
	out := make([]policy.FindingInput, 0, len(findings))
	for _, f := range findings {
		out = append(out, policy.FindingInput{
			Severity: string(f.Severity),
			Scanner:  f.Scanner,
			Title:    f.Title,
		})
	}
	return out
}

func ensureAndWatch(fsw *fsnotify.Watcher, dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	if err := fsw.Add(dir); err != nil {
		return fmt.Errorf("watch: %w", err)
	}

	return nil
}

func ensureAndWatchTree(fsw *fsnotify.Watcher, dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("create dir: %w", err)
	}

	count := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if path != dir {
			switch d.Name() {
			case ".git", "node_modules", "__pycache__", ".venv", "venv":
				return filepath.SkipDir
			}
		}
		if err := fsw.Add(path); err != nil {
			return nil
		}
		count++
		return nil
	})
	if err != nil {
		return count, fmt.Errorf("watch tree: %w", err)
	}
	return count, nil
}

func watchTreeIfDir(fsw *fsnotify.Watcher, path string) error {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return err
	}
	_, err = ensureAndWatchTree(fsw, path)
	return err
}

func watcherEventOp(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create != 0:
		return "create"
	case op&fsnotify.Rename != 0:
		return "rename"
	case op&fsnotify.Remove != 0:
		return "remove"
	case op&fsnotify.Write != 0:
		return "write"
	default:
		return "change"
	}
}
