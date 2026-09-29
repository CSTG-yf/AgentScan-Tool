// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// PolicyEngine is the Phase-3 unified brain. Phase 2 recorded WHAT is
// risky (runtime_detections); this engine decides WHAT TO DO about it
// (runtime_decisions) and dispatches responses (runtime_response_actions)
// to the least-impactful enforcement point:
//
//	runtime_detection
//	        ↓
//	Policy / Decision Engine   ← runtime security mode (observe | action)
//	        ↓
//	runtime_decision  (ALLOW | AUDIT | ALERT | CONFIRM | BLOCK)
//	        ↓
//	enforcement point (prompt → tool → mcp → network → file → process)
//	        ↓
//	runtime_response_actions (what actually executed)
//
// Existing enforcement implementations are NOT rewritten — the proxy
// blocklist, guardrail verdicts and hook decisions keep running; the
// engine only routes verdicts to them and records what happened.
type PolicyEngine struct {
	store *audit.Store
	// mode caches the runtime security mode (observe default) so
	// policy evaluation stays off the hot DB path.
	modeMu     sync.RWMutex
	mode       string
	modeRead   time.Time
	modeTTL    time.Duration
	blocklist  *NetworkBlocklist
	executorMu sync.RWMutex
	executors  map[string]RuntimeExecutor
}

// runtimeSecurityModeSettingKey is the app_settings key holding
// {"mode":"observe"} / {"mode":"action"}.
const runtimeSecurityModeSettingKey = "runtime_security_mode"

// NewPolicyEngine builds the policy engine over one store.
func NewPolicyEngine(store *audit.Store) *PolicyEngine {
	p := &PolicyEngine{
		store:     store,
		mode:      audit.RuntimeSecurityModeObserve,
		modeTTL:   5 * time.Second,
		blocklist: NewNetworkBlocklist(),
		executors: map[string]RuntimeExecutor{},
	}
	p.blocklist.setPersistTarget(store)
	p.RegisterExecutor(ProcessExecutor{})
	p.RegisterExecutor(MCPBlockExecutor{Store: store})
	p.RegisterExecutor(AgentHookBlockExecutor{Store: store})
	p.RegisterExecutor(FileBlockExecutor{Store: store})
	p.reloadMode()
	return p
}

// RegisterExecutor attaches a concrete enforcement implementation to a
// policy point. Sidecar integrations can replace the built-in process
// executor; persisted pre-call gates remain bounded by connector capability.
func (p *PolicyEngine) RegisterExecutor(executor RuntimeExecutor) {
	if p == nil || executor == nil || strings.TrimSpace(executor.Point()) == "" {
		return
	}
	p.executorMu.Lock()
	if p.executors == nil {
		p.executors = map[string]RuntimeExecutor{}
	}
	p.executors[executor.Point()] = executor
	p.executorMu.Unlock()
}

func (p *PolicyEngine) executor(point string) RuntimeExecutor {
	if p == nil {
		return nil
	}
	p.executorMu.RLock()
	defer p.executorMu.RUnlock()
	return p.executors[point]
}

// Blocklist exposes the network blocklist so the proxy can check it.
func (p *PolicyEngine) Blocklist() *NetworkBlocklist {
	if p == nil {
		return nil
	}
	return p.blocklist
}

// SetMode switches the runtime security mode and persists it. Observe
// records would-block decisions without enforcing (false-positive
// tuning); action executes responses.
func (p *PolicyEngine) SetMode(mode string) error {
	if p == nil || p.store == nil {
		return nil
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case audit.RuntimeSecurityModeObserve, audit.RuntimeSecurityModeAction:
	default:
		return nil
	}
	p.modeMu.Lock()
	p.mode = mode
	p.modeRead = time.Now()
	p.modeMu.Unlock()
	return p.store.SaveJSONSetting(runtimeSecurityModeSettingKey, map[string]string{"mode": mode})
}

// Mode returns the current runtime security mode (cached, refreshed
// from app_settings every modeTTL so config changes propagate).
func (p *PolicyEngine) Mode() string {
	if p == nil {
		return audit.RuntimeSecurityModeObserve
	}
	p.modeMu.RLock()
	fresh := time.Since(p.modeRead) < p.modeTTL
	mode := p.mode
	p.modeMu.RUnlock()
	if fresh {
		return mode
	}
	p.reloadMode()
	p.modeMu.RLock()
	defer p.modeMu.RUnlock()
	return p.mode
}

func (p *PolicyEngine) reloadMode() {
	if p == nil || p.store == nil {
		return
	}
	var cfg struct {
		Mode string `json:"mode"`
	}
	if _, err := p.store.LoadJSONSetting(runtimeSecurityModeSettingKey, &cfg); err == nil {
		switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
		case audit.RuntimeSecurityModeAction:
			cfg.Mode = audit.RuntimeSecurityModeAction
		default:
			cfg.Mode = audit.RuntimeSecurityModeObserve
		}
		p.modeMu.Lock()
		p.mode = cfg.Mode
		p.modeRead = time.Now()
		p.modeMu.Unlock()
	}
}

// Decide evaluates the immutable default risk map. Live detections use the
// resolved AgentType policy through processDetectionWithPolicy.
func Decide(severity, category string, confidence float64) string {
	policy := audit.RuntimeRiskPolicy{Rules: audit.DefaultRuntimeRiskPolicyRules()}
	_, decision, _ := policy.Evaluate(RiskScore(severity, category, confidence))
	return decision
}

// RiskScore blends severity, category and confidence into one 0..1
// number: severity dominates (weighted 0.7), confidence refines
// (0.25), attack category adds a small bump (0.05).
func RiskScore(severity, category string, confidence float64) float64 {
	sevWeight := 0.3
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		sevWeight = 1.0
	case "HIGH":
		sevWeight = 0.8
	case "MEDIUM":
		sevWeight = 0.5
	}
	score := sevWeight*0.7 + clamp01(confidence)*0.25
	if strings.EqualFold(strings.TrimSpace(category), "attack") {
		score += 0.05
	}
	return clamp01(score)
}

// EnforcementPlan maps a detection type onto the SMALLEST enforcement
// point that contains the risk. Killing an agent is the last resort —
// a PreToolUse hook block stops a credential read before it happens,
// and a proxy block stops exfiltration without killing the session.
func EnforcementPlan(detectionType string) (point, actionType string) {
	switch detectionType {
	case "prompt_injection":
		// The guardrail inspects prompts before the model sees them.
		return audit.EnforcementPointGuardrail, "PROMPT_BLOCK"
	case "credential_access", "sensitive_file_access",
		"dangerous_command", "tool_abuse":
		// PreToolUse can deny the tool call itself.
		return audit.EnforcementPointAgentHook, "TOOL_BLOCK"
	case "known_malicious_resource_invocation":
		// The MCP/tool gateway refuses the malicious server.
		return audit.EnforcementPointMCP, "MCP_BLOCK"
	case "ssrf_imds_access", "untrusted_network_access",
		"credential_exfiltration", "data_exfiltration",
		"prompt_injection_driven_exfiltration":
		// Stop the bytes at the network boundary.
		return audit.EnforcementPointProxy, "BLOCK_NETWORK"
	case "possible_runtime_exploitation", "suspicious_process":
		// No earlier layer saw it — process-level containment.
		return audit.EnforcementPointProcess, "PROCESS_CONTAIN"
	default:
		// Unknown detection types default to the network boundary,
		// the least invasive broad control.
		return audit.EnforcementPointProxy, "BLOCK_NETWORK"
	}
}

// ProcessDetection runs the full decide → respond → chain-record
// pipeline for one (new or refreshed) detection. Failure-tolerant: a
// policy problem never breaks the event path. When evidence is nil
// the full evidence chain is loaded from the store.
func (p *PolicyEngine) ProcessDetection(d audit.RuntimeDetection, evidence []audit.DetectionEvidence) {
	if p == nil || p.store == nil || d.DetectionID == "" {
		return
	}
	typeID, err := p.store.RuntimeAgentTypeID(d.AgentID)
	if err != nil {
		return
	}
	config, err := p.store.EffectiveRuntimeDetectionConfig(typeID)
	if err != nil || !config.Enabled {
		return
	}
	p.processDetectionWithPolicy(d, evidence, config.RiskPolicy)
}

// Live detection passes its configuration snapshot so a concurrent settings
// save cannot combine rules from one revision with another revision's policy.
func (p *PolicyEngine) processDetectionWithPolicy(d audit.RuntimeDetection, evidence []audit.DetectionEvidence, policy audit.RuntimeRiskPolicy) error {
	if evidence == nil {
		_, ev, err := p.store.GetRuntimeDetectionDetail(d.DetectionID)
		if err != nil {
			return err
		}
		evidence = ev
	}
	mode := p.Mode()
	_, decision, risk := policy.Evaluate(RiskScore(d.Severity, d.Category, d.Confidence))
	point, actionType := EnforcementPlan(d.DetectionType)
	if kind, ok := d.Attributes["blacklist_target_type"].(string); ok {
		switch kind {
		case "command", "tool":
			point, actionType = audit.EnforcementPointAgentHook, "TOOL_BLOCK"
		case "path":
			point, actionType = audit.EnforcementPointFile, "FILE_BLOCK"
		case "mcp":
			point, actionType = audit.EnforcementPointMCP, "MCP_BLOCK"
		case "process":
			point, actionType = audit.EnforcementPointProcess, "PROCESS_CONTAIN"
		case "domain", "url":
			point, actionType = audit.EnforcementPointProxy, "BLOCK_NETWORK"
		}
	}

	reason := decideReason(decision, d, evidence)
	recorded, isNew, err := p.store.RecordRuntimeDecision(audit.RuntimeDecisionInput{
		DetectionID:      d.DetectionID,
		AgentID:          d.AgentID,
		AgentName:        d.AgentName,
		SessionID:        d.SessionID,
		TraceID:          d.TraceID,
		Decision:         decision,
		RiskScore:        risk,
		Confidence:       d.Confidence,
		PolicyID:         policy.PolicyKey + ":v" + strconv.Itoa(policy.Version),
		Reason:           reason,
		EnforcementPoint: point,
		Mode:             mode,
		WouldBlock:       decision == audit.RuntimeDecisionBlock,
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	if !isNew && d.Attributes["enforcement_owner"] != "inspect" {
		return nil
	}

	if d.Attributes["enforcement_owner"] == "inspect" && recorded.Decision == audit.RuntimeDecisionBlock {
		// The synchronous inspect decision owns prevention. Do not repeat
		// network/process/tool enforcement from an observational finding.
		status := audit.ResponseStatusWouldBlock
		result := "observe mode: inspection risk recorded without enforcement"
		if mode == audit.RuntimeSecurityModeAction {
			status = audit.ResponseStatusPlanned
			result = "inspection owns prevention; automatic dispatch suppressed, inspect mode and operation result remain authoritative"
		}
		responses, err := p.store.ListResponseActions(recorded.DecisionID)
		if err != nil {
			return err
		}
		found := false
		for _, response := range responses {
			if response.Executor == "inspect" {
				found = true
			}
		}
		if !found {
			if _, err := p.store.RecordResponseAction(audit.ResponseActionInput{DecisionID: recorded.DecisionID, ActionType: "INSPECT_PREVENTION", Executor: "inspect", Status: status, Result: result, ExecutedAt: time.Now().UTC()}); err != nil {
				return err
			}
		}
	} else {
		p.dispatchResponse(recorded, actionType, evidence)
	}
	p.recordAttackChain(recorded, evidence)
	return nil
}

// dispatchResponse executes (action mode) or simulates (observe mode)
// the response for one fresh decision. Existing enforcement modules
// stay authoritative for their own layers; BLOCK_NETWORK is the one
// response this engine executes directly through the proxy blocklist.
func (p *PolicyEngine) dispatchResponse(decision audit.RuntimeDecision, actionType string, evidence []audit.DetectionEvidence) {
	if decision.Decision != audit.RuntimeDecisionBlock {
		return
	}
	mode := p.Mode()
	switch decision.EnforcementPoint {
	case audit.EnforcementPointProxy:
		hosts := evidenceHosts(evidence)
		if mode == audit.RuntimeSecurityModeAction && len(hosts) > 0 {
			added := p.blocklist.AddHosts(hosts, decision.DecisionID)
			target := strings.Join(added, ", ")
			if target == "" {
				// An already-blocked host is still the target of this response;
				// retaining it keeps the persisted action linked to the live
				// blocklist row and makes rollback/replay deterministic.
				target = strings.Join(hosts, ", ")
			}
			_, _ = p.store.RecordResponseAction(audit.ResponseActionInput{
				DecisionID:        decision.DecisionID,
				ActionType:        actionType,
				Executor:          "proxy",
				Target:            target,
				Status:            audit.ResponseStatusExecuted,
				Result:            "host(s) added to runtime network blocklist; proxy returns 403",
				RollbackSupported: true,
				ExecutedAt:        time.Now().UTC(),
			})
			return
		}
		status := audit.ResponseStatusWouldBlock
		result := "observe mode: would add host(s) to the runtime network blocklist"
		if mode == audit.RuntimeSecurityModeAction {
			// Action mode must never claim a block happened when the event did
			// not contain a host that the proxy blocklist can enforce.
			status = audit.ResponseStatusFailed
			result = "action mode: no network host evidence is available for proxy blocking"
		}
		_, _ = p.store.RecordResponseAction(audit.ResponseActionInput{
			DecisionID:        decision.DecisionID,
			ActionType:        actionType,
			Executor:          "proxy",
			Target:            strings.Join(hosts, ", "),
			Status:            status,
			Result:            result,
			RollbackSupported: true,
			ExecutedAt:        time.Now().UTC(),
		})
	default:
		status, target, result := p.ExecuteNonProxy(context.Background(), decision, actionType, evidence, mode != audit.RuntimeSecurityModeObserve)
		_, _ = p.store.RecordResponseAction(audit.ResponseActionInput{
			DecisionID: decision.DecisionID,
			ActionType: actionType,
			Executor:   decision.EnforcementPoint,
			Target:     target,
			Status:     status,
			Result:     result,
			ExecutedAt: time.Now().UTC(),
		})
	}
}

// ExecuteNonProxy runs an executor for guardrail, hook, MCP, file, and
// process points. force is used by an explicit operator retry; automatic
// policy dispatch passes false so observe mode remains a dry run.
func (p *PolicyEngine) ExecuteNonProxy(ctx context.Context, decision audit.RuntimeDecision, actionType string, evidence []audit.DetectionEvidence, force bool) (status, target, result string) {
	if p == nil {
		return audit.ResponseStatusFailed, "", "runtime policy engine unavailable"
	}
	if !force && p.Mode() == audit.RuntimeSecurityModeObserve {
		return audit.ResponseStatusWouldBlock, "", "observe mode: would dispatch to " + decision.EnforcementPoint + " enforcement"
	}
	executor := p.executor(decision.EnforcementPoint)
	if executor == nil {
		return audit.ResponseStatusFailed, "", "no confirmed executor is available for " + decision.EnforcementPoint
	}
	target, result, err := executor.Execute(ctx, RuntimeExecutionRequest{
		Decision: decision, ActionType: actionType, Evidence: evidence,
	})
	if err != nil {
		return audit.ResponseStatusFailed, target, err.Error()
	}
	return audit.ResponseStatusExecuted, target, result
}

// decideReason builds a human-readable explanation of the verdict.
func decideReason(decision string, d audit.RuntimeDetection, evidence []audit.DetectionEvidence) string {
	var b strings.Builder
	b.WriteString("detection ")
	b.WriteString(d.DetectionType)
	b.WriteString(" severity=")
	b.WriteString(strings.ToUpper(d.Severity))
	b.WriteString(" confidence=")
	b.WriteString(trimFloat(d.Confidence))
	if len(evidence) > 0 {
		b.WriteString(" events=")
		if n := d.EventCount; n > 0 {
			b.WriteString(intToString(n))
		} else {
			b.WriteString(intToString(len(evidence)))
		}
	}
	b.WriteString(" → ")
	b.WriteString(decision)
	return b.String()
}

// evidenceHosts extracts destination hosts from network-shaped
// evidence events (network.request/send/blocked/download) for the
// proxy blocklist.
func evidenceHosts(evidence []audit.DetectionEvidence) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, ev := range evidence {
		e := ev.Event
		if !strings.HasPrefix(e.EventType, "network.") {
			continue
		}
		if h := hostFromTarget(e.Target); h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// hostFromTarget extracts the hostname from a URL-ish target string.
func hostFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	// Bare host[:port]/path shapes.
	if i := strings.IndexAny(target, "/?#"); i > 0 {
		target = target[:i]
	}
	if i := strings.LastIndex(target, ":"); i > 0 {
		target = target[:i]
	}
	if target == "" || strings.ContainsAny(target, " \t") {
		return ""
	}
	return strings.ToLower(target)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func trimFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
}

func intToString(n int) string {
	return strconv.Itoa(n)
}
