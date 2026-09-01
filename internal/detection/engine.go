// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Package detection implements the Phase-2 Runtime Detection Engine.
//
// Phase 1 unified runtime events answer "发生了什么？" (behavior_events);
// this package answers "这里有什么安全问题？" (runtime_detections).
// Every unified event recorded by the Guardrail / Agent Hook / Proxy /
// OS Sensor adapters flows through Engine.EvaluateEvent, which runs a
// set of AGENT-AGNOSTIC rules:
//
//   - Atomic rules fire on a single event (prompt injection, SSRF,
//     sensitive file access, dangerous command, ...).
//   - Correlation rules join multiple events inside a session/trace
//     window (credential read + network send = credential exfiltration;
//     injection + credential read + send = prompt-injection-driven
//     exfiltration; shell + download + write + exec = runtime
//     exploitation).
//
// Rules must NEVER special-case agent products (Claude Code / Codex /
// OpenClaw). The agent is context carried on the detection, not a
// rule input — the same event chain produces the same detection
// regardless of which agent produced it.
package detection

import (
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Rule is one generic detection rule. Agent-specific naming has no
// place here; rules see only the unified event vocabulary.
type Rule interface {
	ID() string
	Name() string
	// Evaluate inspects the triggering event plus the correlation
	// window (same session/trace, time-ordered, trigger included).
	// Returning an empty slice means no detection.
	Evaluate(ctx *EvalContext) []DetectionResult
}

// EvalContext carries everything a rule may look at. Window events
// are ordered oldest → newest and always include Event (the trigger).
type EvalContext struct {
	Event  audit.BehaviorEvent
	Window []audit.BehaviorEvent
	Now    time.Time
	// MaliciousResources caches static resources the scanner flagged
	// malicious, so the static-fusion rule can join runtime tool/MCP
	// invocations with static scan findings (Phase 3: Static Finding +
	// Runtime Event → Detection → Block).
	MaliciousResources []audit.MaliciousStaticResource
}

// DetectionResult is a rule verdict before persistence.
type DetectionResult struct {
	DetectionType string
	Category      string // attack | suspicious | hygiene
	Severity      string // critical | high | medium | low
	Confidence    float64
	Title         string
	Detail        string
	Remediation   string
	Attributes    map[string]any
	// Evidence events in chain order (sequence assigned by the engine
	// from slice order). Outcome feeds the mitigated-status logic.
	Evidence []EvidenceSpec
}

// EvidenceSpec names one behavior event backing a detection.
type EvidenceSpec struct {
	EventID int64
	Role    string // audit.DetectionRoleTrigger / supporting / corroborating
	Outcome string
}

// Engine evaluates unified runtime events against the generic rule
// set and records detections with evidence links. Phase 3 adds the
// policy engine: every recorded detection flows into the unified
// decision → response → attack-chain pipeline.
type Engine struct {
	store  *audit.Store
	rules  []Rule
	window time.Duration
	// maxWindowEvents caps the correlation window query so a noisy
	// session cannot blow up per-event evaluation cost.
	maxWindowEvents int
	policy          *PolicyEngine

	// maliciousRes caches the malicious static-resource list for the
	// static-fusion rule; refreshed at most every maliciousResTTL.
	maliciousResMu   sync.RWMutex
	maliciousRes     []audit.MaliciousStaticResource
	maliciousResRead time.Time
}

// maliciousResTTL bounds static-fusion cache staleness. Scan results
// change on the order of minutes, not per event.
const maliciousResTTL = 30 * time.Second

// DefaultCorrelationWindow is how far back correlated events stay
// linkable into one detection chain (read → send chains usually land
// within seconds; generous margin covers long tool executions).
const DefaultCorrelationWindow = 10 * time.Minute

// NewEngine builds an engine with the given rules. A nil store or
// empty rule set yields a no-op engine so callers never nil-check.
// The engine owns one PolicyEngine (Phase 3): detections flow into
// decisions, responses and attack chains automatically.
func NewEngine(store *audit.Store, rules []Rule) *Engine {
	e := &Engine{
		store:           store,
		rules:           rules,
		window:          DefaultCorrelationWindow,
		maxWindowEvents: 200,
	}
	if e.store != nil {
		e.policy = NewPolicyEngine(store)
	}
	if len(e.rules) == 0 {
		e.rules = nil
	}
	return e
}

// Rules returns the active rule set (tests and introspection).
func (e *Engine) Rules() []Rule { return e.rules }

// Policy exposes the Phase-3 policy engine (mode switching, network
// blocklist) for the gateway.
func (e *Engine) Policy() *PolicyEngine {
	if e == nil {
		return nil
	}
	return e.policy
}

// EvaluateEvent runs all rules against one persisted event. It is
// called by the gateway adapters right after RecordRuntimeEvent and
// must be cheap and failure-tolerant: detection problems never break
// the request path.
func (e *Engine) EvaluateEvent(eventID int64) {
	if e == nil || e.store == nil || eventID <= 0 || len(e.rules) == 0 {
		return
	}
	event, ok, err := e.store.GetRuntimeEvent(eventID)
	if err != nil || !ok {
		return
	}
	window := e.loadWindow(event)
	ctx := &EvalContext{
		Event:              event,
		Window:             window,
		Now:                time.Now().UTC(),
		MaliciousResources: e.loadMaliciousResources(),
	}
	for _, rule := range e.rules {
		results := rule.Evaluate(ctx)
		for _, res := range results {
			e.record(event, rule, res)
		}
	}
}

// loadMaliciousResources serves the static-fusion cache with a TTL so
// per-event evaluation never adds a static_resources query.
func (e *Engine) loadMaliciousResources() []audit.MaliciousStaticResource {
	e.maliciousResMu.RLock()
	fresh := time.Since(e.maliciousResRead) < maliciousResTTL && e.maliciousResRead != (time.Time{})
	cached := e.maliciousRes
	e.maliciousResMu.RUnlock()
	if fresh {
		return cached
	}
	res, err := e.store.ListMaliciousStaticResources()
	if err != nil {
		return nil
	}
	e.maliciousResMu.Lock()
	e.maliciousRes = res
	e.maliciousResRead = time.Now().UTC()
	e.maliciousResMu.Unlock()
	return res
}

// loadWindow fetches the correlation window for one trigger event:
// same session (preferred), else same trace, else same agent, else
// just the trigger. Ordered oldest → newest, trigger included.
func (e *Engine) loadWindow(ev audit.BehaviorEvent) []audit.BehaviorEvent {
	since := ev.Timestamp
	if since.IsZero() {
		since = time.Now().UTC()
	}
	since = since.Add(-e.window)

	f := audit.RuntimeEventFilter{
		Since: since,
		Limit: e.maxWindowEvents,
	}
	switch {
	case ev.SessionID != "":
		f.SessionID = ev.SessionID
	case ev.TraceID != "":
		f.TraceID = ev.TraceID
	case ev.CanonicalAgentID != "":
		f.AgentID = ev.CanonicalAgentID
	default:
		return []audit.BehaviorEvent{ev}
	}
	window, err := e.store.ListRuntimeEvents(f)
	if err != nil || len(window) == 0 {
		return []audit.BehaviorEvent{ev}
	}
	// The trigger was just inserted, so it is in the window; if the
	// query raced or the row is filtered out, append it to be safe.
	found := false
	for _, w := range window {
		if w.ID == ev.ID {
			found = true
			break
		}
	}
	if !found {
		window = append(window, ev)
	}
	return window
}

// record persists one rule verdict with evidence links. Sequence
// numbers follow the evidence slice order (chain order).
func (e *Engine) record(trigger audit.BehaviorEvent, rule Rule, res DetectionResult) {
	if res.DetectionType == "" {
		return
	}
	in := audit.RuntimeDetectionInput{
		AgentID:       trigger.CanonicalAgentID,
		AgentName:     trigger.AgentName,
		SessionID:     trigger.SessionID,
		TraceID:       trigger.TraceID,
		DetectionType: res.DetectionType,
		Category:      res.Category,
		Severity:      res.Severity,
		Confidence:    res.Confidence,
		RuleID:        rule.ID(),
		Title:         res.Title,
		Detail:        res.Detail,
		Remediation:   res.Remediation,
		Attributes:    res.Attributes,
		SeenAt:        time.Now().UTC(),
	}
	seq := 0
	for _, ev := range res.Evidence {
		if ev.EventID <= 0 {
			continue
		}
		if ev.Role == "" {
			ev.Role = audit.DetectionRoleSupporting
		}
		in.Evidence = append(in.Evidence, audit.DetectionEvidenceInput{
			EventID:  ev.EventID,
			Role:     ev.Role,
			Sequence: seq,
			Outcome:  ev.Outcome,
		})
		seq++
	}
	d, _ := e.store.RecordRuntimeDetection(in)
	if e.policy != nil {
		// Phase 3: detection → decision → response → attack chain.
		// ProcessDetection re-reads the merged detection + evidence
		// so escalations see the full chain.
		e.policy.ProcessDetection(d, nil)
	}
}
