// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Phase 3 turns the attack chain from a page-level display
// reconstruction into a backend security object. When the correlation
// engine produces a chain-shaped detection, the policy engine
// persists runtime_attack_chains + runtime_attack_chain_events right
// after the decision, so /api/v1/attack-chains only has to query.

// chainWorthyDetection reports whether a detection represents a full
// attack chain (correlated multi-event detections and the critical
// atomic attack detections). Single suspicious events do not build
// chains.
func chainWorthyDetection(d audit.RuntimeDetection) bool {
	switch d.DetectionType {
	case "prompt_injection_driven_exfiltration",
		"credential_exfiltration",
		"data_exfiltration",
		"possible_runtime_exploitation":
		return true
	default:
		return strings.EqualFold(d.Category, "attack") &&
			strings.EqualFold(d.Severity, "CRITICAL")
	}
}

// chainRelation labels one event's role inside the chain ("为什么这
// 个事件在链上"), derived from the unified event vocabulary.
func chainRelation(ev audit.BehaviorEvent) string {
	switch ev.EventType {
	case audit.RuntimeEventPromptSubmit:
		return "initial_prompt"
	case audit.RuntimeEventContentInjection:
		return "prompt_injection"
	case audit.RuntimeEventContentSecret:
		return "secret_in_prompt"
	case audit.RuntimeEventToolPreCall, audit.RuntimeEventToolPostCall:
		return "tool_call"
	case audit.RuntimeEventFileRead:
		return "file_read"
	case audit.RuntimeEventFileWrite:
		return "file_write"
	case audit.RuntimeEventProcessExec:
		return "process_exec"
	case audit.RuntimeEventNetworkDownload:
		return "download"
	case audit.RuntimeEventNetworkRequest:
		return "network_request"
	case audit.RuntimeEventNetworkSend:
		return "exfiltration"
	case audit.RuntimeEventNetworkBlocked:
		return "blocked"
	default:
		return ev.EventType
	}
}

// recordAttackChain persists the attack chain for one decision. The
// chain identity is the detection (re-fires refresh end_time and
// append events via upsert semantics).
func (p *PolicyEngine) recordAttackChain(decision audit.RuntimeDecision, evidence []audit.DetectionEvidence) {
	if p == nil || p.store == nil {
		return
	}
	d := p.detectionForDecision(decision)
	if d.DetectionID == "" || !chainWorthyDetection(d) {
		return
	}

	links := make([]audit.AttackChainEventLink, 0, len(evidence))
	start := time.Time{}
	end := time.Time{}
	allBlocked := len(evidence) > 0
	for i, ev := range evidence {
		e := ev.Event
		if e.ID <= 0 {
			continue
		}
		links = append(links, audit.AttackChainEventLink{
			EventID:  e.ID,
			Sequence: i,
			Relation: chainRelation(e),
		})
		if !e.Timestamp.IsZero() {
			ts := e.Timestamp
			if start.IsZero() || ts.Before(start) {
				start = ts
			}
			if ts.After(end) {
				end = ts
			}
		}
		if !strings.EqualFold(strings.TrimSpace(e.Outcome), "blocked") {
			allBlocked = false
		}
	}
	if len(links) == 0 {
		return
	}
	now := time.Now().UTC()
	if start.IsZero() {
		start = d.FirstSeenAt
	}
	if end.IsZero() {
		end = now
	}

	status := audit.AttackChainStatusActive
	if allBlocked {
		status = audit.AttackChainStatusContained
	}
	_, _ = p.store.UpsertRuntimeAttackChain(audit.RuntimeAttackChain{
		AgentID:     decision.AgentID,
		AgentName:   decision.AgentName,
		SessionID:   decision.SessionID,
		TraceID:     decision.TraceID,
		AttackType:  d.DetectionType,
		Severity:    d.Severity,
		Status:      status,
		StartTime:   start,
		EndTime:     end,
		DetectionID: d.DetectionID,
		DecisionID:  decision.DecisionID,
	}, links)
}

// detectionForDecision re-reads the detection row behind one decision
// so chain building sees the merged (possibly escalated) severity.
func (p *PolicyEngine) detectionForDecision(decision audit.RuntimeDecision) audit.RuntimeDetection {
	d, _, err := p.store.GetRuntimeDetectionDetail(decision.DetectionID)
	if err != nil {
		return audit.RuntimeDetection{}
	}
	return d
}
