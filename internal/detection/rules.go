// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

// RuleVersion is persisted in API/job metadata so a historical replay can be
// attributed to the exact rule vocabulary that produced its verdicts.
const RuleVersion = "runtime-rules-v1"

// DefaultRules returns the standard agent-agnostic rule set:
//
//	Atomic (single event):
//	  prompt-injection, credential-access, sensitive-file,
//	  ssrf-defense, untrusted-network, dangerous-command,
//	  suspicious-process, tool-abuse, known-malicious-resource
//
//	Correlated (multi-event chains):
//	  credential-exfiltration, injection-driven-exfiltration,
//	  exploit-behavior
//
// Rules must stay generic across agents: the same chain detects the
// same way for Claude Code, Codex, OpenClaw or any future connector.
func DefaultRules() []Rule {
	return []Rule{
		// Atomic detections.
		NewInspectFindingsRule(),
		NewPromptInjectionRule(),
		NewCredentialAccessRule(),
		NewSensitiveFileRule(),
		NewSSRFDefenseRule(),
		NewUntrustedNetworkRule(),
		NewDangerousCommandRule(),
		NewSuspiciousProcessRule(),
		NewToolAbuseRule(),
		// Static ↔ runtime fusion (Phase 3).
		NewKnownMaliciousResourceRule(),
		// Correlated detections.
		NewDataExfiltrationRule(),
		NewPromptInjectionDrivenExfiltrationRule(),
		NewExploitBehaviorRule(),
	}
}
