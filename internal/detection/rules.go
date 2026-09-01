// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

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
