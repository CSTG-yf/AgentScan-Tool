// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type resourceRiskSummary struct {
	RiskLevel         string
	Malicious         bool
	MaxSeverity       string
	FindingCategories []string
	FindingScanners   []string
}

func (w *InstallWatcher) evaluateResourcePreScanDecision(evt InstallEvent) (audit.ResourceDecisionResult, bool, error) {
	if w == nil || w.store == nil || evt.PreScanProfileID <= 0 {
		return audit.ResourceDecisionResult{}, false, nil
	}
	return w.store.EvaluateResourcePreScan(evt.PreScanProfileID, audit.ResourcePreScanDecisionInput{
		AgentTypeID:    evt.AgentTypeID,
		ResourceRuleID: evt.ResourceRuleID,
		ResourceType:   string(evt.Type),
		Path:           evt.Path,
		SourceTrust:    "",
	})
}

func (w *InstallWatcher) evaluateResourcePostScanDecision(evt InstallEvent, result *scanner.ScanResult, scannerName string, risk resourceRiskSummary) (*policy.AdmissionOutput, bool, error) {
	if w == nil || w.store == nil || evt.PostScanProfileID <= 0 || result == nil {
		return nil, false, nil
	}
	decision, matched, err := w.store.EvaluateResourcePostScan(evt.PostScanProfileID, audit.ResourcePostScanDecisionInput{
		ResourceType:      string(evt.Type),
		MaxSeverity:       risk.MaxSeverity,
		RiskLevel:         risk.RiskLevel,
		Malicious:         risk.Malicious,
		FindingCategories: risk.FindingCategories,
		Scanner:           scannerName,
		FindingScanners:   risk.FindingScanners,
	})
	if err != nil || !matched {
		return nil, matched, err
	}
	return resourcePostScanOutput(decision, result), true, nil
}

func (w *InstallWatcher) applyResourcePreScanAction(ctx context.Context, pe *enforce.PolicyEngine, decision audit.ResourceDecisionResult, evt InstallEvent, targetType string) {
	if pe == nil {
		return
	}
	reason := decision.Reason
	if reason == "" {
		reason = fmt.Sprintf("resource %s decision matched rule %d", decision.Phase, decision.RuleID)
	}
	switch decision.InstallAction {
	case "block":
		_ = pe.Block(targetType, evt.Name, reason)
		pe.SetSourcePath(targetType, evt.Name, evt.Path)
	case "allow":
		_ = pe.Allow(targetType, evt.Name, reason)
		pe.SetSourcePath(targetType, evt.Name, evt.Path)
	}
	if decision.FileAction == "quarantine" {
		_ = pe.Quarantine(targetType, evt.Name, reason)
	}
	if resourceRuntimeBlocks(decision.RuntimeAction) {
		_ = pe.Disable(targetType, evt.Name, reason)
	}
	if resourceDecisionBlocks(decision.Decision) || decision.FileAction == "quarantine" || resourceRuntimeBlocks(decision.RuntimeAction) {
		w.enforceBlock(ctx, evt)
	}
}

func (w *InstallWatcher) applyResourcePostScanAction(ctx context.Context, pe *enforce.PolicyEngine, out *policy.AdmissionOutput, evt InstallEvent, targetType string, result *scanner.ScanResult, scannerName string) {
	if pe == nil || out == nil {
		return
	}
	reason := strings.TrimSpace(out.Reason)
	if reason == "" {
		reason = fmt.Sprintf("resource post-scan decision matched for %s %q", targetType, evt.Name)
	}
	switch out.Verdict {
	case "clean":
		_ = w.logger.LogAction(string(audit.ActionInstallClean), evt.Path,
			fmt.Sprintf("type=%s scanner=%s source=db-post-scan", targetType, scannerName))
	case "allowed":
		_ = w.logger.LogAction(string(audit.ActionInstallAllowed), evt.Path,
			fmt.Sprintf("type=%s scanner=%s source=db-post-scan", targetType, scannerName))
	case "warning":
		_ = w.logger.LogAction(string(audit.ActionInstallWarning), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s source=db-post-scan", targetType, result.MaxSeverity(), scannerName))
	case "rejected", "blocked":
		_ = w.logger.LogAction(string(audit.ActionInstallRejected), evt.Path,
			fmt.Sprintf("type=%s severity=%s scanner=%s source=db-post-scan install_action=%s file_action=%s runtime_action=%s",
				targetType, result.MaxSeverity(), scannerName, out.InstallAction, out.FileAction, out.RuntimeAction))
	}

	installAction := coalesce(out.InstallAction, "none")
	fileAction := coalesce(out.FileAction, "none")
	runtimeAction := coalesce(out.RuntimeAction, "allow")
	switch installAction {
	case "block":
		_ = pe.Block(targetType, evt.Name, reason)
		pe.SetSourcePath(targetType, evt.Name, evt.Path)
	case "allow":
		_ = pe.Allow(targetType, evt.Name, reason)
		pe.SetSourcePath(targetType, evt.Name, evt.Path)
	}
	if fileAction == "quarantine" {
		_ = pe.Quarantine(targetType, evt.Name, reason)
	}
	if resourceRuntimeBlocks(runtimeAction) {
		_ = pe.Disable(targetType, evt.Name, reason)
	}
	if resourcePostVerdictBlocks(out.Verdict) && (installAction == "block" || fileAction == "quarantine" || resourceRuntimeBlocks(runtimeAction)) {
		w.enforceBlock(ctx, evt)
		_ = w.logger.LogActionWithEnforcement(string(audit.ActionWatcherBlock), evt.Name,
			fmt.Sprintf("type=%s reason=%s", targetType, reason),
			map[string]string{
				"source_path": evt.Path,
				"install":     installAction,
				"runtime":     runtimeAction,
				"file":        fileAction,
			})
	}
}

func resourceDecisionBlocks(decision string) bool {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "block", "reject", "rejected", "blocked":
		return true
	default:
		return false
	}
}

func resourceDecisionAllows(decision string) bool {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "allow", "allowed", "skip":
		return true
	default:
		return false
	}
}

func resourceRuntimeBlocks(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "disable":
		return true
	default:
		return false
	}
}

func resourcePostVerdictBlocks(verdict string) bool {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "blocked", "rejected":
		return true
	default:
		return false
	}
}

func resourcePostScanOutput(decision audit.ResourceDecisionResult, result *scanner.ScanResult) *policy.AdmissionOutput {
	verdict := "warning"
	switch strings.ToLower(strings.TrimSpace(decision.Decision)) {
	case "block", "reject", "rejected", "blocked":
		verdict = "rejected"
	case "allow", "clean", "ignore":
		if result == nil || len(result.Findings) == 0 {
			verdict = "clean"
		} else {
			verdict = "allowed"
		}
	case "alert", "review":
		verdict = "warning"
	}
	return &policy.AdmissionOutput{
		Verdict:       verdict,
		Reason:        decision.Reason,
		InstallAction: decision.InstallAction,
		FileAction:    decision.FileAction,
		RuntimeAction: decision.RuntimeAction,
	}
}

func (w *InstallWatcher) resourceRiskSummary(result *scanner.ScanResult) resourceRiskSummary {
	summary := resourceRiskSummary{RiskLevel: "clean", MaxSeverity: "INFO"}
	if result == nil {
		return summary
	}
	summary.MaxSeverity = string(result.MaxSeverity())
	if len(result.Findings) == 0 {
		return summary
	}

	bestRank := audit.RiskLevelRank(summary.RiskLevel)
	for i := range result.Findings {
		f := result.Findings[i]
		if strings.TrimSpace(f.Category) != "" {
			summary.FindingCategories = append(summary.FindingCategories, f.Category)
		}
		if strings.TrimSpace(f.Scanner) != "" {
			summary.FindingScanners = append(summary.FindingScanners, f.Scanner)
		}

		eval, err := audit.GovernanceRiskEvaluateResult{}, error(nil)
		if w != nil && w.store != nil {
			eval, err = w.store.EvaluateGovernanceRisk(audit.GovernanceRiskEvaluateInput{
				ResourceType: "",
				Severity:     string(f.Severity),
				RuleID:       firstNonEmptyString(f.RuleID, f.ID),
				Category:     f.Category,
				Tags:         strings.Join(f.Tags, ","),
				Title:        f.Title,
			})
		}
		if err != nil || (w == nil || w.store == nil) {
			// Compatibility fallback for older stores or evaluation failures:
			// keep the previous severity/category heuristic rather than hiding
			// findings when the configurable risk tables cannot be read.
			level := audit.ResourceRiskLevel(string(f.Severity))
			if rank := audit.RiskLevelRank(level); rank > bestRank {
				bestRank = rank
				summary.RiskLevel = level
			}
			if isMaliciousFinding(f) {
				summary.Malicious = true
			}
			continue
		}

		level := strings.ToLower(strings.TrimSpace(eval.RiskLevel))
		if level == "" {
			level = "clean"
		}
		if rank := audit.RiskLevelRank(level); rank > bestRank {
			bestRank = rank
			summary.RiskLevel = level
		}
		if resourceRiskMappingMarksMalicious(eval) {
			summary.Malicious = true
		}
		if eval.MatchedType == "default" && isMaliciousFinding(f) {
			// Compatibility fallback only: if no configurable risk mapping
			// matches this finding, retain the legacy malicious marker.
			summary.Malicious = true
		}
	}
	return summary
}

func resourceRiskMappingMarksMalicious(eval audit.GovernanceRiskEvaluateResult) bool {
	if eval.MatchedType != "rule_id_prefix" && eval.MatchedType != "category" {
		return false
	}
	return audit.RiskLevelRank(eval.RiskLevel) >= audit.RiskLevelRank("high")
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
