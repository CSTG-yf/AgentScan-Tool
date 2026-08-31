// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ScanResourceByID re-runs the admission + scan pipeline for one
// static_resources row on demand (POST /api/v1/static-resources/{id}/scan).
// The row's stored lineage (agent, rule, profile) is reused so the scan
// lands on the same resource identity the periodic pipeline produced.
// Returns the admission verdict.
func (w *InstallWatcher) ScanResourceByID(ctx context.Context, resourceID string) (AdmissionResult, error) {
	if w == nil || w.store == nil {
		return AdmissionResult{}, fmt.Errorf("watcher: store unavailable")
	}
	target, agentID, resourceType, ruleID, profileID, agentTypeID, preScanProfileID, postScanProfileID, ok, err := w.store.GetStaticResourceTargetPath(resourceID)
	if err != nil {
		return AdmissionResult{}, err
	}
	if !ok {
		return AdmissionResult{}, fmt.Errorf("watcher: resource %q not found", resourceID)
	}
	if isVirtualResourceTarget(target) {
		return AdmissionResult{}, fmt.Errorf("watcher: resource %q has no on-disk target to scan", resourceID)
	}

	evt := InstallEvent{
		Type:              InstallType(resourceType),
		Name:              filepath.Base(target),
		Path:              target,
		AgentID:           agentID,
		AgentTypeID:       agentTypeID,
		ResourceID:        resourceID,
		ResourceRuleID:    ruleID,
		ScanProfileID:     profileID,
		PreScanProfileID:  preScanProfileID,
		PostScanProfileID: postScanProfileID,
		Connector:         watcherConnectorName(w.cfg),
		Timestamp:         time.Now().UTC(),
	}
	res := w.runAdmission(ctx, evt)
	return res, nil
}

// RescanAgentResources re-scans every active resource of one agent (or all
// agents when agentID is empty) on demand (POST
// /api/v1/static-resources/rescan). The scan runs synchronously — callers
// that need fire-and-forget semantics wrap it in a goroutine.
func (w *InstallWatcher) RescanAgentResources(ctx context.Context, agentID string) (scanned int, err error) {
	if w == nil || w.store == nil {
		return 0, fmt.Errorf("watcher: store unavailable")
	}
	var ids []string
	if agentID == "" {
		summaries, err := w.store.ListAgentResourceSummaries()
		if err != nil {
			return 0, err
		}
		for _, s := range summaries {
			agentIDs, err := w.store.ListAgentResourceIDs(s.AgentID)
			if err != nil {
				return scanned, err
			}
			ids = append(ids, agentIDs...)
		}
	} else {
		ids, err = w.store.ListAgentResourceIDs(agentID)
		if err != nil {
			return 0, err
		}
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return scanned, ctx.Err()
		}
		if _, err := w.ScanResourceByID(ctx, id); err != nil {
			// One bad resource (missing on disk, virtual target) must not
			// abort the rest of the sweep.
			fmt.Fprintf(os.Stderr, "[watch] on-demand scan %s: %v\n", id, err)
			continue
		}
		scanned++
	}
	return scanned, nil
}

// isVirtualResourceTarget reports whether the stored target is a synthetic
// identifier (e.g. environment://process) rather than a filesystem path.
// Virtual targets have a URI scheme ("xxx://...") and cannot be scanned.
func isVirtualResourceTarget(target string) bool {
	idx := strings.Index(target, "://")
	if idx <= 0 {
		return false
	}
	// A Windows drive path ("C:\...") never contains "://" — a real scheme
	// prefix is alphanumeric only.
	for i := 0; i < idx; i++ {
		c := target[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '+' || c == '.') {
			return false
		}
	}
	return true
}
