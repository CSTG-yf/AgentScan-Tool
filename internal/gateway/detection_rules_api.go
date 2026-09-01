// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/detection"
)

type detectionRuleDescriptor struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// handleDetectionRules exposes the active, agent-agnostic rule vocabulary so
// operators can explain a Detection and choose when a replay is warranted.
func (a *APIServer) handleDetectionRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	engine := activeDetectionEngine()
	if engine == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "detection engine unavailable"})
		return
	}
	rules := engine.Rules()
	items := make([]detectionRuleDescriptor, 0, len(rules))
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		items = append(items, detectionRuleDescriptor{ID: rule.ID(), Name: rule.Name(), Enabled: true})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"version":     detection.RuleVersion,
		"items":       items,
		"rules":       items,
		"count":       len(items),
		"source":      "detection_engine",
		"captured_at": nowRFC3339(),
	})
}
