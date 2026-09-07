// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const pageRefreshSettingsKey = "desktop.page_refresh_settings"

func (a *APIServer) handlePageRefreshSettings(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store is not attached"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		settings := defaultPageScanScheduleSettings()
		ok, err := a.store.LoadJSONSetting(pageRefreshSettingsKey, &settings)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if !ok {
			// One-time compatibility read. Older desktop releases stored page
			// refresh intervals under the misleading scan-schedule key.
			if legacy, legacyErr := a.store.LoadJSONSetting(desktopScanScheduleSettingKey, &settings); legacyErr != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": legacyErr.Error()})
				return
			} else if !legacy {
				settings = defaultPageScanScheduleSettings()
			}
		}
		a.writeJSON(w, http.StatusOK, settings.normalize())
	case http.MethodPut:
		var settings pageScanScheduleSettings
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&settings); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid page refresh settings: " + err.Error()})
			return
		}
		settings = settings.normalize()
		if err := a.store.SaveJSONSetting(pageRefreshSettingsKey, settings); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if a.logger != nil {
			_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionConfigUpdate), pageRefreshSettingsKey, "page refresh settings updated via API")
		}
		a.writeJSON(w, http.StatusOK, settings)
	default:
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (a *APIServer) handleScanSchedules(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/scan-schedules"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		items, err := a.store.ListScanSchedules()
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "source": "sqlite"})
		return
	}
	if strings.ContainsAny(rest, `/\\`) || !audit.IsScanScheduleTaskType(rest) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPut {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	canonicalTask := audit.NormalizeScanTaskType(rest)
	var request struct {
		Enabled     bool           `json:"enabled"`
		IntervalSec int            `json:"interval_sec"`
		Mode        string         `json:"mode"`
		Scope       map[string]any `json:"scope"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scan schedule: " + err.Error()})
		return
	}
	if request.Enabled && (canonicalTask == "behavior_trace" || canonicalTask == "environment") {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": canonicalTask + " is event-driven and cannot be enabled as a scan schedule"})
		return
	}
	item, err := a.store.SaveScanSchedule(audit.ScanSchedule{
		TaskType: canonicalTask, Enabled: request.Enabled, IntervalSec: request.IntervalSec,
		Mode: request.Mode, Scope: request.Scope, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), UpdatedBy: "desktop",
	})
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionConfigUpdate), "scan_schedule:"+item.TaskType, "scan schedule updated via API")
	}
	a.writeJSON(w, http.StatusOK, item)
}
