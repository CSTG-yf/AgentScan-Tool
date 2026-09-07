// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const desktopScanScheduleSettingKey = "desktop.scan_schedule"

type pageScanTaskSchedule struct {
	Enabled     bool `json:"enabled"`
	IntervalSec int  `json:"intervalSec"`
}

type pageScanScheduleSettings struct {
	Version           int                  `json:"version"`
	Environment       pageScanTaskSchedule `json:"environment"`
	AgentDiscovery    pageScanTaskSchedule `json:"agentDiscovery"`
	StaticAssets      pageScanTaskSchedule `json:"staticAssets"`
	BehaviorTrace     pageScanTaskSchedule `json:"behaviorTrace"`
	EventDetection    pageScanTaskSchedule `json:"eventDetection"`
	ProcessGuardAudit pageScanTaskSchedule `json:"processGuardAudit"`
	GatewayAudit      pageScanTaskSchedule `json:"gatewayAudit"`
	RangeStatus       pageScanTaskSchedule `json:"rangeStatus"`
}

type pageStaticResourceScanSettings struct {
	Version                int  `json:"version"`
	RealtimeEnabled        bool `json:"realtimeEnabled"`
	RescanEnabled          bool `json:"rescanEnabled"`
	DebounceMs             int  `json:"debounceMs"`
	SkillIntervalMin       int  `json:"skillIntervalMin"`
	PluginIntervalMin      int  `json:"pluginIntervalMin"`
	MCPIntervalMin         int  `json:"mcpIntervalMin"`
	PromptIntervalMin      int  `json:"promptIntervalMin"`
	CredentialIntervalMin  int  `json:"credentialIntervalMin"`
	EnvironmentIntervalMin int  `json:"environmentIntervalMin"`
}

func (a *APIServer) handleDesktopScanSchedule(w http.ResponseWriter, r *http.Request) {
	a.handlePageRefreshSettings(w, r)
}

func (a *APIServer) handleStaticResourceScanSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, pageStaticResourceScanSettingsFromConfig(a.runtimeConfigSnapshot()).normalize())
	case http.MethodPut:
		var request pageStaticResourceScanSettings
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		current := a.runtimeConfigSnapshot()
		if current == nil {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
			return
		}
		if status, authErr := guardrailConfigPatchAuthorization(r, current); authErr != "" {
			a.writeJSON(w, status, map[string]string{"error": authErr})
			return
		}
		response, err := a.applyStaticResourceScanSettings(r, request.normalize(), current)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, response)
	default:
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (a *APIServer) applyStaticResourceScanSettings(r *http.Request, settings pageStaticResourceScanSettings, current *config.Config) (map[string]any, error) {
	a.configWriteMu.Lock()
	defer a.configWriteMu.Unlock()

	// Re-read under the write lock so concurrent config mutations do not race.
	if latest := a.runtimeConfigSnapshot(); latest != nil {
		current = latest
	}
	configPath := configFilePathForSnapshot(current)
	original, err := captureConfigFileState(configPath)
	if err != nil {
		return nil, err
	}

	updates := staticResourceScanSettingUpdates(settings)
	if err := config.PatchYAMLFile(configPath, updates); err != nil {
		return nil, err
	}
	candidate, err := config.LoadFromFile(configPath)
	if err != nil {
		_ = restoreConfigFileState(configPath, original)
		return nil, fmt.Errorf("static resource scan settings produced invalid config: %w", err)
	}

	diff := diffConfigs(current, candidate)
	live := false
	if a.configReloader != nil {
		if err := a.configReloader(r.Context(), "static_resource_scan_settings_api"); err != nil {
			rollbackErr := restoreConfigFileState(configPath, original)
			if rollbackErr == nil {
				rollbackErr = a.configReloader(r.Context(), "static_resource_scan_settings_api_rollback")
			}
			if rollbackErr != nil {
				err = fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
			}
			return nil, err
		}
		live = true
	} else {
		a.cfgMu.Lock()
		a.scannerCfg = cloneConfig(candidate)
		a.cfgMu.Unlock()
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionConfigUpdate), configPath,
			"static resource scan settings updated via API changed="+strings.Join(diff.Changed, ","))
	}

	return map[string]any{
		"status":          "updated",
		"live":            live,
		"configPath":      configPath,
		"changed":         diff.Changed,
		"restartRequired": diff.RestartRequired,
		"settings":        pageStaticResourceScanSettingsFromConfig(candidate).normalize(),
	}, nil
}

func staticResourceScanSettingUpdates(settings pageStaticResourceScanSettings) map[string]any {
	settings = settings.normalize()
	return map[string]any{
		"watch.realtime_enabled":                settings.RealtimeEnabled,
		"watch.rescan_enabled":                  settings.RescanEnabled,
		"watch.debounce_ms":                     settings.DebounceMs,
		"watch.rescan_skill_interval_min":       settings.SkillIntervalMin,
		"watch.rescan_plugin_interval_min":      settings.PluginIntervalMin,
		"watch.rescan_mcp_interval_min":         settings.MCPIntervalMin,
		"watch.rescan_prompt_interval_min":      settings.PromptIntervalMin,
		"watch.rescan_credential_interval_min":  settings.CredentialIntervalMin,
		"watch.rescan_environment_interval_min": settings.EnvironmentIntervalMin,
		"watch.rescan_content_gated":            true,
	}
}

func defaultPageScanScheduleSettings() pageScanScheduleSettings {
	return pageScanScheduleSettings{
		Version:           1,
		Environment:       pageScanTaskSchedule{Enabled: true, IntervalSec: 10},
		AgentDiscovery:    pageScanTaskSchedule{Enabled: true, IntervalSec: 15},
		StaticAssets:      pageScanTaskSchedule{Enabled: true, IntervalSec: 10},
		BehaviorTrace:     pageScanTaskSchedule{Enabled: true, IntervalSec: 15},
		EventDetection:    pageScanTaskSchedule{Enabled: true, IntervalSec: 8},
		ProcessGuardAudit: pageScanTaskSchedule{Enabled: true, IntervalSec: 10},
		GatewayAudit:      pageScanTaskSchedule{Enabled: true, IntervalSec: 10},
		RangeStatus:       pageScanTaskSchedule{Enabled: true, IntervalSec: 30},
	}
}

func (s pageScanScheduleSettings) normalize() pageScanScheduleSettings {
	if s.Version == 0 {
		s = defaultPageScanScheduleSettings()
	}
	s.Version = 1
	s.Environment = s.Environment.normalize(10)
	s.AgentDiscovery = s.AgentDiscovery.normalize(15)
	s.StaticAssets = s.StaticAssets.normalize(10)
	s.BehaviorTrace = s.BehaviorTrace.normalize(15)
	s.EventDetection = s.EventDetection.normalize(8)
	s.ProcessGuardAudit = s.ProcessGuardAudit.normalize(10)
	s.GatewayAudit = s.GatewayAudit.normalize(10)
	s.RangeStatus = s.RangeStatus.normalize(30)
	return s
}

func (s pageScanTaskSchedule) normalize(defaultIntervalSec int) pageScanTaskSchedule {
	if s.IntervalSec <= 0 {
		s.IntervalSec = defaultIntervalSec
	}
	s.IntervalSec = clampInt(s.IntervalSec, 3, 3600)
	return s
}

func pageStaticResourceScanSettingsFromConfig(cfg *config.Config) pageStaticResourceScanSettings {
	if cfg == nil {
		return defaultPageStaticResourceScanSettings()
	}
	settings := defaultPageStaticResourceScanSettings()
	settings.RealtimeEnabled = cfg.Watch.RealtimeEnabled
	settings.RescanEnabled = cfg.Watch.RescanEnabled
	settings.DebounceMs = cfg.Watch.DebounceMs
	settings.SkillIntervalMin = firstPositiveInt(cfg.Watch.RescanSkillIntervalMin, settings.SkillIntervalMin)
	settings.PluginIntervalMin = firstPositiveInt(cfg.Watch.RescanPluginIntervalMin, settings.PluginIntervalMin)
	settings.MCPIntervalMin = firstPositiveInt(cfg.Watch.RescanMCPIntervalMin, settings.MCPIntervalMin)
	settings.PromptIntervalMin = firstPositiveInt(cfg.Watch.RescanPromptIntervalMin, settings.PromptIntervalMin)
	settings.CredentialIntervalMin = firstPositiveInt(cfg.Watch.RescanCredentialIntervalMin, settings.CredentialIntervalMin)
	settings.EnvironmentIntervalMin = firstPositiveInt(cfg.Watch.RescanEnvironmentIntervalMin, settings.EnvironmentIntervalMin)
	if fallback := cfg.Watch.RescanIntervalMin; fallback > 0 {
		settings.SkillIntervalMin = firstPositiveInt(cfg.Watch.RescanSkillIntervalMin, fallback)
		settings.PluginIntervalMin = firstPositiveInt(cfg.Watch.RescanPluginIntervalMin, fallback)
		settings.MCPIntervalMin = firstPositiveInt(cfg.Watch.RescanMCPIntervalMin, fallback)
		settings.PromptIntervalMin = firstPositiveInt(cfg.Watch.RescanPromptIntervalMin, fallback)
		settings.CredentialIntervalMin = firstPositiveInt(cfg.Watch.RescanCredentialIntervalMin, fallback)
		settings.EnvironmentIntervalMin = firstPositiveInt(cfg.Watch.RescanEnvironmentIntervalMin, fallback)
	}
	return settings.normalize()
}

func defaultPageStaticResourceScanSettings() pageStaticResourceScanSettings {
	return pageStaticResourceScanSettings{
		Version:                1,
		RealtimeEnabled:        true,
		RescanEnabled:          true,
		DebounceMs:             500,
		SkillIntervalMin:       15,
		PluginIntervalMin:      30,
		MCPIntervalMin:         10,
		PromptIntervalMin:      15,
		CredentialIntervalMin:  5,
		EnvironmentIntervalMin: 30,
	}
}

func (s pageStaticResourceScanSettings) normalize() pageStaticResourceScanSettings {
	if s.Version == 0 {
		defaults := defaultPageStaticResourceScanSettings()
		defaults.RealtimeEnabled = s.RealtimeEnabled
		defaults.RescanEnabled = s.RescanEnabled
		s = defaults
	}
	s.Version = 1
	s.DebounceMs = clampInt(firstPositiveInt(s.DebounceMs, 500), 100, 10000)
	s.SkillIntervalMin = clampInt(firstPositiveInt(s.SkillIntervalMin, 15), 1, 1440)
	s.PluginIntervalMin = clampInt(firstPositiveInt(s.PluginIntervalMin, 30), 1, 1440)
	s.MCPIntervalMin = clampInt(firstPositiveInt(s.MCPIntervalMin, 10), 1, 1440)
	s.PromptIntervalMin = clampInt(firstPositiveInt(s.PromptIntervalMin, 15), 1, 1440)
	s.CredentialIntervalMin = clampInt(firstPositiveInt(s.CredentialIntervalMin, 5), 1, 1440)
	s.EnvironmentIntervalMin = clampInt(firstPositiveInt(s.EnvironmentIntervalMin, 30), 1, 1440)
	return s
}

func firstPositiveInt(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
