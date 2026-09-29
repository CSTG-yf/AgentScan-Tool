package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

type privacySettingsResponse struct {
	RedactionEnabled  bool `json:"redactionEnabled"`
	RetainJudgeBodies bool `json:"retainJudgeBodies"`
}

type privacySettingsPatch struct {
	RedactionEnabled  *bool `json:"redactionEnabled"`
	RetainJudgeBodies *bool `json:"retainJudgeBodies"`
}

type notificationSettingsResponse struct {
	Enabled         bool `json:"enabled"`
	BlockEnforced   bool `json:"blockEnforced"`
	BlockWouldBlock bool `json:"blockWouldBlock"`
	HITLApproval    bool `json:"hitlApproval"`
	Hook            bool `json:"hook"`
	Guardrail       bool `json:"guardrail"`
	AssetPolicy     bool `json:"assetPolicy"`
	DedupSeconds    int  `json:"dedupSeconds"`
	MaxPerMinute    int  `json:"maxPerMinute"`
}

type notificationSettingsPatch struct {
	Enabled         *bool `json:"enabled"`
	BlockEnforced   *bool `json:"blockEnforced"`
	BlockWouldBlock *bool `json:"blockWouldBlock"`
	HITLApproval    *bool `json:"hitlApproval"`
	Hook            *bool `json:"hook"`
	Guardrail       *bool `json:"guardrail"`
	AssetPolicy     *bool `json:"assetPolicy"`
	DedupSeconds    *int  `json:"dedupSeconds"`
	MaxPerMinute    *int  `json:"maxPerMinute"`
}

func privacySettingsFromConfig(cfg *config.Config) privacySettingsResponse {
	return privacySettingsResponse{
		RedactionEnabled:  !cfg.Privacy.DisableRedaction,
		RetainJudgeBodies: cfg.Guardrail.RetainJudgeBodies,
	}
}

func notificationSettingsFromConfig(cfg *config.Config) notificationSettingsResponse {
	n := cfg.Notifications
	return notificationSettingsResponse{
		Enabled: n.Enabled, BlockEnforced: n.BlockEnforced,
		BlockWouldBlock: n.BlockWouldBlock, HITLApproval: n.HITLApproval,
		Hook: n.Sources.Hook, Guardrail: n.Sources.Guardrail,
		AssetPolicy:  n.Sources.AssetPolicy,
		DedupSeconds: int(n.EffectiveDedupWindow() / time.Second),
		MaxPerMinute: n.EffectiveMaxPerMinute(),
	}
}

func (a *APIServer) handlePrivacySettings(w http.ResponseWriter, r *http.Request) {
	current := a.runtimeConfigSnapshot()
	if current == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
		return
	}
	if r.Method == http.MethodGet {
		a.writeJSON(w, http.StatusOK, privacySettingsFromConfig(current))
		return
	}
	if r.Method != http.MethodPatch {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if status, authErr := guardrailConfigPatchAuthorization(r, current); authErr != "" {
		a.writeJSON(w, status, map[string]string{"error": authErr})
		return
	}
	var patch privacySettingsPatch
	if err := decodeSystemSettingsPatch(w, r, &patch); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	updates := map[string]any{}
	if patch.RedactionEnabled != nil {
		updates["privacy.disable_redaction"] = !*patch.RedactionEnabled
	}
	if patch.RetainJudgeBodies != nil {
		updates["guardrail.retain_judge_bodies"] = *patch.RetainJudgeBodies
	}
	if len(updates) == 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no privacy settings supplied"})
		return
	}
	a.applySystemSettingsPatch(w, r, current, updates, "privacy", func(cfg *config.Config) any { return privacySettingsFromConfig(cfg) })
}

func (a *APIServer) handleNotificationSettings(w http.ResponseWriter, r *http.Request) {
	current := a.runtimeConfigSnapshot()
	if current == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
		return
	}
	if r.Method == http.MethodGet {
		a.writeJSON(w, http.StatusOK, notificationSettingsFromConfig(current))
		return
	}
	if r.Method != http.MethodPatch {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if status, authErr := guardrailConfigPatchAuthorization(r, current); authErr != "" {
		a.writeJSON(w, status, map[string]string{"error": authErr})
		return
	}
	var patch notificationSettingsPatch
	if err := decodeSystemSettingsPatch(w, r, &patch); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	updates := map[string]any{}
	for _, field := range []struct {
		key   string
		value *bool
	}{
		{"notifications.enabled", patch.Enabled},
		{"notifications.block_enforced", patch.BlockEnforced},
		{"notifications.block_would_block", patch.BlockWouldBlock},
		{"notifications.hitl_approval", patch.HITLApproval},
		{"notifications.sources.hook", patch.Hook},
		{"notifications.sources.guardrail", patch.Guardrail},
		{"notifications.sources.asset_policy", patch.AssetPolicy},
	} {
		if field.value != nil {
			updates[field.key] = *field.value
		}
	}
	if patch.DedupSeconds != nil {
		if *patch.DedupSeconds < 1 || *patch.DedupSeconds > 3600 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dedupSeconds must be between 1 and 3600"})
			return
		}
		updates["notifications.dedup_window"] = fmt.Sprintf("%ds", *patch.DedupSeconds)
	}
	if patch.MaxPerMinute != nil {
		if *patch.MaxPerMinute < 1 || *patch.MaxPerMinute > 600 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "maxPerMinute must be between 1 and 600"})
			return
		}
		updates["notifications.max_per_minute"] = *patch.MaxPerMinute
	}
	if len(updates) == 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no notification settings supplied"})
		return
	}
	a.applySystemSettingsPatch(w, r, current, updates, "notifications", func(cfg *config.Config) any { return notificationSettingsFromConfig(cfg) })
}

func decodeSystemSettingsPatch(w http.ResponseWriter, r *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid settings JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return fmt.Errorf("settings JSON must contain exactly one object")
	}
	return nil
}

func (a *APIServer) applySystemSettingsPatch(w http.ResponseWriter, r *http.Request, current *config.Config, updates map[string]any, section string, project func(*config.Config) any) {
	a.configWriteMu.Lock()
	defer a.configWriteMu.Unlock()
	if latest := a.runtimeConfigSnapshot(); latest != nil {
		current = latest
	}
	if status, authErr := guardrailConfigPatchAuthorization(r, current); authErr != "" {
		a.writeJSON(w, status, map[string]string{"error": authErr})
		return
	}
	path := configFilePathForSnapshot(current)
	original, err := captureConfigFileState(path)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := config.PatchYAMLFile(path, updates); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	candidate, err := config.LoadFromFile(path)
	if err != nil {
		_ = restoreConfigFileState(path, original)
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "settings produced invalid configuration: " + err.Error()})
		return
	}
	diff := diffConfigs(current, candidate)
	live := false
	if a.configReloader != nil {
		if err := a.configReloader(r.Context(), "desktop_"+section+"_settings"); err != nil {
			rollbackErr := restoreConfigFileState(path, original)
			if rollbackErr == nil {
				rollbackErr = a.configReloader(r.Context(), "desktop_"+section+"_settings_rollback")
			}
			if rollbackErr != nil {
				err = fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
			}
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		live = len(diff.RestartRequired) == 0
	} else {
		a.cfgMu.Lock()
		a.scannerCfg = cloneConfig(candidate)
		a.cfgMu.Unlock()
		if len(diff.Changed) > 0 {
			diff.RestartRequired = sortedUniqueStrings(append(diff.RestartRequired, diff.Changed...))
		}
	}
	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionConfigUpdate), path,
			"desktop "+section+" settings updated changed="+strings.Join(diff.Changed, ","))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"settings": project(candidate), "changed": diff.Changed,
		"restartRequired": diff.RestartRequired, "live": live,
	})
}
