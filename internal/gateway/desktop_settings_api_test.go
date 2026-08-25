// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestDesktopScanSchedulePersistsInAuditStore(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, config.DefaultConfig())

	body := bytes.NewBufferString(`{"version":1,"environment":{"enabled":true,"intervalSec":45},"agentDiscovery":{"enabled":true,"intervalSec":9},"staticAssets":{"enabled":true,"intervalSec":300},"behaviorTrace":{"enabled":true,"intervalSec":5},"eventDetection":{"enabled":true,"intervalSec":15},"processGuardAudit":{"enabled":true,"intervalSec":10},"gatewayAudit":{"enabled":true,"intervalSec":10},"rangeStatus":{"enabled":true,"intervalSec":30}}`)
	put := httptest.NewRequest(http.MethodPut, "/api/v1/desktop-scan-schedule", body)
	rec := httptest.NewRecorder()
	api.handleDesktopScanSchedule(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/desktop-scan-schedule", nil)
	rec = httptest.NewRecorder()
	api.handleDesktopScanSchedule(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got pageScanScheduleSettings
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Environment.IntervalSec != 45 || got.AgentDiscovery.IntervalSec != 9 {
		t.Fatalf("scan schedule = %+v, want persisted intervals", got)
	}
}

func TestStaticResourceScanSettingsPatchesGoConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ConfigFilePath = filepath.Join(cfg.DataDir, "config.yaml")
	cfg.Gateway.Token = "test-token"
	cfg.Gateway.ConfigReload.Mode = "hot"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	bindTestConfigRuntime(t, api)

	body := bytes.NewBufferString(`{"version":1,"realtimeEnabled":true,"rescanEnabled":true,"debounceMs":750,"skillIntervalMin":11,"pluginIntervalMin":22,"mcpIntervalMin":7,"promptIntervalMin":13,"credentialIntervalMin":3,"environmentIntervalMin":31}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/static-resource-scan-settings", body)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	api.handleStaticResourceScanSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}
	text := rec.Body.String()
	for _, want := range []string{`"skillIntervalMin":11`, `"credentialIntervalMin":3`, `"live":true`} {
		if !strings.Contains(text, want) {
			t.Fatalf("response missing %s: %s", want, text)
		}
	}

	loaded, err := config.LoadFromFile(cfg.ConfigFilePath)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if loaded.Watch.RescanSkillIntervalMin != 11 || loaded.Watch.RescanCredentialIntervalMin != 3 {
		t.Fatalf("watch config = %+v, want patched intervals", loaded.Watch)
	}
}
