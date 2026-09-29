package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func testSystemSettingsAPI(t *testing.T) (*APIServer, string) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ConfigFilePath = filepath.Join(cfg.DataDir, "config.yaml")
	cfg.Gateway.Token = "settings-test-token"
	cfg.Gateway.ConfigReload.Mode = "hot"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	bindTestConfigRuntime(t, api)
	return api, cfg.ConfigFilePath
}

func patchSystemSettings(t *testing.T, api *APIServer, path, body string, authorized bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(body))
	if authorized {
		req.Header.Set("Authorization", "Bearer settings-test-token")
	}
	rec := httptest.NewRecorder()
	if path == "/api/v1/settings/privacy" {
		api.handlePrivacySettings(rec, req)
	} else {
		api.handleNotificationSettings(rec, req)
	}
	return rec
}

func TestPrivacySettingsPersistAndReportRestart(t *testing.T) {
	api, path := testSystemSettingsAPI(t)
	denied := patchSystemSettings(t, api, "/api/v1/settings/privacy", `{"redactionEnabled":false}`, false)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("unauthorized patch status=%d", denied.Code)
	}
	rec := patchSystemSettings(t, api, "/api/v1/settings/privacy", `{"redactionEnabled":false,"retainJudgeBodies":false}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"restartRequired"`) || !strings.Contains(rec.Body.String(), `"privacy"`) {
		t.Fatalf("privacy patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	loaded, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Privacy.DisableRedaction || loaded.Guardrail.RetainJudgeBodies {
		t.Fatalf("privacy settings not persisted: privacy=%+v retention=%t", loaded.Privacy, loaded.Guardrail.RetainJudgeBodies)
	}
	get := httptest.NewRecorder()
	api.handlePrivacySettings(get, httptest.NewRequest(http.MethodGet, "/api/v1/settings/privacy", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"redactionEnabled":false`) {
		t.Fatalf("privacy GET status=%d body=%s", get.Code, get.Body.String())
	}
}

func TestNotificationSettingsValidatePersistAndHotReload(t *testing.T) {
	api, path := testSystemSettingsAPI(t)
	invalid := patchSystemSettings(t, api, "/api/v1/settings/notifications", `{"dedupSeconds":0}`, true)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid dedup status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	rec := patchSystemSettings(t, api, "/api/v1/settings/notifications", `{"enabled":true,"hook":false,"dedupSeconds":45,"maxPerMinute":30}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"live":true`) {
		t.Fatalf("notification patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	loaded, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Notifications.Enabled || loaded.Notifications.Sources.Hook || loaded.Notifications.DedupWindow != 45*time.Second || loaded.Notifications.MaxPerMinute != 30 {
		t.Fatalf("notification settings not persisted: %+v", loaded.Notifications)
	}
	get := httptest.NewRecorder()
	api.handleNotificationSettings(get, httptest.NewRequest(http.MethodGet, "/api/v1/settings/notifications", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"dedupSeconds":45`) {
		t.Fatalf("notification GET status=%d body=%s", get.Code, get.Body.String())
	}
}

func TestPrivacySettingsRollbackWhenLiveReloadFails(t *testing.T) {
	api, path := testSystemSettingsAPI(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	api.configReloader = func(context.Context, string) error { return errors.New("reload unavailable") }
	rec := patchSystemSettings(t, api, "/api/v1/settings/privacy", `{"redactionEnabled":false}`, true)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("failed reload status=%d body=%s", rec.Code, rec.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("failed reload left modified config: before=%q after=%q", before, after)
	}
}
