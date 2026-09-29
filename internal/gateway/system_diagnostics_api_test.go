package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestStorageSettingsReportRealFilesWithoutClaimingFullUsage(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.AuditDB = filepath.Join(cfg.DataDir, "audit.db")
	cfg.JudgeBodiesDB = filepath.Join(cfg.DataDir, "judge.db")
	if err := os.WriteFile(cfg.AuditDB, []byte("audit"), 0o600); err != nil {
		t.Fatal(err)
	}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	rec := httptest.NewRecorder()
	api.handleStorageSettings(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/storage", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("storage status=%d body=%s", rec.Code, rec.Body.String())
	}
	var data storageSettingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if !data.AuditDB.Exists || data.AuditDB.Bytes != 5 || data.JudgeBodiesDB.Exists || data.KnownStoredBytes != 5 {
		t.Fatalf("storage settings are not actual file sizes: %+v", data)
	}
	if !strings.Contains(data.Note, "未计入") {
		t.Fatalf("storage summary has no incompleteness disclosure: %+v", data)
	}
}

func TestDiagnosticsExportExcludesSensitivePathsAndTokens(t *testing.T) {
	api, path := testSystemSettingsAPI(t)
	rec := httptest.NewRecorder()
	api.handleDiagnosticsExport(rec, httptest.NewRequest(http.MethodPost, "/api/v1/diagnostics/export", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, forbidden := range []string{path, "settings-test-token", "dataDir", "auditDb"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("export contains sensitive field %q: %s", forbidden, rec.Body.String())
		}
	}
	var report diagnosticReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil || report.CapturedAt == "" || len(report.Checks) == 0 {
		t.Fatalf("invalid diagnostic report: %s, err=%v", rec.Body.String(), err)
	}
}

func TestVersionSettingsReportGatewayBuildAndPlatform(t *testing.T) {
	cfg := config.DefaultConfig()
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil, cfg)
	rec := httptest.NewRecorder()
	api.handleVersionSettings(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/versions", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("version status=%d body=%s", rec.Code, rec.Body.String())
	}
	var version versionSettingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &version); err != nil {
		t.Fatal(err)
	}
	if version.GatewayVersion == "" || version.OS == "" || version.Architecture == "" || version.SchemaVersion < 1 {
		t.Fatalf("version settings are incomplete: %+v", version)
	}
}
