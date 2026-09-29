package gateway

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

type storageFileStatus struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Exists bool   `json:"exists"`
	Error  string `json:"error,omitempty"`
}

type storageSettingsResponse struct {
	DataDir          string            `json:"dataDir"`
	AuditDB          storageFileStatus `json:"auditDb"`
	JudgeBodiesDB    storageFileStatus `json:"judgeBodiesDb"`
	GatewayLog       storageFileStatus `json:"gatewayLog"`
	KnownStoredBytes int64             `json:"knownStoredBytes"`
	Note             string            `json:"note"`
}

type versionSettingsResponse struct {
	GatewayVersion string `json:"gatewayVersion"`
	SchemaVersion  int    `json:"schemaVersion"`
	ConfigVersion  uint64 `json:"configGeneration"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
}

type diagnosticCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type diagnosticReport struct {
	CapturedAt string                  `json:"capturedAt"`
	Checks     []diagnosticCheck       `json:"checks"`
	Versions   versionSettingsResponse `json:"versions"`
	Storage    struct {
		AuditBytes       int64 `json:"auditBytes"`
		JudgeBodiesBytes int64 `json:"judgeBodiesBytes"`
		GatewayLogBytes  int64 `json:"gatewayLogBytes"`
	} `json:"storage"`
}

func statStorageFile(path string) storageFileStatus {
	status := storageFileStatus{Path: path}
	if path == "" {
		status.Error = "path not configured"
		return status
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return status
	}
	if err != nil {
		status.Error = "file cannot be inspected"
		return status
	}
	if !info.Mode().IsRegular() {
		status.Error = "path is not a regular file"
		return status
	}
	status.Exists = true
	status.Bytes = info.Size()
	return status
}

func storageSettingsFromConfig(cfg *config.Config) storageSettingsResponse {
	result := storageSettingsResponse{
		DataDir:       cfg.DataDir,
		AuditDB:       statStorageFile(cfg.AuditDB),
		JudgeBodiesDB: statStorageFile(cfg.JudgeBodiesDB),
		GatewayLog:    statStorageFile(filepath.Join(cfg.DataDir, "gateway.jsonl")),
		Note:          "仅统计列出的三个文件；SQLite WAL、备份、隔离文件和其他日志未计入。当前版本不提供自动清理。",
	}
	result.KnownStoredBytes = result.AuditDB.Bytes + result.JudgeBodiesDB.Bytes + result.GatewayLog.Bytes
	return result
}

func currentVersionSettings() versionSettingsResponse {
	p := version.Current()
	return versionSettingsResponse{
		GatewayVersion: p.BinaryVersion,
		SchemaVersion:  p.SchemaVersion,
		ConfigVersion:  p.Generation,
		OS:             runtime.GOOS,
		Architecture:   runtime.GOARCH,
	}
}

func (a *APIServer) handleStorageSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not available"})
		return
	}
	a.writeJSON(w, http.StatusOK, storageSettingsFromConfig(cfg))
}

func (a *APIServer) handleVersionSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	a.writeJSON(w, http.StatusOK, currentVersionSettings())
}

func (a *APIServer) runDiagnostics() diagnosticReport {
	report := diagnosticReport{CapturedAt: time.Now().UTC().Format(time.RFC3339), Versions: currentVersionSettings(), Checks: []diagnosticCheck{}}
	cfg := a.runtimeConfigSnapshot()
	if cfg == nil {
		report.Checks = append(report.Checks, diagnosticCheck{"config", "fail", "配置不可用"})
		return report
	}
	if _, err := config.LoadFromFile(configFilePathForSnapshot(cfg)); err != nil {
		report.Checks = append(report.Checks, diagnosticCheck{"config", "fail", "配置文件无法加载或校验失败"})
	} else {
		report.Checks = append(report.Checks, diagnosticCheck{"config", "ok", "配置文件可加载"})
	}
	storage := storageSettingsFromConfig(cfg)
	report.Storage.AuditBytes = storage.AuditDB.Bytes
	report.Storage.JudgeBodiesBytes = storage.JudgeBodiesDB.Bytes
	report.Storage.GatewayLogBytes = storage.GatewayLog.Bytes
	if storage.AuditDB.Error != "" {
		report.Checks = append(report.Checks, diagnosticCheck{"audit_storage", "fail", storage.AuditDB.Error})
	} else if !storage.AuditDB.Exists {
		report.Checks = append(report.Checks, diagnosticCheck{"audit_storage", "warn", "审计数据库尚不存在"})
	} else {
		report.Checks = append(report.Checks, diagnosticCheck{"audit_storage", "ok", "审计数据库文件可读取"})
	}
	if a.store == nil {
		report.Checks = append(report.Checks, diagnosticCheck{"audit_schema", "warn", "审计数据库连接不可用"})
	} else if schema, err := a.store.SchemaVersion(); err != nil {
		report.Checks = append(report.Checks, diagnosticCheck{"audit_schema", "fail", "无法读取审计数据库版本"})
	} else {
		report.Checks = append(report.Checks, diagnosticCheck{"audit_schema", "ok", "数据库模式版本 " + fmt.Sprint(schema)})
	}
	if a.health != nil {
		snap := a.health.Snapshot()
		report.Checks = append(report.Checks, diagnosticCheck{"gateway", string(snap.Gateway.State), "Gateway 连接状态"})
		report.Checks = append(report.Checks, diagnosticCheck{"guardrail", string(snap.Guardrail.State), "Guardrail 状态"})
	}
	return report
}

func (a *APIServer) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	a.writeJSON(w, http.StatusOK, a.runDiagnostics())
}

func (a *APIServer) handleDiagnosticsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// Only the explicit summary schema is exported: no raw logs, event payloads,
	// usernames, filesystem paths, tokens, or environment variables.
	a.writeJSON(w, http.StatusOK, a.runDiagnostics())
}
