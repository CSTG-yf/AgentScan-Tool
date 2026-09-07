// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Opt-in manual UI review against a temporary database. Start Vite on 1420,
// then RUN_RUNTIME_SETTINGS_UI_REVIEW=1 go test ./internal/gateway
// -run '^TestRuntimeSettingsUIReviewServer$' -v -count=1 -timeout 31m.
// No production service, database, or host enforcement is exposed; review
// jobs operate only on the temporary fixture data.
func TestRuntimeSettingsUIReviewServer(t *testing.T) {
	if os.Getenv("RUN_RUNTIME_SETTINGS_UI_REVIEW") != "1" {
		t.Skip("manual browser review only")
	}
	reviewDuration := 30 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("RUNTIME_SETTINGS_UI_REVIEW_DURATION")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			t.Fatalf("invalid RUNTIME_SETTINGS_UI_REVIEW_DURATION %q", raw)
		}
		reviewDuration = parsed
	}
	a, typeA, typeB := newRuntimeSettingsAPI(t)
	reviewConfig := config.DefaultConfig()
	reviewConfig.DataDir = t.TempDir()
	reviewConfig.ConfigFilePath = reviewConfig.DataDir + "/config.yaml"
	a.scannerCfg = reviewConfig
	a.SetStaticScanTrigger(func(string) error { return nil }, func(string) error { time.Sleep(150 * time.Millisecond); return nil })
	for i := 0; i < 27; i++ {
		typeID := typeA
		if i >= 24 {
			typeID = typeB
		}
		agent, err := a.store.EnsureAgent(audit.AgentIdentityInput{AgentID: fmt.Sprintf("ui-agent-%d", typeID), AgentTypeID: typeID, AgentName: fmt.Sprintf("Review Agent %d", typeID)})
		if err != nil {
			t.Fatal(err)
		}
		event, err := a.store.RecordRuntimeEvent(audit.RuntimeEventInput{CanonicalAgentID: agent.ID, EventType: "tool.pre_call", EventSource: audit.RuntimeSourceAgentHook, ToolName: "review-tool", Target: "review-only-target"})
		if err != nil {
			t.Fatal(err)
		}
		severity, category := "HIGH", "attack"
		if i%3 == 0 {
			severity, category = "vendor-risk", "suspicious"
		}
		detection, err := a.store.RecordRuntimeDetection(audit.RuntimeDetectionInput{AgentID: agent.ID, AgentName: fmt.Sprintf("Review Agent %d", typeID), DetectionType: fmt.Sprintf("review_%d", i), RuleID: fmt.Sprintf("review_rule_%d", i), Severity: severity, Category: category, Confidence: .9, Title: fmt.Sprintf("界面验证事件 %02d", i), SessionID: "review-session", TraceID: fmt.Sprintf("review-trace-%d", i), Evidence: []audit.DetectionEvidenceInput{{EventID: event, Role: "trigger", Sequence: 1}}, SeenAt: time.Now().UTC().Add(time.Duration(i) * time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		activeDetectionEngine().Policy().ProcessDetection(detection, nil)
		decisions, _, err := a.store.ListRuntimeDecisions(audit.RuntimeDecisionFilter{DetectionID: detection.DetectionID, Limit: 1})
		if err != nil || len(decisions) != 1 {
			t.Fatalf("review decision: %v, %d rows", err, len(decisions))
		}
		// Explicit presentation fixtures; these single events do not claim to
		// prove the correlation engine's multi-event chain-building behavior.
		status := audit.AttackChainStatusActive
		if i%4 == 0 {
			status = audit.AttackChainStatusContained
		}
		if _, err := a.store.UpsertRuntimeAttackChain(audit.RuntimeAttackChain{
			AgentID: agent.ID, AgentName: detection.AgentName, SessionID: detection.SessionID, TraceID: detection.TraceID,
			AttackType: detection.DetectionType, Severity: severity, Status: status,
			StartTime: detection.FirstSeenAt, EndTime: detection.LastSeenAt,
			DetectionID: detection.DetectionID, DecisionID: decisions[0].DecisionID, BuilderVersion: "ui-review-fixture",
		}, []audit.AttackChainEventLink{{EventID: event, Sequence: 1, Relation: "tool_call"}}); err != nil {
			t.Fatal(err)
		}
	}
	vite, _ := url.Parse("http://127.0.0.1:1420")
	proxy := httputil.NewSingleHostReverseProxy(vite)
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.URL.Path != "/" {
			return nil
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return err
		}
		body = bytes.ReplaceAll(body, []byte("/src/main.tsx"), []byte("/tests/runtime-settings-review.tsx"))
		response.Body = io.NopCloser(bytes.NewReader(body))
		response.ContentLength = int64(len(body))
		response.Header.Del("Content-Length")
		return nil
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-Review-Fixture") != "runtime-settings" {
				http.Error(w, "review header required", 403)
				return
			}
			if r.URL.Path == runtimeSettingsPrefix || strings.HasPrefix(r.URL.Path, runtimeSettingsPrefix+"/") {
				a.handleRuntimeDetectionSettingsAPI(w, r)
			} else if strings.HasPrefix(r.URL.Path, "/api/v1/jobs") {
				a.handleJobsAPI(w, r)
			} else if strings.HasPrefix(r.URL.Path, "/api/v1/scan-schedules") {
				a.handleScanSchedules(w, r)
			} else if r.URL.Path == "/api/v1/page-refresh-settings" {
				a.handlePageRefreshSettings(w, r)
			} else if r.URL.Path == "/api/v1/static-resource-scan-settings" {
				a.handleStaticResourceScanSettings(w, r)
			} else if r.Method == http.MethodGet {
				switch {
				case strings.HasPrefix(r.URL.Path, "/api/v1/attack-chains"):
					a.handleAttackChains(w, r)
				case strings.HasPrefix(r.URL.Path, "/api/v1/runtime-detections"):
					a.handleRuntimeDetections(w, r)
				case strings.HasPrefix(r.URL.Path, "/api/v1/runtime-decisions"):
					a.handleRuntimeDecisions(w, r)
				case r.URL.Path == "/api/v1/runtime-security/mode":
					a.handleRuntimeSecurityMode(w, r)
				case r.URL.Path == "/api/v1/runtime-security/summary":
					a.handleRuntimeSecuritySummary(w, r)
				case r.URL.Path == "/api/v1/agents":
					a.handleAgentsAPI(w, r)
				default:
					http.NotFound(w, r)
				}
			} else {
				http.NotFound(w, r)
			}
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	defer server.CloseClientConnections()
	t.Logf("Temporary runtime settings review: %s", server.URL)
	timer := time.NewTimer(reviewDuration)
	defer timer.Stop()
	<-timer.C
}
