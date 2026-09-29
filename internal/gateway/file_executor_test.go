package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/detection"
)

func TestRuntimeFileExecutorBlocksNextControlledRead(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	api.scannerCfg.Guardrail.Connector = "codex"
	t.Setenv("DEFENSECLAW_FILE_GUARD_POLICY", filepath.Join(t.TempDir(), "absent-policy.json"))
	path := filepath.Join(t.TempDir(), "protected.txt")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	finding, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "configured_blacklist", Attributes: map[string]any{"blacklist_target_type": "path"},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]interface{}{"file_path": path}
	digest := fileReadDigestFromInput("Read", filepath.Dir(path), input)
	if digest == "" {
		t.Fatal("controlled read had no file digest")
	}
	args, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	SetRuntimeEventStore(store)
	t.Cleanup(func() { SetRuntimeEventStore(nil) })
	api.recordHookRuntimeEvent(context.Background(), agentHookRequest{
		ConnectorName: "codex", HookEventName: "PreToolUse", ToolName: "Read",
		CWD: filepath.Dir(path), ToolArgs: args,
	}, agentHookResponse{Action: "allow", Mode: "action"})
	rows, err := store.ListRuntimeEvents(audit.RuntimeEventFilter{EventSource: audit.RuntimeSourceAgentHook, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Attributes["file_read_path_sha256"] != digest {
		t.Fatalf("recorded hook file identity = %+v", rows)
	}
	decision := audit.RuntimeDecision{DecisionID: "D-file-hook", DetectionID: finding.DetectionID, EnforcementPoint: audit.EnforcementPointFile}
	evidence := []audit.DetectionEvidence{{Event: rows[0]}}
	status, _, _ := detection.NewPolicyEngine(store).ExecuteNonProxy(context.Background(), decision, "FILE_BLOCK", evidence, true)
	if status != audit.ResponseStatusExecuted {
		t.Fatalf("file executor status=%s", status)
	}
	blocked := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PreToolUse", ToolName: "Read", CWD: filepath.Dir(path), ToolInput: input,
	})
	if blocked.Action != "block" || !strings.Contains(blocked.Reason, "persistent pre-read policy") {
		t.Fatalf("next controlled read was not blocked: %+v", blocked)
	}
	api.scannerCfg.Guardrail.Connector = "claudecode"
	other := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: "Read", CWD: filepath.Dir(path), ToolInput: input,
	})
	if strings.Contains(other.Reason, "persistent pre-read policy") {
		t.Fatalf("connector-scoped file block leaked: %+v", other)
	}
	observe, _, err := api.rewriteFileRead("codex", "PreToolUse", "observe", "Read", filepath.Dir(path), input)
	if err != nil || observe != nil {
		t.Fatalf("observe mode enforced file gate: updated=%v err=%v", observe, err)
	}
}
