package detection

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func fileBlacklistDetection(t *testing.T, store *audit.Store) audit.RuntimeDetection {
	t.Helper()
	d, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "configured_blacklist",
		Attributes:    map[string]any{"blacklist_target_type": "path"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestFileExecutorRequiresControlledPreReadEvidence(t *testing.T) {
	store := newDetectionTestStore(t)
	detection := fileBlacklistDetection(t, store)
	decision := audit.RuntimeDecision{DecisionID: "D-file", DetectionID: detection.DetectionID, EnforcementPoint: audit.EnforcementPointFile}
	for _, event := range []audit.BehaviorEvent{
		{EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceOSSensor, Attributes: map[string]any{"connector": "codex", "file_read_path_sha256": strings.Repeat("a", 64)}},
		{EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook, Attributes: map[string]any{"connector": "cursor", "file_read_path_sha256": strings.Repeat("a", 64)}},
		{EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook, Attributes: map[string]any{"connector": "codex", "file_read_path_sha256": "invalid"}},
	} {
		status, _, _ := NewPolicyEngine(store).ExecuteNonProxy(context.Background(), decision, "FILE_BLOCK", []audit.DetectionEvidence{{Event: event}}, true)
		if status != audit.ResponseStatusFailed {
			t.Fatalf("unsupported event was marked executed: %+v", event)
		}
	}
}

func TestFileExecutorPersistsVerifiedScopedGate(t *testing.T) {
	store := newDetectionTestStore(t)
	detection := fileBlacklistDetection(t, store)
	digest := strings.Repeat("a", 64)
	decision := audit.RuntimeDecision{DecisionID: "D-file", DetectionID: detection.DetectionID, EnforcementPoint: audit.EnforcementPointFile}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook,
		Attributes: map[string]any{"connector": "codex", "file_read_path_sha256": digest},
	}}}
	status, target, result := NewPolicyEngine(store).ExecuteNonProxy(context.Background(), decision, "FILE_BLOCK", evidence, true)
	if status != audit.ResponseStatusExecuted || target != digest || !strings.Contains(result, "future exact-file calls") {
		t.Fatalf("file executor result = %s %s %s", status, target, result)
	}
	gate := enforce.NewPolicyEngine(store)
	blocked, err := gate.IsBlockedForConnector("file_read_sha256", digest, "codex")
	if err != nil || !blocked {
		t.Fatalf("codex gate = %v, %v", blocked, err)
	}
	blocked, err = gate.IsBlockedForConnector("file_read_sha256", digest, "claudecode")
	if err != nil || blocked {
		t.Fatalf("gate leaked to Claude Code: %v, %v", blocked, err)
	}
}
