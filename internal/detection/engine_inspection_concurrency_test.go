package detection

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type inspectionGateRule struct {
	entered chan int64
	release <-chan struct{}
}

func (r *inspectionGateRule) ID() string   { return "inspection-gate-test" }
func (r *inspectionGateRule) Name() string { return "inspection gate test" }
func (r *inspectionGateRule) Evaluate(ctx *EvalContext) []DetectionResult {
	r.entered <- ctx.Event.ID
	<-r.release
	return nil
}

func TestInspectionEvaluationUsesSessionScopedLocks(t *testing.T) {
	store := newDetectionTestStore(t)
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	entered := make(chan int64, 3)
	engine := NewEngine(store, []Rule{&inspectionGateRule{entered: entered, release: release}})

	var ids [2]int64
	for i, session := range []string{"session-a", "session-b"} {
		var err error
		ids[i], err = store.RecordRuntimeEvent(audit.RuntimeEventInput{
			EventType: audit.RuntimeEventPromptSubmit, EventSource: audit.RuntimeSourceGuardrail,
			AgentName: "AgentRange / OpsPilot", SessionID: session,
			Attributes: map[string]any{"inspection_status": "complete"},
		})
		if err != nil {
			t.Fatalf("record %s: %v", session, err)
		}
	}
	if engine.inspectionLock(audit.BehaviorEvent{SessionID: "session-a"}) == engine.inspectionLock(audit.BehaviorEvent{SessionID: "session-b"}) {
		t.Fatal("test sessions map to the same lock shard")
	}
	done := make(chan error, 3)
	for _, id := range ids {
		go func(id int64) { done <- engine.EvaluateEventWithError(id) }(id)
	}
	for range ids {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("independent inspection sessions did not evaluate concurrently")
		}
	}
	go func() { done <- engine.EvaluateEventWithError(ids[0]) }()
	select {
	case <-entered:
		t.Fatal("concurrent retry evaluated the same inspection twice")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for range 3 {
		if err := <-done; err != nil {
			t.Fatalf("evaluate inspection: %v", err)
		}
	}

	if err := engine.EvaluateEventWithError(ids[0]); err != nil {
		t.Fatalf("evaluate retry: %v", err)
	}
	select {
	case <-entered:
		t.Fatal("completed inspection evaluated twice")
	default:
	}
}
