package audit

import (
	"testing"
	"time"
)

func TestInspectionPartialEvidenceWriteRecovery(t *testing.T) {
	s, done := newTestStore(t)
	defer done()
	id, err := s.RecordRuntimeEvent(RuntimeEventInput{IngestKey: "test:inspection", EventType: RuntimeEventToolPreCall, AgentName: "AgentRange / OpsPilot", SessionID: "recover"})
	if err != nil {
		t.Fatal(err)
	}
	ev, _, _ := s.GetRuntimeEvent(id)
	// Fail one persistence step after the detection row has been saved.
	if _, err = s.db.Exec(`CREATE TRIGGER fail_evidence BEFORE INSERT ON runtime_detection_events BEGIN SELECT RAISE(FAIL,'test evidence failure'); END`); err != nil {
		t.Fatal(err)
	}
	in := RuntimeDetectionInput{AgentID: ev.CanonicalAgentID, SessionID: ev.SessionID, RuleID: "inspect-findings", DetectionType: "dangerous_code_submission", Severity: "CRITICAL", Evidence: []DetectionEvidenceInput{{EventID: id, Role: DetectionRoleTrigger}}, SeenAt: time.Now().UTC()}
	if _, err = s.RecordRuntimeDetection(in); err == nil {
		t.Fatal("evidence write failure was ignored")
	}
	s.db.Exec(`DROP TRIGGER fail_evidence`)
	d, err := s.RecordRuntimeDetection(in)
	if err != nil || d.EventCount != 1 {
		t.Fatalf("recovery count: %+v %v", d, err)
	}
	d, err = s.RecordRuntimeDetection(in)
	if err != nil || d.EventCount != 1 {
		t.Fatalf("retry count: %+v %v", d, err)
	}
	_, evidence, err := s.GetRuntimeDetectionDetail(d.DetectionID)
	if err != nil || len(evidence) != 1 {
		t.Fatalf("evidence: %+v %v", evidence, err)
	}
}
