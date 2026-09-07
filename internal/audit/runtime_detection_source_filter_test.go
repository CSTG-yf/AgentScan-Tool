package audit

import (
	"testing"
	"time"
)

func TestRuntimeDetectionSourceFilterLegacyPrecedenceAndPagination(t *testing.T) {
	store, done := newTestStore(t)
	defer done()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, row := range []struct{ id, source, attrs, rule, kind string }{
		{"explicit", "hook", `{"source":"legacy"}`, "exfiltration", "exploit"},
		{"attribute", "", `{"source":"legacy"}`, "", "exploit"},
		{"correlation", "", `{}`, "exfiltration", "custom"},
		{"invalid-json", "", `{invalid`, "", "custom"},
		{"non-string", "", `{"source":42}`, "", "custom"},
	} {
		_, err := store.db.Exec(`INSERT INTO runtime_detections (detection_id, source, attributes_json, rule_id, detection_type, first_seen_at, last_seen_at) VALUES (?,?,?,?,?,?,?)`, row.id, row.source, row.attrs, row.rule, row.kind, now, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	for source, count := range map[string]int{"hook": 1, "legacy": 1, "correlation_engine": 1, "runtime_detection": 2, "hook,legacy": 2} {
		filter := RuntimeDetectionFilter{Source: source, Limit: 1, Offset: 0}
		total, err := store.CountRuntimeDetections(filter)
		if err != nil || total != count {
			t.Fatalf("%s total %d want %d: %v", source, total, count, err)
		}
		rows, err := store.ListRuntimeDetections(filter)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s page: %v %v", source, rows, err)
		}
		types, err := store.ListRuntimeDetectionAgentTypeSummaries(filter)
		if err != nil || len(types) != 1 || types[0].TotalEvents != count {
			t.Fatalf("%s summary: %+v %v", source, types, err)
		}
	}
}
