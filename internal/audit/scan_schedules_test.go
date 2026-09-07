package audit

import "testing"

func TestScanSchedulesSeedValidateAndPersist(t *testing.T) {
	store, done := newTestStore(t)
	defer done()
	items, err := store.ListScanSchedules()
	if err != nil || len(items) != len(ScanScheduleTaskTypes) {
		t.Fatalf("seeded schedules = %+v, err=%v", items, err)
	}
	item, err := store.SaveScanSchedule(ScanSchedule{
		TaskType: "static_resources", Enabled: true, IntervalSec: 73,
		Mode: "incremental", Scope: map[string]any{"agent_id": "a-1"}, UpdatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.TaskType != "static_assets" {
		t.Fatalf("canonical task type = %q", item.TaskType)
	}
	loaded, ok, err := store.GetScanSchedule("static_assets")
	if err != nil || !ok || !loaded.Enabled || loaded.IntervalSec != 73 || loaded.Scope["agent_id"] != "a-1" {
		t.Fatalf("loaded schedule = %+v, ok=%v, err=%v", loaded, ok, err)
	}
	if _, err := store.SaveScanSchedule(ScanSchedule{TaskType: "unknown", IntervalSec: 60, Mode: "full"}); err == nil {
		t.Fatal("unknown task type accepted")
	}
	if _, err := store.SaveScanSchedule(ScanSchedule{TaskType: "agent_discovery", IntervalSec: 2, Mode: "full"}); err == nil {
		t.Fatal("unsafe interval accepted")
	}
}

func TestNormalizeScanTriggerCompatibility(t *testing.T) {
	for input, expected := range map[string]string{"schedule": "scheduler", "scheduled": "scheduler", "scheduler": "scheduler", "watcher": "watcher", "": "manual"} {
		if got := NormalizeScanTrigger(input); got != expected {
			t.Fatalf("NormalizeScanTrigger(%q)=%q want %q", input, got, expected)
		}
	}
}
