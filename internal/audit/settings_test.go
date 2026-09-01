// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

func TestStoreJSONSettingRoundTrip(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	type setting struct {
		Version int `json:"version"`
		Every   int `json:"every"`
	}
	if err := store.SaveJSONSetting("desktop.scan_schedule", setting{Version: 1, Every: 15}); err != nil {
		t.Fatalf("SaveJSONSetting: %v", err)
	}
	var got setting
	ok, err := store.LoadJSONSetting("desktop.scan_schedule", &got)
	if err != nil {
		t.Fatalf("LoadJSONSetting: %v", err)
	}
	if !ok {
		t.Fatal("LoadJSONSetting ok=false, want true")
	}
	if got.Version != 1 || got.Every != 15 {
		t.Fatalf("setting = %+v, want version=1 every=15", got)
	}
}
