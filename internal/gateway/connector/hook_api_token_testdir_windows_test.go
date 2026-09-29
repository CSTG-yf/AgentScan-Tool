// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// Go's default Windows temp directory may inherit write access for another
// local account. That is intentionally rejected by the token trust check, so
// positive tests need a private fixture under a verified trusted parent.
func hookAPITestDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("find home directory: %v", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		t.Fatalf("resolve home directory: %v", err)
	}
	if err := hookAPIValidateDirectory(home); err != nil {
		t.Skipf("no trusted Windows test fixture parent: %v", err)
	}
	dir, err := os.MkdirTemp(home, ".defenseclaw-hook-api-test-")
	if err != nil {
		t.Fatalf("create private fixture directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove private fixture directory: %v", err)
		}
	})
	return dir
}
