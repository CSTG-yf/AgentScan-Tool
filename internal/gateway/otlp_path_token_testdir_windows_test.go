// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The default Windows temp root can be writable by unrelated principals.
// A positive token test must use a directory that passes production ACL checks.
func otlpTokenTestDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("find home directory: %v", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		t.Fatalf("resolve home directory: %v", err)
	}
	dir, err := os.MkdirTemp(home, ".defenseclaw-otlp-test-")
	if err != nil {
		t.Fatalf("create token test directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove token test directory: %v", err)
		}
	})
	if _, err := connector.EnsureOTLPPathToken(dir, connector.OTLPScopeGeminiCLI); err != nil {
		t.Skipf("no trusted Windows token test fixture: %v", err)
	}
	path, err := connector.OTLPPathTokenFilePath(dir, connector.OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("resolve seeded token file: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("clear seeded token file: %v", err)
	}
	return dir
}

func trustedTokenTestDir(t *testing.T) string {
	t.Helper()
	return otlpTokenTestDir(t)
}
