//go:build !windows

package config

import (
	"os"
	"testing"
)

func assertRestoredConfigSecurity(t *testing.T, path string, wantMode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != wantMode {
		t.Fatalf("config mode = %o, want %o", got, wantMode)
	}
}
