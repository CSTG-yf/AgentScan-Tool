//go:build !windows

package connector

import (
	"os"
	"testing"
)

func writeUnsafeOTLPTokenFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
