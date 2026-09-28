//go:build windows

package connector

import (
	"os"
	"testing"
)

func assertConnectorFileSecurity(t *testing.T, path string, _ os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := hookAPIValidateOwner(path, info); err != nil {
		t.Fatalf("file owner/DACL is not private: %v", err)
	}
}
