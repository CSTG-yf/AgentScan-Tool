//go:build !windows

package connector

import (
	"os"
	"testing"
)

func assertConnectorFileSecurity(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("file mode = %o, want %o", got, want)
	}
}

func assertConnectorDirSecurity(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	assertConnectorFileSecurity(t, path, want)
}
