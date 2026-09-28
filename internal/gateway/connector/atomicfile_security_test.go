package connector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFileProtectsContentsAndKeepsMatchingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := []byte("token = 'secret'\n")
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	assertConnectorFileSecurity(t, path, 0o600)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("matching secure file was unnecessarily replaced")
	}
}
