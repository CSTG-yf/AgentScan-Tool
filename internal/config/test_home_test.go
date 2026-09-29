package config

import "testing"

// Go resolves the user home from HOME on Unix and USERPROFILE on Windows.
func setTestUserHome(t *testing.T, path string) {
	t.Helper()
	t.Setenv("HOME", path)
	t.Setenv("USERPROFILE", path)
}
