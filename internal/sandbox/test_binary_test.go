package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeOpenShellTestBinary(t *testing.T, unixScript, windowsScript string) string {
	t.Helper()
	name, script := "openshell-sandbox", unixScript
	if runtime.GOOS == "windows" {
		name, script = "openshell-sandbox.cmd", windowsScript
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
