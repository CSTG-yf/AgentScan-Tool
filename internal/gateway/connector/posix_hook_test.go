package connector

import (
	"runtime"
	"testing"
)

func requirePOSIXHookScriptExecution(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses the native Go hook entrypoint; Bash hook script execution is Unix-only")
	}
}
