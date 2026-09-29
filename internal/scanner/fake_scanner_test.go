package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeFakeScanner(t *testing.T, output string, exitCode int) string {
	t.Helper()
	name := "fake-scanner.sh"
	script := "#!/bin/sh\n"
	if runtime.GOOS == "windows" {
		name = "fake-scanner.cmd"
		script = "@echo off\r\n"
		if output != "" {
			script += "echo " + output + "\r\n"
		}
		script += fmt.Sprintf("exit /b %d\r\n", exitCode)
	} else {
		if output != "" {
			script += "printf '%s\\n' '" + output + "'\n"
		}
		script += fmt.Sprintf("exit %d\n", exitCode)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
