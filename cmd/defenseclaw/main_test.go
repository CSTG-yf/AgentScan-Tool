package main

import (
	"path/filepath"
	"testing"
)

func TestIsAntigravityLauncher(t *testing.T) {
	if !isAntigravityLauncher(filepath.Join("hooks", "defenseclaw-antigravity-hook.exe")) {
		t.Fatal("native launcher was not recognized")
	}
	if isAntigravityLauncher(filepath.Join("hooks", "defenseclaw.exe")) {
		t.Fatal("ordinary gateway executable was misidentified")
	}
}
