//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeWindowsProcessName(t *testing.T) {
	tests := map[string]string{
		"Cursor.exe":           "cursor",
		`C:\\Tools\\Codex.EXE`: "codex",
		"  python.exe  ":       "python",
	}
	for input, want := range tests {
		if got := normalizeWindowsProcessName(input); got != want {
			t.Errorf("normalizeWindowsProcessName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestProcessSnapshotWindowsIncludesCurrentProcess(t *testing.T) {
	infos, err := processSnapshotWindows()
	if err != nil {
		t.Fatalf("processSnapshotWindows: %v", err)
	}

	pid := os.Getpid()
	for _, info := range infos {
		if info.PID != pid {
			continue
		}
		if info.Comm == "" {
			t.Fatal("current process has an empty image name")
		}
		if info.PPID <= 0 {
			t.Fatalf("current process has invalid parent PID %d", info.PPID)
		}
		if !info.StartedAt.IsZero() && info.StartedAt.After(time.Now().UTC()) {
			t.Fatalf("current process start time %s is in the future", info.StartedAt)
		}
		return
	}

	// A test runner can briefly replace the process image while a snapshot is
	// being taken. Include the PID in the failure to make that rare issue
	// actionable instead of silently accepting an empty inventory.
	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, info.Comm)
	}
	t.Fatalf("current PID %d not present in process snapshot (names=%s)", pid, strings.Join(names, ","))
}
