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
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// processQueryLimitedInformation is enough for GetProcessTimes and is
	// available to a normal desktop process without administrator privileges.
	processQueryLimitedInformation uint32 = 0x1000

	// Windows FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC.
	windowsToUnixEpoch100ns uint64 = 116444736000000000
)

// processSnapshotWindows enumerates the process table with the native
// Toolhelp32 API. Unlike tasklist, the snapshot includes parent PID and the
// executable image name without depending on localized command output. Start
// time is queried separately where the process permits limited information
// access; a denied query only leaves StartedAt unset for that row. The User
// field remains optional because resolving another process' owner requires an
// additional token query and is commonly denied for system processes.
func processSnapshotWindows() ([]processInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	deadline := time.Now().Add(2 * time.Second)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		if err == windows.ERROR_NO_MORE_FILES {
			return []processInfo{}, nil
		}
		return nil, err
	}

	infos := make([]processInfo, 0, 64)
	for {
		if entry.ProcessID != 0 {
			comm := normalizeWindowsProcessName(windows.UTF16ToString(entry.ExeFile[:]))
			if comm != "" {
				infos = append(infos, processInfo{
					PID:       int(entry.ProcessID),
					PPID:      int(entry.ParentProcessID),
					Comm:      comm,
					StartedAt: windowsProcessStartedAt(int(entry.ProcessID)),
				})
			}
		}

		// Toolhelp enumeration is normally sub-millisecond, but do not let a
		// pathological process table block the discovery scan indefinitely.
		if time.Now().After(deadline) {
			break
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return infos, err
		}
	}
	return infos, nil
}

// normalizeWindowsProcessName converts an image name such as
// "Cursor.exe" to the catalog form "cursor". Signatures are intentionally
// matched against the basename only; command lines and executable paths are
// not collected by the process detector.
func normalizeWindowsProcessName(name string) string {
	name = strings.ToLower(strings.TrimSpace(filepath.Base(name)))
	return strings.TrimSuffix(name, ".exe")
}

func windowsProcessStartedAt(pid int) time.Time {
	h, err := windows.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(h)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}
	}
	ticks := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if ticks <= windowsToUnixEpoch100ns {
		return time.Time{}
	}
	return time.Unix(0, int64(ticks-windowsToUnixEpoch100ns)*100).UTC()
}
