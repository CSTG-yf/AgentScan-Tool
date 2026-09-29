// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

// Package procattr centralises the process-creation attributes applied to every
// external command this product spawns.
package procattr

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// Apply marks cmd so Windows does not allocate a console window for it.
//
// Why this is needed: the managed gateway is started with DETACHED_PROCESS (see
// internal/daemon/proc_windows.go) and therefore owns no console. When a
// console-less process starts a console-subsystem child without this flag,
// Windows allocates a brand-new console for that child, which surfaces to the
// user as a terminal window that flashes for the lifetime of the command.
//
// CREATE_NO_WINDOW is deliberately the only flag set. It makes CreateProcess
// skip console allocation entirely, and Windows documents it as taking
// precedence over STARTF_USESHOWWINDOW — which is all SysProcAttr.HideWindow
// would set. Setting HideWindow as well would add dead
// STARTF_USESHOWWINDOW/SW_HIDE state without preventing the console, so it is
// intentionally omitted.
//
// stdio redirection is unaffected: cmd.Output(), cmd.CombinedOutput(), and
// cmd.Stdout/Stderr keep working, because CREATE_NO_WINDOW suppresses console
// allocation, not the handles os/exec installs.
func Apply(cmd *exec.Cmd) {
	flags := uint32(windows.CREATE_NO_WINDOW)
	if cmd.SysProcAttr != nil {
		// Preserve anything the caller already set rather than clobbering it.
		flags |= cmd.SysProcAttr.CreationFlags
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
}
