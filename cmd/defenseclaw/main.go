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

package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if isAntigravityLauncher(os.Args[0]) {
		launcher, err := os.Executable()
		if err != nil {
			os.Exit(1)
		}
		if _, err := os.Stat(launcher + ".disabled"); err == nil {
			os.Exit(0)
		} else if !os.IsNotExist(err) {
			os.Exit(1)
		}
		if err := os.Setenv("DEFENSECLAW_HOME", filepath.Dir(filepath.Dir(launcher))); err != nil {
			os.Exit(1)
		}
		os.Args = append([]string{os.Args[0], "hook", "--connector", "antigravity"}, os.Args[1:]...)
	}
	cli.SetVersion(version)
	cli.SetBuildInfo(commit, date)
	os.Exit(cli.Execute())
}

func isAntigravityLauncher(path string) bool {
	return strings.EqualFold(filepath.Base(path), "defenseclaw-antigravity-hook.exe")
}
