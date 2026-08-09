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

//go:build !windows

package inventory

// processSnapshotWindows is only called behind the runtime.GOOS guard in the
// shared processSnapshot wrapper. The stub keeps that wrapper buildable on
// POSIX platforms while the native implementation stays Windows-only.
func processSnapshotWindows() ([]processInfo, error) {
	return nil, nil
}
