// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "testing"

func hookAPITestDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
