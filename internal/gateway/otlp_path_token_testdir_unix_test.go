// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

func otlpTokenTestDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func trustedTokenTestDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
