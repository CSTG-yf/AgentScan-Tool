// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/procattr"
)

// RuntimeExecutionRequest is the narrow contract between the policy engine
// and a concrete enforcement point. Evidence is already redacted and loaded
// from the audit store, so executors never need to parse page DTOs.
type RuntimeExecutionRequest struct {
	Decision  audit.RuntimeDecision
	ActionType string
	Evidence  []audit.DetectionEvidence
}

// RuntimeExecutor executes one enforcement point. Implementations must return
// only after the target module confirms success; a queued hand-off belongs to
// the dispatched status and must not be reported as executed.
type RuntimeExecutor interface {
	Point() string
	Execute(context.Context, RuntimeExecutionRequest) (target, result string, err error)
}

// ProcessExecutor is the built-in Windows process containment executor. The
// installed Process Guard service remains the preferred preventative control;
// this executor is the response path for detections discovered after process
// creation (for example, a shell/download/write/exec chain).
type ProcessExecutor struct{}

func (ProcessExecutor) Point() string { return audit.EnforcementPointProcess }

func (ProcessExecutor) Execute(ctx context.Context, req RuntimeExecutionRequest) (string, string, error) {
	if runtime.GOOS != "windows" {
		return "", "", fmt.Errorf("process executor is available only on Windows")
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	seen := map[uint32]bool{}
	var pids []uint32
	for _, evidence := range req.Evidence {
		for _, pid := range []uint32{evidence.Event.ActorPID, evidence.Event.AgentPID} {
			if pid == 0 || pid == uint32(os.Getpid()) || seen[pid] {
				continue
			}
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	if len(pids) == 0 {
		return "", "", fmt.Errorf("process containment has no observed PID")
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, pid := range pids {
		cmd := exec.CommandContext(deadlineCtx, "taskkill.exe", "/PID", strconv.FormatUint(uint64(pid), 10), "/T", "/F")
		procattr.Apply(cmd)
		if output, err := cmd.CombinedOutput(); err != nil {
			message := strings.TrimSpace(string(output))
			if message == "" {
				message = err.Error()
			}
			return strconv.FormatUint(uint64(pid), 10), "", fmt.Errorf("taskkill PID %d failed: %s", pid, message)
		}
	}
	var targets []string
	for _, pid := range pids {
		targets = append(targets, strconv.FormatUint(uint64(pid), 10))
	}
	return strings.Join(targets, ","), "terminated process tree(s) via taskkill", nil
}
