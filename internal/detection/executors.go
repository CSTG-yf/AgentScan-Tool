// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// RuntimeExecutionRequest is the narrow contract between the policy engine
// and a concrete enforcement point. Evidence is already redacted and loaded
// from the audit store, so executors never need to parse page DTOs.
type RuntimeExecutionRequest struct {
	Decision   audit.RuntimeDecision
	ActionType string
	Evidence   []audit.DetectionEvidence
}

// RuntimeExecutor executes one enforcement point. Implementations must return
// only after the target module confirms success; a queued hand-off belongs to
// the dispatched status and must not be reported as executed.
type RuntimeExecutor interface {
	Point() string
	Execute(context.Context, RuntimeExecutionRequest) (target, result string, err error)
}

// ProcessExecutor is the post-detection process containment executor. A
// preventative Process Guard remains preferred: this path cannot undo a
// dangerous operation that has already completed.
type ProcessExecutor struct{}

func (ProcessExecutor) Point() string { return audit.EnforcementPointProcess }

func (ProcessExecutor) Execute(ctx context.Context, req RuntimeExecutionRequest) (string, string, error) {
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
	result, err := terminateProcessTrees(ctx, pids)
	var targets []string
	for _, pid := range pids {
		targets = append(targets, strconv.FormatUint(uint64(pid), 10))
	}
	return strings.Join(targets, ","), result, err
}
