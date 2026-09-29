//go:build !windows && !linux

package detection

import (
	"context"
	"fmt"
)

func terminateProcessTrees(context.Context, []uint32) (string, error) {
	return "", fmt.Errorf("process containment is unsupported on this platform")
}
