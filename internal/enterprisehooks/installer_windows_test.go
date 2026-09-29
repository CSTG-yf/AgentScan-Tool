//go:build windows

package enterprisehooks

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestInstallFailsClosedOnWindows(t *testing.T) {
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		UserHome:      t.TempDir(),
		Registry:      connector.NewDefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported on Windows") {
		t.Fatalf("Install error = %v, want explicit unsupported capability", err)
	}
}
