//go:build !windows

package connector

func antigravityNativeHookCommand(SetupOpts) string    { return "" }
func ensureAntigravityNativeLauncher(SetupOpts) error  { return nil }
func disableAntigravityNativeLauncher(SetupOpts) error { return nil }
