//go:build !windows

package safefile

func securePrivateFile(string) error { return nil }
