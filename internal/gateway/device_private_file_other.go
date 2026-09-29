//go:build !windows

package gateway

func secureDevicePrivateFile(string) error { return nil }
