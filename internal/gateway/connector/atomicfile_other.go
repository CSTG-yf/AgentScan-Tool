//go:build !windows

package connector

import "os"

func atomicFileSecurityMatches(_ string, info os.FileInfo, perm os.FileMode) bool {
	return info.Mode().Perm() == perm.Perm()
}
