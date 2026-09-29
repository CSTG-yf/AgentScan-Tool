//go:build windows

package connector

import "os"

func atomicFileSecurityMatches(path string, info os.FileInfo, _ os.FileMode) bool {
	return hookAPIValidateOwner(path, info) == nil
}
