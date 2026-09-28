//go:build windows

package gateway

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertPrivateDeviceFile(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("private DACL unavailable: %v", err)
	}
	if dacl.AceCount != 3 {
		t.Fatalf("private DACL has %d ACEs, want current user, SYSTEM and Administrators only", dacl.AceCount)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("unexpected ACE %d", i)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user.User.Sid) && !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Fatalf("untrusted SID in private DACL: %s", sid.String())
		}
	}
}
