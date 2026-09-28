//go:build windows

package connector

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const antigravityLauncherName = "defenseclaw-antigravity-hook.exe"

func antigravityNativeHookCommand(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "hooks", antigravityLauncherName)
}

func ensureAntigravityNativeLauncher(opts SetupOpts) error {
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate DefenseClaw executable: %w", err)
	}
	destination := antigravityNativeHookCommand(opts)
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := safefile.ProtectPath(dir, 0o700); err != nil {
		return fmt.Errorf("protect hook directory: %w", err)
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	sourceInfo, err := in.Stat()
	if err != nil {
		return err
	}
	if existing, err := os.Open(destination); err == nil {
		existingInfo, statErr := existing.Stat()
		if statErr == nil && existingInfo.Size() == sourceInfo.Size() {
			sourceHash, hashErr := hashLauncherFile(in)
			if hashErr != nil {
				existing.Close()
				return hashErr
			}
			existingHash, hashErr := hashLauncherFile(existing)
			if hashErr != nil {
				existing.Close()
				return hashErr
			}
			if sourceHash == existingHash {
				existing.Close()
				if err := safefile.ProtectPath(destination, 0o700); err != nil {
					return err
				}
				return removeAntigravityDisabledMarker(destination)
			}
		}
		existing.Close()
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".antigravity-launcher-*.exe")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := safefile.ProtectPath(tmpPath, 0o700); err != nil {
		tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmpPath, sourceInfo.ModTime(), sourceInfo.ModTime()); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("install native hook launcher: %w", err)
	}
	return removeAntigravityDisabledMarker(destination)
}

func hashLauncherFile(file *os.File) ([sha256.Size]byte, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return [sha256.Size]byte{}, err
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return sum, nil
}

func disableAntigravityNativeLauncher(opts SetupOpts) error {
	path := antigravityNativeHookCommand(opts)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return safefile.Write(path+".disabled", []byte("disabled\n"))
}

func removeAntigravityDisabledMarker(path string) error {
	err := os.Remove(path + ".disabled")
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
