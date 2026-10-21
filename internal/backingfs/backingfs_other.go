//go:build !linux

package backingfs

import "errors"

// CheckShared refuses every filesystem: the check reads Linux's mountinfo, and multi-mount is Linux-only.
func CheckShared(cipherdir string) error {
	return errors.New("sharing a cipherdir between mounts is supported on Linux only")
}
