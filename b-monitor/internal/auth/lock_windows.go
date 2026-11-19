package auth

import (
	"errors"
	"os"
)

// Windows is supported for development/tests only. A crashed CLI lock requires
// manual local removal here; the production Linux implementation uses flock.
func AcquireLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("cannot acquire exclusive local lock")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}
