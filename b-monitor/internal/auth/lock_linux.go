package auth

import (
	"errors"
	"os"
	"syscall"
)

// flock is released by the kernel even after a crash, allowing systemd restart.
// Keep the inode in place: unlinking a lock file permits competing lock owners.
func AcquireLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open exclusive local lock")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("cannot acquire exclusive local lock")
	}
	return func() { _ = f.Close() }, nil
}
