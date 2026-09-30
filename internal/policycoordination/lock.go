package policycoordination

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Lock is a process-wide advisory lock used to serialize local and Fleet
// traffic-policy mutations. An empty path intentionally disables cross-process
// locking for isolated unit tests.
type Lock struct {
	file *os.File
}

func Acquire(ctx context.Context, path string) (*Lock, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &Lock{}, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == "/" {
		return nil, errors.New("traffic policy coordination lock path must be a clean absolute path below a directory")
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open traffic policy coordination lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open traffic policy coordination lock")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("traffic policy coordination lock is not a regular file")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure traffic policy coordination lock: %w", err)
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &Lock{file: file}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("acquire traffic policy coordination lock: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, fmt.Errorf("acquire traffic policy coordination lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (lock *Lock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	fd := int(lock.file.Fd())
	unlockErr := unix.Flock(fd, unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	return errors.Join(unlockErr, closeErr)
}
