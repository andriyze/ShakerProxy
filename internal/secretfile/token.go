package secretfile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type tokenFilePolicy struct {
	requirePrivate bool
	ownerUID       uint32
}

func LoadToken(path string) ([]byte, error) {
	return loadToken(path, tokenFilePolicy{})
}

// LoadPrivateToken reads a token only when the opened descriptor is a private
// regular file owned by ownerUID or root. Permission and ownership checks are
// performed after O_NOFOLLOW open, not on a separate path lookup.
func LoadPrivateToken(path string, ownerUID uint32) ([]byte, error) {
	return loadToken(path, tokenFilePolicy{requirePrivate: true, ownerUID: ownerUID})
}

func loadToken(path string, policy tokenFilePolicy) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("token file is unavailable or unsafe")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("token file is unavailable or unsafe")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !validTokenFile(before, policy) || before.Size() < 32 || before.Size() > 129 {
		return nil, errors.New("token file is unavailable or unsafe")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 130))
	if err != nil || len(contents) > 129 {
		return nil, errors.New("token file is unavailable or unsafe")
	}
	after, err := file.Stat()
	if err != nil || !validTokenFile(after, policy) || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() || tokenFileUID(before) != tokenFileUID(after) {
		return nil, errors.New("token file changed while it was read")
	}
	token := bytes.TrimSpace(contents)
	if len(token) < 32 || len(token) > 128 {
		return nil, errors.New("token file is unavailable or unsafe")
	}
	return append([]byte(nil), token...), nil
}

func validTokenFile(info os.FileInfo, policy tokenFilePolicy) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	if !policy.requirePrivate {
		return true
	}
	uid, ok := tokenFileOwner(info)
	return ok && info.Mode().Perm()&0o077 == 0 && (uid == policy.ownerUID || uid == 0)
}

func tokenFileUID(info os.FileInfo) uint32 {
	uid, _ := tokenFileOwner(info)
	return uid
}

func tokenFileOwner(info os.FileInfo) (uint32, bool) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return status.Uid, true
}
