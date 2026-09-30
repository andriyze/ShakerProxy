package daemon

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"shakerproxy.dev/shakerproxy/internal/capture"
)

func NewProductionCaptureManager() (*capture.Manager, error) {
	for _, path := range []string{"/usr/bin/dumpcap", "/usr/bin/systemctl", "/usr/libexec/shakerproxy/shakerproxy-capture-worker"} {
		if err := requireExecutable(path); err != nil {
			return nil, err
		}
	}
	unit, err := os.Lstat("/lib/systemd/system/shakerproxy-capture@.service")
	if err != nil || !unit.Mode().IsRegular() {
		return nil, errors.New("capture service template is unavailable")
	}
	root, err := os.Lstat(capture.DefaultRoot)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 || root.Mode()&os.ModeSetgid == 0 || root.Mode().Perm() != 0o770 {
		return nil, errors.New("capture storage root is unavailable or has unsafe permissions")
	}
	group, err := user.LookupGroup("shakerproxy-capture")
	if err != nil {
		return nil, errors.New("capture service group is unavailable")
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 32)
	stat, ok := root.Sys().(*syscall.Stat_t)
	if err != nil || !ok || uint64(stat.Gid) != groupID {
		return nil, errors.New("capture storage root group is unsafe")
	}
	return &capture.Manager{
		Store:           capture.Store{Root: capture.DefaultRoot},
		Controller:      capture.SystemdController{Runner: capture.OSCommandRunner{}},
		SoftwareVersion: daemonVersion,
	}, nil
}
