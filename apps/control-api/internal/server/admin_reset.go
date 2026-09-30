package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	adminResetRequestName     = "admin-reset.request"
	maxAdminResetRequestBytes = 4 << 10
)

type adminResetRequest struct {
	RequestedAt time.Time `json:"requested_at"`
	RequestedBy string    `json:"requested_by"`
}

// RunAdminResetWatcher polls for the root-only administrator reset request
// written by `shakerproxy admin reset`. Only a regular, root-owned (or the
// configured owner in tests), mode-0600 file is honoured; symlinks are never
// followed. Every request file is deleted after it is handled or rejected.
func (s *Server) RunAdminResetWatcher(ctx context.Context, interval time.Duration) {
	if s.adminResetRequestPath == "" {
		return
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	s.handleAdminResetRequest()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.handleAdminResetRequest()
		}
	}
}

// handleAdminResetRequest processes one pending request. It reports whether an
// administrator reset was performed.
func (s *Server) handleAdminResetRequest() bool {
	path := s.adminResetRequestPath
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		s.logger.Warn("administrator reset request could not be inspected", "path", path, "error", err)
		return false
	}
	if reason := s.adminResetRequestProblem(info); reason != "" {
		s.logger.Warn("administrator reset request rejected and removed", "path", path, "reason", reason)
		_ = os.Remove(path)
		return false
	}
	request, readable, problem := readAdminResetRequest(path, info)
	if problem != "" {
		s.logger.Warn("administrator reset request rejected and removed", "path", path, "reason", problem)
		_ = os.Remove(path)
		return false
	}
	tokenPath, err := s.store.ResetAdministrator()
	if err != nil {
		// Leave the request in place so the next poll retries the reset.
		s.logger.Error("administrator reset failed; it will be retried", "path", path, "error", err)
		return false
	}
	revoked := s.revokeAllSessions()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.logger.Error("administrator reset request could not be removed", "path", path, "error", err)
	}
	attributes := []any{"setup_token_path", tokenPath, "revoked_sessions", revoked}
	if readable {
		attributes = append(attributes, "requested_by", request.RequestedBy, "requested_at", request.RequestedAt)
	} else {
		attributes = append(attributes, "requested_by", "local root (request details are readable only by root)")
	}
	s.logger.Warn("administrator credential reset by local root request; complete setup again with the new one-time setup token", attributes...)
	return true
}

func (s *Server) adminResetRequestProblem(info fs.FileInfo) string {
	if info.Mode()&fs.ModeSymlink != 0 {
		return "request must be a regular file, not a symbolic link"
	}
	if !info.Mode().IsRegular() {
		return "request must be a regular file"
	}
	if info.Mode().Perm() != 0o600 {
		return "request file mode must be 0600"
	}
	if info.Size() > maxAdminResetRequestBytes {
		return "request file is too large"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(s.adminResetOwnerUID) {
		return "request file must be owned by root"
	}
	return ""
}

// readAdminResetRequest reads the request without following symlinks and
// verifies that the opened file is the one that passed the ownership check.
// The control API normally runs unprivileged and cannot read a root-owned
// 0600 file; ownership and mode are then the proof of root intent and the
// request is honoured without its informational details.
func readAdminResetRequest(path string, checked fs.FileInfo) (adminResetRequest, bool, string) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return adminResetRequest{}, false, ""
	}
	if err != nil {
		return adminResetRequest{}, false, "request file could not be opened safely"
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(checked, opened) {
		return adminResetRequest{}, false, "request file changed while it was being checked"
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAdminResetRequestBytes+1))
	if err != nil || len(data) > maxAdminResetRequestBytes {
		return adminResetRequest{}, false, "request file could not be read"
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return adminResetRequest{}, true, ""
	}
	var request adminResetRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return adminResetRequest{}, false, "request file is not the JSON written by `shakerproxy admin reset`"
	}
	if len(request.RequestedBy) > 128 {
		request.RequestedBy = request.RequestedBy[:128]
	}
	return request, true, ""
}
