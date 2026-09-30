package server

import "shakerproxy.dev/shakerproxy/internal/ingest"

func (s *Server) projectDeviceNames(events []ingest.RecentEvent) bool {
	if s.nameResolver == nil {
		return false
	}
	if err := s.nameResolver.Ready(); err != nil {
		s.logger.Warn("device name projection unavailable", "error", err)
		return false
	}
	for index := range events {
		event := &events[index]
		if event.DeviceID == "" {
			continue
		}
		projection, found, err := s.nameResolver.Resolve(event.DeviceID, event.OccurredAt)
		if err != nil {
			s.logger.Warn("device name projection failed", "error", err)
			return false
		}
		if !found {
			continue
		}
		event.DeviceFriendlyName = projection.CurrentFriendlyName
		event.DeviceFriendlyNameAtCapture = projection.FriendlyNameAtCapture
		event.DeviceFriendlyNameAtCaptureKnown = projection.FriendlyNameAtCaptureKnown
		event.DeviceAliasRevision = projection.AliasRevision
		event.DeviceFriendlyNameConflict = projection.CurrentFriendlyNameConflicted
	}
	return true
}

func (s *Server) invalidateDeviceNames() {
	if s.nameResolver != nil {
		s.nameResolver.Invalidate()
	}
}
