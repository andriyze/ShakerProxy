package capture

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

// Reading one connection back out of a recording lets the web UI show a
// cleartext HTTP exchange the way Wireshark's "Follow stream" does. Only
// packet selection and TCP reassembly happen here; parsing the bytes as HTTP
// is left to the unprivileged control API.

const (
	FlowRequestSchema = 1
	// MaxFlowSegments bounds how many capture files one read may open.
	MaxFlowSegments = 12
	// MaxFlowStreamBytes bounds each direction so both fit one gateway
	// response (1 MiB of JSON with base64).
	MaxFlowStreamBytes = 320 << 10
	MaxFlowPackets     = 20_000
	maxFlowScanBytes   = 4 << 20
	maxFlowSpan        = 10 * time.Minute
)

// FlowRequest selects one TCP connection of a capture around a moment.
type FlowRequest struct {
	Schema        int       `json:"schema"`
	SessionID     string    `json:"session_id"`
	Client        string    `json:"client"`
	Server        string    `json:"server"`
	At            time.Time `json:"at"`
	BeforeSeconds int       `json:"before_seconds"`
	AfterSeconds  int       `json:"after_seconds"`
}

func (r FlowRequest) Validate() error {
	if r.Schema != FlowRequestSchema || !ValidSessionID(r.SessionID) || r.At.IsZero() {
		return errors.New("capture flow request identity is invalid")
	}
	client, clientErr := netip.ParseAddrPort(r.Client)
	server, serverErr := netip.ParseAddrPort(r.Server)
	if clientErr != nil || serverErr != nil || client.Port() == 0 || server.Port() == 0 || client.Addr().Zone() != "" || server.Addr().Zone() != "" {
		return errors.New("capture flow endpoints are invalid")
	}
	if r.BeforeSeconds < 0 || r.AfterSeconds < 0 || time.Duration(r.BeforeSeconds+r.AfterSeconds)*time.Second > maxFlowSpan {
		return errors.New("capture flow window is invalid")
	}
	return nil
}

// FlowResult is one connection's two byte streams and what limited them.
type FlowResult struct {
	Schema    int    `json:"schema"`
	SessionID string `json:"session_id"`
	Client    string `json:"client"`
	Server    string `json:"server"`
	// SegmentsRead counts capture files scanned; SegmentsMissing counts files
	// in the window the capture's ring buffer had already removed.
	SegmentsRead    int `json:"segments_read"`
	SegmentsMissing int `json:"segments_missing"`
	// OpenSegment reports that part of the window is in the file still being
	// written, which is read once it closes.
	OpenSegment    bool       `json:"open_segment"`
	PacketsMatched int        `json:"packets_matched"`
	FirstPacketAt  *time.Time `json:"first_packet_at,omitempty"`
	LastPacketAt   *time.Time `json:"last_packet_at,omitempty"`
	// HeadersOnly reports a capture whose snap length cut packet payloads.
	HeadersOnly     bool   `json:"headers_only"`
	LimitReached    bool   `json:"limit_reached"`
	ClientData      []byte `json:"client_data"`
	ServerData      []byte `json:"server_data"`
	ClientGap       bool   `json:"client_gap"`
	ServerGap       bool   `json:"server_gap"`
	ClientTruncated bool   `json:"client_truncated"`
	ServerTruncated bool   `json:"server_truncated"`
	FromStart       bool   `json:"from_start"`
	Closed          bool   `json:"closed"`
}

type flowCandidate struct {
	name     string
	size     int64
	modified time.Time
	start    time.Time
	end      time.Time
}

// ReadFlow returns one TCP connection's reassembled streams from the closed
// files of a capture, whether it is finished or still recording.
func (m *Manager) ReadFlow(ctx context.Context, request FlowRequest) (FlowResult, error) {
	if err := request.Validate(); err != nil {
		return FlowResult{}, err
	}
	client, _ := netip.ParseAddrPort(request.Client)
	server, _ := netip.ParseAddrPort(request.Server)
	view, err := m.Get(ctx, request.SessionID)
	if err != nil {
		return FlowResult{}, err
	}
	candidates, err := m.flowCandidates(view)
	if err != nil {
		return FlowResult{}, err
	}
	windowStart := request.At.Add(-time.Duration(request.BeforeSeconds) * time.Second)
	windowEnd := request.At.Add(time.Duration(request.AfterSeconds) * time.Second)
	result := FlowResult{Schema: 1, SessionID: request.SessionID, Client: request.Client, Server: request.Server, ClientData: []byte{}, ServerData: []byte{}}
	if view.Active && (len(candidates) == 0 || candidates[len(candidates)-1].end.Before(windowEnd)) {
		result.OpenSegment = true
	}
	selected := make([]flowCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.end.Before(windowStart) && !candidate.start.After(windowEnd) {
			selected = append(selected, candidate)
		}
	}
	if len(selected) > MaxFlowSegments {
		// Keep the files nearest the moment asked about, then read them in
		// recording order.
		sort.SliceStable(selected, func(i, j int) bool {
			return flowDistance(selected[i], request.At) < flowDistance(selected[j], request.At)
		})
		selected = selected[:MaxFlowSegments]
		sort.SliceStable(selected, func(i, j int) bool { return selected[i].end.Before(selected[j].end) })
	}
	directory, err := m.Store.ArtifactDirectory(request.SessionID)
	if err != nil {
		return FlowResult{}, err
	}
	scan := pcapng.TCPFlowScan{}
	key := pcapng.TCPFlowKey{Client: client, Server: server}
	limits := pcapng.TCPFlowLimits{MaxPackets: MaxFlowPackets, MaxPayloadBytes: maxFlowScanBytes}
	for _, candidate := range selected {
		if err := ctx.Err(); err != nil {
			return FlowResult{}, err
		}
		file, err := openFlowSegment(directory, candidate)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, errFlowSegmentChanged) {
			// The ring buffer removed (or is replacing) the file.
			result.SegmentsMissing++
			continue
		}
		if err != nil {
			return FlowResult{}, err
		}
		scanErr := pcapng.ScanTCPFlow(ctx, bufio.NewReaderSize(file, 256<<10), key, windowStart, windowEnd, limits, &scan)
		closeErr := file.Close()
		if scanErr != nil {
			return FlowResult{}, scanErr
		}
		if closeErr != nil {
			return FlowResult{}, closeErr
		}
		result.SegmentsRead++
		if scan.LimitReached {
			break
		}
	}
	result.LimitReached = scan.LimitReached
	result.PacketsMatched = len(scan.Segments)
	for _, segment := range scan.Segments {
		if segment.At.IsZero() {
			continue
		}
		at := segment.At.UTC()
		if result.FirstPacketAt == nil || at.Before(*result.FirstPacketAt) {
			result.FirstPacketAt = &at
		}
		if result.LastPacketAt == nil || at.After(*result.LastPacketAt) {
			last := at
			result.LastPacketAt = &last
		}
	}
	clientStream := pcapng.ReassembleTCP(scan.Segments, true, MaxFlowStreamBytes)
	serverStream := pcapng.ReassembleTCP(scan.Segments, false, MaxFlowStreamBytes)
	result.ClientData, result.ServerData = append([]byte{}, clientStream.Data...), append([]byte{}, serverStream.Data...)
	result.ClientGap, result.ServerGap = clientStream.Gap, serverStream.Gap
	result.ClientTruncated, result.ServerTruncated = clientStream.Truncated, serverStream.Truncated
	result.HeadersOnly = clientStream.Cut || serverStream.Cut
	result.FromStart = clientStream.FromStart
	result.Closed = clientStream.FIN || serverStream.FIN
	return result, nil
}

func flowDistance(candidate flowCandidate, at time.Time) time.Duration {
	switch {
	case at.Before(candidate.start):
		return candidate.start.Sub(at)
	case at.After(candidate.end):
		return at.Sub(candidate.end)
	default:
		return 0
	}
}

// flowCandidates lists a capture's closed files with the time each covers:
// the finalized manifest of a finished capture, or the closed-segment feed
// of one still recording.
func (m *Manager) flowCandidates(view View) ([]flowCandidate, error) {
	candidates := []flowCandidate{}
	if view.Manifest != nil {
		files := append([]CaptureFile(nil), view.Manifest.Files...)
		sort.SliceStable(files, func(i, j int) bool { return files[i].Name < files[j].Name })
		for _, file := range files {
			candidates = append(candidates, flowCandidate{name: file.Name, size: file.SizeBytes, modified: file.Modified, end: file.Modified})
		}
	} else {
		feed, err := m.Store.ReadActiveSegmentFeed(view.Session.ID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		segments := append([]ClosedCaptureSegment(nil), feed.Segments...)
		sort.SliceStable(segments, func(i, j int) bool { return segments[i].Sequence < segments[j].Sequence })
		for _, segment := range segments {
			candidates = append(candidates, flowCandidate{name: segment.Name, size: segment.SizeBytes, modified: segment.Modified, end: segment.ClosedAt})
		}
	}
	rotation := time.Duration(view.Session.Request.SegmentSeconds) * time.Second
	for index := range candidates {
		switch {
		case index > 0:
			candidates[index].start = candidates[index-1].end
		case rotation > 0 && !view.Session.StartedAt.IsZero() && candidates[index].end.Add(-rotation).Before(view.Session.StartedAt):
			candidates[index].start = view.Session.StartedAt
		case rotation > 0:
			candidates[index].start = candidates[index].end.Add(-rotation)
		default:
			candidates[index].start = view.Session.StartedAt
		}
	}
	return candidates, nil
}

var errFlowSegmentChanged = errors.New("capture file no longer matches its record")

// openFlowSegment opens a closed capture file only if it is still the regular,
// unchanged file the manifest or feed describes.
func openFlowSegment(directory string, candidate flowCandidate) (*os.File, error) {
	if !captureFileName(candidate.name) || candidate.name != filepath.Base(candidate.name) {
		return nil, errors.New("capture file name is invalid")
	}
	path := filepath.Join(directory, candidate.name)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() != candidate.size || !before.ModTime().Equal(candidate.modified) {
		return nil, errFlowSegmentChanged
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		file.Close()
		return nil, errFlowSegmentChanged
	}
	return file, nil
}
