package capture

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

const (
	SchemaVersion       = 1
	DefaultRoot         = "/var/lib/shakerproxy/pcap"
	DefaultReserveBytes = uint64(1 << 30)
	// Analyzers only read closed ring members, so the rotation interval is
	// the main term of packet-to-UI latency (see docs/protocol-discovery.md).
	// 30 s rotation with a 64 x 8 MiB ring keeps traffic visible within about
	// half a minute while retaining ~32 minutes of low-rate capture in 512 MiB.
	DefaultSegmentSizeMiB   = 8
	DefaultSegmentSeconds   = 30
	DefaultMaxFiles         = 64
	DefaultStopAfterSeconds = 3600
	DefaultHeaderSnapLength = 256
	MaxSessionBytes         = uint64(8 << 30)
	MaxArtifactChunkBytes   = 256 << 10
)

type Mode string

const (
	ModeHeaders Mode = "HEADERS_ONLY"
	ModeFull    Mode = "FULL_PACKETS"
)

type State string

const (
	StateStarting        State = "STARTING"
	StateRunning         State = "RUNNING"
	StateStopped         State = "STOPPED"
	StateCompleted       State = "COMPLETED"
	StateFailed          State = "FAILED"
	StateStoragePressure State = "STORAGE_PRESSURE"
)

var (
	sessionIDPattern = regexp.MustCompile(`^capture-[a-f0-9]{32}$`)
	interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
)

type StartRequest struct {
	Name             string `json:"name"`
	Description      string `json:"description,omitempty"`
	Mode             Mode   `json:"mode"`
	SnapLength       int    `json:"snap_length,omitempty"`
	SegmentSizeMiB   int    `json:"segment_size_mib"`
	SegmentSeconds   int    `json:"segment_seconds"`
	MaxFiles         int    `json:"max_files"`
	StopAfterSeconds int    `json:"stop_after_seconds"`
	RetentionLock    bool   `json:"retention_lock"`
	CaseID           string `json:"case_id,omitempty"`
	IdempotencyKey   string `json:"idempotency_key"`
	Administrator    string `json:"administrator"`
	StartReason      string `json:"start_reason,omitempty"`
	// Automatic marks the lab recording gatewayd keeps running while a lab
	// routes (see lab_recording.go). Only gatewayd sets it; a manual capture
	// replaces an automatic one.
	Automatic bool `json:"automatic,omitempty"`
}

func (r StartRequest) WithDefaults() StartRequest {
	if r.Mode == "" {
		r.Mode = ModeHeaders
	}
	if r.SegmentSizeMiB == 0 {
		r.SegmentSizeMiB = DefaultSegmentSizeMiB
	}
	if r.SegmentSeconds == 0 {
		r.SegmentSeconds = DefaultSegmentSeconds
	}
	if r.MaxFiles == 0 {
		r.MaxFiles = DefaultMaxFiles
	}
	if r.StopAfterSeconds == 0 {
		r.StopAfterSeconds = DefaultStopAfterSeconds
	}
	if r.Mode == ModeHeaders && r.SnapLength == 0 {
		r.SnapLength = DefaultHeaderSnapLength
	}
	return r
}

func (r StartRequest) Validate() error {
	r = r.WithDefaults()
	if err := validateText("capture name", r.Name, 1, 96); err != nil {
		return err
	}
	if err := validateText("capture description", r.Description, 0, 1024); err != nil {
		return err
	}
	if err := validateText("case ID", r.CaseID, 0, 96); err != nil {
		return err
	}
	if err := validateText("administrator", r.Administrator, 1, 96); err != nil {
		return err
	}
	if err := validateText("start reason", r.StartReason, 0, 256); err != nil {
		return err
	}
	if !validOpaqueKey(r.IdempotencyKey) {
		return errors.New("capture idempotency key must contain 16 to 128 ASCII letters, digits, hyphens, or underscores")
	}
	switch r.Mode {
	case ModeHeaders:
		if r.SnapLength < 96 || r.SnapLength > 512 {
			return errors.New("header capture snap length must be between 96 and 512 bytes")
		}
	case ModeFull:
		if r.SnapLength != 0 && (r.SnapLength < 512 || r.SnapLength > 262144) {
			return errors.New("full capture snap length must be zero or between 512 and 262144 bytes")
		}
	default:
		return errors.New("capture mode must be HEADERS_ONLY or FULL_PACKETS")
	}
	if r.SegmentSizeMiB < 1 || r.SegmentSizeMiB > 1024 {
		return errors.New("capture segment size must be between 1 and 1024 MiB")
	}
	if r.SegmentSeconds < 10 || r.SegmentSeconds > 3600 {
		return errors.New("capture segment duration must be between 10 and 3600 seconds")
	}
	if r.MaxFiles < 2 || r.MaxFiles > 64 {
		return errors.New("capture ring must contain between 2 and 64 files")
	}
	if r.StopAfterSeconds < 10 || r.StopAfterSeconds > 86400 {
		return errors.New("capture stop deadline must be between 10 seconds and 24 hours")
	}
	if uint64(r.SegmentSizeMiB)*uint64(r.MaxFiles) > MaxSessionBytes>>20 {
		return errors.New("capture ring quota exceeds 8 GiB")
	}
	return nil
}

type Source struct {
	InterfaceName     string `json:"interface_name"`
	InterfaceStableID string `json:"interface_stable_id"`
	// SingleArmGateway and SingleArmLabCIDR are set for single-arm labs, whose
	// one interface also carries ShakerProxy's own NATed copy of every lab
	// flow. Packets between the gateway and hosts outside the lab are not
	// recorded, so each flow appears once, from the device.
	SingleArmGateway string `json:"single_arm_gateway,omitempty"`
	SingleArmLabCIDR string `json:"single_arm_lab_cidr,omitempty"`
}

func (s Source) Validate() error {
	if !interfacePattern.MatchString(s.InterfaceName) {
		return errors.New("capture interface name is invalid")
	}
	if strings.TrimSpace(s.InterfaceStableID) == "" || len(s.InterfaceStableID) > 256 {
		return errors.New("capture interface stable identity is invalid")
	}
	if s.SingleArmGateway != "" || s.SingleArmLabCIDR != "" {
		if _, err := s.singleArmFilter(); err != nil {
			return err
		}
	}
	return nil
}

// singleArmFilter derives the fixed BPF exclusion from validated addresses;
// no free-form filter text is ever accepted.
func (s Source) singleArmFilter() (string, error) {
	gateway, gatewayErr := netip.ParseAddr(s.SingleArmGateway)
	prefix, prefixErr := netip.ParsePrefix(s.SingleArmLabCIDR)
	if gatewayErr != nil || prefixErr != nil || !gateway.Is4() || !prefix.Addr().Is4() || prefix != prefix.Masked() || !prefix.Contains(gateway) {
		return "", errors.New("single-arm capture scope is invalid")
	}
	// Record what lab devices send through ShakerProxy: frames to or from its
	// own interface, since a shared LAN otherwise floods the capture with other
	// hosts' multicast and broadcast. ShakerProxy's own traffic (the NATed
	// copy of each flow, its upstream DNS, management sessions) is left out,
	// except the DNS it answers for lab devices.
	if mac, err := interfaceHardwareAddress(s.InterfaceName); err == nil {
		return fmt.Sprintf("ether host %[1]s and (not host %[2]s or (dst host %[2]s and dst port 53) or (src host %[2]s and src port 53))", mac, gateway), nil
	}
	// Without the interface address, leave out only ShakerProxy talking to
	// (or hearing from) a host outside the lab. BPF "net" matches either
	// endpoint and the gateway is inside the lab, so the exclusion is
	// directional.
	return fmt.Sprintf("not ((src host %[1]s and not dst net %[2]s) or (dst host %[1]s and not src net %[2]s))", gateway, prefix), nil
}

// interfaceHardwareAddress reads a network interface's MAC address; tests
// replace it.
var interfaceHardwareAddress = func(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return "", errors.New("interface name is invalid")
	}
	raw, err := os.ReadFile(filepath.Join("/sys/class/net", name, "address"))
	if err != nil {
		return "", err
	}
	mac, err := net.ParseMAC(strings.TrimSpace(string(raw)))
	if err != nil || len(mac) != 6 {
		return "", errors.New("interface has no Ethernet address")
	}
	return mac.String(), nil
}

type Session struct {
	Schema            int          `json:"schema"`
	ID                string       `json:"id"`
	Request           StartRequest `json:"request"`
	Source            Source       `json:"source"`
	OperatingMode     string       `json:"operating_mode"`
	PolicyRevision    string       `json:"policy_revision,omitempty"`
	SoftwareVersion   string       `json:"software_version"`
	StartedAt         time.Time    `json:"started_at"`
	StopAt            time.Time    `json:"stop_at"`
	ReserveBytes      uint64       `json:"reserve_bytes"`
	OutputBaseName    string       `json:"output_base_name"`
	DumpcapExecutable string       `json:"dumpcap_executable"`
	CaptureFilter     string       `json:"capture_filter"`
}

func (s Session) Validate() error {
	if s.Schema != SchemaVersion || !ValidSessionID(s.ID) {
		return errors.New("capture session identity is invalid")
	}
	if err := s.Request.Validate(); err != nil {
		return err
	}
	if err := s.Source.Validate(); err != nil {
		return err
	}
	if s.StartedAt.IsZero() || !s.StopAt.After(s.StartedAt) || s.StopAt.Sub(s.StartedAt) > 24*time.Hour+time.Second {
		return errors.New("capture session time bounds are invalid")
	}
	if s.ReserveBytes < DefaultReserveBytes {
		return errors.New("capture storage reserve is too small")
	}
	if s.OutputBaseName != "capture.pcapng" || s.DumpcapExecutable != "/usr/bin/dumpcap" {
		return errors.New("capture executable or output name is not approved")
	}
	if s.CaptureFilter != "" {
		return errors.New("raw capture filters are unavailable in this schema")
	}
	return nil
}

type WorkerStatus struct {
	Schema              int       `json:"schema"`
	SessionID           string    `json:"session_id"`
	State               State     `json:"state"`
	StartedAt           time.Time `json:"started_at,omitempty"`
	EndedAt             time.Time `json:"ended_at,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
	PacketsCaptured     uint64    `json:"packets_captured"`
	PacketsReceived     uint64    `json:"packets_received"`
	KernelDrops         uint64    `json:"kernel_drops"`
	DumpcapDrops        uint64    `json:"dumpcap_drops"`
	StopReason          string    `json:"stop_reason,omitempty"`
	Failure             string    `json:"failure,omitempty"`
	AnalyzerFeedError   string    `json:"analyzer_feed_error,omitempty"`
	AnalyzerFeedEvicted uint64    `json:"analyzer_feed_evicted"`
}

type CaptureFile struct {
	Name              string             `json:"name"`
	SizeBytes         int64              `json:"size_bytes"`
	SHA256            string             `json:"sha256"`
	Modified          time.Time          `json:"modified_at"`
	PacketMembership  *pcapng.Membership `json:"packet_membership,omitempty"`
	RewriteManifestID string             `json:"rewrite_manifest_id,omitempty"`
}

type Manifest struct {
	Schema          int           `json:"schema"`
	SessionID       string        `json:"session_id"`
	CreatedAt       time.Time     `json:"created_at"`
	SessionSHA256   string        `json:"session_sha256"`
	Files           []CaptureFile `json:"files"`
	TotalSizeBytes  int64         `json:"total_size_bytes"`
	PacketsCaptured uint64        `json:"packets_captured"`
	PacketsReceived uint64        `json:"packets_received"`
	KernelDrops     uint64        `json:"kernel_drops"`
	DumpcapDrops    uint64        `json:"dumpcap_drops"`
}

type ClosedCaptureSegment struct {
	Sequence  uint64    `json:"sequence"`
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	Modified  time.Time `json:"modified_at"`
	ClosedAt  time.Time `json:"closed_at"`
}

type ActiveSegmentFeed struct {
	Schema          int                    `json:"schema"`
	SessionID       string                 `json:"session_id"`
	Revision        uint64                 `json:"revision"`
	PublishedAt     time.Time              `json:"published_at"`
	EvictedSegments uint64                 `json:"evicted_segments"`
	Segments        []ClosedCaptureSegment `json:"segments"`
}

func (f ActiveSegmentFeed) Validate() error {
	return validateActiveSegmentFeed(f, f.SessionID)
}

type View struct {
	Session         Session       `json:"session"`
	State           State         `json:"state"`
	Active          bool          `json:"active"`
	Worker          *WorkerStatus `json:"worker,omitempty"`
	Manifest        *Manifest     `json:"manifest,omitempty"`
	CurrentFiles    int           `json:"current_files"`
	CurrentBytes    int64         `json:"current_bytes"`
	StoragePressure bool          `json:"storage_pressure"`
	EvidenceHold    *EvidenceHold `json:"evidence_hold,omitempty"`
}

type ArtifactChunk struct {
	SessionID  string `json:"session_id"`
	FileName   string `json:"file_name"`
	FileSHA256 string `json:"file_sha256"`
	Offset     int64  `json:"offset"`
	TotalBytes int64  `json:"total_bytes"`
	Data       []byte `json:"data"`
	EOF        bool   `json:"eof"`
}

func ValidSessionID(id string) bool { return sessionIDPattern.MatchString(id) }

func validOpaqueKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func validateText(label, value string, min, max int) error {
	if len(value) < min || len(value) > max || value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must contain between %d and %d trimmed bytes", label, min, max)
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}
