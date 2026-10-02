package analyzer

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	SchemaVersion = 1
	// DefaultPollInterval is how often the worker looks for newly closed
	// capture segments; a scan is a directory listing plus small metadata
	// reads, so a short interval keeps analysis near-live cheaply.
	DefaultPollInterval   = 2 * time.Second
	DefaultAnalysisLimit  = 30 * time.Minute
	DefaultMaxOutputBytes = int64(256 << 20)
	MaxOutputFiles        = 64
	MaxEventsPerCapture   = 1_000_000
	MaxActiveRecent       = 128
	maxMetadataBytes      = 1 << 20
	// MaxCaptureRetryDelay caps the exponential backoff applied to a capture
	// whose analysis keeps failing, so one bad capture cannot re-run a parser
	// every poll interval forever.
	MaxCaptureRetryDelay = 10 * time.Minute
)

type Engine string

const (
	EngineZeek     Engine = "ZEEK"
	EngineSuricata Engine = "SURICATA"
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ParseEngine(value string) (Engine, error) {
	engine := Engine(strings.ToUpper(strings.TrimSpace(value)))
	switch engine {
	case EngineZeek, EngineSuricata:
		return engine, nil
	default:
		return "", errors.New("analyzer engine must be ZEEK or SURICATA")
	}
}

type Config struct {
	Engine         Engine
	CaptureRoot    string
	StateRoot      string
	WorkRoot       string
	IngestURL      string
	Token          []byte
	SourceVersion  string
	PollInterval   time.Duration
	AnalysisLimit  time.Duration
	MaxOutputBytes int64
}

func (c Config) WithDefaults() Config {
	if c.PollInterval == 0 {
		c.PollInterval = DefaultPollInterval
	}
	if c.AnalysisLimit == 0 {
		c.AnalysisLimit = DefaultAnalysisLimit
	}
	if c.MaxOutputBytes == 0 {
		c.MaxOutputBytes = DefaultMaxOutputBytes
	}
	return c
}

func (c Config) Validate() error {
	c = c.WithDefaults()
	if _, err := ParseEngine(string(c.Engine)); err != nil {
		return err
	}
	for label, path := range map[string]string{"capture root": c.CaptureRoot, "state root": c.StateRoot, "work root": c.WorkRoot} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
			return fmt.Errorf("%s must be an absolute non-root path", label)
		}
	}
	if pathsOverlap(c.CaptureRoot, c.StateRoot) || pathsOverlap(c.CaptureRoot, c.WorkRoot) || pathsOverlap(c.StateRoot, c.WorkRoot) {
		return errors.New("analyzer capture, state, and work roots must not overlap")
	}
	if len(c.Token) < 32 || len(c.Token) > 128 {
		return errors.New("analyzer token must contain 32 to 128 bytes")
	}
	for _, char := range c.Token {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return errors.New("analyzer token contains an invalid character")
		}
	}
	if !validText(c.SourceVersion, 1, 64) {
		return errors.New("analyzer source version is invalid")
	}
	parsed, err := url.Parse(c.IngestURL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return errors.New("analyzer ingest URL must be a plain internal HTTP origin")
	}
	if c.PollInterval < time.Second || c.PollInterval > time.Minute {
		return errors.New("analyzer poll interval must be between one second and one minute")
	}
	if c.AnalysisLimit < time.Minute || c.AnalysisLimit > 2*time.Hour {
		return errors.New("analyzer time limit must be between one minute and two hours")
	}
	if c.MaxOutputBytes < 1<<20 || c.MaxOutputBytes > 1<<30 {
		return errors.New("analyzer output limit must be between 1 MiB and 1 GiB")
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	for _, pair := range [][2]string{{first, second}, {second, first}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

type Checkpoint struct {
	Schema              int       `json:"schema"`
	Engine              Engine    `json:"engine"`
	CaptureSessionID    string    `json:"capture_session_id"`
	ManifestSHA256      string    `json:"manifest_sha256"`
	CaptureFiles        int       `json:"capture_files"`
	EventsDelivered     int       `json:"events_delivered"`
	OutputBytes         int64     `json:"output_bytes"`
	AnalysisCompletedAt time.Time `json:"analysis_completed_at"`
	ActiveSegments      uint64    `json:"active_segments,omitempty"`
	MissedSegments      uint64    `json:"missed_segments,omitempty"`
}

type ProcessedSegment struct {
	Sequence  uint64    `json:"sequence"`
	Name      string    `json:"name"`
	SizeBytes int64     `json:"size_bytes"`
	Modified  time.Time `json:"modified_at"`
	SHA256    string    `json:"sha256"`
	// Finalized marks a manifest member recorded while analyzing a finalized
	// capture, so a retry resumes after it instead of re-delivering it.
	Finalized bool `json:"finalized,omitempty"`
}

type ActiveProgress struct {
	Schema                int                `json:"schema"`
	Engine                Engine             `json:"engine"`
	CaptureSessionID      string             `json:"capture_session_id"`
	FeedRevision          uint64             `json:"feed_revision"`
	FeedEvictedSegments   uint64             `json:"feed_evicted_segments"`
	LastCompletedSequence uint64             `json:"last_completed_sequence"`
	SegmentsProcessed     uint64             `json:"segments_processed"`
	MissedSegments        uint64             `json:"missed_segments"`
	EventsDelivered       int                `json:"events_delivered"`
	OutputBytes           int64              `json:"output_bytes"`
	Recent                []ProcessedSegment `json:"recent"`
	UpdatedAt             time.Time          `json:"updated_at"`
}

type Status struct {
	Schema            int       `json:"schema"`
	Engine            Engine    `json:"engine"`
	SourceVersion     string    `json:"source_version"`
	RulesetID         string    `json:"ruleset_id,omitempty"`
	RulesetVersion    string    `json:"ruleset_version,omitempty"`
	RulesetSHA256     string    `json:"ruleset_sha256,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastScanAt        time.Time `json:"last_scan_at,omitempty"`
	LastSuccessAt     time.Time `json:"last_success_at,omitempty"`
	ScanInProgress    bool      `json:"scan_in_progress"`
	CurrentCaptureID  string    `json:"current_capture_id,omitempty"`
	CompletedCaptures uint64    `json:"completed_captures"`
	DeliveredEvents   uint64    `json:"delivered_events"`
	LastError         string    `json:"last_error,omitempty"`
	// Live reports live analysis of the lab recording (Zeek only).
	Live *LiveStatus `json:"live,omitempty"`
}

type ScanResult struct {
	Discovered int
	Skipped    int
	Completed  int
	Segments   int
	Events     int
	// Deferred counts captures not attempted because an earlier failure put
	// them in retry backoff.
	Deferred int
	Errors   []error
}

func validText(value string, min, max int) bool {
	if len(value) < min || len(value) > max || value != strings.TrimSpace(value) {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}
