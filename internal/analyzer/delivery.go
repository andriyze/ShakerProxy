package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

type Sender interface {
	Send(context.Context, Engine, string, []byte) error
}

// ErrEventRejected reports that ingest quarantined one analyzer event (HTTP
// 422). The event can never be accepted, so delivery skips it and continues
// instead of failing, and endlessly re-analyzing, the whole capture artifact.
var ErrEventRejected = errors.New("ingest rejected the analyzer event")

type HTTPSender struct {
	Origin        *url.URL
	Token         []byte
	SourceVersion string
	Client        *http.Client
}

func NewHTTPSender(config Config) (*HTTPSender, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	origin, _ := url.Parse(config.IngestURL)
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("analyzer ingest redirects are disabled")
		},
	}
	return &HTTPSender{Origin: origin, Token: append([]byte(nil), config.Token...), SourceVersion: config.SourceVersion, Client: client}, nil
}

func (s *HTTPSender) Send(ctx context.Context, engine Engine, captureSessionID string, event []byte) error {
	if s == nil || s.Origin == nil || s.Client == nil || len(event) == 0 || len(event) > ingest.MaxPayloadBytes {
		return errors.New("analyzer delivery input is invalid")
	}
	path := "/v1/adapters/zeek"
	if engine == EngineSuricata {
		path = "/v1/adapters/suricata"
	} else if engine != EngineZeek {
		return errors.New("unsupported analyzer delivery engine")
	}
	endpoint := *s.Origin
	endpoint.Path = path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(event))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+string(s.Token))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-ShakerProxy-Source-Version", s.SourceVersion)
	request.Header.Set("X-ShakerProxy-Capture-Session-ID", captureSessionID)
	response, err := s.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if readErr != nil || len(body) > 16<<10 {
		return errors.New("analyzer ingest response exceeded its byte limit")
	}
	if response.StatusCode == http.StatusUnprocessableEntity {
		return fmt.Errorf("%w: HTTP %d: %s", ErrEventRejected, response.StatusCode, strings.TrimSpace(string(body)))
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("analyzer ingest returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func deliverEventFiles(ctx context.Context, sender Sender, engine Engine, sessionID string, files []EventFile, maxOutputBytes int64, maxEvents int) (int, int64, error) {
	if len(files) > MaxOutputFiles {
		return 0, 0, errors.New("analyzer output file count exceeds its safety limit")
	}
	if maxEvents < 0 || maxEvents > MaxEventsPerCapture {
		return 0, 0, errors.New("analyzer event limit is invalid")
	}
	var totalBytes int64
	validated := make(map[string]os.FileInfo, len(files))
	for _, eventFile := range files {
		info, err := os.Lstat(eventFile.Path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || filepath.Base(eventFile.Path) == "" {
			return 0, 0, errors.New("analyzer output is not a regular file")
		}
		if info.Size() < 0 || info.Size() > maxOutputBytes-totalBytes {
			return 0, 0, errors.New("analyzer output exceeds its byte limit")
		}
		totalBytes += info.Size()
		validated[eventFile.Path] = info
	}
	delivered := 0
	for _, eventFile := range files {
		var flowIDs map[uint64]uint64
		if engine == EngineSuricata {
			var err error
			flowIDs, err = withEventFile(eventFile, validated[eventFile.Path], suricataFlowIdentities)
			if err != nil {
				return delivered, totalBytes, err
			}
		}
		_, err := withEventFile(eventFile, validated[eventFile.Path], func(file *os.File) (struct{}, error) {
			return struct{}{}, scanEventLines(file, func(line []byte) error {
				if delivered >= maxEvents {
					return errors.New("analyzer event count exceeds its safety limit")
				}
				event := append([]byte(nil), line...)
				var err error
				switch engine {
				case EngineZeek:
					event, err = addZeekPath(event, eventFile.ZeekPath)
				case EngineSuricata:
					event, err = normalizeSuricataOutput(event, flowIDs)
				}
				if err != nil {
					return err
				}
				if event == nil {
					return nil
				}
				if err := sender.Send(ctx, engine, sessionID, event); err != nil {
					if errors.Is(err, ErrEventRejected) {
						return nil
					}
					return err
				}
				delivered++
				return nil
			})
		})
		if err != nil {
			return delivered, totalBytes, err
		}
	}
	return delivered, totalBytes, nil
}

// withEventFile opens a validated analyzer output without following links and
// confirms it is still the file that passed validation.
func withEventFile[T any](eventFile EventFile, validated os.FileInfo, visit func(*os.File) (T, error)) (T, error) {
	var zero T
	descriptor, err := unix.Open(eventFile.Path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return zero, err
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(eventFile.Path))
	if file == nil {
		unix.Close(descriptor)
		return zero, errors.New("open analyzer output descriptor")
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || validated == nil || !os.SameFile(validated, openedInfo) {
		file.Close()
		return zero, errors.New("analyzer output changed during validation")
	}
	result, visitErr := visit(file)
	closeErr := file.Close()
	if visitErr != nil || closeErr != nil {
		return zero, errors.Join(visitErr, closeErr)
	}
	return result, nil
}

// scanEventLines visits each non-empty line. Lines longer than the ingest
// payload bound can never be accepted, so they are skipped rather than
// aborting delivery of every other event in the file.
func scanEventLines(file io.Reader, visit func([]byte) error) error {
	reader := bufio.NewReaderSize(file, ingest.MaxPayloadBytes+1)
	for {
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) {
			for errors.Is(readErr, bufio.ErrBufferFull) {
				_, readErr = reader.ReadSlice('\n')
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return readErr
			}
			continue
		}
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			if err := visit(trimmed); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

type suricataFlowIdentity struct {
	tuple [sha256.Size]byte
	first string
}

// suricataFlowIdentities maps each Suricata flow_id in one EVE output to a
// value derived only from traffic: the direction-independent endpoint pair,
// the transport, and the earliest event timestamp of that flow. Suricata seeds
// its flow hash randomly per run, so raw flow_id values (and therefore
// content-derived event IDs) differ every time the same artifact is analyzed.
func suricataFlowIdentities(file *os.File) (map[uint64]uint64, error) {
	flows := make(map[uint64]*suricataFlowIdentity)
	err := scanEventLines(file, func(line []byte) error {
		var event struct {
			FlowID    json.Number `json:"flow_id"`
			Timestamp string      `json:"timestamp"`
			SrcIP     string      `json:"src_ip"`
			SrcPort   json.Number `json:"src_port"`
			DestIP    string      `json:"dest_ip"`
			DestPort  json.Number `json:"dest_port"`
			Proto     string      `json:"proto"`
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if decoder.Decode(&event) != nil || event.FlowID == "" {
			return nil
		}
		flowID, err := strconv.ParseUint(event.FlowID.String(), 10, 64)
		if err != nil {
			return nil
		}
		endpoints := []string{event.SrcIP + "|" + event.SrcPort.String(), event.DestIP + "|" + event.DestPort.String()}
		sort.Strings(endpoints)
		tuple := sha256.Sum256([]byte(strings.ToUpper(event.Proto) + "\x00" + endpoints[0] + "\x00" + endpoints[1]))
		identity, exists := flows[flowID]
		if !exists {
			flows[flowID] = &suricataFlowIdentity{tuple: tuple, first: event.Timestamp}
			return nil
		}
		if event.Timestamp != "" && (identity.first == "" || event.Timestamp < identity.first) {
			identity.first = event.Timestamp
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	mapped := make(map[uint64]uint64, len(flows))
	for flowID, identity := range flows {
		digest := sha256.Sum256(append(identity.tuple[:], identity.first...))
		// Keep the value within JavaScript's exact integer range and at a fixed
		// 16 decimal digits so it is always a valid envelope flow identifier.
		mapped[flowID] = binary.BigEndian.Uint64(digest[:8])&(1<<52-1) | 1<<52
	}
	return mapped, nil
}

// normalizeSuricataOutput drops per-run engine statistics (stamped with
// analysis wall-clock time) and replaces run-specific flow identifiers with
// their deterministic equivalents. A nil event means the line is skipped.
func normalizeSuricataOutput(event []byte, flowIDs map[uint64]uint64) ([]byte, error) {
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(event))
	if err := decoder.Decode(&fields); err != nil || fields == nil || decoder.Decode(&struct{}{}) != io.EOF {
		// Let ingest quarantine malformed output rather than hiding it.
		return event, nil
	}
	var eventType string
	if json.Unmarshal(fields["event_type"], &eventType) == nil && eventType == "stats" {
		return nil, nil
	}
	changed := false
	for _, name := range []string{"flow_id", "parent_id"} {
		raw, present := fields[name]
		if !present {
			continue
		}
		original, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			continue
		}
		if replacement, known := flowIDs[original]; known {
			fields[name] = json.RawMessage(strconv.FormatUint(replacement, 10))
			changed = true
		}
	}
	if !changed {
		return event, nil
	}
	encoded, err := json.Marshal(fields)
	if err != nil || len(encoded) > ingest.MaxPayloadBytes {
		return nil, errors.New("Suricata event exceeds its byte limit after flow normalization")
	}
	return encoded, nil
}

func addZeekPath(event []byte, path string) ([]byte, error) {
	if !validLogName(path) || len(event) == 0 || len(event) > ingest.MaxPayloadBytes {
		return nil, errors.New("Zeek event metadata is invalid")
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(event))
	if err := decoder.Decode(&fields); err != nil || fields == nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("Zeek output line is not a JSON object")
	}
	if existing, ok := fields["_path"]; ok {
		var value string
		if json.Unmarshal(existing, &value) != nil || value != path {
			return nil, errors.New("Zeek output path conflicts with its filename")
		}
	} else {
		encodedPath, _ := json.Marshal(path)
		fields["_path"] = encodedPath
	}
	encoded, err := json.Marshal(fields)
	if err != nil || len(encoded) > ingest.MaxPayloadBytes {
		return nil, errors.New("Zeek event exceeds its byte limit after path attribution")
	}
	return encoded, nil
}
