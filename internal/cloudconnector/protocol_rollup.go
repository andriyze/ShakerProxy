package cloudconnector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/protocolclass"
)

const (
	// MetadataProtocolSummary is an hourly, per-device rollup of which catalog
	// protocols a sensor observed.
	MetadataProtocolSummary MetadataEventType = "protocol.summary"

	// ProtocolSummaryCapability is advertised by sensors that roll up protocol
	// usage, and by clouds that accept protocol.summary metadata. The connector
	// queues protocol.summary events only after the cloud has advertised it, so
	// an older cloud never sees (and never rejects) the new event type.
	ProtocolSummaryCapability = "metadata.protocol-summary"

	ProtocolSummarySchema = 1
	ProtocolSummaryBucket = time.Hour

	// MaxProtocolRollupAggregates bounds the (hour, device, protocol) state.
	MaxProtocolRollupAggregates = 20000
	// ProtocolRollupLateWindow is how long after an hour closes a late
	// connection record can still be added to it.
	ProtocolRollupLateWindow = 26 * time.Hour

	protocolRollupFile               = "protocol-rollup.json"
	protocolRollupDocumentSchema     = 1
	protocolRollupPersistInterval    = time.Minute
	protocolRollupOpenBucketInterval = 15 * time.Minute
	maxProtocolRollupFileBytes       = 16 << 20
	maxProtocolSummaryPorts          = 5
	maxProtocolRollupPorts           = 16
	maxProtocolRollupSources         = 4
	maxProtocolFlowDuration          = 7 * 24 * time.Hour
)

// protocolRollupConnectionKinds lists the analyzer records that summarize one
// finished connection. Only these are counted: DNS, TLS and alert records
// describe the same connections again and would double count them.
var protocolRollupConnectionKinds = map[string]string{
	"zeek.conn":     "zeek",
	"suricata.flow": "suricata",
}

// ProtocolSummary is the protocol.summary payload: one hour of one device's
// (or, with an empty local_device_id, unattributed) use of one catalog
// protocol. Totals are cumulative for the hour, so a summary that is sent
// again with larger totals supersedes the earlier one instead of adding to it.
type ProtocolSummary struct {
	Schema         int                   `json:"schema"`
	LocalDeviceID  string                `json:"local_device_id"`
	DeviceCategory string                `json:"device_category,omitempty"`
	Protocol       string                `json:"protocol"`
	Label          string                `json:"label"`
	Description    string                `json:"description"`
	Category       string                `json:"category"`
	Visibility     string                `json:"visibility"`
	Evidence       string                `json:"evidence"`
	Exotic         bool                  `json:"exotic"`
	BucketStart    time.Time             `json:"bucket_start"`
	BucketSeconds  int                   `json:"bucket_seconds"`
	Flows          uint64                `json:"flows"`
	Bytes          uint64                `json:"bytes"`
	FirstSeen      time.Time             `json:"first_seen"`
	LastSeen       time.Time             `json:"last_seen"`
	Ports          []ProtocolSummaryPort `json:"ports"`
}

// ProtocolSummaryPort is one of the busiest server ports for the protocol.
type ProtocolSummaryPort struct {
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Flows     uint64 `json:"flows"`
}

// ProtocolRollup aggregates flow.summary connection records into hourly
// protocol.summary events. State lives in memory and is persisted to the
// connector state directory at most once a minute and on every emission, so a
// crash loses at most about a minute of counts. Because summaries carry
// cumulative totals, lost counts only make the cloud undercount; nothing is
// ever counted twice.
type ProtocolRollup struct {
	Root string
	Now  func() time.Time

	mu         sync.Mutex
	loaded     bool
	aggregates map[protocolRollupKey]*protocolRollupAggregate
	stats      protocolRollupStats
	dirty      bool
	savedAt    time.Time
}

type protocolRollupKey struct {
	bucket   int64
	device   string
	protocol string
}

type protocolRollupCounters struct {
	Flows         uint64            `json:"flows"`
	Bytes         uint64            `json:"bytes"`
	AnalyzerFlows uint64            `json:"analyzer_flows,omitempty"`
	FirstSeen     time.Time         `json:"first_seen"`
	LastSeen      time.Time         `json:"last_seen"`
	Ports         map[string]uint64 `json:"ports,omitempty"`
}

type protocolRollupAggregate struct {
	BucketStart   time.Time                          `json:"bucket_start"`
	LocalDeviceID string                             `json:"local_device_id,omitempty"`
	Protocol      string                             `json:"protocol"`
	Sources       map[string]*protocolRollupCounters `json:"sources"`
	Pending       bool                               `json:"pending"`
	EmittedAt     time.Time                          `json:"emitted_at,omitempty"`
}

type protocolRollupStats struct {
	LateFlows         uint64    `json:"late_flows"`
	EvictedAggregates uint64    `json:"evicted_aggregates"`
	ExpiredUnsent     uint64    `json:"expired_unsent"`
	LastEmittedAt     time.Time `json:"last_emitted_at,omitempty"`
}

type protocolRollupDocument struct {
	SchemaVersion int                        `json:"schema_version"`
	Stats         protocolRollupStats        `json:"stats"`
	Aggregates    []*protocolRollupAggregate `json:"aggregates"`
}

type protocolRollupFlow struct {
	device     string
	protocol   string
	evidence   protocolclass.Evidence
	source     string
	transport  string
	serverPort int
	bytes      uint64
	start      time.Time
	end        time.Time
}

// Observe counts the connection records among events. Other event types and
// malformed payloads are ignored: the rollup is derived data and must never
// block the metadata queue.
func (rollup *ProtocolRollup) Observe(events []LocalMetadataEvent) error {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	rollup.ensureLoaded()
	now := rollup.now()
	for _, event := range events {
		if event.Type != MetadataFlowSummary {
			continue
		}
		flow, ok := decodeProtocolRollupFlow(event)
		if !ok {
			continue
		}
		rollup.observe(flow, now)
		rollup.dirty = true
	}
	if rollup.dirty && now.Sub(rollup.savedAt) >= protocolRollupPersistInterval {
		return rollup.saveLocked(now)
	}
	return nil
}

// Emit hands protocol.summary events for aggregates that changed since they
// were last queued to enqueue: closed hours right away, the open hour at most
// every 15 minutes, oldest first and at most MaxMetadataEnqueueEvents per call.
// Aggregates are marked as sent only when enqueue succeeds. categories maps a
// local device ID to its inventory category.
func (rollup *ProtocolRollup) Emit(categories map[string]string, enqueue func([]LocalMetadataEvent) error) (int, error) {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	rollup.ensureLoaded()
	now := rollup.now()
	if rollup.pruneExpired(now) {
		rollup.dirty = true
	}
	candidates := make([]protocolRollupKey, 0)
	for key, aggregate := range rollup.aggregates {
		if !aggregate.Pending {
			continue
		}
		closed := !aggregate.BucketStart.Add(ProtocolSummaryBucket).After(now)
		if closed || aggregate.EmittedAt.IsZero() || now.Sub(aggregate.EmittedAt) >= protocolRollupOpenBucketInterval {
			candidates = append(candidates, key)
		}
	}
	sortProtocolRollupKeys(candidates)
	if len(candidates) > MaxMetadataEnqueueEvents {
		candidates = candidates[:MaxMetadataEnqueueEvents]
	}
	events := make([]LocalMetadataEvent, 0, len(candidates))
	selected := make([]protocolRollupKey, 0, len(candidates))
	for _, key := range candidates {
		aggregate := rollup.aggregates[key]
		summary, ok := aggregate.summary(categories[aggregate.LocalDeviceID])
		if !ok {
			// Nothing reportable (for example a protocol removed from the
			// catalog by an upgrade); stop retrying it.
			aggregate.Pending = false
			rollup.dirty = true
			continue
		}
		event, err := protocolSummaryEvent(summary, now)
		if err != nil {
			aggregate.Pending = false
			rollup.dirty = true
			continue
		}
		events = append(events, event)
		selected = append(selected, key)
	}
	if len(events) != 0 {
		if err := enqueue(events); err != nil {
			return 0, err
		}
		for _, key := range selected {
			aggregate := rollup.aggregates[key]
			aggregate.Pending = false
			aggregate.EmittedAt = now
		}
		rollup.stats.LastEmittedAt = now
		rollup.dirty = true
		return len(events), rollup.saveLocked(now)
	}
	if rollup.dirty && now.Sub(rollup.savedAt) >= protocolRollupPersistInterval {
		return 0, rollup.saveLocked(now)
	}
	return 0, nil
}

// Persist writes the rollup state if it changed since the last write.
func (rollup *ProtocolRollup) Persist() error {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	if !rollup.loaded || !rollup.dirty {
		return nil
	}
	return rollup.saveLocked(rollup.now())
}

// Summary reports bounded rollup health for heartbeats and local status.
func (rollup *ProtocolRollup) Summary() map[string]any {
	rollup.mu.Lock()
	defer rollup.mu.Unlock()
	rollup.ensureLoaded()
	pending := 0
	for _, aggregate := range rollup.aggregates {
		if aggregate.Pending {
			pending++
		}
	}
	var lastEmitted *time.Time
	if !rollup.stats.LastEmittedAt.IsZero() {
		value := rollup.stats.LastEmittedAt
		lastEmitted = &value
	}
	return map[string]any{
		"aggregates":         len(rollup.aggregates),
		"pending":            pending,
		"late_flows":         rollup.stats.LateFlows,
		"evicted_aggregates": rollup.stats.EvictedAggregates,
		"expired_unsent":     rollup.stats.ExpiredUnsent,
		"last_emitted_at":    lastEmitted,
		"max_aggregates":     MaxProtocolRollupAggregates,
	}
}

func decodeProtocolRollupFlow(event LocalMetadataEvent) (protocolRollupFlow, bool) {
	var payload struct {
		LocalDeviceID       string `json:"local_device_id"`
		DestinationPort     int    `json:"destination_port"`
		SourcePort          int    `json:"source_port"`
		Transport           string `json:"transport"`
		ApplicationProtocol string `json:"application_protocol"`
		BytesSent           uint64 `json:"bytes_sent"`
		BytesReceived       uint64 `json:"bytes_received"`
		DurationMS          uint64 `json:"duration_ms"`
		Attributes          struct {
			EventKind        string `json:"event_kind"`
			ProtocolEvidence string `json:"protocol_evidence"`
		} `json:"attributes"`
	}
	if event.ObservedAt.IsZero() || json.Unmarshal(event.Payload, &payload) != nil {
		return protocolRollupFlow{}, false
	}
	source, ok := protocolRollupConnectionKinds[payload.Attributes.EventKind]
	if !ok {
		return protocolRollupFlow{}, false
	}
	protocol := payload.ApplicationProtocol
	evidence := protocolclass.Evidence(payload.Attributes.ProtocolEvidence)
	if !protocolclass.ValidID(protocol) || !validProtocolEvidence(evidence) {
		// Records projected before protocol classification carried the raw
		// analyzer service; classify them the same way the projection would.
		classification := protocolclass.Classify(protocolclass.Observation{
			Transport:  payload.Transport,
			Service:    payload.ApplicationProtocol,
			ServerPort: payload.DestinationPort,
			ClientPort: payload.SourcePort,
		})
		protocol, evidence = classification.Protocol, classification.Evidence
	}
	device := strings.TrimSpace(payload.LocalDeviceID)
	if device != "" && !metadataEventIDPattern.MatchString(device) {
		device = ""
	}
	duration := time.Duration(payload.DurationMS) * time.Millisecond
	if payload.DurationMS > uint64(maxProtocolFlowDuration/time.Millisecond) {
		duration = maxProtocolFlowDuration
	}
	start := event.ObservedAt.UTC()
	transport := strings.ToLower(payload.Transport)
	port := payload.DestinationPort
	if port < 0 || port > 65535 {
		port = 0
	}
	return protocolRollupFlow{
		device:     device,
		protocol:   protocol,
		evidence:   evidence,
		source:     source,
		transport:  transport,
		serverPort: port,
		bytes:      saturatingAdd(payload.BytesSent, payload.BytesReceived),
		start:      start,
		end:        start.Add(duration),
	}, true
}

func (rollup *ProtocolRollup) observe(flow protocolRollupFlow, now time.Time) {
	end := flow.end
	if end.After(now) {
		end = now
	}
	start := flow.start
	if start.After(end) {
		start = end
	}
	// A connection is counted in the hour it was last active, so long-lived
	// sessions (MQTT, VPN tunnels) are not dropped as late arrivals.
	bucket := end.Truncate(ProtocolSummaryBucket)
	if bucket.Add(ProtocolSummaryBucket + ProtocolRollupLateWindow).Before(now) {
		rollup.stats.LateFlows++
		return
	}
	key := protocolRollupKey{bucket: bucket.Unix(), device: flow.device, protocol: flow.protocol}
	aggregate := rollup.aggregates[key]
	if aggregate == nil {
		if len(rollup.aggregates) >= MaxProtocolRollupAggregates {
			rollup.makeRoom(now)
		}
		aggregate = &protocolRollupAggregate{
			BucketStart:   bucket,
			LocalDeviceID: flow.device,
			Protocol:      flow.protocol,
			Sources:       map[string]*protocolRollupCounters{},
		}
		rollup.aggregates[key] = aggregate
	}
	counters := aggregate.Sources[flow.source]
	if counters == nil {
		if len(aggregate.Sources) >= maxProtocolRollupSources {
			return
		}
		counters = &protocolRollupCounters{FirstSeen: start, LastSeen: end}
		aggregate.Sources[flow.source] = counters
	}
	counters.Flows = saturatingAdd(counters.Flows, 1)
	counters.Bytes = saturatingAdd(counters.Bytes, flow.bytes)
	if flow.evidence == protocolclass.EvidenceAnalyzer {
		counters.AnalyzerFlows = saturatingAdd(counters.AnalyzerFlows, 1)
	}
	if start.Before(counters.FirstSeen) {
		counters.FirstSeen = start
	}
	if end.After(counters.LastSeen) {
		counters.LastSeen = end
	}
	if flow.serverPort > 0 && (flow.transport == "tcp" || flow.transport == "udp") {
		portKey := flow.transport + "/" + strconv.Itoa(flow.serverPort)
		if counters.Ports == nil {
			counters.Ports = map[string]uint64{}
		}
		if _, tracked := counters.Ports[portKey]; tracked || len(counters.Ports) < maxProtocolRollupPorts {
			counters.Ports[portKey] = saturatingAdd(counters.Ports[portKey], 1)
		}
	}
	aggregate.Pending = true
}

// preferredSource picks one analyzer's view of the hour. Zeek and Suricata
// usually both record the same connections, so their counts are alternatives,
// not addends; the busier view wins and a sensor running only one analyzer
// still reports everything.
func (aggregate *protocolRollupAggregate) preferredSource() *protocolRollupCounters {
	names := make([]string, 0, len(aggregate.Sources))
	for name := range aggregate.Sources {
		names = append(names, name)
	}
	sort.Strings(names)
	var best *protocolRollupCounters
	for _, name := range names {
		counters := aggregate.Sources[name]
		if counters == nil || counters.Flows == 0 {
			continue
		}
		if best == nil || counters.Flows > best.Flows || counters.Flows == best.Flows && counters.Bytes > best.Bytes {
			best = counters
		}
	}
	return best
}

func (aggregate *protocolRollupAggregate) summary(deviceCategory string) (ProtocolSummary, bool) {
	counters := aggregate.preferredSource()
	protocol, known := protocolclass.Lookup(aggregate.Protocol)
	if counters == nil || !known {
		return ProtocolSummary{}, false
	}
	evidence := protocolclass.EvidencePort
	switch {
	case protocol.Category == protocolclass.CategoryUnknown:
		evidence = protocolclass.EvidenceUnclassified
	case counters.AnalyzerFlows > 0:
		evidence = protocolclass.EvidenceAnalyzer
	}
	if aggregate.LocalDeviceID == "" {
		deviceCategory = ""
	}
	return ProtocolSummary{
		Schema:         ProtocolSummarySchema,
		LocalDeviceID:  aggregate.LocalDeviceID,
		DeviceCategory: normalizeDeviceCategory(deviceCategory),
		Protocol:       protocol.ID,
		Label:          protocol.Label,
		Description:    protocol.Description,
		Category:       string(protocol.Category),
		Visibility:     string(protocol.Visibility),
		Evidence:       string(evidence),
		Exotic:         protocol.Exotic,
		BucketStart:    aggregate.BucketStart.UTC(),
		BucketSeconds:  int(ProtocolSummaryBucket / time.Second),
		Flows:          counters.Flows,
		Bytes:          counters.Bytes,
		FirstSeen:      counters.FirstSeen.UTC(),
		LastSeen:       counters.LastSeen.UTC(),
		Ports:          topProtocolPorts(counters.Ports, maxProtocolSummaryPorts),
	}, true
}

func topProtocolPorts(counts map[string]uint64, limit int) []ProtocolSummaryPort {
	ports := make([]ProtocolSummaryPort, 0, len(counts))
	for key, flows := range counts {
		transport, number, found := strings.Cut(key, "/")
		port, err := strconv.Atoi(number)
		if !found || err != nil || port <= 0 || port > 65535 || (transport != "tcp" && transport != "udp") {
			continue
		}
		ports = append(ports, ProtocolSummaryPort{Transport: transport, Port: port, Flows: flows})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Flows != ports[j].Flows {
			return ports[i].Flows > ports[j].Flows
		}
		if ports[i].Transport != ports[j].Transport {
			return ports[i].Transport < ports[j].Transport
		}
		return ports[i].Port < ports[j].Port
	})
	if len(ports) > limit {
		ports = ports[:limit]
	}
	return ports
}

func protocolSummaryEvent(summary ProtocolSummary, now time.Time) (LocalMetadataEvent, error) {
	encoded, err := json.Marshal(summary)
	if err != nil {
		return LocalMetadataEvent{}, err
	}
	if len(encoded) > 64<<10 {
		return LocalMetadataEvent{}, errors.New("protocol summary exceeds 64 KiB")
	}
	observedAt := summary.LastSeen
	if observedAt.After(now) {
		observedAt = now
	}
	// The ID is derived from the content, so re-queuing an unchanged summary
	// is deduplicated by the queue, and a changed one gets a new ID.
	digest := sha256.Sum256(encoded)
	return LocalMetadataEvent{
		EventID:    "protocol-summary-" + hex.EncodeToString(digest[:20]),
		Type:       MetadataProtocolSummary,
		ObservedAt: observedAt,
		Payload:    encoded,
	}, nil
}

// pruneExpired drops hours that can no longer receive late records.
func (rollup *ProtocolRollup) pruneExpired(now time.Time) bool {
	changed := false
	for key, aggregate := range rollup.aggregates {
		if !aggregate.BucketStart.Add(ProtocolSummaryBucket + ProtocolRollupLateWindow).Before(now) {
			continue
		}
		if aggregate.Pending {
			rollup.stats.ExpiredUnsent++
		}
		delete(rollup.aggregates, key)
		changed = true
	}
	return changed
}

// makeRoom evicts about 5% of the state, already-sent hours first and oldest
// first, so a burst of new devices or protocols cannot grow state unbounded.
func (rollup *ProtocolRollup) makeRoom(now time.Time) {
	rollup.pruneExpired(now)
	if len(rollup.aggregates) < MaxProtocolRollupAggregates {
		return
	}
	keys := make([]protocolRollupKey, 0, len(rollup.aggregates))
	for key := range rollup.aggregates {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := rollup.aggregates[keys[i]], rollup.aggregates[keys[j]]
		if left.Pending != right.Pending {
			return !left.Pending
		}
		return protocolRollupKeyLess(keys[i], keys[j])
	})
	evict := len(keys) / 20
	if evict < 1 {
		evict = 1
	}
	for _, key := range keys[:evict] {
		if rollup.aggregates[key].Pending {
			rollup.stats.ExpiredUnsent++
		}
		delete(rollup.aggregates, key)
		rollup.stats.EvictedAggregates++
	}
}

func sortProtocolRollupKeys(keys []protocolRollupKey) {
	sort.Slice(keys, func(i, j int) bool { return protocolRollupKeyLess(keys[i], keys[j]) })
}

func protocolRollupKeyLess(left, right protocolRollupKey) bool {
	if left.bucket != right.bucket {
		return left.bucket < right.bucket
	}
	if left.device != right.device {
		return left.device < right.device
	}
	return left.protocol < right.protocol
}

// ensureLoaded reads persisted state once. A missing, oversized or corrupt
// file starts an empty rollup: it is derived data and must not stop the
// connector.
func (rollup *ProtocolRollup) ensureLoaded() {
	if rollup.loaded {
		return
	}
	rollup.loaded = true
	rollup.aggregates = map[protocolRollupKey]*protocolRollupAggregate{}
	rollup.savedAt = rollup.now()
	if strings.TrimSpace(rollup.Root) == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(rollup.Root, protocolRollupFile))
	if err != nil || len(data) > maxProtocolRollupFileBytes {
		rollup.dirty = err == nil
		return
	}
	var document protocolRollupDocument
	if json.Unmarshal(data, &document) != nil || document.SchemaVersion != protocolRollupDocumentSchema || len(document.Aggregates) > MaxProtocolRollupAggregates {
		rollup.dirty = true
		return
	}
	rollup.stats = document.Stats
	for _, aggregate := range document.Aggregates {
		if !validPersistedProtocolAggregate(aggregate) {
			rollup.dirty = true
			continue
		}
		aggregate.BucketStart = aggregate.BucketStart.UTC()
		key := protocolRollupKey{bucket: aggregate.BucketStart.Unix(), device: aggregate.LocalDeviceID, protocol: aggregate.Protocol}
		rollup.aggregates[key] = aggregate
	}
}

func validPersistedProtocolAggregate(aggregate *protocolRollupAggregate) bool {
	if aggregate == nil || !protocolclass.ValidID(aggregate.Protocol) || aggregate.BucketStart.IsZero() || !aggregate.BucketStart.Equal(aggregate.BucketStart.Truncate(ProtocolSummaryBucket)) {
		return false
	}
	if aggregate.LocalDeviceID != "" && !metadataEventIDPattern.MatchString(aggregate.LocalDeviceID) {
		return false
	}
	if len(aggregate.Sources) == 0 || len(aggregate.Sources) > maxProtocolRollupSources {
		return false
	}
	for _, counters := range aggregate.Sources {
		if counters == nil || len(counters.Ports) > maxProtocolRollupPorts || counters.LastSeen.Before(counters.FirstSeen) {
			return false
		}
	}
	return true
}

func (rollup *ProtocolRollup) saveLocked(now time.Time) error {
	if strings.TrimSpace(rollup.Root) == "" {
		return errors.New("protocol rollup root is required")
	}
	keys := make([]protocolRollupKey, 0, len(rollup.aggregates))
	for key := range rollup.aggregates {
		keys = append(keys, key)
	}
	sortProtocolRollupKeys(keys)
	document := protocolRollupDocument{SchemaVersion: protocolRollupDocumentSchema, Stats: rollup.stats, Aggregates: make([]*protocolRollupAggregate, 0, len(keys))}
	for _, key := range keys {
		document.Aggregates = append(document.Aggregates, rollup.aggregates[key])
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if len(encoded) > maxProtocolRollupFileBytes {
		return fmt.Errorf("protocol rollup state exceeds %d bytes", maxProtocolRollupFileBytes)
	}
	if err := atomicWrite(filepath.Join(rollup.Root, protocolRollupFile), append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	rollup.dirty = false
	rollup.savedAt = now
	return nil
}

func (rollup *ProtocolRollup) now() time.Time {
	if rollup.Now != nil {
		return rollup.Now().UTC()
	}
	return time.Now().UTC()
}

func validProtocolEvidence(value protocolclass.Evidence) bool {
	switch value {
	case protocolclass.EvidenceAnalyzer, protocolclass.EvidencePort, protocolclass.EvidenceUnclassified:
		return true
	default:
		return false
	}
}

// saturatingAdd adds counters without wrapping. It saturates at MaxInt64 so
// every counter also fits the cloud's signed 64-bit columns.
func saturatingAdd(left, right uint64) uint64 {
	const maximum = uint64(math.MaxInt64)
	if left >= maximum || right >= maximum-left {
		return maximum
	}
	return left + right
}
