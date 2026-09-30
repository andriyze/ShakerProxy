package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

const (
	projectionSchema       = 1
	maximumProjectionBytes = 8 << 20
	maximumProjectionItems = deviceinventory.MaxDevices
	projectionRefresh      = 24 * time.Hour
)

type configuration struct {
	InventoryPath   string
	StatePath       string
	ConnectorSocket string
	Interval        time.Duration
	Timeout         time.Duration
}

type metadataConnector interface {
	Status(context.Context) (cloudconnector.LocalConnectorStatus, error)
	Enqueue(context.Context, []cloudconnector.LocalMetadataEvent) error
}

type forwarder struct {
	configuration configuration
	connector     metadataConnector
	logger        *slog.Logger
	now           func() time.Time
}

type deviceProjection struct {
	LocalDeviceID string    `json:"local_device_id"`
	PayloadSHA256 string    `json:"payload_sha256"`
	EnqueuedAt    time.Time `json:"enqueued_at"`
}

type projectionState struct {
	SchemaVersion  int                `json:"schema_version"`
	SensorID       string             `json:"sensor_id"`
	OrganizationID string             `json:"organization_id"`
	Devices        []deviceProjection `json:"devices"`
}

type deviceMetadataPayload struct {
	LocalDeviceID string    `json:"local_device_id"`
	FriendlyName  string    `json:"friendly_name,omitempty"`
	Category      string    `json:"category,omitempty"`
	Vendor        string    `json:"vendor,omitempty"`
	PrimaryMAC    string    `json:"primary_mac,omitempty"`
	CurrentIPv4   string    `json:"current_ipv4,omitempty"`
	CurrentIPv6   string    `json:"current_ipv6,omitempty"`
	Hostnames     []string  `json:"hostnames,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	Confidence    float64   `json:"confidence"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config := configuration{
		InventoryPath:   environmentOr("SHAKERPROXY_INVENTORY_PATH", "/var/lib/shakerproxy/inventory/inventory.json"),
		StatePath:       environmentOr("SHAKERPROXY_DEVICE_CLOUD_STATE", "/var/lib/shakerproxy/forwarders/device-cloud-state.json"),
		ConnectorSocket: environmentOr("SHAKERPROXY_CLOUD_CONNECTOR_SOCKET", "/run/shakerproxy-cloud/connector.sock"),
		Interval:        durationEnvironment("SHAKERPROXY_DEVICE_CLOUD_INTERVAL", 30*time.Second, 5*time.Second, 5*time.Minute),
		Timeout:         durationEnvironment("SHAKERPROXY_DEVICE_CLOUD_TIMEOUT", 10*time.Second, time.Second, time.Minute),
	}
	if err := validateConfiguration(config); err != nil {
		logger.Error("device cloud forwarder configuration rejected", "error", err)
		os.Exit(1)
	}
	client, err := cloudconnector.NewLocalMetadataClient(config.ConnectorSocket, config.Timeout)
	if err != nil {
		logger.Error("device cloud forwarder connector rejected", "error", err)
		os.Exit(1)
	}
	instance := &forwarder{configuration: config, connector: client, logger: logger, now: time.Now}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := instance.healthcheck(); err != nil {
			logger.Error("device cloud forwarder unhealthy", "error", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: inventory-cloud-forwarderd [healthcheck]")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("device cloud forwarder starting", "inventory", config.InventoryPath, "interval", config.Interval)
	if err := instance.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("device cloud forwarder stopped", "error", err)
		os.Exit(1)
	}
}

func validateConfiguration(config configuration) error {
	for name, value := range map[string]string{"inventory path": config.InventoryPath, "state path": config.StatePath, "connector socket": config.ConnectorSocket} {
		if strings.TrimSpace(value) == "" || !filepath.IsAbs(value) || strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s must be absolute", name)
		}
	}
	if config.InventoryPath == config.StatePath || config.InventoryPath == config.ConnectorSocket || config.StatePath == config.ConnectorSocket {
		return errors.New("device cloud forwarder paths must be distinct")
	}
	return nil
}

func (f *forwarder) run(ctx context.Context) error {
	ticker := time.NewTicker(f.configuration.Interval)
	defer ticker.Stop()
	for {
		if err := f.sync(ctx); err != nil && ctx.Err() == nil {
			f.logger.Warn("device cloud projection deferred", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (f *forwarder) sync(ctx context.Context) error {
	status, err := f.connector.Status(ctx)
	if err != nil {
		return err
	}
	if !status.Enrolled {
		return nil
	}
	snapshot, err := (&deviceinventory.Store{Path: f.configuration.InventoryPath}).Snapshot()
	if err != nil {
		return fmt.Errorf("read device inventory: %w", err)
	}
	state, err := loadProjectionState(f.configuration.StatePath)
	if err != nil {
		return err
	}
	now := f.now().UTC()
	events, nextState, changed, err := projectDeviceMetadata(snapshot, status, state, now)
	if err != nil {
		return err
	}
	if len(events) != 0 {
		if err := f.connector.Enqueue(ctx, events); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		if err := saveProjectionState(f.configuration.StatePath, nextState); err != nil {
			return err
		}
	}
	if len(events) != 0 {
		f.logger.Info("device cloud metadata queued", "devices", len(events), "inventory_devices", len(snapshot.Devices))
	}
	return nil
}

func projectDeviceMetadata(snapshot deviceinventory.Snapshot, status cloudconnector.LocalConnectorStatus, previous projectionState, now time.Time) ([]cloudconnector.LocalMetadataEvent, projectionState, bool, error) {
	identityChanged := previous.SchemaVersion != projectionSchema || previous.SensorID != status.SensorID || previous.OrganizationID != status.OrganizationID
	known := make(map[string]deviceProjection, len(previous.Devices))
	if !identityChanged {
		for _, record := range previous.Devices {
			known[record.LocalDeviceID] = record
		}
	}
	current := make(map[string]struct{}, len(snapshot.Devices))
	selected := make(map[string]deviceProjection)
	events := make([]cloudconnector.LocalMetadataEvent, 0, cloudconnector.MaxMetadataEnqueueEvents)
	payloadBytes := 0
	for _, device := range snapshot.Devices {
		current[device.ID] = struct{}{}
		payload, err := projectDevice(device)
		if err != nil {
			return nil, projectionState{}, false, err
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, projectionState{}, false, err
		}
		if len(encoded) > 64<<10 {
			return nil, projectionState{}, false, fmt.Errorf("device %s metadata exceeds 64 KiB", device.ID)
		}
		digest := sha256.Sum256(encoded)
		digestText := hex.EncodeToString(digest[:])
		record, found := known[device.ID]
		if found && record.PayloadSHA256 == digestText && record.EnqueuedAt.After(now.Add(-projectionRefresh)) {
			continue
		}
		eventOverhead := len(encoded) + len(device.ID) + 512
		if len(events) >= cloudconnector.MaxMetadataEnqueueEvents || len(events) != 0 && payloadBytes+eventOverhead > cloudconnector.MaxMetadataRequestBytes-(32<<10) {
			continue
		}
		eventDigest := sha256.Sum256([]byte(status.SensorID + "\x00" + status.OrganizationID + "\x00" + device.ID + "\x00" + digestText))
		events = append(events, cloudconnector.LocalMetadataEvent{
			EventID:    "device-upsert-" + hex.EncodeToString(eventDigest[:16]),
			Type:       cloudconnector.MetadataDeviceUpsert,
			ObservedAt: now,
			Payload:    encoded,
		})
		payloadBytes += eventOverhead
		selected[device.ID] = deviceProjection{LocalDeviceID: device.ID, PayloadSHA256: digestText, EnqueuedAt: now}
	}
	next := projectionState{SchemaVersion: projectionSchema, SensorID: status.SensorID, OrganizationID: status.OrganizationID}
	for id, record := range known {
		if _, exists := current[id]; !exists {
			continue
		}
		if replacement, exists := selected[id]; exists {
			record = replacement
		}
		next.Devices = append(next.Devices, record)
		delete(selected, id)
	}
	for _, record := range selected {
		next.Devices = append(next.Devices, record)
	}
	sort.Slice(next.Devices, func(i, j int) bool { return next.Devices[i].LocalDeviceID < next.Devices[j].LocalDeviceID })
	changed := identityChanged || len(next.Devices) != len(previous.Devices)
	return events, next, changed, nil
}

func projectDevice(device deviceinventory.Device) (deviceMetadataPayload, error) {
	if !deviceinventory.ValidDeviceID(device.ID) {
		return deviceMetadataPayload{}, fmt.Errorf("inventory contains invalid device ID %q", device.ID)
	}
	payload := deviceMetadataPayload{
		LocalDeviceID: device.ID,
		FriendlyName:  device.FriendlyName,
		Category:      device.Category,
		Tags:          append([]string(nil), device.Tags...),
		Confidence:    float64(device.AttributionConfidence) / 100,
		FirstSeenAt:   device.FirstSeen.UTC(),
		LastSeenAt:    device.LastSeen.UTC(),
	}
	if payload.Confidence < 0 {
		payload.Confidence = 0
	} else if payload.Confidence > 1 {
		payload.Confidence = 1
	}
	if device.Vendor != nil {
		payload.Vendor = device.Vendor.Name
	}
	for _, identity := range device.Identities {
		if identity.Kind == deviceinventory.IdentityMAC {
			if mac, err := net.ParseMAC(identity.Value); err == nil {
				payload.PrimaryMAC = strings.ToLower(mac.String())
				break
			}
		}
	}
	for _, address := range device.Addresses {
		if !address.Active {
			continue
		}
		ip := net.ParseIP(address.Address)
		if ip == nil {
			continue
		}
		if ip.To4() != nil && payload.CurrentIPv4 == "" {
			payload.CurrentIPv4 = ip.To4().String()
		} else if ip.To4() == nil && payload.CurrentIPv6 == "" {
			payload.CurrentIPv6 = ip.String()
		}
	}
	for _, hostname := range device.Hostnames {
		if value := strings.TrimSpace(hostname.Hostname); value != "" {
			payload.Hostnames = append(payload.Hostnames, value)
		}
	}
	sort.Strings(payload.Hostnames)
	sort.Strings(payload.Tags)
	return payload, nil
}

func loadProjectionState(path string) (projectionState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return projectionState{SchemaVersion: projectionSchema}, nil
	}
	if err != nil {
		return projectionState{}, fmt.Errorf("read device cloud projection state: %w", err)
	}
	if len(data) > maximumProjectionBytes {
		return projectionState{}, errors.New("device cloud projection state exceeds 8 MiB")
	}
	var state projectionState
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return projectionState{}, fmt.Errorf("decode device cloud projection state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return projectionState{}, errors.New("device cloud projection state has trailing data")
	}
	if state.SchemaVersion != projectionSchema || len(state.Devices) > maximumProjectionItems {
		return projectionState{}, errors.New("device cloud projection state schema or size is invalid")
	}
	seen := make(map[string]struct{}, len(state.Devices))
	for _, record := range state.Devices {
		if !deviceinventory.ValidDeviceID(record.LocalDeviceID) || len(record.PayloadSHA256) != 64 || record.EnqueuedAt.IsZero() {
			return projectionState{}, errors.New("device cloud projection record is invalid")
		}
		if _, err := hex.DecodeString(record.PayloadSHA256); err != nil {
			return projectionState{}, errors.New("device cloud projection digest is invalid")
		}
		if _, duplicate := seen[record.LocalDeviceID]; duplicate {
			return projectionState{}, errors.New("device cloud projection contains a duplicate device")
		}
		seen[record.LocalDeviceID] = struct{}{}
	}
	return state, nil
}

func saveProjectionState(path string, state projectionState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("refusing non-regular device cloud projection state")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil || len(encoded) > maximumProjectionBytes {
		return errors.New("device cloud projection state serialization exceeds 8 MiB")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".device-cloud-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (f *forwarder) healthcheck() error {
	if info, err := os.Stat(filepath.Dir(f.configuration.InventoryPath)); err != nil || !info.IsDir() {
		return errors.New("device inventory directory is unavailable")
	}
	if info, err := os.Stat(filepath.Dir(f.configuration.StatePath)); err != nil || !info.IsDir() {
		return errors.New("device cloud state directory is unavailable")
	}
	if info, err := os.Stat(f.configuration.ConnectorSocket); err != nil || info.Mode()&os.ModeSocket == 0 {
		return errors.New("cloud connector socket is unavailable")
	}
	return nil
}

func environmentOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnvironment(name string, fallback, minimum, maximum time.Duration) time.Duration {
	value, err := time.ParseDuration(strings.TrimSpace(os.Getenv(name)))
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}
