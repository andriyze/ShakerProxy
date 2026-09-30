package cloudconnector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	deviceRuntimeSchema = 1
	deviceRuntimeFile   = "device-runtime.json"
	MaxRuntimeDevices   = 4096
)

type DeviceRuntimeRecord struct {
	LocalDeviceID string    `json:"local_device_id"`
	FriendlyName  string    `json:"friendly_name,omitempty"`
	Platform      string    `json:"platform"`
	Category      string    `json:"category,omitempty"`
	IPv4          []string  `json:"ipv4,omitempty"`
	IPv6          []string  `json:"ipv6,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type deviceRuntimeDocument struct {
	SchemaVersion int                   `json:"schema_version"`
	Devices       []DeviceRuntimeRecord `json:"devices"`
}

type DeviceRuntimeStore struct {
	Root string
	Now  func() time.Time
	mu   sync.Mutex
}

type DeviceRuntimeSnapshot struct {
	DevicePlatforms map[string]string
	DeviceIPv4      map[string][]string
	DeviceIPv6      map[string][]string
	DeviceByIP      map[string]string
	FriendlyNames   map[string]string
	// DeviceCategories holds the inventory's canonical category per device
	// (for example "tv" or "camera"); devices without one are absent.
	DeviceCategories map[string]string
}

func (store *DeviceRuntimeStore) ObserveMetadata(events []LocalMetadataEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	document, err := store.load()
	if err != nil {
		return err
	}
	byID := make(map[string]DeviceRuntimeRecord, len(document.Devices))
	for _, device := range document.Devices {
		byID[device.LocalDeviceID] = device
	}
	changed := false
	for _, event := range events {
		if event.Type != MetadataDeviceUpsert {
			continue
		}
		var payload struct {
			LocalDeviceID string    `json:"local_device_id"`
			FriendlyName  string    `json:"friendly_name"`
			Platform      string    `json:"platform"`
			Category      string    `json:"category"`
			CurrentIPv4   string    `json:"current_ipv4"`
			CurrentIPv6   string    `json:"current_ipv6"`
			LastSeenAt    time.Time `json:"last_seen_at"`
		}
		if err := json.Unmarshal(event.Payload, &payload); err != nil {
			return fmt.Errorf("decode device runtime metadata: %w", err)
		}
		payload.LocalDeviceID = strings.TrimSpace(payload.LocalDeviceID)
		if payload.LocalDeviceID == "" || len(payload.LocalDeviceID) > 128 {
			return errors.New("device runtime metadata has an invalid local device ID")
		}
		record := byID[payload.LocalDeviceID]
		record.LocalDeviceID = payload.LocalDeviceID
		if name := strings.TrimSpace(payload.FriendlyName); name != "" {
			if len(name) > 128 {
				return errors.New("device runtime friendly name exceeds 128 characters")
			}
			record.FriendlyName = name
		}
		platform := normalizeDevicePlatform(payload.Platform)
		if platform != "unknown" || record.Platform == "" {
			record.Platform = platform
		}
		if category := normalizeDeviceCategory(payload.Category); category != "" {
			record.Category = category
		}
		if ip := net.ParseIP(strings.TrimSpace(payload.CurrentIPv4)); ip != nil && ip.To4() != nil {
			address := ip.To4().String()
			removeRuntimeAddress(byID, payload.LocalDeviceID, address)
			record.IPv4 = []string{address}
		}
		if ip := net.ParseIP(strings.TrimSpace(payload.CurrentIPv6)); ip != nil && ip.To4() == nil {
			address := ip.String()
			removeRuntimeAddress(byID, payload.LocalDeviceID, address)
			record.IPv6 = []string{address}
		}
		updatedAt := payload.LastSeenAt.UTC()
		if updatedAt.IsZero() {
			updatedAt = event.ObservedAt.UTC()
		}
		if updatedAt.IsZero() {
			updatedAt = store.now()
		}
		if updatedAt.After(record.UpdatedAt) {
			record.UpdatedAt = updatedAt
		}
		byID[payload.LocalDeviceID] = record
		changed = true
	}
	if !changed {
		return nil
	}
	document.Devices = document.Devices[:0]
	for _, device := range byID {
		document.Devices = append(document.Devices, normalizeDeviceRecord(device))
	}
	pruneDeviceRuntime(&document, store.now())
	return store.save(document)
}

func (store *DeviceRuntimeStore) Rename(localDeviceID, friendlyName string) (DeviceRuntimeRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	localDeviceID = strings.TrimSpace(localDeviceID)
	friendlyName = strings.TrimSpace(friendlyName)
	if localDeviceID == "" || len(localDeviceID) > 128 || friendlyName == "" || len(friendlyName) > 128 {
		return DeviceRuntimeRecord{}, errors.New("device ID or friendly name is invalid")
	}
	document, err := store.load()
	if err != nil {
		return DeviceRuntimeRecord{}, err
	}
	for index := range document.Devices {
		if document.Devices[index].LocalDeviceID != localDeviceID {
			continue
		}
		document.Devices[index].FriendlyName = friendlyName
		document.Devices[index].UpdatedAt = store.now()
		if err := store.save(document); err != nil {
			return DeviceRuntimeRecord{}, err
		}
		return document.Devices[index], nil
	}
	return DeviceRuntimeRecord{}, errors.New("local device runtime was not found")
}

func (store *DeviceRuntimeStore) Snapshot() (DeviceRuntimeSnapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	document, err := store.load()
	if err != nil {
		return DeviceRuntimeSnapshot{}, err
	}
	snapshot := DeviceRuntimeSnapshot{
		DevicePlatforms:  make(map[string]string),
		DeviceIPv4:       make(map[string][]string),
		DeviceIPv6:       make(map[string][]string),
		DeviceByIP:       make(map[string]string),
		FriendlyNames:    make(map[string]string),
		DeviceCategories: make(map[string]string),
	}
	for _, device := range document.Devices {
		snapshot.DevicePlatforms[device.LocalDeviceID] = normalizeDevicePlatform(device.Platform)
		if device.Category != "" {
			snapshot.DeviceCategories[device.LocalDeviceID] = device.Category
		}
		if device.FriendlyName != "" {
			snapshot.FriendlyNames[device.LocalDeviceID] = device.FriendlyName
		}
		if len(device.IPv4) != 0 {
			snapshot.DeviceIPv4[device.LocalDeviceID] = append([]string(nil), device.IPv4...)
			for _, address := range device.IPv4 {
				snapshot.DeviceByIP[address] = device.LocalDeviceID
			}
		}
		if len(device.IPv6) != 0 {
			snapshot.DeviceIPv6[device.LocalDeviceID] = append([]string(nil), device.IPv6...)
			for _, address := range device.IPv6 {
				snapshot.DeviceByIP[address] = device.LocalDeviceID
			}
		}
	}
	return snapshot, nil
}

func (store *DeviceRuntimeStore) Summary() (map[string]any, error) {
	snapshot, err := store.Snapshot()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"device_count":         len(snapshot.DevicePlatforms),
		"named_device_count":   len(snapshot.FriendlyNames),
		"mapped_address_count": len(snapshot.DeviceByIP),
		"mobile_device_count":  countMobilePlatforms(snapshot.DevicePlatforms),
	}, nil
}

func (store *DeviceRuntimeStore) load() (deviceRuntimeDocument, error) {
	if strings.TrimSpace(store.Root) == "" {
		return deviceRuntimeDocument{}, errors.New("device runtime root is required")
	}
	data, err := os.ReadFile(filepath.Join(store.Root, deviceRuntimeFile))
	if errors.Is(err, os.ErrNotExist) {
		return deviceRuntimeDocument{SchemaVersion: deviceRuntimeSchema, Devices: []DeviceRuntimeRecord{}}, nil
	}
	if err != nil {
		return deviceRuntimeDocument{}, err
	}
	if len(data) > 8<<20 {
		return deviceRuntimeDocument{}, errors.New("device runtime file exceeds 8 MiB")
	}
	var document deviceRuntimeDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return deviceRuntimeDocument{}, fmt.Errorf("decode device runtime: %w", err)
	}
	if document.SchemaVersion != deviceRuntimeSchema || len(document.Devices) > MaxRuntimeDevices {
		return deviceRuntimeDocument{}, errors.New("device runtime schema or count is invalid")
	}
	return document, nil
}

func (store *DeviceRuntimeStore) save(document deviceRuntimeDocument) error {
	document.SchemaVersion = deviceRuntimeSchema
	sort.Slice(document.Devices, func(i, j int) bool { return document.Devices[i].LocalDeviceID < document.Devices[j].LocalDeviceID })
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded) > 8<<20 {
		return errors.New("device runtime serialization exceeds 8 MiB")
	}
	return atomicWrite(filepath.Join(store.Root, deviceRuntimeFile), append(encoded, '\n'), 0o600)
}

func removeRuntimeAddress(devices map[string]DeviceRuntimeRecord, ownerID, address string) {
	for deviceID, record := range devices {
		if deviceID == ownerID {
			continue
		}
		record.IPv4 = removeAddress(record.IPv4, address)
		record.IPv6 = removeAddress(record.IPv6, address)
		devices[deviceID] = record
	}
}

func removeAddress(values []string, address string) []string {
	result := values[:0]
	for _, value := range values {
		if value != address {
			result = append(result, value)
		}
	}
	return result
}

func normalizeDeviceRecord(record DeviceRuntimeRecord) DeviceRuntimeRecord {
	record.LocalDeviceID = strings.TrimSpace(record.LocalDeviceID)
	record.FriendlyName = strings.TrimSpace(record.FriendlyName)
	record.Platform = normalizeDevicePlatform(record.Platform)
	record.Category = normalizeDeviceCategory(record.Category)
	record.IPv4 = normalizeAddresses(record.IPv4, true, 16)
	record.IPv6 = normalizeAddresses(record.IPv6, false, 32)
	return record
}

func normalizeDevicePlatform(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "android", "android-phone", "android-tablet":
		return "android"
	case "android-tv", "google-tv", "google tv":
		return "android-tv"
	case "ios", "iphone", "ipad", "ipados":
		return "ios"
	case "tvos", "apple-tv":
		return "tvos"
	case "windows", "macos", "linux", "smart-tv", "embedded", "iot":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "unknown"
	}
}

// normalizeDeviceCategory keeps the inventory's canonical category when it is
// a short lowercase token; "unknown" and anything else is dropped.
func normalizeDeviceCategory(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "unknown" || len(value) > 64 {
		return ""
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return ""
		}
	}
	return value
}

func normalizeAddresses(values []string, ipv4 bool, maximum int) []string {
	result := make([]string, 0, len(values))
	for _, raw := range values {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || (ipv4 && ip.To4() == nil) || (!ipv4 && ip.To4() != nil) {
			continue
		}
		value := ip.String()
		if ipv4 {
			value = ip.To4().String()
		}
		result = appendUniqueAddress(result, value, maximum)
	}
	sort.Strings(result)
	return result
}

func appendUniqueAddress(values []string, value string, maximum int) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	values = append(values, value)
	if len(values) > maximum {
		values = append([]string(nil), values[len(values)-maximum:]...)
	}
	return values
}

func pruneDeviceRuntime(document *deviceRuntimeDocument, now time.Time) {
	cutoff := now.Add(-90 * 24 * time.Hour)
	filtered := document.Devices[:0]
	for _, device := range document.Devices {
		if device.UpdatedAt.Before(cutoff) && device.FriendlyName == "" {
			continue
		}
		filtered = append(filtered, device)
	}
	document.Devices = filtered
	if len(document.Devices) <= MaxRuntimeDevices {
		return
	}
	sort.Slice(document.Devices, func(i, j int) bool { return document.Devices[i].UpdatedAt.After(document.Devices[j].UpdatedAt) })
	document.Devices = append([]DeviceRuntimeRecord(nil), document.Devices[:MaxRuntimeDevices]...)
}

func countMobilePlatforms(platforms map[string]string) int {
	count := 0
	for _, platform := range platforms {
		if platform == "android" || platform == "android-tv" || platform == "ios" || platform == "tvos" {
			count++
		}
	}
	return count
}

func (store *DeviceRuntimeStore) now() time.Time {
	if store.Now != nil {
		return store.Now().UTC()
	}
	return time.Now().UTC()
}
