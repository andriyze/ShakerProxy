package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

type connectorStub struct {
	status  cloudconnector.LocalConnectorStatus
	batches [][]cloudconnector.LocalMetadataEvent
}

func (stub *connectorStub) Status(context.Context) (cloudconnector.LocalConnectorStatus, error) {
	return stub.status, nil
}

func (stub *connectorStub) Enqueue(_ context.Context, events []cloudconnector.LocalMetadataEvent) error {
	stub.batches = append(stub.batches, append([]cloudconnector.LocalMetadataEvent(nil), events...))
	return nil
}

func TestForwarderPersistsAcknowledgedInventoryProjection(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	inventoryPath := filepath.Join(root, "inventory", "inventory.json")
	store := &deviceinventory.Store{Path: inventoryPath, Now: func() time.Time { return now }}
	if _, err := store.ReconcileDHCP4([]deviceinventory.DHCP4Lease{{
		Address:       netip.MustParseAddr("10.44.0.15"),
		HardwareAddr:  "02:00:00:00:00:15",
		Hostname:      "living-room-tv",
		ValidLifetime: 2 * time.Hour,
		ExpiresAt:     now.Add(time.Hour),
	}}); err != nil {
		t.Fatal(err)
	}
	connector := &connectorStub{status: cloudconnector.LocalConnectorStatus{Enrolled: true, SensorID: "sensor-1", OrganizationID: "org-1", ProtocolVersion: cloudconnector.ProtocolVersion}}
	instance := &forwarder{
		configuration: configuration{InventoryPath: inventoryPath, StatePath: filepath.Join(root, "state", "devices.json")},
		connector:     connector,
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:           func() time.Time { return now },
	}
	if err := instance.sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := instance.sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(connector.batches) != 1 || len(connector.batches[0]) != 1 {
		t.Fatalf("durable projection did not suppress an unchanged device: %#v", connector.batches)
	}
	state, err := loadProjectionState(instance.configuration.StatePath)
	if err != nil || len(state.Devices) != 1 || state.SensorID != "sensor-1" {
		t.Fatalf("unexpected persisted projection state: %#v %v", state, err)
	}
}

func TestProjectDeviceMetadataIsStableBoundedAndRefreshable(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	snapshot := deviceinventory.Snapshot{Schema: 1, Devices: []deviceinventory.Device{{
		Schema: 1, ID: "device-0123456789abcdef0123456789abcdef", FriendlyName: "Living Room TV", Category: "tv", Tags: []string{"release", "living-room"},
		Identities: []deviceinventory.Identity{{Kind: deviceinventory.IdentityMAC, Value: "02:00:00:00:00:15"}},
		Addresses:  []deviceinventory.AddressObservation{{Address: "10.44.0.15", Family: "IPv4", Active: true}},
		Hostnames:  []deviceinventory.HostnameObservation{{Hostname: "living-room-tv"}},
		FirstSeen:  now.Add(-time.Hour), LastSeen: now, AttributionConfidence: 95,
	}}}
	status := cloudconnector.LocalConnectorStatus{Enrolled: true, SensorID: "sensor-1", OrganizationID: "org-1", ProtocolVersion: cloudconnector.ProtocolVersion}
	events, state, changed, err := projectDeviceMetadata(snapshot, status, projectionState{}, now)
	if err != nil || !changed || len(events) != 1 || len(state.Devices) != 1 {
		t.Fatalf("unexpected first projection: events=%d state=%#v changed=%t err=%v", len(events), state, changed, err)
	}
	var payload deviceMetadataPayload
	if err := json.Unmarshal(events[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.LocalDeviceID != snapshot.Devices[0].ID || payload.PrimaryMAC != "02:00:00:00:00:15" || payload.CurrentIPv4 != "10.44.0.15" || payload.Confidence != 0.95 {
		t.Fatalf("unexpected device payload: %#v", payload)
	}
	events, _, _, err = projectDeviceMetadata(snapshot, status, state, now.Add(time.Hour))
	if err != nil || len(events) != 0 {
		t.Fatalf("unchanged recent device was requeued: events=%d err=%v", len(events), err)
	}
	events, _, _, err = projectDeviceMetadata(snapshot, status, state, now.Add(projectionRefresh+time.Second))
	if err != nil || len(events) != 1 {
		t.Fatalf("periodic device refresh was not queued: events=%d err=%v", len(events), err)
	}
}

func TestProjectionResetsForNewCloudIdentityAndPrunesDeletedDevices(t *testing.T) {
	now := time.Now().UTC()
	previous := projectionState{SchemaVersion: projectionSchema, SensorID: "old-sensor", OrganizationID: "old-org", Devices: []deviceProjection{{LocalDeviceID: "device-0123456789abcdef0123456789abcdef", PayloadSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", EnqueuedAt: now}}}
	status := cloudconnector.LocalConnectorStatus{Enrolled: true, SensorID: "new-sensor", OrganizationID: "new-org", ProtocolVersion: cloudconnector.ProtocolVersion}
	events, state, changed, err := projectDeviceMetadata(deviceinventory.Snapshot{}, status, previous, now)
	if err != nil || len(events) != 0 || !changed || len(state.Devices) != 0 || state.SensorID != "new-sensor" {
		t.Fatalf("cloud identity reset was not projected safely: events=%d state=%#v changed=%t err=%v", len(events), state, changed, err)
	}
}

func TestProjectionStateRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := root + "/target.json"
	if err := saveProjectionState(target, projectionState{SchemaVersion: projectionSchema}); err != nil {
		t.Fatal(err)
	}
	link := root + "/link.json"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := saveProjectionState(link, projectionState{SchemaVersion: projectionSchema}); err == nil {
		t.Fatal("symlink projection state was accepted")
	}
}
