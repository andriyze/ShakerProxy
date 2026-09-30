package cloudconnector

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalMetadataClientUsesBoundedUnixAPI(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "connector.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(LocalConnectorStatus{Enrolled: true, SensorID: "sensor-1", OrganizationID: "org-1", ProtocolVersion: ProtocolVersion})
		case "/v1/metadata/enqueue":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	defer server.Shutdown(context.Background())

	client, err := NewLocalMetadataClient(socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(t.Context())
	if err != nil || !status.Enrolled || status.SensorID != "sensor-1" {
		t.Fatalf("unexpected connector status: %#v %v", status, err)
	}
	event := LocalMetadataEvent{EventID: "device-1", Type: MetadataDeviceUpsert, ObservedAt: time.Now().UTC(), Payload: json.RawMessage(`{"local_device_id":"device-1"}`)}
	if err := client.Enqueue(t.Context(), []LocalMetadataEvent{event}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalMetadataClientRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := NewLocalMetadataClient("relative.sock", 5*time.Second); err == nil {
		t.Fatal("relative connector socket was accepted")
	}
	if _, err := NewLocalMetadataClient(filepath.Join(os.TempDir(), "connector.sock"), 0); err == nil {
		t.Fatal("unbounded connector timeout was accepted")
	}
}
