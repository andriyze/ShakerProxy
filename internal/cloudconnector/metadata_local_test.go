package cloudconnector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLocalServerWiresBoundedMetadataQueue(t *testing.T) {
	now := time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)
	queue := &MetadataQueue{Root: t.TempDir(), Now: func() time.Time { return now }}
	handler := LocalServer{MetadataQueue: queue}.Handler()

	body := `{"events":[{"event_id":"event-test","type":"dns.event","observed_at":"2026-09-02T18:00:00Z","payload":{"query":"example.test"}}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/metadata/enqueue", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("metadata enqueue failed with %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/metadata/status", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metadata status failed with %d: %s", response.Code, response.Body.String())
	}
	var summary struct {
		EventCount int `json:"event_count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &summary); err != nil || summary.EventCount != 1 {
		t.Fatalf("metadata queue status mismatch: %+v %v", summary, err)
	}
}

func TestLocalMetadataAPIRejectsQueryAndTrailingJSON(t *testing.T) {
	queue := &MetadataQueue{Root: t.TempDir()}
	handler := LocalServer{MetadataQueue: queue}.Handler()
	for _, target := range []string{"/v1/metadata/status?extra=1", "/v1/metadata/enqueue?extra=1"} {
		request := httptest.NewRequest(map[string]string{"/v1/metadata/status?extra=1": http.MethodGet, "/v1/metadata/enqueue?extra=1": http.MethodPost}[target], target, strings.NewReader(`{"events":[]}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query was accepted by %s: %d", target, response.Code)
		}
	}
	if _, err := decodeMetadataEnqueue(strings.NewReader(`{"events":[]} {"events":[]}`), 1024); err == nil {
		t.Fatal("trailing metadata JSON was accepted")
	}
}

func TestLocalMetadataPersistsStableDeviceRuntime(t *testing.T) {
	now := time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)
	root := t.TempDir()
	queue := &MetadataQueue{Root: root, Now: func() time.Time { return now }}
	deviceRuntime := &DeviceRuntimeStore{Root: root, Now: func() time.Time { return now }}
	handler := LocalServer{Client: Client{Root: root}, MetadataQueue: queue, DeviceRuntime: deviceRuntime}.Handler()
	body := `{"events":[{"event_id":"device-observation","type":"device.upsert","observed_at":"2026-09-02T18:00:00Z","payload":{"local_device_id":"device-tv","friendly_name":"Living Room TV","platform":"Google TV","current_ipv4":"10.44.0.15","last_seen_at":"2026-09-02T18:00:00Z"}}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/metadata/enqueue", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("device metadata enqueue failed with %d: %s", response.Code, response.Body.String())
	}
	snapshot, err := deviceRuntime.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DevicePlatforms["device-tv"] != "android-tv" || snapshot.DeviceByIP["10.44.0.15"] != "device-tv" || snapshot.FriendlyNames["device-tv"] != "Living Room TV" {
		t.Fatalf("device runtime was not projected from metadata: %#v", snapshot)
	}
}
