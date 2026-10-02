package agentapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const parityRecordID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func exchangeBody(cookie string) string {
	return `{"schema":1,"record_id":"` + parityRecordID + `","source":"CAPTURE","state":"AVAILABLE","matched":0,"exchanges":[{"request":{"method":"GET","target":"/","proto":"HTTP/1.1","headers":{"items":[{"name":"Host","value":"tv.example"},{"name":"Cookie","value":"` + cookie + `","sensitive":true}],"bytes":20},"body":{"content_type":"","body_bytes":0,"decoded_preview":false,"preview_bytes":0,"preview_encoding":"utf-8","preview":"","truncated":false,"complete":true}}}]}`
}

func TestHTTPExchangeRequiresTheServersRedactionMarker(t *testing.T) {
	for name, testCase := range map[string]struct {
		marker, cookie string
		ok             bool
	}{
		"redacted":           {"credentials-redacted", "[redacted]", true},
		"no marker":          {"", "[redacted]", false},
		"marker but cookies": {"credentials-redacted", "sid=secret", false},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/events/"+parityRecordID+"/http-exchange" || r.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(w, "unexpected", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if testCase.marker != "" {
					w.Header().Set("X-ShakerProxy-HTTP-Exchange", testCase.marker)
				}
				fmt.Fprint(w, exchangeBody(testCase.cookie))
			}))
			defer server.Close()
			client, err := NewClient(server.URL, testToken, nil)
			if err != nil {
				t.Fatal(err)
			}
			exchange, err := client.HTTPExchange(context.Background(), parityRecordID)
			if testCase.ok != (err == nil) {
				t.Fatalf("err = %v", err)
			}
			if testCase.ok && (len(exchange.Exchanges) != 1 || exchange.Exchanges[0].Request.Headers.Items[1].Value != "[redacted]") {
				t.Fatalf("exchange = %+v", exchange)
			}
		})
	}
}

func liveEventJSON(id string) string {
	return `{"record_id":"` + id + `","source":"ZEEK","kind":"zeek.dns","occurred_at":"2026-10-02T15:00:00Z","received_at":"2026-10-02T15:00:01Z","source_version":"8.2.1","parser_version":"1","device_friendly_name_at_capture_known":false,"confidence":90,"dns_query":"example.com"}`
}

func TestFollowTrafficReturnsTheFirstBatchAfterTheCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events/live" || r.URL.Query().Get("cursor") != "start" || r.URL.Query().Get("q") != "service:dns" || r.URL.Query().Get("limit") != "10" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		fmt.Fprint(w, ": connected\n\n: heartbeat\n\n")
		flusher.Flush()
		fmt.Fprintf(w, "id: next\nevent: events\ndata: {\"schema\":1,\"generated_at\":\"2026-10-02T15:00:02Z\",\"events\":[%s,%s],\"next_cursor\":\"next\",\"device_labels_available\":true}\n\n",
			liveEventJSON(strings.Repeat("a", 64)), liveEventJSON(strings.Repeat("b", 64)))
		flusher.Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := client.FollowTraffic(context.Background(), FollowRequest{Query: "service:dns", Cursor: "start", Limit: 10, Wait: 5 * time.Second})
	if err != nil || len(batch.Events) != 2 || batch.NextCursor != "next" || batch.TimedOut || batch.Events[0].DNSQuery != "example.com" {
		t.Fatalf("batch = %+v err=%v", batch, err)
	}
}

func TestFollowTrafficKeepsTheCursorWhenNothingArrives(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": connected\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := NewClient(server.URL, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	batch, err := client.FollowTraffic(context.Background(), FollowRequest{Cursor: "start", Limit: 5, Wait: 200 * time.Millisecond})
	if err != nil || len(batch.Events) != 0 || batch.NextCursor != "start" || !batch.TimedOut || time.Since(started) > 5*time.Second {
		t.Fatalf("batch = %+v err=%v after %s", batch, err, time.Since(started))
	}
	if _, err := client.FollowTraffic(context.Background(), FollowRequest{Limit: 5}); err == nil {
		t.Fatal("follow without a cursor was accepted")
	}
	if _, err := client.FollowTraffic(context.Background(), FollowRequest{Cursor: "x", Limit: 5, Wait: time.Minute}); err == nil {
		t.Fatal("an unbounded wait was accepted")
	}
}

func TestAgentDeviceNamingFieldsAreValidated(t *testing.T) {
	now := time.Date(2026, 10, 2, 15, 0, 0, 0, time.UTC)
	device := Device{Schema: 1, ID: "device-" + strings.Repeat("a", 32), DisplayName: "Pixel", Addresses: []DeviceAddress{}, Hostnames: []DeviceHostname{}, FirstSeen: now, LastSeen: now,
		PinnedAddress: "192.168.10.201", FormerIDs: []string{"device-" + strings.Repeat("b", 32)}}
	if err := validateAgentDevice(device); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Device){
		"bad pinned address": func(d *Device) { d.PinnedAddress = "192.168.10.201/24" },
		"own ID as former":   func(d *Device) { d.FormerIDs = []string{d.ID} },
		"bad former ID":      func(d *Device) { d.FormerIDs = []string{"aa:bb:cc:dd:ee:ff"} },
		"too many former":    func(d *Device) { d.FormerIDs = make([]string, 17) },
	} {
		changed := device
		change(&changed)
		if validateAgentDevice(changed) == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
