package server

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/inventory"
)

func TestDeviceInventoryReconcilesKeaLeaseWithoutPrivilegedRPC(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	directory := t.TempDir()
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	expiry := time.Now().Add(10 * time.Minute).Unix()
	contents := fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n10.77.0.111,52:54:00:ab:cd:01,01:52:54:00:ab:cd:01,600,%d,1,0,0,camera.local,0,,0\n", expiry)
	if err := os.WriteFile(server.keaLeasePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.refreshInventory(); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	request.Host = "shakerproxy.test"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	var snapshot inventory.Snapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || !snapshot.Devices[0].Online || snapshot.Devices[0].AttributionConfidence != 95 || snapshot.Devices[0].Identities[0].Kind != inventory.IdentityDHCPClientID {
		t.Fatalf("unexpected inventory: %#v", snapshot)
	}

	detailRequest := httptest.NewRequest(http.MethodGet, "/api/v1/devices/"+snapshot.Devices[0].ID, nil)
	detailRequest.Host = "shakerproxy.test"
	detailRequest.Header.Set("Authorization", "Bearer "+session)
	detailRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(detailRecorder, detailRequest)
	if detailRecorder.Code != http.StatusOK {
		t.Fatalf("unexpected detail response %d: %s", detailRecorder.Code, detailRecorder.Body.String())
	}
}

func TestDeviceInventoryBindsLeasesToConfirmedGatewayScope(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "gateway.sock")
	server, _ := configuredAPIServer(t, socketPath)
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	expiry := time.Now().Add(10 * time.Minute).Unix()
	contents := fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n10.77.0.113,52:54:00:ab:cd:03,01:52:54:00:ab:cd:03,600,%d,1,0,0,fixture.local,0,,0\n", expiry)
	if err := os.WriteFile(server.keaLeasePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	vlan := 20
	requests := startGatewayStub(t, socketPath, gatewayprotocol.Status{LabInterface: "enp2s0.20", LabVLANID: &vlan, LabScopePlanHash: activationTestPlanHash})
	snapshot, err := server.refreshInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || len(snapshot.Devices[0].Addresses) != 1 {
		t.Fatalf("unexpected scoped inventory: %#v", snapshot)
	}
	address := snapshot.Devices[0].Addresses[0]
	if address.Interface != "enp2s0.20" || address.VLANID == nil || *address.VLANID != 20 || address.ScopePlanSHA256 != activationTestPlanHash {
		t.Fatalf("confirmed gateway scope was not bound to the lease: %#v", address)
	}
	select {
	case request := <-requests:
		if request.Method != "GetManagedState" {
			t.Fatalf("unexpected gateway method %q", request.Method)
		}
	case <-time.After(time.Second):
		t.Fatal("inventory reconciliation did not request managed gateway state")
	}
}

func TestDeviceInventoryRejectsMalformedLeaseEvidence(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	directory := t.TempDir()
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	if err := os.WriteFile(server.keaLeasePath, []byte("attacker-controlled,not-kea\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.refreshInventory(); err == nil {
		t.Fatal("malformed lease evidence was accepted by the background adapter")
	}
}

func TestDeviceInventoryRequiresAuthentication(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	request.Host = "shakerproxy.test"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected response %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/device-audit", nil)
	request.Host = "shakerproxy.test"
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated device audit returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/devices/device-0123456789abcdef0123456789abcdef/traffic-deletion-preview", strings.NewReader(`{}`))
	request.Host = "shakerproxy.test"
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated device traffic deletion preview returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodPut, "/api/v1/devices/device-0123456789abcdef0123456789abcdef/metadata", strings.NewReader(`{}`))
	request.Host = "shakerproxy.test"
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated device mutation returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeviceInventoryQueryIsStrictScopedAndDeterministic(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	vlan := 20
	planHash := strings.Repeat("e", 64)
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.10"), HardwareAddr: "52:54:00:00:00:10", Hostname: "old-sensor", ValidLifetime: time.Hour, ExpiresAt: now.Add(-48 * time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.20"), HardwareAddr: "52:54:00:00:00:20", Hostname: "camera", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour), Interface: "enp2s0.20", VLANID: &vlan, ScopePlanSHA256: planHash},
	})
	if err != nil || len(snapshot.Devices) != 2 {
		t.Fatalf("seed inventory failed: %#v err=%v", snapshot, err)
	}
	var currentID, oldID string
	for _, device := range snapshot.Devices {
		if device.Online {
			currentID = device.ID
		} else {
			oldID = device.ID
		}
	}
	if _, err := server.inventory.UpdateMetadata(currentID, "admin", "device-query-meta-01", inventory.DeviceMetadata{FriendlyName: "Alpha Camera", Category: "camera", Tags: []string{"reviewed", "test bench"}, Notes: "north fixture"}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.inventory.UpdateMetadata(oldID, "admin", "device-query-meta-02", inventory.DeviceMetadata{FriendlyName: "Zulu Sensor", Category: "sensor", Tags: []string{"legacy"}}); err != nil {
		t.Fatal(err)
	}
	query := func(target string) (int, inventory.Snapshot) {
		request := authenticatedJSONRequest(http.MethodGet, target, "", session, "")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		var result inventory.Snapshot
		_ = json.Unmarshal(recorder.Body.Bytes(), &result)
		return recorder.Code, result
	}
	if code, result := query("/api/v1/devices?view=online&interface=enp2s0.20&vlan_id=20&category=camera&tag=reviewed&q=north&ip_family=ipv4&min_confidence=80"); code != http.StatusOK || len(result.Devices) != 1 || result.Devices[0].ID != currentID {
		t.Fatalf("scoped query returned code=%d devices=%#v", code, result.Devices)
	}
	if code, result := query("/api/v1/devices?view=recent"); code != http.StatusOK || len(result.Devices) != 1 || result.Devices[0].ID != currentID {
		t.Fatalf("recent view returned code=%d devices=%#v", code, result.Devices)
	}
	if code, result := query("/api/v1/devices?tag=test%20bench&q=camera"); code != http.StatusOK || len(result.Devices) != 1 || result.Devices[0].ID != currentID {
		t.Fatalf("canonical tag and suggested-name search returned code=%d devices=%#v", code, result.Devices)
	}
	if code, result := query("/api/v1/devices?sort=name&direction=asc"); code != http.StatusOK || len(result.Devices) != 2 || result.Devices[0].FriendlyName != "Alpha Camera" || result.Devices[1].FriendlyName != "Zulu Sensor" {
		t.Fatalf("name ordering returned code=%d devices=%#v", code, result.Devices)
	}
	// Tag and category filters are case- and whitespace-insensitive.
	for _, target := range []string{"/api/v1/devices?tag=Reviewed", "/api/v1/devices?tag=%20REVIEWED%20", "/api/v1/devices?category=Camera&tag=Test%20Bench"} {
		if code, result := query(target); code != http.StatusOK || len(result.Devices) != 1 || result.Devices[0].ID != currentID {
			t.Fatalf("normalized filter %q returned code=%d devices=%#v", target, code, result.Devices)
		}
	}
	for _, target := range []string{"/api/v1/devices?unknown=true", "/api/v1/devices?view=online&view=all", "/api/v1/devices?vlan_id=4095", "/api/v1/devices?category=camera.home", "/api/v1/devices?ip_family=ipx", "/api/v1/devices?min_confidence=101", "/api/v1/devices?warnings=maybe"} {
		if code, _ := query(target); code != http.StatusBadRequest {
			t.Fatalf("invalid query %q returned %d", target, code)
		}
	}
}

func TestInventorySyncReconcilesImmediatelyAndStopsWithContext(t *testing.T) {
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	directory := t.TempDir()
	server.inventory = &inventory.Store{Path: filepath.Join(directory, "inventory.json")}
	server.keaLeasePath = filepath.Join(directory, "kea-leases4.csv")
	expiry := time.Now().Add(10 * time.Minute).Unix()
	contents := fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n10.77.0.112,52:54:00:ab:cd:02,01:52:54:00:ab:cd:02,600,%d,1,0,0,sensor.local,0,,0\n", expiry)
	if err := os.WriteFile(server.keaLeasePath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { server.RunInventorySync(ctx, time.Hour); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		snapshot, err := server.inventory.Snapshot()
		if err == nil && len(snapshot.Devices) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background reconciliation did not complete: %#v err=%v", snapshot, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("inventory sync did not stop with its context")
	}
}

func TestDeviceMetadataEndpointReauthenticatesAndAuditsIdempotently(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	now := time.Now().UTC()
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:ab:cd:01", ClientID: "01:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	invalid := authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", `{"password":"`+activationTestPassword+`","friendly_name":"Bench Camera","owner":"Lab","tags":[],"notes":"","unexpected":true}`, session, "device-metadata-api-0000")
	invalidRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(invalidRecorder, invalid)
	if invalidRecorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown metadata field returned %d: %s", invalidRecorder.Code, invalidRecorder.Body.String())
	}
	body := `{"password":"wrong","friendly_name":"Bench Camera","owner":"Lab","location":"North bench","category":"camera","icon":"camera","tags":["Camera"],"notes":"Authorized"}`
	request := authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", body, session, "device-metadata-api-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("failed reauthentication returned %d: %s", recorder.Code, recorder.Body.String())
	}
	body = `{"password":"` + activationTestPassword + `","friendly_name":"Bench Camera","owner":"Lab","location":"North bench","category":"Camera","icon":"camera","tags":["Camera","bench"],"notes":"Authorized"}`
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", body, session, "device-metadata-api-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"friendly_name":"Bench Camera"`) || !strings.Contains(recorder.Body.String(), `"location":"North bench"`) || !strings.Contains(recorder.Body.String(), `"category":"camera"`) || !strings.Contains(recorder.Body.String(), `"icon":"camera"`) || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("metadata update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", body, session, "device-metadata-api-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"replayed":true`) {
		t.Fatalf("metadata replay returned %d: %s", recorder.Code, recorder.Body.String())
	}
	unsafeBody := `{"password":"` + activationTestPassword + `","friendly_name":"Bench Camera","owner":"Lab","location":"North bench","category":"camera","icon":"data-svg","tags":[],"notes":""}`
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", unsafeBody, session, "device-metadata-api-0002")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("unsafe icon returned %d: %s", recorder.Code, recorder.Body.String())
	}
	legacyBody := `{"password":"` + activationTestPassword + `","notes":"Updated by an older client"}`
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", legacyBody, session, "device-metadata-api-0003")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"notes":"Updated by an older client"`) || !strings.Contains(recorder.Body.String(), `"location":"North bench"`) || !strings.Contains(recorder.Body.String(), `"category":"camera"`) || !strings.Contains(recorder.Body.String(), `"icon":"camera"`) {
		t.Fatalf("legacy metadata patch did not preserve additive fields: %d %s", recorder.Code, recorder.Body.String())
	}
	auditRequest := httptest.NewRequest(http.MethodGet, "/api/v1/device-audit?limit=10", nil)
	auditRequest.Host = "shakerproxy.test"
	auditRequest.Header.Set("Authorization", "Bearer "+session)
	auditRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(auditRecorder, auditRequest)
	if auditRecorder.Code != http.StatusOK || !strings.Contains(auditRecorder.Body.String(), `"action":"DEVICE_METADATA_UPDATED"`) || !strings.Contains(auditRecorder.Body.String(), `"actor":"admin"`) || strings.Contains(auditRecorder.Body.String(), activationTestPassword) {
		t.Fatalf("device audit returned %d: %s", auditRecorder.Code, auditRecorder.Body.String())
	}
}

func TestAddressAliasAPIRequiresScopeReauthenticationAndRevision(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	now := time.Date(2026, 9, 1, 18, 0, 0, 0, time.UTC)
	server.inventory.Now = func() time.Time { return now }
	body := `{"password":"wrong","name":"Bench camera","prefix":"10.77.0.44","interface":"enp2s0","vlan_id":20,"valid_from":"2026-09-01T17:00:00Z","priority":25,"confidence":80,"reason":"Manual fixture label"}`
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/address-aliases", body, session, "address-alias-api-0001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("failed reauthentication returned %d: %s", recorder.Code, recorder.Body.String())
	}
	body = strings.Replace(body, `"wrong"`, `"`+activationTestPassword+`"`, 1)
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/address-aliases", body, session, "address-alias-api-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"prefix":"10.77.0.44/32"`) || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("address alias creation returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var created inventory.AddressAliasMutationResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/address-aliases", body, session, "address-alias-api-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"replayed":true`) {
		t.Fatalf("address alias replay returned %d: %s", recorder.Code, recorder.Body.String())
	}
	update := strings.TrimSuffix(body, "}") + `,"expected_revision":1}`
	update = strings.Replace(update, `"Bench camera"`, `"North bench camera"`, 1)
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/address-aliases/"+created.Alias.ID, update, session, "address-alias-api-0002")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"revision":2`) || !strings.Contains(recorder.Body.String(), `"name":"North bench camera"`) {
		t.Fatalf("address alias update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/address-aliases/"+created.Alias.ID, update, session, "address-alias-api-0003")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"address_alias_revision_conflict"`) {
		t.Fatalf("stale address alias update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	resolveURL := "/api/v1/address-aliases/resolve?address=10.77.0.44&interface=enp2s0&vlan_id=20&at=2026-09-01T18%3A00%3A00Z"
	request = authenticatedJSONRequest(http.MethodGet, resolveURL, "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"matched":true`) || !strings.Contains(recorder.Body.String(), `"name":"North bench camera"`) {
		t.Fatalf("address alias resolution returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/address-aliases", strings.TrimSuffix(body, "}")+`,"unexpected":true}`, session, "address-alias-api-0004")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown address alias field returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeviceAPIsProjectReviewOnlyDHCPNameSuggestions(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	now := time.Now().UTC()
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.77"), HardwareAddr: "52:54:00:00:00:77", Hostname: "camera-77.local", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	for _, path := range []string{"/api/v1/devices", "/api/v1/devices/" + deviceID} {
		request := authenticatedJSONRequest(http.MethodGet, path, "", session, "")
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"suggested_names":[{"name":"camera-77.local","source":"DHCP4_LEASE","confidence":75`) {
			t.Fatalf("%s omitted bounded suggestion evidence: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	body := `{"password":"` + activationTestPassword + `","friendly_name":"camera-77.local","reason":"Reviewed DHCP hostname","expected_revision":0}`
	request := authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", body, session, "device-suggestion-api-01")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), `"suggested_names"`) {
		t.Fatalf("accepted alias remained a suggestion: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeviceAliasExportIsAuthenticatedBoundedAndStandardsCompliant(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	now := time.Now().UTC()
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.88"), HardwareAddr: "52:54:00:00:00:88", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	if _, err := server.inventory.UpdateMetadata(deviceID, "admin", "device-export-api-01", inventory.DeviceMetadata{FriendlyName: `Bench, "Camera"`, Owner: "Secret owner", Tags: []string{"camera,lab", "reviewed"}, Notes: "Secret note"}); err != nil {
		t.Fatal(err)
	}
	unauthenticated := authenticatedJSONRequest(http.MethodGet, "/api/v1/device-aliases/export?format=json", "", session, "")
	unauthenticated.Header.Del("Authorization")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, unauthenticated)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated export returned %d", recorder.Code)
	}
	request := authenticatedJSONRequest(http.MethodGet, "/api/v1/device-aliases/export?format=json", "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Header().Get("Content-Disposition"), ".json") || !strings.Contains(recorder.Body.String(), `"friendly_name": "Bench, \"Camera\""`) || strings.Contains(recorder.Body.String(), "Secret owner") || strings.Contains(recorder.Body.String(), "Secret note") {
		t.Fatalf("JSON alias export was unsafe or incomplete: %d %#v %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodGet, "/api/v1/device-aliases/export?format=csv", "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatalf("CSV alias export returned %d: %s", recorder.Code, recorder.Body.String())
	}
	reader := csv.NewReader(strings.NewReader(recorder.Body.String()))
	records, err := reader.ReadAll()
	if err != nil || len(records) != 2 || strings.Join(records[0], ",") != "device_id,friendly_name,alias_revision,tags_json" || records[1][0] != deviceID || records[1][1] != `Bench, "Camera"` || records[1][2] != "1" || records[1][3] != `["camera,lab","reviewed"]` {
		t.Fatalf("CSV alias export did not round-trip fields: %#v err=%v", records, err)
	}
	request = authenticatedJSONRequest(http.MethodGet, "/api/v1/device-aliases/export?format=xml", "", session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unsupported export format returned %d", recorder.Code)
	}
}

func TestDeviceAliasImportAPIRequiresPreviewReauthenticationAndExactReplay(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	now := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.99"), HardwareAddr: "52:54:00:00:00:99", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID
	document, err := json.Marshal(inventory.AliasTagExport{Schema: inventory.SchemaVersion, GeneratedAt: now, Entries: []inventory.AliasTagExportEntry{{DeviceID: deviceID, FriendlyName: "Imported camera", AliasRevision: 0, Tags: []string{"Camera", "Imported"}}}})
	if err != nil {
		t.Fatal(err)
	}
	previewBody, err := json.Marshal(map[string]any{"format": "json", "content": string(document), "reason": "Reviewed inventory worksheet"})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/device-aliases/import-preview", string(previewBody), session, "")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(recorder.Body.String(), `"ready":true`) || !strings.Contains(recorder.Body.String(), `"expected_tags_sha256"`) {
		t.Fatalf("alias/tag import preview returned %d: %s", recorder.Code, recorder.Body.String())
	}
	unchanged, err := server.inventory.Get(deviceID)
	if err != nil || unchanged.FriendlyName != "" || len(unchanged.Tags) != 0 {
		t.Fatalf("preview mutated inventory: %#v err=%v", unchanged, err)
	}
	var preview inventory.AliasTagImportPreview
	if err := json.Unmarshal(recorder.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	applyBody, err := json.Marshal(map[string]any{"password": "wrong", "preview": preview})
	if err != nil {
		t.Fatal(err)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/device-aliases/import", string(applyBody), session, "device-import-api-001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("import without reauthentication returned %d", recorder.Code)
	}
	applyBody, err = json.Marshal(map[string]any{"password": activationTestPassword, "preview": preview})
	if err != nil {
		t.Fatal(err)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/device-aliases/import", string(applyBody), session, "device-import-api-001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"updated_devices":1`) || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("import apply returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/device-aliases/import", string(applyBody), session, "device-import-api-001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"replayed":true`) {
		t.Fatalf("import replay returned %d: %s", recorder.Code, recorder.Body.String())
	}
	updated, err := server.inventory.Get(deviceID)
	if err != nil || updated.FriendlyName != "Imported camera" || !slices.Equal(updated.Tags, []string{"camera", "imported"}) {
		t.Fatalf("import was not applied: %#v err=%v", updated, err)
	}
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/device-aliases/import-preview", strings.TrimSuffix(string(previewBody), "}")+`,"unexpected":true}`, session, "")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown import preview field returned %d", recorder.Code)
	}
}

func TestDeviceAliasEndpointUsesOptimisticConcurrencyAndHistory(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json"), Now: func() time.Time { return now }}
	server.nameResolver = &inventory.NameResolver{Store: server.inventory}
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:ab:cd:01", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	deviceID := snapshot.Devices[0].ID

	invalid := authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", `{"password":"`+activationTestPassword+`","friendly_name":"Bench Camera","reason":"Asset label","expected_revision":0,"unexpected":true}`, session, "device-alias-api-0000")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, invalid)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown alias field returned %d: %s", recorder.Code, recorder.Body.String())
	}
	wrongPasswordBody := `{"password":"wrong","friendly_name":"Bench Camera","reason":"Matched asset label","expected_revision":0}`
	request := authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", wrongPasswordBody, session, "device-alias-api-auth")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("failed alias reauthentication returned %d: %s", recorder.Code, recorder.Body.String())
	}

	body := `{"password":"` + activationTestPassword + `","friendly_name":"Bench Camera","reason":"Matched asset label","expected_revision":0}`
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", body, session, "device-alias-api-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"alias_revision":1`) || !strings.Contains(recorder.Body.String(), `"previous_friendly_name":""`) || !strings.Contains(recorder.Body.String(), `"reason":"Matched asset label"`) || strings.Contains(recorder.Body.String(), activationTestPassword) {
		t.Fatalf("alias update returned %d: %s", recorder.Code, recorder.Body.String())
	}
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", body, session, "device-alias-api-0001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"replayed":true`) {
		t.Fatalf("alias replay returned %d: %s", recorder.Code, recorder.Body.String())
	}
	staleBody := `{"password":"` + activationTestPassword + `","friendly_name":"North Camera","reason":"Moved","expected_revision":0}`
	request = authenticatedJSONRequest(http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", staleBody, session, "device-alias-api-0002")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"alias_revision_conflict"`) {
		t.Fatalf("stale alias revision returned %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeviceSplitAndMergeEndpointsRequireExactEvidenceAndAuditBoth(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.inventory = &inventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	now := time.Now().UTC()
	snapshot, err := server.inventory.ReconcileDHCP4([]inventory.DHCP4Lease{
		{Address: netip.MustParseAddr("10.77.0.111"), HardwareAddr: "52:54:00:ab:cd:01", ClientID: "01:01", Hostname: "first", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
		{Address: netip.MustParseAddr("10.77.0.112"), HardwareAddr: "52:54:00:ab:cd:01", ClientID: "01:02", Hostname: "second", ValidLifetime: time.Hour, ExpiresAt: now.Add(time.Hour)},
	})
	if err != nil || len(snapshot.Devices) != 1 {
		t.Fatalf("seed inventory failed: %#v err=%v", snapshot, err)
	}
	source := snapshot.Devices[0]
	selectedAddress := source.Addresses[1]
	for _, candidate := range source.Addresses {
		if candidate.Address == "10.77.0.112" {
			selectedAddress = candidate
		}
	}
	payload, err := json.Marshal(splitDeviceRequest{Password: activationTestPassword, Selection: inventory.SplitSelection{
		Identities: []inventory.IdentitySelector{{Kind: inventory.IdentityDHCPClientID, Value: "01:02", Source: inventory.SourceDHCP4Lease}},
		Addresses:  []inventory.AddressSelector{{Address: selectedAddress.Address, Source: selectedAddress.Source, ValidFrom: selectedAddress.ValidFrom, ValidUntil: selectedAddress.ValidUntil}},
		Hostnames:  []inventory.HostnameSelector{{Hostname: "second", Source: inventory.SourceDHCP4Lease}},
		Metadata:   inventory.DeviceMetadata{FriendlyName: "Split Fixture"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+source.ID+"/split", string(payload), session, "device-split-api-00001")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("split returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var splitResult inventory.MutationResult
	if json.Unmarshal(recorder.Body.Bytes(), &splitResult) != nil || len(splitResult.Devices) != 2 {
		t.Fatalf("invalid split response: %s", recorder.Body.String())
	}
	newID := splitResult.Audit.ResultDeviceIDs[1]
	mergeBody := `{"password":"` + activationTestPassword + `","source_device_id":"` + newID + `"}`
	request = authenticatedJSONRequest(http.MethodPost, "/api/v1/devices/"+source.ID+"/merge", mergeBody, session, "device-merge-api-00001")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"action":"DEVICES_MERGED"`) {
		t.Fatalf("merge returned %d: %s", recorder.Code, recorder.Body.String())
	}
	audit, err := server.inventory.AuditLog(10)
	if err != nil || len(audit) != 2 || audit[0].Action != inventory.AuditDevicesMerged || audit[1].Action != inventory.AuditDeviceSplit {
		t.Fatalf("unexpected split/merge audit: %#v err=%v", audit, err)
	}
}
