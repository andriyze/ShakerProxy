package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/casework"
	"shakerproxy.dev/shakerproxy/internal/forwarder"
	"shakerproxy.dev/shakerproxy/internal/ingest"
	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
	"shakerproxy.dev/shakerproxy/internal/savedview"
)

func TestCaseManagementAPIRenamesEditsRemovesAndDeletes(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "gateway.sock")
	startGatewaySequenceStub(t, socketPath, capture.View{Session: capture.Session{ID: caseAPICaptureID}})
	caseStore := &casework.Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	server, session := configuredAPIServerWithConfig(t, socketPath, func(config *Config) { config.Cases = caseStore })
	snapshots := &eventQuerySnapshotRepositoryFake{}
	server.eventSnapshots = snapshots
	if _, err := snapshots.CreateEventQuerySnapshot(context.Background(), "admin", "device.name:TV", ingest.RecentEventQuery{}, time.Hour); err != nil {
		t.Fatal(err)
	}

	created := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases", `{"name":"TV firmware","description":"Line one\r\nLine two"}`, "")
	var item casework.Case
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &item) != nil || item.Description != "Line one\nLine two" {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	renamed := serveCaseRequest(t, server, session, http.MethodPatch, "/api/v1/cases/"+item.ID, `{"name":"TV firmware 2.1","description":"Steps:\n1. boot\n2. update"}`, "")
	if renamed.Code != http.StatusOK || json.Unmarshal(renamed.Body.Bytes(), &item) != nil || item.Name != "TV firmware 2.1" || item.Revision != 2 || item.Timeline[1].Action != "CASE_UPDATED" {
		t.Fatalf("rename returned %d: %s", renamed.Code, renamed.Body.String())
	}
	stale := serveCaseRequest(t, server, session, http.MethodPatch, "/api/v1/cases/"+item.ID, `{"expected_revision":1,"name":"Other"}`, "")
	if code, _ := decodeErrorBody(t, stale); stale.Code != http.StatusConflict || code != "case_revision_changed" {
		t.Fatalf("stale rename returned %d %s", stale.Code, code)
	}

	snapshotEvidence := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/"+item.ID+"/evidence", `{"kind":"QUERY_SNAPSHOT","artifact_id":"`+snapshots.snapshot.ID+`"}`, "")
	if snapshotEvidence.Code != http.StatusCreated || json.Unmarshal(snapshotEvidence.Body.Bytes(), &item) != nil {
		t.Fatalf("snapshot evidence returned %d: %s", snapshotEvidence.Code, snapshotEvidence.Body.String())
	}
	pinned := item.Evidence[0]
	if pinned.Kind != casework.EvidenceQuerySnapshot || pinned.Query == nil || pinned.Query.CanonicalQuery != "device.name:TV" || pinned.Query.MatchedCount != 42 || pinned.Query.DatasetWatermark.RecordID != strings.Repeat("a", 64) || !strings.HasPrefix(pinned.Label, "Traffic query: ") {
		t.Fatalf("query snapshot was not pinned: %#v", pinned)
	}
	expired := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/"+item.ID+"/evidence", `{"kind":"QUERY_SNAPSHOT","artifact_id":"qsnap-ffffffffffffffffffffffffffffffff"}`, "")
	if code, message := decodeErrorBody(t, expired); expired.Code != http.StatusUnprocessableEntity || code != "evidence_unavailable" || !strings.Contains(message, "freeze the query again") {
		t.Fatalf("missing snapshot returned %d %s %q", expired.Code, code, message)
	}
	captureEvidence := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/cases/"+item.ID+"/evidence", `{"kind":"CAPTURE","artifact_id":"`+caseAPICaptureID+`"}`, "")
	if captureEvidence.Code != http.StatusCreated || json.Unmarshal(captureEvidence.Body.Bytes(), &item) != nil || len(item.Evidence) != 2 {
		t.Fatalf("capture evidence returned %d: %s", captureEvidence.Code, captureEvidence.Body.String())
	}

	removed := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/cases/"+item.ID+"/evidence/"+pinned.ID, "", "")
	if removed.Code != http.StatusOK || json.Unmarshal(removed.Body.Bytes(), &item) != nil || len(item.Evidence) != 1 || item.Timeline[len(item.Timeline)-1].Action != "EVIDENCE_REMOVED" {
		t.Fatalf("evidence removal returned %d: %s", removed.Code, removed.Body.String())
	}
	missing := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/cases/"+item.ID+"/evidence/"+pinned.ID, "", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("removing absent evidence returned %d", missing.Code)
	}

	deleteWithoutPassword := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/cases/"+item.ID, "", "")
	if code, _ := decodeErrorBody(t, deleteWithoutPassword); deleteWithoutPassword.Code != http.StatusUnauthorized || code != "reauthentication_required" {
		t.Fatalf("case delete without confirmation returned %d %s", deleteWithoutPassword.Code, code)
	}
	deleted := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/cases/"+item.ID, `{"password":"`+activationTestPassword+`"}`, "")
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"deleted":true`) {
		t.Fatalf("case delete returned %d: %s", deleted.Code, deleted.Body.String())
	}
	if gone := serveCaseRequest(t, server, session, http.MethodGet, "/api/v1/cases/"+item.ID, "", ""); gone.Code != http.StatusNotFound {
		t.Fatalf("deleted case still readable: %d", gone.Code)
	}
}

func TestCaseDeleteAndEvidenceRemovalRespectActiveHold(t *testing.T) {
	caseStore := &casework.Store{Path: filepath.Join(t.TempDir(), "cases.json")}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.Cases = caseStore })
	item, err := caseStore.Create("Held", "", "admin", "create")
	if err != nil {
		t.Fatal(err)
	}
	item, err = caseStore.AddEvidence(item.ID, item.Revision, casework.EvidenceCapture, caseAPICaptureID, "Capture", "admin", "attach")
	if err != nil {
		t.Fatal(err)
	}
	item, err = caseStore.RecordHold(item.ID, item.Revision, true, "preserve", "admin", "case-hold-operation-9001", []casework.HoldResult{{EvidenceID: item.Evidence[0].ID, ArtifactID: caseAPICaptureID, Protected: true, Revision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	remove := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/cases/"+item.ID+"/evidence/"+item.Evidence[0].ID, "", "")
	if code, message := decodeErrorBody(t, remove); remove.Code != http.StatusConflict || code != "case_hold_active" || !strings.Contains(message, "release the hold") {
		t.Fatalf("removing held capture returned %d %s %q", remove.Code, code, message)
	}
	deleted := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/cases/"+item.ID, `{"password":"`+activationTestPassword+`"}`, "")
	if code, _ := decodeErrorBody(t, deleted); deleted.Code != http.StatusConflict || code != "case_hold_active" {
		t.Fatalf("deleting held case returned %d %s", deleted.Code, code)
	}
}

func TestForwarderAPIEditsAndDeletes(t *testing.T) {
	manager := &forwarder.Manager{Root: t.TempDir()}
	server, session := configuredAPIServerWithConfig(t, filepath.Join(t.TempDir(), "absent.sock"), func(config *Config) { config.Forwarders = manager })
	created, err := manager.Create(forwarder.CreateRequest{Name: "SOC", Kind: forwarder.KindWebhook, Destination: "https://hooks.example.com/events", Actor: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	id := created.Integration.ID
	unconfirmed := serveCaseRequest(t, server, session, http.MethodPatch, "/api/v1/integrations/forwarders/"+id, `{"name":"SOC 2"}`, "")
	if unconfirmed.Code != http.StatusUnauthorized {
		t.Fatalf("unconfirmed edit returned %d", unconfirmed.Code)
	}
	edited := serveCaseRequest(t, server, session, http.MethodPatch, "/api/v1/integrations/forwarders/"+id, `{"name":"SOC 2","destination":"https://hooks.example.net/shakerproxy","classes":["ALERT","AUDIT"],"password":"`+activationTestPassword+`"}`, "")
	var item forwarder.PublicIntegration
	if edited.Code != http.StatusOK || json.Unmarshal(edited.Body.Bytes(), &item) != nil || item.Name != "SOC 2" || item.Destination != "https://hooks.example.net/shakerproxy" || len(item.Classes) != 2 || item.Revision != 2 {
		t.Fatalf("edit returned %d: %s", edited.Code, edited.Body.String())
	}
	invalid := serveCaseRequest(t, server, session, http.MethodPatch, "/api/v1/integrations/forwarders/"+id, `{"destination":"http://127.0.0.1/x"}`, "")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("unsafe destination returned %d: %s", invalid.Code, invalid.Body.String())
	}
	deleted := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/integrations/forwarders/"+id, "", "")
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"deleted":true`) {
		t.Fatalf("delete returned %d: %s", deleted.Code, deleted.Body.String())
	}
	status, err := manager.Status()
	if err != nil || len(status) != 0 {
		t.Fatalf("forwarder still listed after delete: %#v %v", status, err)
	}
	again := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/integrations/forwarders/"+id, "", "")
	if code, _ := decodeErrorBody(t, again); again.Code != http.StatusNotFound || code != "forwarder_not_found" {
		t.Fatalf("second delete returned %d %s", again.Code, code)
	}
}

func inventoryAPIServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	server, _ := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	server.inventory = &deviceinventory.Store{Path: filepath.Join(t.TempDir(), "inventory.json")}
	seedInventoryDevice(t, server)
	token, _, err := server.newVerifiedSession("admin")
	if err != nil {
		t.Fatal(err)
	}
	return server, token, firstDeviceID(t, server)
}

func TestNoOpDeviceEditsReturnOKAndReplayAfterMergeDoesNotPanic(t *testing.T) {
	server, session, deviceID := inventoryAPIServer(t)
	first := serveCaseRequest(t, server, session, http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", `{"friendly_name":"Bench TV"}`, "")
	if first.Code != http.StatusOK {
		t.Fatalf("metadata update returned %d: %s", first.Code, first.Body.String())
	}
	same := serveCaseRequest(t, server, session, http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", `{"friendly_name":"Bench TV"}`, "")
	if same.Code != http.StatusOK || !strings.Contains(same.Body.String(), `"unchanged":true`) || strings.Contains(same.Body.String(), `"audit"`) {
		t.Fatalf("no-op metadata update returned %d: %s", same.Code, same.Body.String())
	}
	var device deviceinventory.Device
	snapshot, _ := server.inventory.Snapshot()
	device = snapshot.Devices[0]
	sameAlias := serveCaseRequest(t, server, session, http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", `{"friendly_name":"Bench TV","reason":"same","expected_revision":1}`, "")
	if sameAlias.Code != http.StatusOK || !strings.Contains(sameAlias.Body.String(), `"unchanged":true`) {
		t.Fatalf("no-op alias update returned %d: %s", sameAlias.Code, sameAlias.Body.String())
	}
	// Rename with a key, then merge the device away and replay the rename.
	renamed := serveCaseRequest(t, server, session, http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", `{"friendly_name":"Hall TV","reason":"moved","expected_revision":1}`, "alias-replay-after-merge-01")
	if renamed.Code != http.StatusOK {
		t.Fatalf("rename returned %d: %s", renamed.Code, renamed.Body.String())
	}
	lease := deviceinventory.DHCP4Lease{Address: netip.MustParseAddr("10.77.0.21"), HardwareAddr: "52:54:00:00:00:21", ValidLifetime: time.Hour, ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := server.inventory.ReconcileDHCP4([]deviceinventory.DHCP4Lease{{Address: netip.MustParseAddr("10.77.0.20"), HardwareAddr: "52:54:00:00:00:20", Hostname: "camera", ValidLifetime: time.Hour, ExpiresAt: time.Now().Add(time.Hour)}, lease}); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = server.inventory.Snapshot()
	target := ""
	for _, candidate := range snapshot.Devices {
		if candidate.ID != device.ID {
			target = candidate.ID
		}
	}
	merged := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/devices/"+target+"/merge", `{"source_device_id":"`+deviceID+`"}`, "")
	if merged.Code != http.StatusOK {
		t.Fatalf("merge returned %d: %s", merged.Code, merged.Body.String())
	}
	replay := serveCaseRequest(t, server, session, http.MethodPut, "/api/v1/devices/"+deviceID+"/alias", `{"friendly_name":"Hall TV","reason":"moved","expected_revision":1}`, "alias-replay-after-merge-01")
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replayed":true`) || !strings.Contains(replay.Body.String(), `"devices":[]`) {
		t.Fatalf("replay after merge returned %d: %s", replay.Code, replay.Body.String())
	}
}

func TestAddressAliasListDeleteAndResolveDefaultsToNow(t *testing.T) {
	server, session, _ := inventoryAPIServer(t)
	created := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/address-aliases", `{"name":"Bench switch","prefix":"10.77.0.2","interface":"lab0","valid_from":"2026-01-01T00:00:00Z","priority":10,"confidence":90,"reason":"static"}`, "")
	var result deviceinventory.AddressAliasMutationResult
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &result) != nil {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	listed := serveCaseRequest(t, server, session, http.MethodGet, "/api/v1/address-aliases", "", "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), result.Alias.ID) {
		t.Fatalf("list returned %d: %s", listed.Code, listed.Body.String())
	}
	resolved := serveCaseRequest(t, server, session, http.MethodGet, "/api/v1/address-aliases/resolve?address=10.77.0.2&interface=lab0", "", "")
	if resolved.Code != http.StatusOK || !strings.Contains(resolved.Body.String(), `"matched":true`) || !strings.Contains(resolved.Body.String(), "Bench switch") {
		t.Fatalf("resolve without at returned %d: %s", resolved.Code, resolved.Body.String())
	}
	badAt := serveCaseRequest(t, server, session, http.MethodGet, "/api/v1/address-aliases/resolve?address=10.77.0.2&interface=lab0&at=yesterday", "", "")
	if code, message := decodeErrorBody(t, badAt); badAt.Code != http.StatusBadRequest || code != "invalid_request" || !strings.Contains(message, "RFC 3339") {
		t.Fatalf("bad at returned %d %s %q", badAt.Code, code, message)
	}
	stale := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/address-aliases/"+result.Alias.ID, `{"expected_revision":9}`, "")
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale delete returned %d: %s", stale.Code, stale.Body.String())
	}
	deleted := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/address-aliases/"+result.Alias.ID, "", "address-alias-delete-0001")
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"deleted":true`) {
		t.Fatalf("delete returned %d: %s", deleted.Code, deleted.Body.String())
	}
	replay := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/address-aliases/"+result.Alias.ID, "", "address-alias-delete-0001")
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"replayed":true`) {
		t.Fatalf("delete replay returned %d: %s", replay.Code, replay.Body.String())
	}
	gone := serveCaseRequest(t, server, session, http.MethodDelete, "/api/v1/address-aliases/"+result.Alias.ID, "", "")
	if gone.Code != http.StatusNotFound {
		t.Fatalf("delete of missing alias returned %d", gone.Code)
	}
}

func TestDeviceAuditSupportsCursorPaging(t *testing.T) {
	server, session, deviceID := inventoryAPIServer(t)
	for _, notes := range []string{"one", "two", "three", "four", "five"} {
		if response := serveCaseRequest(t, server, session, http.MethodPut, "/api/v1/devices/"+deviceID+"/metadata", `{"notes":"`+notes+`"}`, ""); response.Code != http.StatusOK {
			t.Fatalf("metadata update returned %d", response.Code)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 5; pages++ {
		target := "/api/v1/device-audit?limit=2"
		if cursor != "" {
			target += "&before=" + cursor
		}
		response := serveCaseRequest(t, server, session, http.MethodGet, target, "", "")
		var page deviceinventory.AuditPage
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.RetainedEvents != 5 {
			t.Fatalf("audit page returned %d: %s", response.Code, response.Body.String())
		}
		for _, event := range page.Events {
			if seen[event.ID] {
				t.Fatalf("audit event %s repeated across pages", event.ID)
			}
			seen[event.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("paging returned %d of 5 events", len(seen))
	}
	invalid := serveCaseRequest(t, server, session, http.MethodGet, "/api/v1/device-audit?before=audit-ffffffffffffffffffffffffffffffff", "", "")
	if code, _ := decodeErrorBody(t, invalid); invalid.Code != http.StatusBadRequest || code != "invalid_cursor" {
		t.Fatalf("unknown cursor returned %d %s", invalid.Code, code)
	}
}

func TestSavedViewDuplicateInheritsScopeAndBackendRejectionsAreBadRequests(t *testing.T) {
	server, session := configuredAPIServer(t, filepath.Join(t.TempDir(), "absent.sock"))
	repository := &savedViewRepositoryFake{}
	server.savedViews = repository
	created := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/saved-views", `{"scope":"shared","name":"Shared DNS","page":"live-traffic","canonical_query":"source:zeek","time_behavior":{"mode":"query"},"sort":[{"field":"occurred_at","direction":"desc"}],"columns":["source","occurred_at"],"pinned_columns":["source"],"density":"compact","chart":{"visible":false}}`, "")
	var view savedview.View
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &view) != nil {
		t.Fatalf("create returned %d: %s", created.Code, created.Body.String())
	}
	duplicate := serveCaseRequest(t, server, session, http.MethodPost, "/api/v1/saved-views/"+view.ID+"/duplicate", `{}`, "")
	var copy savedview.View
	if duplicate.Code != http.StatusCreated || json.Unmarshal(duplicate.Body.Bytes(), &copy) != nil || copy.Configuration.Scope != savedview.ScopeShared || copy.Configuration.Name != "Shared DNS (copy)" {
		t.Fatalf("duplicate returned %d: %s", duplicate.Code, duplicate.Body.String())
	}
	recorder := httptest.NewRecorder()
	server.writeSavedViewError(recorder, &savedview.InvalidError{Message: "saved view query is invalid"})
	if code, message := decodeErrorBody(t, recorder); recorder.Code != http.StatusBadRequest || code != "invalid_saved_view" || !strings.Contains(message, "query is invalid") {
		t.Fatalf("backend rejection mapped to %d %s %q", recorder.Code, code, message)
	}
}
