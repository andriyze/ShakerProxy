package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/configlock"
	"shakerproxy.dev/shakerproxy/internal/firewall"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
	"shakerproxy.dev/shakerproxy/internal/pcapng"
)

func TestPrivilegedMutationHonorsApplianceConfigurationLock(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := &configlock.Manager{Path: filepath.Join(t.TempDir(), "config.lock")}
	current, err := manager.Acquire(t.Context(), configlock.Request{OperationID: "update-01234567", Category: configlock.CategoryUpdate, Actor: "installer"})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Release()
	server := NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	server.SetConfigurationLock(manager)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	params, _ := json.Marshal(gatewayprotocol.SetOperatingModeParams{Mode: gatewayprotocol.ModeEmergency})
	_, rpcErr := server.dispatch(ctx, gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "locked-mutation", Method: "SetOperatingMode", Params: params})
	if rpcErr == nil || rpcErr.Code != -32060 || store.Get().OperatingMode != gatewayprotocol.ModeSetupSafe {
		t.Fatalf("locked mutation was not rejected: rpc=%+v state=%+v", rpcErr, store.Get())
	}
	result, rpcErr := server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "lock-status", Method: "GetManagedState", Params: json.RawMessage(`{}`)})
	status, ok := result.(gatewayprotocol.Status)
	if rpcErr != nil || !ok || status.ConfigurationLock == nil || !status.ConfigurationLock.Active || status.ConfigurationLock.Record == nil || status.ConfigurationLock.Record.Category != configlock.CategoryUpdate {
		t.Fatalf("active configuration lock was not observable: result=%+v rpc=%+v", result, rpcErr)
	}
}

func TestManagedStateExposesLabScopeOnlyForConfirmedPlan(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	vlan := 20
	staged := &networkplan.StagedPlan{
		PlanHash: stateTestPlanHash,
		Plan: networkplan.Plan{Interfaces: []networkplan.Interface{{
			StableID: "pci-0000:02:00.0", CurrentName: "enp2s0.20", Role: networkplan.RoleLab, VLANID: &vlan,
		}}},
		Status: string(networktransaction.PhaseConfirmed),
		Transaction: &networktransaction.Record{
			Phase: networktransaction.PhaseConfirmed,
		},
	}
	store.mu.Lock()
	store.state.StagedNetworkPlan = staged
	store.mu.Unlock()
	server := NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	result, rpcErr := server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "scope-test", Method: "GetManagedState", Params: json.RawMessage(`{}`)})
	status, ok := result.(gatewayprotocol.Status)
	if rpcErr != nil || !ok || status.LabInterface != "enp2s0.20" || status.LabVLANID == nil || *status.LabVLANID != 20 || status.LabScopePlanHash != stateTestPlanHash {
		t.Fatalf("confirmed plan scope was not exposed: status=%#v rpc=%#v", result, rpcErr)
	}
	vlan = 30
	if *status.LabVLANID != 20 {
		t.Fatal("managed status leaked the mutable plan VLAN pointer")
	}
	store.mu.Lock()
	store.state.StagedNetworkPlan.Transaction.Phase = networktransaction.PhaseAwaitingConfirmation
	store.state.StagedNetworkPlan.Status = string(networktransaction.PhaseAwaitingConfirmation)
	store.mu.Unlock()
	result, rpcErr = server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "scope-test-2", Method: "GetManagedState", Params: json.RawMessage(`{}`)})
	status, ok = result.(gatewayprotocol.Status)
	if rpcErr != nil || !ok || status.LabInterface != "" || status.LabVLANID != nil || status.LabScopePlanHash != "" {
		t.Fatalf("unconfirmed plan leaked attribution scope: status=%#v rpc=%#v", result, rpcErr)
	}
}

func TestCaptureAuditObjectsAreDerivedFromValidatedSessionID(t *testing.T) {
	id := "capture-0123456789abcdef0123456789abcdef"
	want := []string{
		"capture session " + id,
		"shakerproxy-capture@0123456789abcdef0123456789abcdef.service",
		"/var/lib/shakerproxy/pcap/" + id,
	}
	if got := captureAuditObjects(id); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected capture audit objects: %#v", got)
	}
	if got := captureAuditObjects("capture-../../etc"); got != nil {
		t.Fatalf("unsafe capture ID produced audit objects: %#v", got)
	}
}

func TestRewritePCAPAuditBindsSourceHashAndObjects(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	request := capture.PCAPRewriteRequest{
		Schema: capture.PCAPRewriteSchema, ID: "pcap-rewrite-0123456789abcdef0123456789abcdef",
		SessionID: "capture-0123456789abcdef0123456789abcdef", FileName: "capture.pcapng",
		OriginalSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Selection:      pcapng.SelectionRule{Schema: pcapng.SelectionRuleSchema, Identities: []pcapng.SelectionIdentity{{Kind: pcapng.SelectionIdentityIP, Value: "10.77.0.2", StartAt: &start, EndAt: &end}}},
		ToolVersion:    "test-v1",
	}
	params, err := json.Marshal(gatewayprotocol.RewritePCAPParams{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	hash, objects := server.auditDetails(gatewayprotocol.Request{Method: "RewritePCAP", Params: params}, nil)
	if hash != request.OriginalSHA256 || len(objects) != 5 || objects[3] != "capture artifact capture.pcapng" || objects[4] != "PCAP rewrite "+request.ID {
		t.Fatalf("rewrite audit evidence is incomplete: hash=%q objects=%#v", hash, objects)
	}
}

func TestDeletePCAPArtifactAuditBindsReviewedSource(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	request := capture.PCAPArtifactDeletionRequest{
		Schema: capture.PCAPArtifactDeletionSchema, ID: "pcap-delete-0123456789abcdef0123456789abcdef",
		SessionID: "capture-0123456789abcdef0123456789abcdef", FileName: "capture.pcapng",
		OriginalSHA256:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Selection:       pcapng.SelectionRule{Schema: pcapng.SelectionRuleSchema, Identities: []pcapng.SelectionIdentity{{Kind: pcapng.SelectionIdentityIP, Value: "10.77.0.2", StartAt: &start, EndAt: &end}}},
		ExpectedPackets: 10, ExpectedMatchedPackets: 4, ExpectedCollateralPackets: 6,
	}
	params, err := json.Marshal(gatewayprotocol.DeletePCAPArtifactParams{Request: request})
	if err != nil {
		t.Fatal(err)
	}
	hash, objects := server.auditDetails(gatewayprotocol.Request{Method: "DeletePCAPArtifact", Params: params}, nil)
	if hash != request.OriginalSHA256 || len(objects) != 5 || objects[3] != "capture artifact capture.pcapng" || objects[4] != "PCAP artifact deletion "+request.ID {
		t.Fatalf("artifact deletion audit evidence is incomplete: hash=%q objects=%#v", hash, objects)
	}
}

func TestReleasedEvidenceHoldAuditRetainsOwningCaseIdentity(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hold := capture.EvidenceHold{
		SessionID: "capture-0123456789abcdef0123456789abcdef",
		Revision:  2,
		History: []capture.HoldEvent{{
			CaseID: "case-0123456789abcdef0123456789abcdef",
		}},
	}
	_, objects := server.auditDetails(gatewayprotocol.Request{Method: "SetCaptureEvidenceHold"}, hold)
	if got := objects[len(objects)-1]; got != "case case-0123456789abcdef0123456789abcdef evidence hold revision 2" {
		t.Fatalf("release audit lost owning case: %q", got)
	}
}

func TestBindFirewallInspectionRecordsBackendAndBlocksImpact(t *testing.T) {
	preview := networkplan.Preview{FirewallBackend: "iptables"}
	inspection := firewall.Inspection{SelectedBackend: "iptables-nft", DockerFirewallBackend: "iptables", ApplyReady: false}

	bindHostInspection(&preview, gatewayprotocol.HostInspection{Firewall: inspection})

	if preview.FirewallBackend != "iptables-nft" || preview.FirewallEnvironment.SelectedBackend != "iptables-nft" {
		t.Fatalf("firewall evidence was not bound: %+v", preview)
	}
	if len(preview.Impact) != 1 || preview.Impact[0] != "Host apply remains blocked by firewall coexistence preflight" {
		t.Fatalf("blocking impact was not recorded: %+v", preview.Impact)
	}
}

func TestBindFirewallInspectionMarksUnavailableBackend(t *testing.T) {
	preview := networkplan.Preview{FirewallBackend: "iptables"}
	bindHostInspection(&preview, gatewayprotocol.HostInspection{})
	if preview.FirewallBackend != "unavailable" {
		t.Fatalf("unexpected backend: %q", preview.FirewallBackend)
	}
}

func TestSetupSafeServerDoesNotExposeNetworkCommit(t *testing.T) {
	store, err := OpenStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(store, logger)
	params, err := json.Marshal(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	_, rpcErr := server.dispatch(t.Context(), gatewayprotocol.Request{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: "test", Method: "CommitNetworkPlan", Params: params})
	if rpcErr == nil || rpcErr.Code != -32030 {
		t.Fatalf("setup-safe daemon exposed network commit: %+v", rpcErr)
	}
}
