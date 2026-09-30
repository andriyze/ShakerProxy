package trafficpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeNFT struct {
	exists     bool
	checked    [][]byte
	applied    [][]byte
	checkError error
	applyError error
}

func (fake *fakeNFT) TableExists(context.Context) (bool, error) {
	return fake.exists, nil
}

func (fake *fakeNFT) Check(_ context.Context, script []byte) error {
	fake.checked = append(fake.checked, append([]byte(nil), script...))
	return fake.checkError
}

func (fake *fakeNFT) Apply(_ context.Context, script []byte) error {
	fake.applied = append(fake.applied, append([]byte(nil), script...))
	if fake.applyError != nil {
		return fake.applyError
	}
	fake.exists = !strings.Contains(string(script), "delete table inet "+OwnedNFTTable) || strings.Contains(string(script), "table inet "+OwnedNFTTable+" {")
	return nil
}

type fixedProbe bool

func (probe fixedProbe) Available(context.Context, int) bool { return bool(probe) }

type statusCheckingCleaner struct {
	statusPath string
	policyID   string
	calls      int
	err        error
}

func (cleaner *statusCheckingCleaner) Relinquish(context.Context) error {
	cleaner.calls++
	data, readErr := os.ReadFile(cleaner.statusPath)
	if readErr != nil {
		cleaner.err = readErr
		return readErr
	}
	var status Status
	if decodeErr := json.Unmarshal(data, &status); decodeErr != nil {
		cleaner.err = decodeErr
		return decodeErr
	}
	cleaner.policyID = status.PolicyID
	return cleaner.err
}

func testApplyRequest(t *testing.T, policyID string, revision uint64, dnsMode, tlsMode string) ApplyRequest {
	t.Helper()
	document := EnforcementDocument{
		SchemaVersion: SchemaVersion,
		Enabled:       true,
		EncryptedDNS: EnforcementDNSPolicy{
			Mode:             dnsMode,
			RedirectPlainDNS: true,
			BlockDoT:         true,
			BlockDoQ:         true,
			BlockKnownDoH:    true,
			FailMode:         "passthrough",
		},
		TLS: TLSInterceptionPolicy{
			Mode:              tlsMode,
			FailMode:          "passthrough",
			AutoBypassPinning: true,
			PinningThreshold:  3,
		},
		Resolvers: []ResolverPolicyTarget{
			{
				Provider:        "Test Resolver",
				Hostnames:       []string{"dns.example.test"},
				IPv4:            []string{"192.0.2.53"},
				Transports:      []string{"doh", "dot"},
				Dedicated:       true,
				SafeToBlockByIP: true,
				Source:          "test",
			},
		},
	}
	if err := document.NormalizeAndValidate(time.Now()); err != nil {
		t.Fatal(err)
	}
	digest, err := document.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return ApplyRequest{
		PolicyID: policyID,
		Revision: revision,
		Digest:   digest,
		Policy:   document,
		Runtime: Runtime{
			TestInterfaces: []string{"lab0"},
			ScopeIPv4:      []string{"10.44.0.0/24"},
			LocalDNSPort:   53,
			MITMPort:       8080,
		},
	}
}

func TestManagerAppliesAndRollsBackPolicyTransactionally(t *testing.T) {
	root := t.TempDir()
	fake := &fakeNFT{}
	now := time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)
	manager := &Manager{
		StateRoot:       filepath.Join(root, "state"),
		ProxyPolicyPath: filepath.Join(root, "mitm", "policy.json"),
		NFT:             fake,
		Probe:           fixedProbe(true),
		Now:             func() time.Time { return now },
	}
	first := testApplyRequest(t, "policy-first", 1, "block", "all")
	status, err := manager.Apply(t.Context(), first)
	if err != nil {
		t.Fatal(err)
	}
	if status.PolicyID != first.PolicyID || status.Revision != first.Revision || len(fake.checked) != 1 || len(fake.applied) != 1 {
		t.Fatalf("unexpected first apply: %#v checks=%d applies=%d", status, len(fake.checked), len(fake.applied))
	}
	proxy, err := os.ReadFile(manager.ProxyPolicyPath)
	if err != nil || !strings.Contains(string(proxy), "policy-first") {
		t.Fatalf("first MITM policy was not projected: %v %s", err, proxy)
	}

	fake.exists = true
	second := testApplyRequest(t, "policy-second", 2, "observe", "off")
	status, err = manager.Apply(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
	if status.PolicyID != second.PolicyID || len(fake.applied) != 2 {
		t.Fatalf("unexpected second apply: %#v", status)
	}
	status, err = manager.Rollback(t.Context(), RollbackRequest{
		ExpectedPolicyID: second.PolicyID,
		ExpectedRevision: second.Revision,
		ExpectedDigest:   second.Digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status.PolicyID != first.PolicyID || status.Revision != first.Revision || status.Digest != first.Digest {
		t.Fatalf("rollback did not restore first policy: %#v", status)
	}
	proxy, err = os.ReadFile(manager.ProxyPolicyPath)
	if err != nil || !strings.Contains(string(proxy), "policy-first") {
		t.Fatalf("rollback did not restore MITM policy: %v %s", err, proxy)
	}
}

func TestManagerRejectsDigestMismatchBeforeNFTExecution(t *testing.T) {
	root := t.TempDir()
	fake := &fakeNFT{}
	stateRoot := filepath.Join(root, "state")
	cleaner := &statusCheckingCleaner{statusPath: filepath.Join(stateRoot, statusFile)}
	manager := &Manager{
		StateRoot:            stateRoot,
		ProxyPolicyPath:      filepath.Join(root, "mitm", "policy.json"),
		CoordinationLockPath: filepath.Join(root, "traffic-policy.lock"),
		NFT:                  fake,
		Probe:                fixedProbe(true),
		LocalPolicyCleaner:   cleaner,
	}
	request := testApplyRequest(t, "policy-bad", 1, "block", "all")
	request.Digest = strings.Repeat("0", 64)
	if _, err := manager.Apply(t.Context(), request); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	if len(fake.checked) != 0 || len(fake.applied) != 0 {
		t.Fatal("nftables was invoked before policy integrity validation")
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if cleaner.calls != 0 || status.PolicyID != "" {
		t.Fatalf("invalid policy claimed Fleet ownership: cleaner_calls=%d status=%#v", cleaner.calls, status)
	}
}

func TestManagerClaimsFleetOwnershipBeforeLocalPolicyHandoff(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	cleaner := &statusCheckingCleaner{statusPath: filepath.Join(stateRoot, statusFile)}
	fake := &fakeNFT{}
	manager := &Manager{
		StateRoot:            stateRoot,
		ProxyPolicyPath:      filepath.Join(root, "mitm", "policy.json"),
		CoordinationLockPath: filepath.Join(root, "traffic-policy.lock"),
		NFT:                  fake,
		Probe:                fixedProbe(true),
		LocalPolicyCleaner:   cleaner,
	}
	request := testApplyRequest(t, "fleet-policy", 1, "block", "all")
	status, err := manager.Apply(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if cleaner.calls != 1 || cleaner.policyID != request.PolicyID {
		t.Fatalf("local policy handoff ran without Fleet ownership claim: calls=%d policy=%q", cleaner.calls, cleaner.policyID)
	}
	if status.PolicyID != request.PolicyID || len(fake.applied) != 1 {
		t.Fatalf("Fleet policy was not activated after handoff: status=%#v applies=%d", status, len(fake.applied))
	}
}

func TestManagerHandoffFailureLeavesFleetOwnershipFailOpen(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	cleaner := &statusCheckingCleaner{statusPath: filepath.Join(stateRoot, statusFile), err: errors.New("synthetic local cleanup failure")}
	fake := &fakeNFT{}
	manager := &Manager{
		StateRoot:            stateRoot,
		ProxyPolicyPath:      filepath.Join(root, "mitm", "policy.json"),
		CoordinationLockPath: filepath.Join(root, "traffic-policy.lock"),
		NFT:                  fake,
		Probe:                fixedProbe(true),
		LocalPolicyCleaner:   cleaner,
	}
	request := testApplyRequest(t, "fleet-policy", 1, "block", "all")
	if _, err := manager.Apply(t.Context(), request); err == nil || !strings.Contains(err.Error(), "relinquish local traffic policy") {
		t.Fatalf("local handoff failure was not reported: %v", err)
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.PolicyID != request.PolicyID || status.LastError == "" || len(fake.applied) != 0 {
		t.Fatalf("failed handoff was not retained as fail-open Fleet ownership: status=%#v applies=%d", status, len(fake.applied))
	}
}

func TestManagerRestoresProxySnapshotWhenNFTApplyFails(t *testing.T) {
	root := t.TempDir()
	proxyPath := filepath.Join(root, "mitm", "policy.json")
	if err := os.MkdirAll(filepath.Dir(proxyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyPath, []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNFT{applyError: errors.New("synthetic nft failure")}
	manager := &Manager{
		StateRoot:       filepath.Join(root, "state"),
		ProxyPolicyPath: proxyPath,
		NFT:             fake,
		Probe:           fixedProbe(true),
	}
	request := testApplyRequest(t, "policy-fail", 1, "block", "all")
	if _, err := manager.Apply(t.Context(), request); err == nil {
		t.Fatal("synthetic nft failure was ignored")
	}
	proxy, err := os.ReadFile(proxyPath)
	if err != nil || string(proxy) != "previous\n" {
		t.Fatalf("proxy policy was not restored after nft failure: %v %q", err, proxy)
	}
}

func TestManagerKeepsCloudPolicyFailOpenDuringEmergencyBypassAndRestoresIt(t *testing.T) {
	root := t.TempDir()
	gatewayState := filepath.Join(root, "gateway-state.json")
	if err := os.WriteFile(gatewayState, []byte("{\"emergency_bypass\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNFT{}
	manager := &Manager{
		StateRoot:        filepath.Join(root, "state"),
		ProxyPolicyPath:  filepath.Join(root, "mitm", "policy.json"),
		GatewayStatePath: gatewayState,
		NFT:              fake,
		Probe:            fixedProbe(true),
	}
	request := testApplyRequest(t, "policy-bypass", 1, "block", "all")
	status, err := manager.Apply(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !status.EmergencyBypass || fake.exists || len(fake.applied) != 0 {
		t.Fatalf("policy enforced during emergency bypass: status=%#v applies=%d exists=%t", status, len(fake.applied), fake.exists)
	}
	if _, err := os.Stat(filepath.Join(manager.StateRoot, activeRequestFile)); err != nil {
		t.Fatalf("desired policy was not retained during bypass: %v", err)
	}

	if err := os.WriteFile(gatewayState, []byte("{\"emergency_bypass\":false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enabled, err := manager.ReconcileEmergencyBypass(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, err = manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if enabled || status.EmergencyBypass || !fake.exists || len(fake.applied) != 1 || !strings.Contains(string(fake.applied[0]), "table inet "+OwnedNFTTable) {
		t.Fatalf("policy was not restored after bypass: status=%#v applies=%q exists=%t", status, fake.applied, fake.exists)
	}
}

func TestManagerEmergencyBypassRemovesAlreadyActiveCloudPolicy(t *testing.T) {
	root := t.TempDir()
	gatewayState := filepath.Join(root, "gateway-state.json")
	if err := os.WriteFile(gatewayState, []byte("{\"emergency_bypass\":false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNFT{}
	manager := &Manager{
		StateRoot:        filepath.Join(root, "state"),
		ProxyPolicyPath:  filepath.Join(root, "mitm", "policy.json"),
		GatewayStatePath: gatewayState,
		NFT:              fake,
		Probe:            fixedProbe(true),
	}
	if _, err := manager.Apply(t.Context(), testApplyRequest(t, "policy-active", 1, "block", "all")); err != nil {
		t.Fatal(err)
	}
	if !fake.exists {
		t.Fatal("test policy did not create its nftables table")
	}
	if err := os.WriteFile(gatewayState, []byte("{\"emergency_bypass\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enabled, err := manager.ReconcileEmergencyBypass(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || !status.EmergencyBypass || fake.exists || !strings.Contains(string(fake.applied[len(fake.applied)-1]), "delete table inet "+OwnedNFTTable) {
		t.Fatalf("active policy survived emergency bypass: status=%#v applies=%q exists=%t", status, fake.applied, fake.exists)
	}
}

func TestManagerInvalidGatewayStateFailsOpen(t *testing.T) {
	root := t.TempDir()
	gatewayState := filepath.Join(root, "gateway-state.json")
	if err := os.WriteFile(gatewayState, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNFT{exists: true}
	manager := &Manager{
		StateRoot:        filepath.Join(root, "state"),
		ProxyPolicyPath:  filepath.Join(root, "mitm", "policy.json"),
		GatewayStatePath: gatewayState,
		NFT:              fake,
		Probe:            fixedProbe(true),
	}
	if _, err := manager.ReconcileEmergencyBypass(t.Context()); err == nil {
		t.Fatal("invalid gateway state was accepted")
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if fake.exists || !status.EmergencyBypass || status.LastError == "" {
		t.Fatalf("invalid gateway state did not fail open: status=%#v exists=%t", status, fake.exists)
	}

	target := filepath.Join(root, "real-state.json")
	if err := os.WriteFile(target, []byte("{\"emergency_bypass\":false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "gateway-state-link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readEmergencyBypass(symlink); err == nil {
		t.Fatal("symlinked gateway state was accepted")
	}
}

func TestManagerStartupReconciliationRemovesStaleTableWithoutDesiredPolicy(t *testing.T) {
	root := t.TempDir()
	gatewayState := filepath.Join(root, "gateway-state.json")
	if err := os.WriteFile(gatewayState, []byte("{\"emergency_bypass\":false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNFT{exists: true}
	manager := &Manager{
		StateRoot:        filepath.Join(root, "state"),
		ProxyPolicyPath:  filepath.Join(root, "mitm", "policy.json"),
		GatewayStatePath: gatewayState,
		NFT:              fake,
		Probe:            fixedProbe(true),
	}
	enabled, err := manager.InitializeEmergencyBypass(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if enabled || fake.exists || len(fake.applied) != 1 || !strings.Contains(string(fake.applied[0]), "delete table inet "+OwnedNFTTable) {
		t.Fatalf("startup left stale enforcement active: enabled=%t applies=%q exists=%t", enabled, fake.applied, fake.exists)
	}
}
