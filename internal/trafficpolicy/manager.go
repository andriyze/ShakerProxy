package trafficpolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"shakerproxy.dev/shakerproxy/internal/policycoordination"
)

const (
	activeRequestFile   = "active-request.json"
	activeNFTFile       = "active.nft"
	previousRequestFile = "previous-request.json"
	previousNFTFile     = "previous.nft"
	previousProxyFile   = "previous-proxy.json"
	statusFile          = "status.json"
)

type NFTExecutor interface {
	TableExists(context.Context) (bool, error)
	Check(context.Context, []byte) error
	Apply(context.Context, []byte) error
}

type MITMProbe interface {
	Available(context.Context, int) bool
}

type LocalPolicyCleaner interface {
	Relinquish(context.Context) error
}

type Manager struct {
	StateRoot            string
	ProxyPolicyPath      string
	GatewayStatePath     string
	CoordinationLockPath string
	NFT                  NFTExecutor
	Probe                MITMProbe
	LocalPolicyCleaner   LocalPolicyCleaner
	Now                  func() time.Time
	mu                   sync.Mutex
}

type Preview struct {
	PolicyID         string `json:"policy_id"`
	Revision         uint64 `json:"revision"`
	Digest           string `json:"digest"`
	NFTablesSHA256   string `json:"nftables_sha256"`
	NFTablesBytes    int    `json:"nftables_bytes"`
	ProxyPolicyBytes int    `json:"proxy_policy_bytes"`
	ResolverIPv4     int    `json:"resolver_ipv4"`
	ResolverIPv6     int    `json:"resolver_ipv6"`
	TLSBypassRules   int    `json:"tls_bypass_rules"`
	TLSDegraded      bool   `json:"tls_degraded"`
}

type RollbackRequest struct {
	ExpectedPolicyID string `json:"expected_policy_id"`
	ExpectedRevision uint64 `json:"expected_revision"`
	ExpectedDigest   string `json:"expected_digest"`
}

func (m *Manager) Preview(ctx context.Context, request ApplyRequest) (Preview, error) {
	if err := m.validateConfiguration(); err != nil {
		return Preview{}, err
	}
	exists, err := m.NFT.TableExists(ctx)
	if err != nil {
		return Preview{}, err
	}
	available := request.Policy.TLS.Mode == "off" || m.Probe.Available(ctx, request.Runtime.MITMPort)
	compiled, err := Compile(request, CompileOptions{ReplaceExisting: exists, TLSBackendAvailable: available}, m.now())
	if err != nil {
		return Preview{}, err
	}
	nftDigest := sha256Hex(compiled.NFTables)
	return Preview{
		PolicyID:         request.PolicyID,
		Revision:         request.Revision,
		Digest:           request.Digest,
		NFTablesSHA256:   nftDigest,
		NFTablesBytes:    len(compiled.NFTables),
		ProxyPolicyBytes: len(compiled.ProxyPolicy),
		ResolverIPv4:     compiled.ResolverIPv4,
		ResolverIPv6:     compiled.ResolverIPv6,
		TLSBypassRules:   compiled.TLSBypassRules,
		TLSDegraded:      compiled.TLSDegraded,
	}, nil
}

func (m *Manager) Apply(ctx context.Context, request ApplyRequest) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateConfiguration(); err != nil {
		return Status{}, err
	}
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		return Status{}, err
	}
	defer coordination.Release()
	emergencyBypass, err := readEmergencyBypass(m.GatewayStatePath)
	if err != nil {
		status, _ := m.Status()
		return m.recordBypassRestoreFailure(ctx, status, fmt.Errorf("read gateway emergency bypass state: %w", err))
	}
	now := m.now()
	exists, err := m.NFT.TableExists(ctx)
	if err != nil {
		return m.recordFailure(request, fmt.Errorf("inspect owned nftables table: %w", err))
	}
	available := request.Policy.TLS.Mode == "off" || m.Probe.Available(ctx, request.Runtime.MITMPort)
	compiled, err := Compile(request, CompileOptions{ReplaceExisting: exists, TLSBackendAvailable: available}, now)
	if err != nil {
		return m.recordFailure(request, err)
	}
	if len(bytes.TrimSpace(compiled.NFTables)) != 0 {
		if err := m.NFT.Check(ctx, compiled.NFTables); err != nil {
			return m.recordFailure(request, fmt.Errorf("nftables validation failed: %w", err))
		}
	}
	if err := m.claimOwnership(request); err != nil {
		return Status{}, fmt.Errorf("claim Fleet traffic policy ownership: %w", err)
	}
	if m.LocalPolicyCleaner != nil {
		if err := m.LocalPolicyCleaner.Relinquish(ctx); err != nil {
			return m.recordFailure(request, fmt.Errorf("relinquish local traffic policy: %w", err))
		}
	}
	requestJSON, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return m.recordFailure(request, err)
	}
	requestJSON = append(requestJSON, '\n')

	previousRequest, _ := os.ReadFile(filepath.Join(m.StateRoot, activeRequestFile))
	previousNFT, _ := os.ReadFile(filepath.Join(m.StateRoot, activeNFTFile))
	previousProxy, _ := os.ReadFile(m.ProxyPolicyPath)

	if err := m.prepareRollback(previousRequest, previousNFT, previousProxy); err != nil {
		return m.recordFailure(request, fmt.Errorf("prepare traffic policy rollback: %w", err))
	}
	if err := atomicWrite(m.ProxyPolicyPath, compiled.ProxyPolicy, 0o640); err != nil {
		return m.recordFailure(request, fmt.Errorf("publish MITM policy snapshot: %w", err))
	}
	if emergencyBypass {
		if err := m.removeOwnedTable(ctx); err != nil {
			return m.recordFailure(request, fmt.Errorf("activate emergency bypass: %w", err))
		}
	} else if len(bytes.TrimSpace(compiled.NFTables)) != 0 {
		if err := m.NFT.Apply(ctx, compiled.NFTables); err != nil {
			_ = m.restoreProxy(previousProxy)
			if len(bytes.TrimSpace(previousNFT)) != 0 {
				_ = m.NFT.Apply(ctx, previousNFT)
			}
			return m.recordFailure(request, fmt.Errorf("apply nftables traffic policy: %w", err))
		}
	}
	if err := atomicWrite(filepath.Join(m.StateRoot, activeRequestFile), requestJSON, 0o600); err != nil {
		return m.recordFailure(request, fmt.Errorf("persist active traffic policy: %w", err))
	}
	if err := atomicWrite(filepath.Join(m.StateRoot, activeNFTFile), compiled.NFTables, 0o600); err != nil {
		return m.recordFailure(request, fmt.Errorf("persist active nftables policy: %w", err))
	}
	status := Status{
		SchemaVersion:    SchemaVersion,
		PolicyID:         request.PolicyID,
		Revision:         request.Revision,
		Digest:           request.Digest,
		Enabled:          request.Policy.Enabled,
		EncryptedDNSMode: request.Policy.EncryptedDNS.Mode,
		TLSMode:          request.Policy.TLS.Mode,
		EmergencyBypass:  emergencyBypass,
		AppliedAt:        now,
	}
	if compiled.TLSDegraded {
		status.LastError = "TLS interception backend unavailable; fail-mode policy was compiled without active interception"
	}
	if err := m.writeStatus(status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) Rollback(ctx context.Context, request RollbackRequest) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateConfiguration(); err != nil {
		return Status{}, err
	}
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		return Status{}, err
	}
	defer coordination.Release()
	current, err := m.Status()
	if err != nil {
		return Status{}, err
	}
	if strings.TrimSpace(request.ExpectedPolicyID) == "" || request.ExpectedPolicyID != current.PolicyID || request.ExpectedRevision != current.Revision || request.ExpectedDigest != current.Digest {
		return current, errors.New("traffic policy rollback precondition does not match active state")
	}
	emergencyBypass, err := readEmergencyBypass(m.GatewayStatePath)
	if err != nil {
		return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("read gateway emergency bypass state: %w", err))
	}
	previousRequest, requestErr := os.ReadFile(filepath.Join(m.StateRoot, previousRequestFile))
	previousNFT, nftErr := os.ReadFile(filepath.Join(m.StateRoot, previousNFTFile))
	previousProxy, proxyErr := os.ReadFile(filepath.Join(m.StateRoot, previousProxyFile))
	if requestErr != nil && !errors.Is(requestErr, os.ErrNotExist) {
		return current, requestErr
	}
	if nftErr != nil && !errors.Is(nftErr, os.ErrNotExist) {
		return current, nftErr
	}
	if proxyErr != nil && !errors.Is(proxyErr, os.ErrNotExist) {
		return current, proxyErr
	}
	if len(bytes.TrimSpace(previousNFT)) != 0 {
		if err := m.NFT.Check(ctx, previousNFT); err != nil {
			return current, fmt.Errorf("rollback nftables validation failed: %w", err)
		}
		if !emergencyBypass {
			if err := m.NFT.Apply(ctx, previousNFT); err != nil {
				return current, fmt.Errorf("rollback nftables apply failed: %w", err)
			}
		} else if err := m.removeOwnedTable(ctx); err != nil {
			return current, fmt.Errorf("rollback nftables apply failed: %w", err)
		}
	} else {
		exists, err := m.NFT.TableExists(ctx)
		if err != nil {
			return current, err
		}
		if exists {
			deleteScript := []byte("delete table inet " + OwnedNFTTable + "\n")
			if err := m.NFT.Apply(ctx, deleteScript); err != nil {
				return current, fmt.Errorf("remove active traffic policy table: %w", err)
			}
		}
	}
	if len(previousProxy) != 0 {
		if err := atomicWrite(m.ProxyPolicyPath, previousProxy, 0o640); err != nil {
			return current, err
		}
	} else {
		_ = os.Remove(m.ProxyPolicyPath)
	}
	if len(previousRequest) == 0 {
		_ = os.Remove(filepath.Join(m.StateRoot, activeRequestFile))
		_ = os.Remove(filepath.Join(m.StateRoot, activeNFTFile))
		status := Status{SchemaVersion: SchemaVersion, EmergencyBypass: emergencyBypass, AppliedAt: m.now()}
		if err := m.writeStatus(status); err != nil {
			return status, err
		}
		return status, nil
	}
	var restored ApplyRequest
	if err := json.Unmarshal(previousRequest, &restored); err != nil {
		return current, fmt.Errorf("decode rollback traffic policy: %w", err)
	}
	if err := atomicWrite(filepath.Join(m.StateRoot, activeRequestFile), previousRequest, 0o600); err != nil {
		return current, err
	}
	if err := atomicWrite(filepath.Join(m.StateRoot, activeNFTFile), previousNFT, 0o600); err != nil {
		return current, err
	}
	status := Status{
		SchemaVersion:    SchemaVersion,
		PolicyID:         restored.PolicyID,
		Revision:         restored.Revision,
		Digest:           restored.Digest,
		Enabled:          restored.Policy.Enabled,
		EncryptedDNSMode: restored.Policy.EncryptedDNS.Mode,
		TLSMode:          restored.Policy.TLS.Mode,
		EmergencyBypass:  emergencyBypass,
		AppliedAt:        m.now(),
	}
	if err := m.writeStatus(status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) Status() (Status, error) {
	if err := m.validateConfiguration(); err != nil {
		return Status{}, err
	}
	data, err := os.ReadFile(filepath.Join(m.StateRoot, statusFile))
	if errors.Is(err, os.ErrNotExist) {
		return Status{SchemaVersion: SchemaVersion}, nil
	}
	if err != nil {
		return Status{}, err
	}
	if len(data) > 64<<10 {
		return Status{}, errors.New("traffic policy status exceeds size limit")
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		return Status{}, fmt.Errorf("decode traffic policy status: %w", err)
	}
	if status.SchemaVersion != SchemaVersion {
		return Status{}, errors.New("unsupported traffic policy status schema")
	}
	return status, nil
}

// ReconcileEmergencyBypass makes the root-owned gateway state authoritative
// for the separately managed cloud policy table. Invalid state fails open.
func (m *Manager) ReconcileEmergencyBypass(ctx context.Context) (bool, error) {
	enabled, readErr := readEmergencyBypass(m.GatewayStatePath)
	if readErr != nil {
		return true, m.failOpenForGatewayStateError(ctx, readErr)
	}
	status, statusErr := m.Status()
	stateFailure := strings.HasPrefix(status.LastError, "read gateway emergency bypass state:")
	if statusErr == nil && status.EmergencyBypass == enabled && !stateFailure {
		return enabled, nil
	}
	_, reconcileErr := m.SetEmergencyBypass(ctx, enabled)
	return enabled, errors.Join(statusErr, reconcileErr)
}

// InitializeEmergencyBypass performs a forced startup reconciliation so a
// crash between table removal and status persistence cannot revive or strand
// enforcement across a service restart.
func (m *Manager) InitializeEmergencyBypass(ctx context.Context) (bool, error) {
	enabled, readErr := readEmergencyBypass(m.GatewayStatePath)
	if readErr != nil {
		return true, m.failOpenForGatewayStateError(ctx, readErr)
	}
	_, err := m.SetEmergencyBypass(ctx, enabled)
	return enabled, err
}

func (m *Manager) failOpenForGatewayStateError(ctx context.Context, readErr error) error {
	status, cleanupErr := m.SetEmergencyBypass(ctx, true)
	failure := errors.Join(fmt.Errorf("read gateway emergency bypass state: %w", readErr), cleanupErr)
	m.mu.Lock()
	status.SchemaVersion = SchemaVersion
	status.EmergencyBypass = true
	status.LastError = failure.Error()
	writeErr := m.writeStatus(status)
	m.mu.Unlock()
	return errors.Join(failure, writeErr)
}

// SetEmergencyBypass removes all owned enforcement immediately when enabled,
// while retaining the desired policy. Disabling recompiles and restores that
// policy without rotating rollback history.
func (m *Manager) SetEmergencyBypass(ctx context.Context, enabled bool) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateConfiguration(); err != nil {
		return Status{}, err
	}
	coordination, err := policycoordination.Acquire(ctx, m.CoordinationLockPath)
	if err != nil {
		return Status{}, err
	}
	defer coordination.Release()
	current, err := m.Status()
	if err != nil {
		return Status{}, err
	}
	if enabled {
		if err := m.removeOwnedTable(ctx); err != nil {
			current.EmergencyBypass = true
			current.LastError = err.Error()
			_ = m.writeStatus(current)
			return current, err
		}
		current.EmergencyBypass = true
		current.LastError = ""
		if err := m.writeStatus(current); err != nil {
			return current, err
		}
		return current, nil
	}

	requestData, err := readBoundedRegularFile(filepath.Join(m.StateRoot, activeRequestFile), 512<<10)
	if errors.Is(err, os.ErrNotExist) {
		if err := m.removeOwnedTable(ctx); err != nil {
			return m.recordBypassRestoreFailure(ctx, current, err)
		}
		current.EmergencyBypass = false
		current.LastError = ""
		if err := m.writeStatus(current); err != nil {
			return current, err
		}
		return current, nil
	}
	if err != nil {
		return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("read active traffic policy: %w", err))
	}
	request, err := decodeApplyRequest(requestData)
	if err != nil {
		return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("decode active traffic policy: %w", err))
	}
	exists, err := m.NFT.TableExists(ctx)
	if err != nil {
		return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("inspect owned nftables table: %w", err))
	}
	available := request.Policy.TLS.Mode == "off" || m.Probe.Available(ctx, request.Runtime.MITMPort)
	compiled, err := Compile(request, CompileOptions{ReplaceExisting: exists, TLSBackendAvailable: available}, m.now())
	if err != nil {
		return m.recordBypassRestoreFailure(ctx, current, err)
	}
	if len(bytes.TrimSpace(compiled.NFTables)) != 0 {
		if err := m.NFT.Check(ctx, compiled.NFTables); err != nil {
			return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("nftables validation failed: %w", err))
		}
	}
	if err := atomicWrite(m.ProxyPolicyPath, compiled.ProxyPolicy, 0o640); err != nil {
		return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("publish MITM policy snapshot: %w", err))
	}
	if len(bytes.TrimSpace(compiled.NFTables)) != 0 {
		if err := m.NFT.Apply(ctx, compiled.NFTables); err != nil {
			return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("restore nftables traffic policy: %w", err))
		}
	}
	if err := atomicWrite(filepath.Join(m.StateRoot, activeNFTFile), compiled.NFTables, 0o600); err != nil {
		return m.recordBypassRestoreFailure(ctx, current, fmt.Errorf("persist active nftables policy: %w", err))
	}
	status := statusForRequest(request, m.now())
	if compiled.TLSDegraded {
		status.LastError = "TLS interception backend unavailable; fail-mode policy was compiled without active interception"
	}
	if err := m.writeStatus(status); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) prepareRollback(request, nft, proxy []byte) error {
	if err := os.MkdirAll(m.StateRoot, 0o700); err != nil {
		return err
	}
	if len(request) != 0 {
		if err := atomicWrite(filepath.Join(m.StateRoot, previousRequestFile), request, 0o600); err != nil {
			return err
		}
	} else {
		_ = os.Remove(filepath.Join(m.StateRoot, previousRequestFile))
	}
	if len(nft) != 0 {
		if err := atomicWrite(filepath.Join(m.StateRoot, previousNFTFile), nft, 0o600); err != nil {
			return err
		}
	} else {
		_ = os.Remove(filepath.Join(m.StateRoot, previousNFTFile))
	}
	if len(proxy) != 0 {
		if err := atomicWrite(filepath.Join(m.StateRoot, previousProxyFile), proxy, 0o600); err != nil {
			return err
		}
	} else {
		_ = os.Remove(filepath.Join(m.StateRoot, previousProxyFile))
	}
	return nil
}

func (m *Manager) restoreProxy(previous []byte) error {
	if len(previous) == 0 {
		return os.Remove(m.ProxyPolicyPath)
	}
	return atomicWrite(m.ProxyPolicyPath, previous, 0o640)
}

func (m *Manager) removeOwnedTable(ctx context.Context) error {
	exists, err := m.NFT.TableExists(ctx)
	if err != nil {
		return fmt.Errorf("inspect owned nftables table: %w", err)
	}
	if !exists {
		return nil
	}
	if err := m.NFT.Apply(ctx, []byte("delete table inet "+OwnedNFTTable+"\n")); err != nil {
		return fmt.Errorf("remove owned nftables table: %w", err)
	}
	return nil
}

func (m *Manager) recordBypassRestoreFailure(ctx context.Context, status Status, failure error) (Status, error) {
	cleanupErr := m.removeOwnedTable(ctx)
	failure = errors.Join(failure, cleanupErr)
	status.SchemaVersion = SchemaVersion
	status.EmergencyBypass = true
	status.LastError = failure.Error()
	_ = m.writeStatus(status)
	return status, failure
}

func (m *Manager) recordFailure(_ ApplyRequest, failure error) (Status, error) {
	status, _ := m.Status()
	status.SchemaVersion = SchemaVersion
	status.LastError = failure.Error()
	_ = m.writeStatus(status)
	return status, failure
}

func (m *Manager) claimOwnership(request ApplyRequest) error {
	status, err := m.Status()
	if err != nil {
		return err
	}
	if strings.TrimSpace(status.PolicyID) != "" {
		return nil
	}
	status = statusForRequest(request, m.now())
	status.LastError = "traffic policy activation is waiting for local policy handoff"
	return m.writeStatus(status)
}

func (m *Manager) writeStatus(status Status) error {
	encoded, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(m.StateRoot, statusFile), append(encoded, '\n'), 0o600)
}

func statusForRequest(request ApplyRequest, appliedAt time.Time) Status {
	return Status{
		SchemaVersion:    SchemaVersion,
		PolicyID:         request.PolicyID,
		Revision:         request.Revision,
		Digest:           request.Digest,
		Enabled:          request.Policy.Enabled,
		EncryptedDNSMode: request.Policy.EncryptedDNS.Mode,
		TLSMode:          request.Policy.TLS.Mode,
		AppliedAt:        appliedAt,
	}
}

func readEmergencyBypass(path string) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	data, err := readBoundedRegularFile(path, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state struct {
		EmergencyBypass bool `json:"emergency_bypass"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&state); err != nil {
		return false, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return false, errors.New("gateway state must contain exactly one JSON value")
	}
	return state.EmergencyBypass, nil
}

func decodeApplyRequest(data []byte) (ApplyRequest, error) {
	var request ApplyRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return ApplyRequest{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ApplyRequest{}, errors.New("active traffic policy must contain exactly one JSON value")
	}
	return request, nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("refusing non-regular state file")
	}
	if info.Size() > maximum {
		return nil, errors.New("state file exceeds size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		return nil, errors.New("state file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("state file exceeds size limit")
	}
	return data, nil
}

func (m *Manager) validateConfiguration() error {
	if strings.TrimSpace(m.StateRoot) == "" || strings.TrimSpace(m.ProxyPolicyPath) == "" {
		return errors.New("traffic policy state and proxy paths are required")
	}
	if m.NFT == nil || m.Probe == nil {
		return errors.New("traffic policy nftables executor and MITM probe are required")
	}
	if strings.TrimSpace(m.CoordinationLockPath) != "" && m.LocalPolicyCleaner == nil {
		return errors.New("coordinated Fleet traffic policy requires a local policy cleaner")
	}
	return nil
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

type CommandNFT struct {
	Binary string
}

func (executor CommandNFT) TableExists(ctx context.Context) (bool, error) {
	binary := executor.Binary
	if binary == "" {
		binary = "/usr/sbin/nft"
	}
	command := exec.CommandContext(ctx, binary, "list", "table", "inet", OwnedNFTTable)
	output, err := command.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 && bytes.Contains(bytes.ToLower(output), []byte("no such file")) {
		return false, nil
	}
	return false, fmt.Errorf("nft list table failed: %w: %s", err, boundedOutput(output))
}

func (executor CommandNFT) Check(ctx context.Context, script []byte) error {
	return executor.run(ctx, true, script)
}

func (executor CommandNFT) Apply(ctx context.Context, script []byte) error {
	return executor.run(ctx, false, script)
}

func (executor CommandNFT) run(ctx context.Context, check bool, script []byte) error {
	if len(script) > 2<<20 {
		return errors.New("nftables traffic policy exceeds 2 MiB")
	}
	binary := executor.Binary
	if binary == "" {
		binary = "/usr/sbin/nft"
	}
	arguments := []string{"-f", "-"}
	if check {
		arguments = append([]string{"--check"}, arguments...)
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Stdin = bytes.NewReader(script)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft command failed: %w: %s", err, boundedOutput(output))
	}
	return nil
}

type TCPMITMProbe struct {
	Host string
}

func (probe TCPMITMProbe) Available(ctx context.Context, port int) bool {
	host := probe.Host
	if host == "" {
		host = "127.0.0.1"
	}
	dialer := net.Dialer{Timeout: 800 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".shakerproxy-traffic-policy-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest[:])
}

func boundedOutput(value []byte) string {
	const maximum = 4096
	value = bytes.TrimSpace(value)
	if len(value) > maximum {
		value = value[:maximum]
	}
	return string(value)
}
