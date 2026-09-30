package networktransaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultTransactionRoot = "/var/lib/shakerproxy/gatewayd/transactions"
	maxWatchdogFileBytes   = 64 << 10
)

type WatchdogManifest struct {
	Schema    int          `json:"schema"`
	ApplyID   string       `json:"apply_id"`
	PlanHash  string       `json:"plan_hash"`
	CreatedAt time.Time    `json:"created_at"`
	ConfirmBy time.Time    `json:"confirm_by"`
	Rollback  RollbackSpec `json:"rollback"`
}

type RollbackSpec struct {
	InitialMode                string `json:"initial_mode"`
	NetplanExisted             bool   `json:"netplan_existed"`
	NetplanSHA256              string `json:"netplan_sha256,omitempty"`
	NetplanMode                uint32 `json:"netplan_mode,omitempty"`
	DHCP4ConfigExisted         bool   `json:"dhcp4_config_existed"`
	DHCP4ConfigSHA256          string `json:"dhcp4_config_sha256,omitempty"`
	DHCP4ConfigMode            uint32 `json:"dhcp4_config_mode,omitempty"`
	IPv4Forwarding             int    `json:"ipv4_forwarding"`
	IPv4SendRedirectsInterface string `json:"ipv4_send_redirects_interface,omitempty"`
	IPv4SendRedirects          int    `json:"ipv4_send_redirects,omitempty"`
	IptablesPath               string `json:"iptables_path"`
	HostapdManaged             bool   `json:"hostapd_managed,omitempty"`
	HostapdConfigExisted       bool   `json:"hostapd_config_existed,omitempty"`
	HostapdConfigSHA256        string `json:"hostapd_config_sha256,omitempty"`
	HostapdConfigMode          uint32 `json:"hostapd_config_mode,omitempty"`

	// IPv6 records the prior IPv6 state; it is zero for IPv4-only applies.
	IPv6 IPv6RollbackSpec `json:"ipv6,omitzero"`
}

type Confirmation struct {
	Schema      int       `json:"schema"`
	ApplyID     string    `json:"apply_id"`
	PlanHash    string    `json:"plan_hash"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

type WatchdogOutcome struct {
	Schema     int       `json:"schema"`
	ApplyID    string    `json:"apply_id"`
	PlanHash   string    `json:"plan_hash"`
	Status     string    `json:"status"`
	FinishedAt time.Time `json:"finished_at"`
	Detail     string    `json:"detail,omitempty"`
}

type FileStore struct{ Root string }

func (s FileStore) TransactionDirectory(applyID string) (string, error) {
	return s.transactionDirectory(applyID)
}

func NewWatchdogManifest(record Record, now time.Time, window time.Duration, rollback RollbackSpec) (WatchdogManifest, error) {
	if err := record.Validate(); err != nil {
		return WatchdogManifest{}, err
	}
	if record.Phase != PhasePreparing {
		return WatchdogManifest{}, errors.New("watchdog manifest requires a preparing transaction")
	}
	if window < MinRollbackWindow || window > MaxRollbackWindow {
		return WatchdogManifest{}, fmt.Errorf("rollback window must be between %s and %s", MinRollbackWindow, MaxRollbackWindow)
	}
	createdAt := now.UTC()
	if createdAt.Before(record.CreatedAt) {
		return WatchdogManifest{}, errors.New("watchdog creation time precedes the transaction")
	}
	manifest := WatchdogManifest{Schema: SchemaVersion, ApplyID: record.ApplyID, PlanHash: record.PlanHash, CreatedAt: createdAt, ConfirmBy: createdAt.Add(window), Rollback: rollback}
	return manifest, manifest.Validate()
}

func (m WatchdogManifest) Validate() error {
	if m.Schema != SchemaVersion || !applyIDPattern.MatchString(m.ApplyID) || !planHashPattern.MatchString(m.PlanHash) {
		return errors.New("watchdog manifest identity is invalid")
	}
	if m.CreatedAt.IsZero() || m.ConfirmBy.IsZero() {
		return errors.New("watchdog manifest timestamps are required")
	}
	window := m.ConfirmBy.Sub(m.CreatedAt)
	if window < MinRollbackWindow || window > MaxRollbackWindow {
		return errors.New("watchdog manifest rollback window is invalid")
	}
	if err := m.Rollback.Validate(); err != nil {
		return fmt.Errorf("invalid rollback specification: %w", err)
	}
	return nil
}

func (r RollbackSpec) Validate() error {
	if r.InitialMode != "SETUP_SAFE_NO_SHAKERPROXY" {
		return errors.New("rollback initial mode is unsupported")
	}
	if r.NetplanExisted {
		if !planHashPattern.MatchString(r.NetplanSHA256) || r.NetplanMode&^0o777 != 0 {
			return errors.New("Netplan backup metadata is invalid")
		}
	} else if r.NetplanSHA256 != "" || r.NetplanMode != 0 {
		return errors.New("absent Netplan file cannot have backup metadata")
	}
	if r.DHCP4ConfigExisted {
		if !planHashPattern.MatchString(r.DHCP4ConfigSHA256) || r.DHCP4ConfigMode&^0o777 != 0 {
			return errors.New("DHCPv4 configuration backup metadata is invalid")
		}
	} else if r.DHCP4ConfigSHA256 != "" || r.DHCP4ConfigMode != 0 {
		return errors.New("absent DHCPv4 configuration cannot have backup metadata")
	}
	if r.IPv4Forwarding != 0 && r.IPv4Forwarding != 1 {
		return errors.New("IPv4 forwarding snapshot must be zero or one")
	}
	if r.IPv4SendRedirectsInterface == "" {
		if r.IPv4SendRedirects != 0 {
			return errors.New("IPv4 redirect snapshot requires an interface")
		}
	} else if !safeRollbackInterfaceName(r.IPv4SendRedirectsInterface) || r.IPv4SendRedirects != 0 && r.IPv4SendRedirects != 1 {
		return errors.New("IPv4 redirect snapshot is invalid")
	}
	if r.IptablesPath != "/usr/sbin/iptables" && r.IptablesPath != "/usr/bin/iptables" {
		return errors.New("iptables rollback path is not approved")
	}
	if err := r.IPv6.Validate(); err != nil {
		return err
	}
	if r.IPv6.Ip6tablesPath != "" && r.IPv6.Ip6tablesPath != strings.TrimSuffix(r.IptablesPath, "iptables")+"ip6tables" {
		return errors.New("ip6tables rollback path does not match the approved iptables path")
	}
	return r.validateAccessPoint()
}

func safeRollbackInterfaceName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	for _, character := range name {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '_' && character != '.' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func (s FileStore) WriteManifest(manifest WatchdogManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	directory, err := s.transactionDirectory(manifest.ApplyID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create transaction directory: %w", err)
	}
	if current, err := s.ReadManifest(manifest.ApplyID); err == nil {
		if current == manifest {
			return nil
		}
		return errors.New("watchdog manifest already exists with different content")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect existing watchdog manifest: %w", err)
	}
	return writeAtomicJSON(directory, "manifest.json", manifest)
}

func (s FileStore) ReadManifest(applyID string) (WatchdogManifest, error) {
	directory, err := s.transactionDirectory(applyID)
	if err != nil {
		return WatchdogManifest{}, err
	}
	var manifest WatchdogManifest
	if err := readStrictJSON(filepath.Join(directory, "manifest.json"), &manifest); err != nil {
		return WatchdogManifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return WatchdogManifest{}, err
	}
	if manifest.ApplyID != applyID {
		return WatchdogManifest{}, errors.New("watchdog manifest apply ID does not match its directory")
	}
	return manifest, nil
}

func (s FileStore) Confirm(applyID, planHash string, now time.Time) (Confirmation, error) {
	manifest, err := s.ReadManifest(applyID)
	if err != nil {
		return Confirmation{}, err
	}
	if planHash != manifest.PlanHash {
		return Confirmation{}, errors.New("confirmation plan hash does not match the watchdog manifest")
	}
	if now.Before(manifest.CreatedAt) {
		return Confirmation{}, errors.New("confirmation time precedes the watchdog manifest")
	}
	if !now.Before(manifest.ConfirmBy) {
		return Confirmation{}, errors.New("watchdog confirmation deadline has elapsed")
	}
	confirmation := Confirmation{Schema: SchemaVersion, ApplyID: applyID, PlanHash: planHash, ConfirmedAt: now.UTC()}
	directory, _ := s.transactionDirectory(applyID)
	if confirmed, err := s.IsConfirmed(manifest); err == nil && confirmed {
		return s.ReadConfirmation(applyID)
	} else if err != nil {
		return Confirmation{}, err
	}
	if err := writeAtomicJSON(directory, "confirmed.json", confirmation); err != nil {
		return Confirmation{}, err
	}
	return confirmation, nil
}

func (s FileStore) ReadConfirmation(applyID string) (Confirmation, error) {
	manifest, err := s.ReadManifest(applyID)
	if err != nil {
		return Confirmation{}, err
	}
	directory, err := s.transactionDirectory(applyID)
	if err != nil {
		return Confirmation{}, err
	}
	var confirmation Confirmation
	if err := readStrictJSON(filepath.Join(directory, "confirmed.json"), &confirmation); err != nil {
		return Confirmation{}, err
	}
	if confirmation.Schema != SchemaVersion || confirmation.ApplyID != manifest.ApplyID || confirmation.PlanHash != manifest.PlanHash || confirmation.ConfirmedAt.Before(manifest.CreatedAt) || !confirmation.ConfirmedAt.Before(manifest.ConfirmBy) {
		return Confirmation{}, errors.New("watchdog confirmation marker is invalid")
	}
	return confirmation, nil
}

// LatestConfirmed returns the most recently confirmed transaction's manifest.
// It recovers the running plan's rollback snapshot when the gateway state no
// longer names it; only one plan can be applied at a time, so the newest
// confirmed transaction is the one the host is running.
func (s FileStore) LatestConfirmed() (WatchdogManifest, error) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return WatchdogManifest{}, err
	}
	var latest WatchdogManifest
	var latestAt time.Time
	for _, entry := range entries {
		if !entry.IsDir() || !ValidApplyID(entry.Name()) {
			continue
		}
		confirmation, err := s.ReadConfirmation(entry.Name())
		if err != nil {
			continue
		}
		if latestAt.IsZero() || confirmation.ConfirmedAt.After(latestAt) {
			manifest, err := s.ReadManifest(entry.Name())
			if err != nil {
				continue
			}
			latest, latestAt = manifest, confirmation.ConfirmedAt
		}
	}
	if latestAt.IsZero() {
		return WatchdogManifest{}, os.ErrNotExist
	}
	return latest, nil
}

func (s FileStore) IsConfirmed(manifest WatchdogManifest) (bool, error) {
	confirmation, err := s.ReadConfirmation(manifest.ApplyID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if confirmation.PlanHash != manifest.PlanHash || confirmation.ApplyID != manifest.ApplyID {
		return false, errors.New("watchdog confirmation does not match the supplied manifest")
	}
	return true, nil
}

func (s FileStore) WriteOutcome(outcome WatchdogOutcome) error {
	if err := outcome.Validate(); err != nil {
		return err
	}
	directory, err := s.transactionDirectory(outcome.ApplyID)
	if err != nil {
		return err
	}
	if current, err := s.ReadOutcome(outcome.ApplyID); err == nil {
		if current == outcome {
			return nil
		}
		return errors.New("watchdog outcome already exists with different content")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomicJSON(directory, "outcome.json", outcome)
}

func (s FileStore) ReadOutcome(applyID string) (WatchdogOutcome, error) {
	directory, err := s.transactionDirectory(applyID)
	if err != nil {
		return WatchdogOutcome{}, err
	}
	var outcome WatchdogOutcome
	if err := readStrictJSON(filepath.Join(directory, "outcome.json"), &outcome); err != nil {
		return WatchdogOutcome{}, err
	}
	if err := outcome.Validate(); err != nil {
		return WatchdogOutcome{}, err
	}
	if outcome.ApplyID != applyID {
		return WatchdogOutcome{}, errors.New("watchdog outcome apply ID does not match its directory")
	}
	return outcome, nil
}

func (o WatchdogOutcome) Validate() error {
	if o.Schema != SchemaVersion || !applyIDPattern.MatchString(o.ApplyID) || !planHashPattern.MatchString(o.PlanHash) || o.FinishedAt.IsZero() {
		return errors.New("watchdog outcome is invalid")
	}
	switch o.Status {
	case "CONFIRMED", "ROLLED_BACK":
		if o.Detail != "" {
			return errors.New("successful watchdog outcome cannot contain failure detail")
		}
	case "ROLLBACK_FAILED":
		if o.Detail == "" || len(o.Detail) > 8192 {
			return errors.New("failed watchdog outcome requires detail")
		}
	default:
		return errors.New("watchdog outcome status is invalid")
	}
	return nil
}

func (s FileStore) transactionDirectory(applyID string) (string, error) {
	if !applyIDPattern.MatchString(applyID) {
		return "", errors.New("invalid apply ID")
	}
	if !filepath.IsAbs(s.Root) {
		return "", errors.New("transaction root must be absolute")
	}
	directory := filepath.Join(filepath.Clean(s.Root), applyID)
	if filepath.Dir(directory) != filepath.Clean(s.Root) {
		return "", errors.New("transaction directory escaped its root")
	}
	return directory, nil
}

func writeAtomicJSON(directory, name string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(directory, ".watchdog-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(directory, name)); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func readStrictJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("watchdog state is not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxWatchdogFileBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxWatchdogFileBytes {
		return errors.New("watchdog state exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}
