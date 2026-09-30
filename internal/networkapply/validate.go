package networkapply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/networkplan"
	"shakerproxy.dev/shakerproxy/internal/networktransaction"
)

const (
	maxArtifactBytes = 1 << 20
	maxCommandOutput = 64 << 10
)

type Evidence struct {
	Schema                int       `json:"schema"`
	ValidatedAt           time.Time `json:"validated_at"`
	NetplanSHA256         string    `json:"netplan_sha256"`
	FirewallSHA256        string    `json:"firewall_sha256"`
	KeaDHCP4SHA256        string    `json:"kea_dhcp4_sha256"`
	NetplanGenerated      bool      `json:"netplan_generated"`
	FirewallRestoreOK     bool      `json:"firewall_restore_tested"`
	KeaDHCP4ConfigOK      bool      `json:"kea_dhcp4_config_tested"`
	TransactionApplyID    string    `json:"transaction_apply_id"`
	FirewallIPv6SHA256    string    `json:"firewall_ipv6_sha256,omitempty"`
	FirewallIPv6RestoreOK bool      `json:"firewall_ipv6_restore_tested,omitempty"`
	RadvdSHA256           string    `json:"radvd_sha256,omitempty"`
	RadvdConfigOK         bool      `json:"radvd_config_tested,omitempty"`
}

func (e Evidence) Validate() error {
	if e.Schema != 1 || e.ValidatedAt.IsZero() || !networktransaction.ValidApplyID(e.TransactionApplyID) || len(e.NetplanSHA256) != 64 || len(e.FirewallSHA256) != 64 || len(e.KeaDHCP4SHA256) != 64 || !e.NetplanGenerated || !e.FirewallRestoreOK || !e.KeaDHCP4ConfigOK {
		return errors.New("native syntax evidence is invalid")
	}
	if _, err := hex.DecodeString(e.NetplanSHA256); err != nil {
		return errors.New("Netplan evidence digest is invalid")
	}
	if _, err := hex.DecodeString(e.FirewallSHA256); err != nil {
		return errors.New("firewall evidence digest is invalid")
	}
	if _, err := hex.DecodeString(e.KeaDHCP4SHA256); err != nil {
		return errors.New("Kea DHCPv4 evidence digest is invalid")
	}
	return validateIPv6Evidence(e)
}

func ReadEvidence(store networktransaction.FileStore, applyID string) (Evidence, error) {
	directory, err := store.TransactionDirectory(applyID)
	if err != nil {
		return Evidence{}, err
	}
	file, err := os.Open(filepath.Join(directory, "syntax-evidence.json"))
	if err != nil {
		return Evidence{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Evidence{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCommandOutput {
		return Evidence{}, errors.New("native syntax evidence is not a bounded regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxCommandOutput+1))
	decoder.DisallowUnknownFields()
	var evidence Evidence
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Evidence{}, errors.New("multiple JSON values are not allowed")
	}
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	if evidence.TransactionApplyID != applyID {
		return Evidence{}, errors.New("native syntax evidence apply ID does not match its directory")
	}
	return evidence, nil
}

type Runner interface {
	Run(context.Context, string, []string, string) error
}

type Validator struct {
	Store  networktransaction.FileStore
	Runner Runner
	Now    func() time.Time
}

func (v Validator) Validate(ctx context.Context, staged networkplan.StagedPlan) (Evidence, error) {
	if staged.Transaction == nil || staged.Transaction.Phase != networktransaction.PhasePreparing {
		return Evidence{}, errors.New("syntax validation requires a preparing network transaction")
	}
	if err := staged.Transaction.Validate(); err != nil {
		return Evidence{}, err
	}
	if staged.ApplyID != staged.Transaction.ApplyID || staged.PlanHash != staged.Transaction.PlanHash || staged.PlanHash != staged.Preview.Validation.PlanHash {
		return Evidence{}, errors.New("staged plan and transaction identity do not match")
	}
	if !staged.Preview.Validation.Valid {
		return Evidence{}, errors.New("invalid plan cannot enter native syntax validation")
	}
	if !staged.Preview.FirewallEnvironment.ApplyReady {
		return Evidence{}, errors.New("firewall environment is not apply-ready")
	}
	if staged.Preview.FirewallBackend != "iptables-nft" && staged.Preview.FirewallBackend != "iptables-legacy" {
		return Evidence{}, errors.New("preview selected an unsupported firewall backend")
	}
	if staged.Preview.NetplanYAML == "" || staged.Preview.FirewallRestoreIPv4 == "" || networkplan.UsesManagedDHCP4(staged.Plan) && staged.Preview.KeaDHCP4JSON == "" {
		return Evidence{}, errors.New("rendered network artifacts are incomplete")
	}
	if len(staged.Preview.NetplanYAML) > maxArtifactBytes || len(staged.Preview.FirewallRestoreIPv4) > maxArtifactBytes || len(staged.Preview.KeaDHCP4JSON) > maxArtifactBytes {
		return Evidence{}, errors.New("rendered network artifact exceeds size limit")
	}
	if v.Runner == nil {
		return Evidence{}, errors.New("native syntax command runner is required")
	}
	directory, err := v.Store.TransactionDirectory(staged.ApplyID)
	if err != nil {
		return Evidence{}, err
	}
	syntaxRoot := filepath.Join(directory, "syntax-root")
	netplanDirectory := filepath.Join(syntaxRoot, "etc", "netplan")
	if err := os.MkdirAll(netplanDirectory, 0o750); err != nil {
		return Evidence{}, fmt.Errorf("create syntax root: %w", err)
	}
	if err := writeAtomicFile(netplanDirectory, "90-shakerproxy.yaml", []byte(staged.Preview.NetplanYAML), 0o600); err != nil {
		return Evidence{}, fmt.Errorf("stage Netplan syntax input: %w", err)
	}
	commandCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := v.Runner.Run(commandCtx, "/usr/sbin/netplan", []string{"generate", "--root-dir", syntaxRoot}, ""); err != nil {
		return Evidence{}, fmt.Errorf("Netplan native syntax validation failed: %w", err)
	}
	if err := v.Runner.Run(commandCtx, "/usr/sbin/iptables-restore", []string{"--test"}, staged.Preview.FirewallRestoreIPv4); err != nil {
		return Evidence{}, fmt.Errorf("iptables restore validation failed: %w", err)
	}
	if networkplan.UsesManagedDHCP4(staged.Plan) {
		if err := v.Runner.Run(commandCtx, "/usr/sbin/kea-dhcp4", []string{"-t", "/dev/stdin"}, staged.Preview.KeaDHCP4JSON); err != nil {
			return Evidence{}, fmt.Errorf("Kea DHCPv4 native configuration validation failed: %w", err)
		}
	}
	ipv6Evidence, err := v.validateIPv6Syntax(commandCtx, staged)
	if err != nil {
		return Evidence{}, err
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	evidence := Evidence{
		Schema:             1,
		ValidatedAt:        now().UTC(),
		NetplanSHA256:      digest(staged.Preview.NetplanYAML),
		FirewallSHA256:     digest(staged.Preview.FirewallRestoreIPv4),
		KeaDHCP4SHA256:     digest(staged.Preview.KeaDHCP4JSON),
		NetplanGenerated:   true,
		FirewallRestoreOK:  true,
		KeaDHCP4ConfigOK:   true,
		TransactionApplyID: staged.ApplyID,
	}
	ipv6Evidence.bind(&evidence)
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	if err := writeAtomicJSON(directory, "syntax-evidence.json", evidence); err != nil {
		return Evidence{}, fmt.Errorf("persist syntax evidence: %w", err)
	}
	return evidence, nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func writeAtomicFile(directory, name string, contents []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(directory, ".network-artifact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
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

func writeAtomicJSON(directory, name string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(directory, name, append(encoded, '\n'), 0o640)
}

type OSRunner struct{ TransactionRoot string }

func (r OSRunner) Run(ctx context.Context, path string, arguments []string, input string) error {
	if !r.allowed(path, arguments, input) {
		return errors.New("native syntax command is not allowlisted")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Stdin = strings.NewReader(input)
	var stdout cappedBuffer
	var stderr cappedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return errors.New("native syntax command output exceeded limit")
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if len(message) > 512 {
			message = message[:512]
		}
		if message != "" {
			return fmt.Errorf("fixed command failed: %w: %s", err, message)
		}
		return fmt.Errorf("fixed command failed: %w", err)
	}
	return nil
}

func (r OSRunner) allowed(path string, arguments []string, input string) bool {
	if allowedIPv6Syntax(path, arguments, input) {
		return true
	}
	if path == "/usr/sbin/iptables-restore" {
		return len(arguments) == 1 && arguments[0] == "--test" && input != "" && len(input) <= maxArtifactBytes
	}
	if path == "/usr/sbin/kea-dhcp4" {
		if len(arguments) != 2 || arguments[0] != "-t" || input == "" || len(input) > maxArtifactBytes {
			return false
		}
		return arguments[1] == "/dev/stdin"
	}
	if path != "/usr/sbin/netplan" || len(arguments) != 3 || arguments[0] != "generate" || arguments[1] != "--root-dir" || input != "" {
		return false
	}
	return r.allowedTransactionPath(arguments[2], "syntax-root")
}

func (r OSRunner) allowedTransactionPath(raw string, suffix ...string) bool {
	root := filepath.Clean(r.TransactionRoot)
	if !filepath.IsAbs(root) {
		return false
	}
	target := filepath.Clean(raw)
	relative, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return false
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) != len(suffix)+1 || !networktransaction.ValidApplyID(parts[0]) {
		return false
	}
	for index, expected := range suffix {
		if parts[index+1] != expected {
			return false
		}
	}
	return true
}

type cappedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := maxCommandOutput - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return original, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.exceeded = true
	}
	_, _ = b.Buffer.Write(p)
	return original, nil
}
