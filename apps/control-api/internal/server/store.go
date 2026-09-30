package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"shakerproxy.dev/shakerproxy/internal/capture"
)

const maxCaptureExportRecords = 4096

type Admin struct {
	Username          string `json:"username"`
	PasswordHash      string `json:"password_hash"`
	CreatedAt         string `json:"created_at"`
	PasswordChangedAt string `json:"password_changed_at,omitempty"`
}

type Store struct {
	dataDir   string
	tokenPath string
	mu        sync.Mutex
}

type CaptureExportRecord struct {
	Schema     int       `json:"schema"`
	ID         string    `json:"id"`
	SessionID  string    `json:"session_id"`
	FileName   string    `json:"file_name"`
	SHA256     string    `json:"sha256"`
	Username   string    `json:"username"`
	RangeStart int64     `json:"range_start"`
	RangeEnd   int64     `json:"range_end"`
	BytesSent  int64     `json:"bytes_sent"`
	Complete   bool      `json:"complete"`
	ExportedAt time.Time `json:"exported_at"`
}

type captureExportLedger struct {
	Schema  int                   `json:"schema"`
	Records []CaptureExportRecord `json:"records"`
}

func NewStore(dataDir, tokenPath string) *Store {
	return &Store{dataDir: dataDir, tokenPath: tokenPath}
}

func (s *Store) IsConfigured() (bool, error) {
	_, err := os.Stat(filepath.Join(s.dataDir, "admin.json"))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (s *Store) CreateAdmin(setupToken, username, password string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	configured, err := s.IsConfigured()
	if err != nil {
		return nil, err
	}
	if configured {
		return nil, errors.New("appliance is already configured")
	}
	expectedHash, err := s.readSetupTokenVerifier()
	if err != nil {
		return nil, errors.New("setup token verifier is unavailable")
	}
	providedHash := sha256.Sum256([]byte(setupToken))
	if len(expectedHash) != sha256.Size || subtle.ConstantTimeCompare(providedHash[:], expectedHash) != 1 || setupToken == "" {
		return nil, errors.New("invalid setup token")
	}
	if username != "admin" {
		return nil, errors.New("the initial administrator username must be admin")
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	admin := Admin{Username: username, PasswordHash: hash, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return nil, err
	}
	recoveryCodes, err := generateRecoveryCodes(8)
	if err != nil {
		return nil, err
	}
	digests := make([]string, len(recoveryCodes))
	for i, code := range recoveryCodes {
		digest := sha256.Sum256([]byte(code))
		digests[i] = hex.EncodeToString(digest[:])
	}
	recoveryBytes, _ := json.MarshalIndent(map[string]any{"sha256_digests": digests}, "", "  ")
	if err := atomicWrite(filepath.Join(s.dataDir, "recovery-codes.json"), append(recoveryBytes, '\n'), 0o600); err != nil {
		return nil, err
	}
	// Commit the admin marker last. If any earlier write fails, setup remains
	// retryable and the one-time verifier has not been consumed.
	b, err := json.MarshalIndent(admin, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(filepath.Join(s.dataDir, "admin.json"), append(b, '\n'), 0o600); err != nil {
		return nil, err
	}
	// The successful admin record is the authoritative consumed marker. The
	// verifier contains no bearer secret and can remain mounted read-only. A
	// setup token rotated by an administrator reset is one-time: its plaintext
	// receipt is removed once consumed (its digest stays and keeps superseding
	// the installation verifier).
	_ = os.Remove(s.rotatedSetupTokenPath())
	return recoveryCodes, nil
}

// rotatedSetupTokenPath holds the plaintext one-time setup token written by an
// administrator reset; rotatedSetupDigestPath holds its SHA-256 verifier. When
// the digest exists it supersedes the (read-only) installation verifier so the
// original installation token can never be replayed after a reset.
func (s *Store) rotatedSetupTokenPath() string {
	return filepath.Join(s.dataDir, "setup-token")
}

func (s *Store) rotatedSetupDigestPath() string {
	return filepath.Join(s.dataDir, "setup-token.sha256")
}

func (s *Store) readSetupTokenVerifier() ([]byte, error) {
	digest, err := os.ReadFile(s.rotatedSetupDigestPath())
	if err == nil {
		return digest, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return os.ReadFile(s.tokenPath)
}

var (
	errSetupRequired    = errors.New("administrator is not configured")
	errWeakPassword     = errors.New("new password does not meet the password policy")
	errRecoveryRejected = errors.New("recovery code or username is invalid")
)

// RecoverAdmin replaces the administrator password after redeeming one of the
// hashed, single-use recovery codes created at setup. The code is consumed
// before the new password is stored so a crash can never make a code reusable.
func (s *Store) RecoverAdmin(username, recoveryCode, newPassword string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	adminBytes, err := os.ReadFile(filepath.Join(s.dataDir, "admin.json"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, errSetupRequired
	}
	if err != nil {
		return 0, err
	}
	var admin Admin
	if err := json.Unmarshal(adminBytes, &admin); err != nil {
		return 0, err
	}
	if err := validatePassword(newPassword); err != nil {
		return 0, fmt.Errorf("%w: %v", errWeakPassword, err)
	}
	usernameMatches := subtle.ConstantTimeCompare([]byte(username), []byte(admin.Username)) == 1
	codesPath := filepath.Join(s.dataDir, "recovery-codes.json")
	codesBytes, err := os.ReadFile(codesPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, errRecoveryRejected
	}
	if err != nil {
		return 0, err
	}
	var codes struct {
		SHA256Digests []string `json:"sha256_digests"`
	}
	if err := json.Unmarshal(codesBytes, &codes); err != nil {
		return 0, errors.New("recovery code store is invalid")
	}
	provided := sha256.Sum256([]byte(normalizeRecoveryCode(recoveryCode)))
	providedHex := hex.EncodeToString(provided[:])
	matched := -1
	for index, digest := range codes.SHA256Digests {
		if subtle.ConstantTimeCompare([]byte(digest), []byte(providedHex)) == 1 {
			matched = index
		}
	}
	if matched < 0 || !usernameMatches || strings.TrimSpace(recoveryCode) == "" {
		return 0, errRecoveryRejected
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return 0, err
	}
	remaining := append(append([]string{}, codes.SHA256Digests[:matched]...), codes.SHA256Digests[matched+1:]...)
	remainingBytes, _ := json.MarshalIndent(map[string]any{"sha256_digests": remaining}, "", "  ")
	if err := atomicWrite(codesPath, append(remainingBytes, '\n'), 0o600); err != nil {
		return 0, err
	}
	admin.PasswordHash = hash
	admin.PasswordChangedAt = time.Now().UTC().Format(time.RFC3339Nano)
	updated, err := json.MarshalIndent(admin, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := atomicWrite(filepath.Join(s.dataDir, "admin.json"), append(updated, '\n'), 0o600); err != nil {
		return 0, err
	}
	return len(remaining), nil
}

// normalizeRecoveryCode accepts codes typed in lower case, with spaces, or
// without the dashes shown at setup.
func normalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.Join(strings.Fields(code), ""))
	if len(code) == 14 && !strings.Contains(code, "-") {
		code = code[:5] + "-" + code[5:10] + "-" + code[10:]
	}
	return code
}

// ResetAdministrator performs a local root-requested reset: it rotates a new
// one-time setup token (plaintext receipt and digest in the data directory),
// then removes the administrator credential and recovery codes so setup works
// as on first run. It returns the path of the new setup-token receipt.
func (s *Store) ResetAdministrator() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := hex.EncodeToString(random)
	digest := sha256.Sum256([]byte(token))
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return "", err
	}
	if err := atomicWrite(s.rotatedSetupTokenPath(), []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := atomicWrite(s.rotatedSetupDigestPath(), digest[:], 0o600); err != nil {
		return "", err
	}
	for _, name := range []string{"admin.json", "recovery-codes.json"} {
		if err := os.Remove(filepath.Join(s.dataDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return s.rotatedSetupTokenPath(), nil
}

func (s *Store) Authenticate(username, password string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(s.dataDir, "admin.json"))
	if err != nil {
		return false, err
	}
	var admin Admin
	if err := json.Unmarshal(b, &admin); err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(username), []byte(admin.Username)) != 1 {
		return false, nil
	}
	return verifyPassword(password, admin.PasswordHash)
}

func (s *Store) RecordCaptureExport(record CaptureExportRecord) (CaptureExportRecord, error) {
	bytesSent, complete := record.BytesSent, record.Complete
	record.BytesSent, record.Complete = 0, false
	started, err := s.BeginCaptureExport(record)
	if err != nil {
		return CaptureExportRecord{}, err
	}
	return s.FinishCaptureExport(started.ID, bytesSent, complete)
}

func (s *Store) BeginCaptureExport(record CaptureExportRecord) (CaptureExportRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !capture.ValidSessionID(record.SessionID) || !validCaptureArtifactName(record.FileName) || !validSHA256(record.SHA256) || record.Username == "" || len(record.Username) > 96 || record.RangeStart < 0 || record.RangeEnd < record.RangeStart || record.BytesSent != 0 || record.Complete {
		return CaptureExportRecord{}, errors.New("capture export record is invalid")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return CaptureExportRecord{}, err
	}
	record.Schema = 1
	record.ID = "export-" + hex.EncodeToString(idBytes)
	record.ExportedAt = time.Now().UTC()
	ledger, err := s.readCaptureExportsLocked()
	if err != nil {
		return CaptureExportRecord{}, err
	}
	if err := s.pruneCaptureExportsLocked(&ledger, record.ExportedAt); err != nil {
		return CaptureExportRecord{}, err
	}
	ledger.Records = append(ledger.Records, record)
	encoded, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return CaptureExportRecord{}, err
	}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return CaptureExportRecord{}, err
	}
	if err := atomicWrite(filepath.Join(s.dataDir, "capture-exports.json"), append(encoded, '\n'), 0o600); err != nil {
		return CaptureExportRecord{}, err
	}
	return record, nil
}

func (s *Store) FinishCaptureExport(id string, bytesSent int64, complete bool) (CaptureExportRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" || bytesSent < 0 {
		return CaptureExportRecord{}, errors.New("capture export completion is invalid")
	}
	ledger, err := s.readCaptureExportsLocked()
	if err != nil {
		return CaptureExportRecord{}, err
	}
	index := -1
	for candidate := range ledger.Records {
		if ledger.Records[candidate].ID == id {
			index = candidate
			break
		}
	}
	if index < 0 || bytesSent > ledger.Records[index].RangeEnd-ledger.Records[index].RangeStart+1 || (complete && bytesSent != ledger.Records[index].RangeEnd-ledger.Records[index].RangeStart+1) {
		return CaptureExportRecord{}, errors.New("capture export completion does not match a started record")
	}
	ledger.Records[index].BytesSent = bytesSent
	ledger.Records[index].Complete = complete
	encoded, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return CaptureExportRecord{}, err
	}
	if err := atomicWrite(filepath.Join(s.dataDir, "capture-exports.json"), append(encoded, '\n'), 0o600); err != nil {
		return CaptureExportRecord{}, err
	}
	return ledger.Records[index], nil
}

func (s *Store) ListCaptureExports(sessionID string) ([]CaptureExportRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ledger, err := s.readCaptureExportsLocked()
	if err != nil {
		return nil, err
	}
	records := make([]CaptureExportRecord, 0)
	for _, record := range ledger.Records {
		if sessionID == "" || record.SessionID == sessionID {
			records = append(records, record)
		}
	}
	return records, nil
}

func (s *Store) readCaptureExportsLocked() (captureExportLedger, error) {
	path := filepath.Join(s.dataDir, "capture-exports.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return captureExportLedger{Schema: 1, Records: []CaptureExportRecord{}}, nil
	}
	if err != nil {
		return captureExportLedger{}, err
	}
	if len(data) > 8<<20 {
		return captureExportLedger{}, errors.New("capture export ledger is too large")
	}
	var ledger captureExportLedger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ledger); err != nil || ledger.Schema != 1 || len(ledger.Records) > maxCaptureExportRecords {
		return captureExportLedger{}, errors.New("capture export ledger is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return captureExportLedger{}, errors.New("capture export ledger has trailing data")
	}
	seen := make(map[string]struct{}, len(ledger.Records))
	for _, record := range ledger.Records {
		if !validCaptureExportRecord(record) {
			return captureExportLedger{}, errors.New("capture export ledger contains an invalid record")
		}
		if _, exists := seen[record.ID]; exists {
			return captureExportLedger{}, errors.New("capture export ledger contains duplicate identities")
		}
		seen[record.ID] = struct{}{}
	}
	return ledger, nil
}

func validCaptureExportRecord(record CaptureExportRecord) bool {
	idHex := strings.TrimPrefix(record.ID, "export-")
	if record.Schema != 1 || len(idHex) != 32 || !capture.ValidSessionID(record.SessionID) || !validCaptureArtifactName(record.FileName) || !validSHA256(record.SHA256) || record.Username == "" || len(record.Username) > 96 || record.RangeStart < 0 || record.RangeEnd < record.RangeStart || record.BytesSent < 0 || record.BytesSent > record.RangeEnd-record.RangeStart+1 || record.ExportedAt.IsZero() {
		return false
	}
	if _, err := hex.DecodeString(idHex); err != nil {
		return false
	}
	return !record.Complete || record.BytesSent == record.RangeEnd-record.RangeStart+1
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func validatePassword(password string) error {
	if len(password) < 14 {
		return errors.New("password must contain at least 14 characters")
	}
	if len(password) > 1024 {
		return errors.New("password is too long")
	}
	var upper, lower, digit, symbol bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			symbol = true
		}
	}
	if !upper || !lower || !digit || !symbol {
		return errors.New("password must include upper, lower, number, and symbol characters")
	}
	return nil
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	const memory, iterations, parallelism, keyLength = 64 * 1024, 3, 2, 32
	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(password, encoded string) (bool, error) {
	var memory, iterations uint32
	var parallelism uint8
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, errors.New("invalid password hash")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, err
	}
	if memory != 64*1024 || iterations != 3 || parallelism != 2 {
		return false, errors.New("unsupported password hash parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	if len(salt) != 16 || len(expected) != 32 {
		return false, errors.New("invalid password hash dimensions")
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func generateRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := range codes {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		raw := strings.ToUpper(base64.RawStdEncoding.EncodeToString(b))
		codes[i] = raw[:5] + "-" + raw[5:10] + "-" + raw[10:]
	}
	return codes, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	return os.Rename(tmpName, path)
}
