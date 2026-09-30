// Package apitoken provides durable, hash-only API credentials with narrowly
// defined scopes. The clear-text credential exists only in Create's response.
package apitoken

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	SchemaVersion        = 1
	MaxTokens            = 256
	MaxAudit             = 16384
	AuditCompactionBatch = MaxAudit / 4
	MinLifetime          = 5 * time.Minute
	MaxLifetime          = 90 * 24 * time.Hour
)

type Scope string

const (
	ScopeSystemRead    Scope = "system:read"
	ScopeDevicesRead   Scope = "devices:read"
	ScopeTrafficRead   Scope = "traffic:read"
	ScopeCapturesRead  Scope = "captures:read"
	ScopeCapturesWrite Scope = "captures:write"
	ScopeCasesRead     Scope = "cases:read"
	ScopeCasesWrite    Scope = "cases:write"
	ScopeMetricsRead   Scope = "metrics:read"
	// ScopeLabWrite runs lab actions on devices: test sessions, device
	// controls (decrypt HTTPS, block internet or domains) and CA trust state.
	// It is not a sensitive scope: it changes lab behaviour, not evidence.
	ScopeLabWrite Scope = "lab:write"
)

var (
	ErrInvalidCredential = errors.New("invalid API token")
	ErrForbidden         = errors.New("API token is not authorized for this request")
	ErrResourceForbidden = errors.New("API token is not authorized for this resource")
	validScopes          = map[Scope]struct{}{
		ScopeSystemRead: {}, ScopeDevicesRead: {}, ScopeTrafficRead: {},
		ScopeCapturesRead: {}, ScopeCapturesWrite: {}, ScopeCasesRead: {}, ScopeCasesWrite: {},
		ScopeMetricsRead: {}, ScopeLabWrite: {},
	}
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$`)
	idPattern     = regexp.MustCompile(`^tok_[a-f0-9]{24}$`)
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	devicePattern = regexp.MustCompile(`^device-[a-f0-9]{32}$`)
	casePattern   = regexp.MustCompile(`^case-[a-f0-9]{32}$`)
)

type Restrictions struct {
	DeviceIDs []string `json:"device_ids,omitempty"`
	CaseIDs   []string `json:"case_ids,omitempty"`
}

type Record struct {
	ID                string       `json:"id"`
	Name              string       `json:"name"`
	Creator           string       `json:"creator"`
	Scopes            []Scope      `json:"scopes"`
	Restrictions      Restrictions `json:"restrictions,omitempty"`
	CreatedAt         time.Time    `json:"created_at"`
	ExpiresAt         time.Time    `json:"expires_at"`
	RevokedAt         *time.Time   `json:"revoked_at,omitempty"`
	LastUsedAt        *time.Time   `json:"last_used_at,omitempty"`
	UseCount          uint64       `json:"use_count"`
	SensitiveApproved bool         `json:"sensitive_approved,omitempty"`
	TokenSHA256       string       `json:"token_sha256"`
}

type PublicRecord struct {
	ID                string       `json:"id"`
	Name              string       `json:"name"`
	Creator           string       `json:"creator"`
	Scopes            []Scope      `json:"scopes"`
	Restrictions      Restrictions `json:"restrictions,omitempty"`
	CreatedAt         time.Time    `json:"created_at"`
	ExpiresAt         time.Time    `json:"expires_at"`
	RevokedAt         *time.Time   `json:"revoked_at,omitempty"`
	LastUsedAt        *time.Time   `json:"last_used_at,omitempty"`
	UseCount          uint64       `json:"use_count"`
	SensitiveApproved bool         `json:"sensitive_approved,omitempty"`
	State             string       `json:"state"`
}

type AuditEntry struct {
	Revision   uint64    `json:"revision"`
	Action     string    `json:"action"`
	TokenID    string    `json:"token_id"`
	Actor      string    `json:"actor"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
	Previous   string    `json:"previous_hash"`
	Hash       string    `json:"hash"`
}

type document struct {
	SchemaVersion       int          `json:"schema_version"`
	Revision            uint64       `json:"revision"`
	Tokens              []Record     `json:"tokens"`
	AuditAnchorRevision uint64       `json:"audit_anchor_revision,omitempty"`
	AuditAnchorHash     string       `json:"audit_anchor_hash,omitempty"`
	Audit               []AuditEntry `json:"audit"`
}

type CreateRequest struct {
	Name                  string
	Creator               string
	Scopes                []Scope
	Restrictions          Restrictions
	ExpiresAt             time.Time
	SensitiveAcknowledged bool
}

type Created struct {
	Token  PublicRecord `json:"token"`
	Secret string       `json:"secret"`
}

type Principal struct {
	TokenID      string
	Actor        string
	Creator      string
	Scopes       []Scope
	Restrictions Restrictions
}

type Store struct {
	Path string
	Now  func() time.Time
	mu   sync.Mutex
}

func AllowedScopes() []Scope {
	result := make([]Scope, 0, len(validScopes))
	for scope := range validScopes {
		result = append(result, scope)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// SensitiveScopes lists scopes that can alter or exfiltrate evidence and
// therefore require an explicit acknowledgement at token creation.
func SensitiveScopes() []Scope {
	return []Scope{ScopeCapturesWrite, ScopeCasesWrite}
}

func hasSensitiveScope(scopes []Scope) bool {
	for _, sensitive := range SensitiveScopes() {
		if containsScope(scopes, sensitive) {
			return true
		}
	}
	return false
}

func (s *Store) Create(request CreateRequest) (Created, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	request.Name = strings.TrimSpace(request.Name)
	request.Creator = strings.TrimSpace(request.Creator)
	request.Scopes = normalizeScopes(request.Scopes)
	request.Restrictions.DeviceIDs = normalizeIDs(request.Restrictions.DeviceIDs)
	request.Restrictions.CaseIDs = normalizeIDs(request.Restrictions.CaseIDs)
	if err := validateCreate(request, now); err != nil {
		return Created{}, err
	}
	doc, err := s.load()
	if err != nil {
		return Created{}, err
	}
	active := 0
	for _, token := range doc.Tokens {
		if token.RevokedAt == nil && token.ExpiresAt.After(now) {
			active++
		}
	}
	if active >= MaxTokens {
		return Created{}, errors.New("active API token limit reached")
	}
	compactTokenRecords(&doc, now)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return Created{}, fmt.Errorf("generate API token: %w", err)
	}
	secret := "lgt_" + base64.RawURLEncoding.EncodeToString(secretBytes)
	digest := sha256.Sum256([]byte(secret))
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return Created{}, fmt.Errorf("generate API token ID: %w", err)
	}
	record := Record{ID: "tok_" + hex.EncodeToString(idBytes), Name: request.Name, Creator: request.Creator, Scopes: request.Scopes, Restrictions: request.Restrictions, CreatedAt: now, ExpiresAt: request.ExpiresAt.UTC(), SensitiveApproved: request.SensitiveAcknowledged, TokenSHA256: hex.EncodeToString(digest[:])}
	doc.Tokens = append(doc.Tokens, record)
	if err := appendAudit(&doc, "created", record.ID, request.Creator, "", "", "token created", now); err != nil {
		return Created{}, err
	}
	if err := s.save(doc); err != nil {
		return Created{}, err
	}
	return Created{Token: public(record, now), Secret: secret}, nil
}

func (s *Store) List() ([]PublicRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	now := s.now()
	result := make([]PublicRecord, 0, len(doc.Tokens))
	for _, token := range doc.Tokens {
		result = append(result, public(token, now))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, nil
}

func (s *Store) Revoke(id, actor, reason string) (PublicRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reason = strings.TrimSpace(reason)
	if !idPattern.MatchString(id) || strings.TrimSpace(actor) == "" || len(reason) < 3 || len(reason) > 256 {
		return PublicRecord{}, errors.New("invalid token ID or actor")
	}
	doc, err := s.load()
	if err != nil {
		return PublicRecord{}, err
	}
	now := s.now()
	for index := range doc.Tokens {
		if doc.Tokens[index].ID != id {
			continue
		}
		if doc.Tokens[index].RevokedAt == nil {
			doc.Tokens[index].RevokedAt = &now
			if err := appendAudit(&doc, "revoked", id, actor, "", "", reason, now); err != nil {
				return PublicRecord{}, err
			}
			if err := s.save(doc); err != nil {
				return PublicRecord{}, err
			}
		}
		return public(doc.Tokens[index], now), nil
	}
	return PublicRecord{}, os.ErrNotExist
}

func (s *Store) Authenticate(secret string, required Scope, method, path, resourceID string) (Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(secret) < 40 || len(secret) > 128 || !strings.HasPrefix(secret, "lgt_") {
		return Principal{}, ErrInvalidCredential
	}
	if _, ok := validScopes[required]; !ok {
		return Principal{}, errors.New("unsupported required scope")
	}
	if len(method) > 12 || len(path) > 512 || !strings.HasPrefix(path, "/api/v1/") {
		return Principal{}, errors.New("invalid API request audit fields")
	}
	doc, err := s.load()
	if err != nil {
		return Principal{}, err
	}
	digest := sha256.Sum256([]byte(secret))
	wanted := hex.EncodeToString(digest[:])
	matched := -1
	for index := range doc.Tokens {
		if subtle.ConstantTimeCompare([]byte(doc.Tokens[index].TokenSHA256), []byte(wanted)) == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return Principal{}, ErrInvalidCredential
	}
	token := &doc.Tokens[matched]
	now := s.now()
	if token.RevokedAt != nil || !token.ExpiresAt.After(now) {
		return Principal{}, ErrInvalidCredential
	}
	if !containsScope(token.Scopes, required) {
		return Principal{}, ErrForbidden
	}
	if (len(token.Restrictions.DeviceIDs) > 0 && !containsID(token.Restrictions.DeviceIDs, resourceID)) || (len(token.Restrictions.CaseIDs) > 0 && !containsID(token.Restrictions.CaseIDs, resourceID)) {
		return Principal{}, ErrResourceForbidden
	}
	token.LastUsedAt = &now
	token.UseCount++
	if err := appendAudit(&doc, "used", token.ID, "token:"+token.Name, strings.ToUpper(method), path, "", now); err != nil {
		return Principal{}, err
	}
	if err := s.save(doc); err != nil {
		return Principal{}, err
	}
	return Principal{TokenID: token.ID, Actor: "token:" + token.Name, Creator: token.Creator, Scopes: append([]Scope(nil), token.Scopes...), Restrictions: token.Restrictions}, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Store) load() (document, error) {
	doc := document{SchemaVersion: SchemaVersion, Tokens: []Record{}, Audit: []AuditEntry{}}
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return document{}, fmt.Errorf("read API token store: %w", err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return document{}, fmt.Errorf("decode API token store: %w", err)
	}
	if err := validateDocument(doc); err != nil {
		return document{}, err
	}
	return doc, nil
}

func (s *Store) save(doc document) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode API token store: %w", err)
	}
	data = append(data, '\n')
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create API token directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".api-tokens-*")
	if err != nil {
		return fmt.Errorf("create API token temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, s.Path); err != nil {
		return fmt.Errorf("replace API token store: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validateCreate(request CreateRequest, now time.Time) error {
	if !namePattern.MatchString(request.Name) {
		return errors.New("token name must be 1-64 safe characters")
	}
	if len(request.Creator) < 1 || len(request.Creator) > 128 {
		return errors.New("token creator is invalid")
	}
	if len(request.Scopes) == 0 || len(request.Scopes) > len(validScopes) {
		return errors.New("at least one supported scope is required")
	}
	for _, scope := range request.Scopes {
		if _, ok := validScopes[scope]; !ok {
			return fmt.Errorf("unsupported API token scope %q", scope)
		}
	}
	if hasSensitiveScope(request.Scopes) && !request.SensitiveAcknowledged {
		return errors.New("write scopes require explicit sensitive-scope acknowledgement")
	}
	lifetime := request.ExpiresAt.Sub(now)
	if lifetime < MinLifetime || lifetime > MaxLifetime {
		return fmt.Errorf("token lifetime must be between %s and %s", MinLifetime, MaxLifetime)
	}
	if len(request.Restrictions.DeviceIDs) > 64 || len(request.Restrictions.CaseIDs) > 64 {
		return errors.New("too many token restrictions")
	}
	if len(request.Restrictions.DeviceIDs) > 0 && len(request.Restrictions.CaseIDs) > 0 {
		return errors.New("device and case restrictions cannot be combined")
	}
	if len(request.Restrictions.DeviceIDs) > 0 && (len(request.Scopes) != 1 || request.Scopes[0] != ScopeDevicesRead) {
		return errors.New("device restrictions require only devices:read")
	}
	if len(request.Restrictions.CaseIDs) > 0 {
		for _, scope := range request.Scopes {
			if scope != ScopeCasesRead && scope != ScopeCasesWrite {
				return errors.New("case restrictions may only be used with case scopes")
			}
		}
	}
	for _, id := range request.Restrictions.DeviceIDs {
		if !devicePattern.MatchString(id) {
			return errors.New("token restriction contains an invalid device identifier")
		}
	}
	for _, id := range request.Restrictions.CaseIDs {
		if !casePattern.MatchString(id) {
			return errors.New("token restriction contains an invalid case identifier")
		}
	}
	return nil
}

func validateDocument(doc document) error {
	if doc.SchemaVersion != SchemaVersion || len(doc.Tokens) > MaxTokens*4 || len(doc.Audit) > MaxAudit {
		return errors.New("API token store has invalid bounds or schema")
	}
	ids := make(map[string]struct{}, len(doc.Tokens))
	for _, token := range doc.Tokens {
		if !idPattern.MatchString(token.ID) || !digestPattern.MatchString(token.TokenSHA256) || len(token.Scopes) == 0 {
			return errors.New("API token store contains an invalid record")
		}
		if _, exists := ids[token.ID]; exists {
			return errors.New("API token store contains duplicate IDs")
		}
		ids[token.ID] = struct{}{}
		if err := validateCreate(CreateRequest{Name: token.Name, Creator: token.Creator, Scopes: token.Scopes, Restrictions: token.Restrictions, ExpiresAt: token.ExpiresAt, SensitiveAcknowledged: token.SensitiveApproved}, token.CreatedAt); err != nil {
			return fmt.Errorf("API token store contains invalid token %s: %w", token.ID, err)
		}
	}
	previous := doc.AuditAnchorHash
	for index, entry := range doc.Audit {
		if entry.Revision != doc.AuditAnchorRevision+uint64(index)+1 || entry.Previous != previous || auditHash(entry) != entry.Hash || !idPattern.MatchString(entry.TokenID) || len(entry.Actor) < 1 || len(entry.Actor) > 128 || len(entry.Reason) > 256 {
			return errors.New("API token audit chain is invalid")
		}
		switch entry.Action {
		case "created", "revoked":
			if entry.Method != "" || entry.Path != "" || len(entry.Reason) < 3 {
				return errors.New("API token lifecycle audit entry is invalid")
			}
		case "used":
			if entry.Method == "" || !strings.HasPrefix(entry.Path, "/api/v1/") || entry.Reason != "" {
				return errors.New("API token use audit entry is invalid")
			}
		default:
			return errors.New("API token audit action is invalid")
		}
		previous = entry.Hash
	}
	if doc.AuditAnchorRevision == 0 && doc.AuditAnchorHash != "" || doc.AuditAnchorRevision != 0 && !digestPattern.MatchString(doc.AuditAnchorHash) {
		return errors.New("API token audit anchor is invalid")
	}
	if doc.Revision != doc.AuditAnchorRevision+uint64(len(doc.Audit)) {
		return errors.New("API token revision does not match audit chain")
	}
	return nil
}

func appendAudit(doc *document, action, tokenID, actor, method, path, reason string, now time.Time) error {
	if len(doc.Audit) >= MaxAudit {
		compactAudit(doc)
	}
	previous := doc.AuditAnchorHash
	if len(doc.Audit) > 0 {
		previous = doc.Audit[len(doc.Audit)-1].Hash
	}
	entry := AuditEntry{Revision: doc.Revision + 1, Action: action, TokenID: tokenID, Actor: actor, Method: method, Path: path, Reason: reason, OccurredAt: now, Previous: previous}
	entry.Hash = auditHash(entry)
	doc.Audit = append(doc.Audit, entry)
	doc.Revision = entry.Revision
	return nil
}

func compactAudit(doc *document) {
	if len(doc.Audit) < MaxAudit || AuditCompactionBatch < 1 {
		return
	}
	removed := AuditCompactionBatch
	if removed > len(doc.Audit) {
		removed = len(doc.Audit)
	}
	anchor := doc.Audit[removed-1]
	doc.AuditAnchorRevision = anchor.Revision
	doc.AuditAnchorHash = anchor.Hash
	retained := make([]AuditEntry, len(doc.Audit)-removed)
	copy(retained, doc.Audit[removed:])
	doc.Audit = retained
}

func compactTokenRecords(doc *document, now time.Time) {
	const maximumRecords = MaxTokens * 4
	if len(doc.Tokens) < maximumRecords {
		return
	}
	active := make([]Record, 0, MaxTokens)
	inactive := make([]Record, 0, len(doc.Tokens))
	for _, token := range doc.Tokens {
		if token.RevokedAt == nil && token.ExpiresAt.After(now) {
			active = append(active, token)
		} else {
			inactive = append(inactive, token)
		}
	}
	budget := maximumRecords - 1 - len(active)
	if budget < 0 {
		budget = 0
	}
	if len(inactive) > budget {
		inactive = inactive[len(inactive)-budget:]
	}
	doc.Tokens = append(active, inactive...)
}

func auditHash(entry AuditEntry) string {
	entry.Hash = ""
	data, _ := json.Marshal(entry)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func public(record Record, now time.Time) PublicRecord {
	state := "active"
	if record.RevokedAt != nil {
		state = "revoked"
	} else if !record.ExpiresAt.After(now) {
		state = "expired"
	}
	return PublicRecord{ID: record.ID, Name: record.Name, Creator: record.Creator, Scopes: append([]Scope(nil), record.Scopes...), Restrictions: record.Restrictions, CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt, RevokedAt: record.RevokedAt, LastUsedAt: record.LastUsedAt, UseCount: record.UseCount, SensitiveApproved: record.SensitiveApproved, State: state}
}

func normalizeScopes(scopes []Scope) []Scope {
	seen := make(map[Scope]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = Scope(strings.TrimSpace(string(scope)))
		seen[scope] = struct{}{}
	}
	result := make([]Scope, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func normalizeIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			seen[id] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func containsScope(scopes []Scope, required Scope) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func containsID(ids []string, wanted string) bool {
	if wanted == "" {
		return false
	}
	for _, id := range ids {
		if subtle.ConstantTimeCompare([]byte(id), []byte(wanted)) == 1 {
			return true
		}
	}
	return false
}
