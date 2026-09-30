package forwarder

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"shakerproxy.dev/shakerproxy/internal/ingest"
)

const (
	MaxIntegrations = 32
	MaxPending      = 4096
	MaxStateBytes   = 12 << 20
	MaxJSONLBytes   = 64 << 20
	MaxConfigAudit  = 2048
	// configAuditRollover keeps the audit (about 350 bytes per entry) well
	// inside maxConfigBytes; older entries roll off behind a hash anchor.
	configAuditRollover = 512
	maxConfigBytes      = 256 << 10
	maxDeliveryTries    = 1000000
)

type Kind string

const (
	KindJSONL     Kind = "JSONL"
	KindWebhook   Kind = "WEBHOOK"
	KindSyslogTLS Kind = "SYSLOG_TLS"
)

var (
	idPattern        = regexp.MustCompile(`^fwd_[a-f0-9]{24}$`)
	appliancePattern = regexp.MustCompile(`^appliance_[a-f0-9]{32}$`)
	namePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$`)
	dnsLabelPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	ErrConflict      = errors.New("forwarder configuration revision conflict")
)

type Integration struct {
	ID          string       `json:"id"`
	Revision    uint64       `json:"revision"`
	Name        string       `json:"name"`
	Kind        Kind         `json:"kind"`
	Destination string       `json:"destination"`
	Classes     []EventClass `json:"classes"`
	Enabled     bool         `json:"enabled"`
	HMACSecret  string       `json:"hmac_secret,omitempty"`
	CreatedBy   string       `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type PublicIntegration struct {
	ID          string       `json:"id"`
	Revision    uint64       `json:"revision"`
	Name        string       `json:"name"`
	Kind        Kind         `json:"kind"`
	Destination string       `json:"destination"`
	Classes     []EventClass `json:"classes"`
	Enabled     bool         `json:"enabled"`
	CreatedBy   string       `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type CreateRequest struct {
	Name        string
	Kind        Kind
	Destination string
	Classes     []EventClass
	Actor       string
}

type Created struct {
	Integration PublicIntegration `json:"integration"`
	HMACSecret  string            `json:"hmac_secret,omitempty"`
}

type ConfigurationAudit struct {
	Revision   uint64    `json:"revision"`
	Action     string    `json:"action"`
	Forwarder  string    `json:"forwarder_id"`
	Actor      string    `json:"actor"`
	Reason     string    `json:"reason"`
	OccurredAt time.Time `json:"occurred_at"`
	Previous   string    `json:"previous_hash"`
	Hash       string    `json:"hash"`
}

type configuration struct {
	SchemaVersion int                  `json:"schema_version"`
	Revision      uint64               `json:"revision"`
	ApplianceID   string               `json:"appliance_id"`
	Integrations  []Integration        `json:"integrations"`
	Audit         []ConfigurationAudit `json:"audit"`
	// AuditAnchor is the hash of the newest audit entry dropped when the
	// bounded audit rolled over; the retained chain continues from it.
	AuditAnchor string `json:"audit_anchor,omitempty"`
}

// UpdateRequest is a partial edit of a forwarder. Kind cannot change.
type UpdateRequest struct {
	Name        *string
	Destination *string
	Classes     *[]EventClass
	Actor       string
	Reason      string
}

type Delivery struct {
	Event         SafeEvent `json:"event"`
	Digest        string    `json:"digest"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
}

type deliveryState struct {
	SchemaVersion int        `json:"schema_version"`
	ForwarderID   string     `json:"forwarder_id"`
	NextSequence  uint64     `json:"next_sequence"`
	Pending       []Delivery `json:"pending"`
	Dropped       uint64     `json:"dropped"`
	Delivered     uint64     `json:"delivered"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

type Status struct {
	Integration   PublicIntegration `json:"integration"`
	Queued        int               `json:"queued"`
	Dropped       uint64            `json:"dropped"`
	Delivered     uint64            `json:"delivered"`
	LastSuccessAt *time.Time        `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time        `json:"last_failure_at,omitempty"`
	LastError     string            `json:"last_error,omitempty"`
}

type Manager struct {
	Root string
	Now  func() time.Time
	mu   sync.Mutex
}

func AllowedClasses() []EventClass {
	return []EventClass{ClassAlert, ClassAudit, ClassDevice, ClassDNS, ClassNetworkObservation, ClassHealth}
}

func (m *Manager) Create(request CreateRequest) (Created, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	storeLock, err := m.lockStore()
	if err != nil {
		return Created{}, err
	}
	defer unlockStore(storeLock)
	request.Name = strings.TrimSpace(request.Name)
	request.Actor = strings.TrimSpace(request.Actor)
	if !allClassesValid(request.Classes) {
		return Created{}, errors.New("forwarder includes an unsupported event class")
	}
	request.Classes = normalizeClasses(request.Classes)
	if !namePattern.MatchString(request.Name) || len(request.Actor) < 1 || len(request.Actor) > 128 {
		return Created{}, errors.New("forwarder name or actor is invalid")
	}
	doc, err := m.loadConfiguration(true)
	if err != nil {
		return Created{}, err
	}
	if len(doc.Integrations) >= MaxIntegrations {
		return Created{}, errors.New("forwarder integration limit reached")
	}
	id, err := randomID("fwd_", 12)
	if err != nil {
		return Created{}, err
	}
	destination, err := normalizeDestination(request.Kind, request.Destination, id)
	if err != nil {
		return Created{}, err
	}
	if len(request.Classes) == 0 {
		request.Classes = AllowedClasses()
	}
	secret := ""
	if request.Kind == KindWebhook {
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			return Created{}, err
		}
		secret = base64.RawURLEncoding.EncodeToString(secretBytes)
	}
	now := m.now()
	integration := Integration{ID: id, Revision: 1, Name: request.Name, Kind: request.Kind, Destination: destination, Classes: request.Classes, Enabled: false, HMACSecret: secret, CreatedBy: request.Actor, CreatedAt: now, UpdatedAt: now}
	doc.Integrations = append(doc.Integrations, integration)
	if err := appendConfigAudit(&doc, "created_disabled", id, request.Actor, "new integrations are disabled by default", now); err != nil {
		return Created{}, err
	}
	if err := m.saveConfiguration(doc); err != nil {
		return Created{}, err
	}
	return Created{Integration: publicIntegration(integration), HMACSecret: secret}, nil
}

func (m *Manager) SetEnabled(id string, expectedRevision uint64, enabled bool, actor, reason string) (PublicIntegration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	storeLock, err := m.lockStore()
	if err != nil {
		return PublicIntegration{}, err
	}
	defer unlockStore(storeLock)
	actor, reason = strings.TrimSpace(actor), strings.TrimSpace(reason)
	if !idPattern.MatchString(id) || len(actor) < 1 || len(actor) > 128 || len(reason) < 3 || len(reason) > 256 {
		return PublicIntegration{}, errors.New("forwarder activation request is invalid")
	}
	doc, err := m.loadConfiguration(false)
	if err != nil {
		return PublicIntegration{}, err
	}
	for index := range doc.Integrations {
		item := &doc.Integrations[index]
		if item.ID != id {
			continue
		}
		if expectedRevision != 0 && item.Revision != expectedRevision {
			return PublicIntegration{}, ErrConflict
		}
		if item.Enabled != enabled {
			item.Enabled = enabled
			item.Revision++
			item.UpdatedAt = m.now()
			action := "disabled"
			if enabled {
				action = "enabled"
			}
			if err := appendConfigAudit(&doc, action, id, actor, reason, item.UpdatedAt); err != nil {
				return PublicIntegration{}, err
			}
			if err := m.saveConfiguration(doc); err != nil {
				return PublicIntegration{}, err
			}
		}
		return publicIntegration(*item), nil
	}
	return PublicIntegration{}, os.ErrNotExist
}

// Update edits a forwarder's name, destination or event classes. Kind and the
// webhook signing secret are unchanged. A request that matches the stored
// values returns the forwarder without a new revision.
func (m *Manager) Update(id string, expectedRevision uint64, request UpdateRequest) (PublicIntegration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	storeLock, err := m.lockStore()
	if err != nil {
		return PublicIntegration{}, err
	}
	defer unlockStore(storeLock)
	actor, reason := strings.TrimSpace(request.Actor), strings.TrimSpace(request.Reason)
	if reason == "" {
		reason = "forwarder settings updated"
	}
	if !idPattern.MatchString(id) || len(actor) < 1 || len(actor) > 128 || len(reason) < 3 || len(reason) > 256 {
		return PublicIntegration{}, errors.New("forwarder update request is invalid")
	}
	if request.Name == nil && request.Destination == nil && request.Classes == nil {
		return PublicIntegration{}, errors.New("forwarder update must change name, destination or classes")
	}
	doc, err := m.loadConfiguration(false)
	if err != nil {
		return PublicIntegration{}, err
	}
	for index := range doc.Integrations {
		item := &doc.Integrations[index]
		if item.ID != id {
			continue
		}
		if expectedRevision != 0 && item.Revision != expectedRevision {
			return PublicIntegration{}, ErrConflict
		}
		next := *item
		if request.Name != nil {
			next.Name = strings.TrimSpace(*request.Name)
			if !namePattern.MatchString(next.Name) {
				return PublicIntegration{}, errors.New("forwarder name must be 1-64 letters, digits, spaces, dots, dashes or underscores")
			}
		}
		if request.Destination != nil {
			destination, err := normalizeDestination(item.Kind, *request.Destination, item.ID)
			if err != nil {
				return PublicIntegration{}, err
			}
			next.Destination = destination
		}
		if request.Classes != nil {
			if !allClassesValid(*request.Classes) {
				return PublicIntegration{}, errors.New("forwarder includes an unsupported event class")
			}
			classes := normalizeClasses(*request.Classes)
			if len(classes) == 0 {
				return PublicIntegration{}, errors.New("choose at least one event class")
			}
			next.Classes = classes
		}
		if next.Name == item.Name && next.Destination == item.Destination && slices.Equal(next.Classes, item.Classes) {
			return publicIntegration(*item), nil
		}
		next.Revision++
		next.UpdatedAt = m.now()
		*item = next
		if err := appendConfigAudit(&doc, "updated", id, actor, reason, item.UpdatedAt); err != nil {
			return PublicIntegration{}, err
		}
		if err := m.saveConfiguration(doc); err != nil {
			return PublicIntegration{}, err
		}
		return publicIntegration(*item), nil
	}
	return PublicIntegration{}, os.ErrNotExist
}

// Delete removes a forwarder and its pending delivery queue. A local JSONL
// forwarder's output file is kept for the operator to collect or remove.
func (m *Manager) Delete(id string, expectedRevision uint64, actor, reason string) (PublicIntegration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	storeLock, err := m.lockStore()
	if err != nil {
		return PublicIntegration{}, err
	}
	defer unlockStore(storeLock)
	actor, reason = strings.TrimSpace(actor), strings.TrimSpace(reason)
	if reason == "" {
		reason = "forwarder deleted"
	}
	if !idPattern.MatchString(id) || len(actor) < 1 || len(actor) > 128 || len(reason) < 3 || len(reason) > 256 {
		return PublicIntegration{}, errors.New("forwarder deletion request is invalid")
	}
	doc, err := m.loadConfiguration(false)
	if err != nil {
		return PublicIntegration{}, err
	}
	for index, item := range doc.Integrations {
		if item.ID != id {
			continue
		}
		if expectedRevision != 0 && item.Revision != expectedRevision {
			return PublicIntegration{}, ErrConflict
		}
		doc.Integrations = append(append([]Integration(nil), doc.Integrations[:index]...), doc.Integrations[index+1:]...)
		if err := appendConfigAudit(&doc, "deleted", id, actor, reason, m.now()); err != nil {
			return PublicIntegration{}, err
		}
		if err := m.saveConfiguration(doc); err != nil {
			return PublicIntegration{}, err
		}
		if err := os.Remove(filepath.Join(m.Root, "state", id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return publicIntegration(item), fmt.Errorf("forwarder deleted but its delivery queue could not be removed: %w", err)
		}
		return publicIntegration(item), nil
	}
	return PublicIntegration{}, os.ErrNotExist
}

func validAuditHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (m *Manager) Status() ([]Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	storeLock, err := m.lockStore()
	if err != nil {
		return nil, err
	}
	defer unlockStore(storeLock)
	doc, err := m.loadConfiguration(true)
	if err != nil {
		return nil, err
	}
	result := make([]Status, 0, len(doc.Integrations))
	for _, integration := range doc.Integrations {
		state, err := m.loadState(integration.ID)
		if err != nil {
			return nil, err
		}
		result = append(result, Status{Integration: publicIntegration(integration), Queued: len(state.Pending), Dropped: state.Dropped, Delivered: state.Delivered, LastSuccessAt: state.LastSuccessAt, LastFailureAt: state.LastFailureAt, LastError: state.LastError})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Integration.CreatedAt.After(result[j].Integration.CreatedAt) })
	return result, nil
}

func (m *Manager) Enqueue(envelope ingest.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	storeLock, err := m.lockStore()
	if err != nil {
		return err
	}
	defer unlockStore(storeLock)
	doc, err := m.loadConfiguration(true)
	if err != nil {
		return err
	}
	for _, integration := range doc.Integrations {
		if !integration.Enabled || !hasClass(integration.Classes, classify(envelope)) {
			continue
		}
		state, err := m.loadState(integration.ID)
		if err != nil {
			return err
		}
		state.NextSequence++
		event, err := Project(doc.ApplianceID, state.NextSequence, envelope)
		if err != nil {
			return err
		}
		if len(state.Pending) >= MaxPending {
			state.Pending = append([]Delivery(nil), state.Pending[1:]...)
			state.Dropped++
		}
		state.Pending = append(state.Pending, Delivery{Event: event, Digest: EventDigest(event)})
		if err := m.saveState(state); err != nil {
			return err
		}
	}
	return nil
}

// lockStore serializes the queue and configuration across ingestd, forwarderd,
// and control-api processes. The in-memory mutex alone only protects one
// process and is therefore insufficient for the shared durable volume.
func (m *Manager) lockStore() (*os.File, error) {
	if err := os.MkdirAll(m.Root, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(m.Root, ".store.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open forwarder store lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire forwarder store lock: %w", err)
	}
	return file, nil
}

func unlockStore(file *os.File) {
	if file == nil {
		return
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}

func (m *Manager) loadConfiguration(create bool) (configuration, error) {
	path := filepath.Join(m.Root, "config.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		id, idErr := randomID("appliance_", 16)
		if idErr != nil {
			return configuration{}, idErr
		}
		doc := configuration{SchemaVersion: SchemaVersion, ApplianceID: id, Integrations: []Integration{}, Audit: []ConfigurationAudit{}}
		if err := writeExclusiveJSON(path, doc); err == nil {
			return doc, nil
		} else if !errors.Is(err, os.ErrExist) {
			return configuration{}, err
		}
		data, err = os.ReadFile(path)
		if err != nil {
			return configuration{}, err
		}
	}
	if err != nil && len(data) == 0 {
		return configuration{}, err
	}
	if len(data) == 0 || len(data) > maxConfigBytes {
		return configuration{}, errors.New("forwarder configuration has invalid bounds")
	}
	var doc configuration
	if err := json.Unmarshal(data, &doc); err != nil {
		return configuration{}, errors.New("forwarder configuration is invalid JSON")
	}
	if err := validateConfiguration(doc); err != nil {
		return configuration{}, fmt.Errorf("forwarder configuration is invalid: %w", err)
	}
	return doc, nil
}

func (m *Manager) saveConfiguration(doc configuration) error {
	return writeAtomicJSON(filepath.Join(m.Root, "config.json"), doc)
}

func (m *Manager) loadState(id string) (deliveryState, error) {
	state := deliveryState{SchemaVersion: SchemaVersion, ForwarderID: id, Pending: []Delivery{}}
	data, err := os.ReadFile(filepath.Join(m.Root, "state", id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return deliveryState{}, err
	}
	if len(data) == 0 || len(data) > MaxStateBytes || json.Unmarshal(data, &state) != nil || state.SchemaVersion != SchemaVersion || state.ForwarderID != id || len(state.Pending) > MaxPending {
		return deliveryState{}, errors.New("forwarder delivery state is invalid")
	}
	for _, delivery := range state.Pending {
		if delivery.Event.Validate() != nil || delivery.Digest != EventDigest(delivery.Event) || delivery.Attempts < 0 || delivery.Attempts > maxDeliveryTries {
			return deliveryState{}, errors.New("forwarder delivery queue integrity is invalid")
		}
	}
	return state, nil
}

func (m *Manager) saveState(state deliveryState) error {
	return writeAtomicJSON(filepath.Join(m.Root, "state", state.ForwarderID+".json"), state)
}

func validateConfiguration(doc configuration) error {
	if doc.SchemaVersion != SchemaVersion || !validApplianceID(doc.ApplianceID) || len(doc.Integrations) > MaxIntegrations || len(doc.Audit) > MaxConfigAudit || doc.Revision < uint64(len(doc.Audit)) || doc.AuditAnchor == "" && doc.Revision != uint64(len(doc.Audit)) || doc.AuditAnchor != "" && !validAuditHash(doc.AuditAnchor) {
		return errors.New("invalid configuration header")
	}
	ids := map[string]struct{}{}
	for _, item := range doc.Integrations {
		if !idPattern.MatchString(item.ID) || item.Revision == 0 || !namePattern.MatchString(item.Name) || len(item.CreatedBy) < 1 || len(item.CreatedBy) > 128 || item.CreatedAt.IsZero() || item.UpdatedAt.Before(item.CreatedAt) || len(item.Classes) == 0 || len(item.Classes) > len(AllowedClasses()) {
			return errors.New("invalid integration")
		}
		if _, ok := ids[item.ID]; ok {
			return errors.New("duplicate integration")
		}
		ids[item.ID] = struct{}{}
		if normalized, err := normalizeDestination(item.Kind, item.Destination, item.ID); err != nil {
			return err
		} else if normalized != item.Destination {
			return errors.New("integration destination is not canonical")
		}
		if item.Kind == KindWebhook && !validHMACSecret(item.HMACSecret) || item.Kind != KindWebhook && item.HMACSecret != "" {
			return errors.New("invalid integration secret")
		}
		if !slices.Equal(normalizeClasses(item.Classes), item.Classes) {
			return errors.New("integration classes are not canonical")
		}
	}
	previous := doc.AuditAnchor
	firstRevision := doc.Revision - uint64(len(doc.Audit)) + 1
	for index, entry := range doc.Audit {
		if entry.Revision != firstRevision+uint64(index) || entry.Previous != previous || configAuditHash(entry) != entry.Hash || !idPattern.MatchString(entry.Forwarder) || len(entry.Actor) < 1 || len(entry.Actor) > 128 || len(entry.Reason) < 3 || len(entry.Reason) > 256 {
			return errors.New("configuration audit chain is invalid")
		}
		switch entry.Action {
		case "created_disabled", "enabled", "disabled", "updated", "deleted":
		default:
			return errors.New("configuration audit action is invalid")
		}
		previous = entry.Hash
	}
	return nil
}

func normalizeDestination(kind Kind, raw, id string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 2048 {
		return "", errors.New("forwarder destination is too long")
	}
	switch kind {
	case KindJSONL:
		expected := "local://" + id + ".jsonl"
		if raw == "" || raw == expected {
			return expected, nil
		}
		return "", errors.New("JSONL forwarders use their fixed appliance-local destination")
	case KindWebhook:
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() != "" && parsed.Port() != "443" || !safeExternalHostname(parsed.Hostname()) {
			return "", errors.New("webhook destination must be an external HTTPS URL on port 443 without credentials, query, or fragment")
		}
		return parsed.String(), nil
	case KindSyslogTLS:
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "tls" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() != "6514" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || !safeExternalHostname(parsed.Hostname()) {
			return "", errors.New("syslog destination must be tls://external-host:6514")
		}
		return parsed.String(), nil
	default:
		return "", errors.New("forwarder transport is unsupported")
	}
}

func safeExternalHostname(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.ContainsAny(host, " \t\r\n/%") {
		return false
	}
	if address := net.ParseIP(host); address != nil {
		return safeExternalIP(address)
	}
	if len(host) > 253 || !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func safeExternalIP(address net.IP) bool {
	if address == nil || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	for _, network := range []string{"100.64.0.0/10", "198.18.0.0/15"} {
		_, prefix, _ := net.ParseCIDR(network)
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func normalizeClasses(classes []EventClass) []EventClass {
	allowed := map[EventClass]struct{}{}
	for _, value := range AllowedClasses() {
		allowed[value] = struct{}{}
	}
	seen := map[EventClass]struct{}{}
	for _, class := range classes {
		if _, ok := allowed[class]; ok {
			seen[class] = struct{}{}
		}
	}
	result := make([]EventClass, 0, len(seen))
	for class := range seen {
		result = append(result, class)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func allClassesValid(classes []EventClass) bool {
	allowed := map[EventClass]struct{}{}
	for _, value := range AllowedClasses() {
		allowed[value] = struct{}{}
	}
	for _, class := range classes {
		if _, ok := allowed[class]; !ok {
			return false
		}
	}
	return true
}

func hasClass(classes []EventClass, wanted EventClass) bool {
	for _, class := range classes {
		if class == wanted {
			return true
		}
	}
	return false
}

func appendConfigAudit(doc *configuration, action, id, actor, reason string, now time.Time) error {
	if len(doc.Audit) >= configAuditRollover {
		// Roll the bounded audit over well before the configuration file
		// reaches maxConfigBytes: keep the newest entries and anchor the
		// retained chain to the last dropped hash.
		drop := len(doc.Audit) - configAuditRollover + configAuditRollover/4
		doc.AuditAnchor = doc.Audit[drop-1].Hash
		doc.Audit = append([]ConfigurationAudit(nil), doc.Audit[drop:]...)
	}
	previous := doc.AuditAnchor
	if len(doc.Audit) > 0 {
		previous = doc.Audit[len(doc.Audit)-1].Hash
	}
	entry := ConfigurationAudit{Revision: doc.Revision + 1, Action: action, Forwarder: id, Actor: actor, Reason: reason, OccurredAt: now, Previous: previous}
	entry.Hash = configAuditHash(entry)
	doc.Audit = append(doc.Audit, entry)
	doc.Revision = entry.Revision
	return nil
}

func configAuditHash(entry ConfigurationAudit) string {
	entry.Hash = ""
	encoded, _ := json.Marshal(entry)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func publicIntegration(item Integration) PublicIntegration {
	return PublicIntegration{ID: item.ID, Revision: item.Revision, Name: item.Name, Kind: item.Kind, Destination: item.Destination, Classes: append([]EventClass(nil), item.Classes...), Enabled: item.Enabled, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt}
}

func randomID(prefix string, bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}

func validApplianceID(id string) bool { return appliancePattern.MatchString(id) }

func validHMACSecret(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func writeAtomicJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".forwarder-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
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
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace forwarder state: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeExclusiveJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
