package casework

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Schema             = 1
	MaxCases           = 1024
	MaxEvidencePerCase = 1024
	MaxTimelineEvents  = 2048
)

type Status string

const (
	StatusOpen   Status = "OPEN"
	StatusClosed Status = "CLOSED"
)

type EvidenceKind string

const (
	EvidenceCapture       EvidenceKind = "CAPTURE"
	EvidenceQuerySnapshot EvidenceKind = "QUERY_SNAPSHOT"
	EvidenceCaptureExport EvidenceKind = "CAPTURE_EXPORT"
)

type HoldState string

const (
	HoldInactive HoldState = "INACTIVE"
	HoldActive   HoldState = "ACTIVE"
	HoldPartial  HoldState = "PARTIAL"
)

var (
	caseIDPattern     = regexp.MustCompile(`^case-[a-f0-9]{32}$`)
	evidenceIDPattern = regexp.MustCompile(`^evidence-[a-f0-9]{32}$`)
	captureIDPattern  = regexp.MustCompile(`^capture-[a-f0-9]{32}$`)
	snapshotIDPattern = regexp.MustCompile(`^qsnap-[a-f0-9]{32}$`)
	exportIDPattern   = regexp.MustCompile(`^export-[a-f0-9]{32}$`)
)

type Evidence struct {
	ID         string       `json:"id"`
	Kind       EvidenceKind `json:"kind"`
	ArtifactID string       `json:"artifact_id"`
	Label      string       `json:"label"`
	AddedBy    string       `json:"added_by"`
	AddedAt    time.Time    `json:"added_at"`
	// Query pins what a QUERY_SNAPSHOT matched when it was attached. Query
	// snapshots expire within an hour; the canonical query plus the dataset
	// watermark keep the evidence reproducible afterwards (re-run the query
	// over records at or below the watermark). Records deleted later by
	// retention or deletion jobs are not restored.
	Query *QuerySnapshotPin `json:"query,omitempty"`
}

// QuerySnapshotPin is the durable part of an event query snapshot.
type QuerySnapshotPin struct {
	CanonicalQuery    string         `json:"canonical_query"`
	QueryAnchor       *time.Time     `json:"query_anchor,omitempty"`
	MatchedCount      int64          `json:"matched_count"`
	CountRelation     string         `json:"count_relation"`
	SnapshotCreatedAt time.Time      `json:"snapshot_created_at"`
	SnapshotSHA256    string         `json:"snapshot_sha256"`
	DatasetWatermark  QueryWatermark `json:"dataset_watermark"`
}

// QueryWatermark is the ingest boundary a query snapshot was frozen at.
type QueryWatermark struct {
	IngestSequence int64     `json:"ingest_sequence"`
	ReceivedAt     time.Time `json:"received_at"`
	RecordID       string    `json:"record_id"`
}

// EvidenceInput describes evidence to attach. Query is required for
// QUERY_SNAPSHOT evidence and must be empty for other kinds.
type EvidenceInput struct {
	Kind       EvidenceKind
	ArtifactID string
	Label      string
	Query      *QuerySnapshotPin
}

// Update is a partial change to a case's name and description.
type Update struct {
	Name        *string
	Description *string
}

var (
	// ErrRevisionChanged reports an expected_revision that no longer matches.
	ErrRevisionChanged = errors.New("case revision changed")
	// ErrCaseLimit reports that the case ledger is full.
	ErrCaseLimit = errors.New("case limit reached")
	// ErrHoldActive reports an operation blocked by an active evidence hold.
	ErrHoldActive = errors.New("case evidence hold is active")
)

const addedAfterHoldFailure = "Added after the hold was applied; apply the hold again to protect this capture."

type HoldResult struct {
	EvidenceID string `json:"evidence_id"`
	ArtifactID string `json:"artifact_id"`
	Protected  bool   `json:"protected"`
	Revision   uint64 `json:"revision,omitempty"`
	Failure    string `json:"failure,omitempty"`
}

type Hold struct {
	State         HoldState    `json:"state"`
	DesiredActive bool         `json:"desired_active"`
	Reason        string       `json:"reason,omitempty"`
	Actor         string       `json:"actor,omitempty"`
	OperationID   string       `json:"operation_id,omitempty"`
	UpdatedAt     time.Time    `json:"updated_at,omitempty"`
	Results       []HoldResult `json:"results"`
}

type TimelineEvent struct {
	Revision       uint64    `json:"revision"`
	Action         string    `json:"action"`
	Actor          string    `json:"actor"`
	Reason         string    `json:"reason"`
	OccurredAt     time.Time `json:"occurred_at"`
	PreviousSHA256 string    `json:"previous_sha256,omitempty"`
	SHA256         string    `json:"sha256"`
}

type Case struct {
	Schema      int             `json:"schema"`
	ID          string          `json:"id"`
	Revision    uint64          `json:"revision"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Status      Status          `json:"status"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Evidence    []Evidence      `json:"evidence"`
	Hold        Hold            `json:"hold"`
	Timeline    []TimelineEvent `json:"timeline"`
}

type Store struct {
	Path   string
	Now    func() time.Time
	Random func([]byte) (int, error)
	mu     sync.Mutex
}

type ledger struct {
	Schema int    `json:"schema"`
	Cases  []Case `json:"cases"`
}

func ValidCaseID(value string) bool { return caseIDPattern.MatchString(value) }

func (s *Store) Create(name, description, actor, reason string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateText("case name", name, 1, 96); err != nil {
		return Case{}, err
	}
	description = normalizeDescription(description)
	if err := validateDescription(description); err != nil {
		return Case{}, err
	}
	if err := validateText("case actor", actor, 1, 96); err != nil {
		return Case{}, err
	}
	if err := validateText("case reason", reason, 1, 512); err != nil {
		return Case{}, err
	}
	current, err := s.read()
	if err != nil {
		return Case{}, err
	}
	if len(current.Cases) >= MaxCases {
		return Case{}, fmt.Errorf("%w: the maximum of %d cases exists; delete cases you no longer need", ErrCaseLimit, MaxCases)
	}
	id, err := s.newID("case-", func(value string) bool {
		for _, item := range current.Cases {
			if item.ID == value {
				return true
			}
		}
		return false
	})
	if err != nil {
		return Case{}, err
	}
	now := s.now()
	item := Case{Schema: Schema, ID: id, Revision: 1, Name: name, Description: description, Status: StatusOpen, CreatedBy: actor, CreatedAt: now, UpdatedAt: now, Evidence: []Evidence{}, Hold: Hold{State: HoldInactive, Results: []HoldResult{}}, Timeline: []TimelineEvent{}}
	if err := appendTimeline(&item, "CASE_CREATED", actor, reason, now); err != nil {
		return Case{}, err
	}
	if err := item.Validate(); err != nil {
		return Case{}, err
	}
	current.Cases = append(current.Cases, item)
	if err := s.write(current); err != nil {
		return Case{}, err
	}
	return item, nil
}

func (s *Store) List() ([]Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read()
	if err != nil {
		return nil, err
	}
	items := append([]Case(nil), current.Cases...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items, nil
}

func (s *Store) Get(id string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read()
	if err != nil {
		return Case{}, err
	}
	_, item := findCase(current.Cases, id)
	if item == nil {
		return Case{}, os.ErrNotExist
	}
	return *item, nil
}

func (s *Store) AddEvidence(caseID string, expectedRevision uint64, kind EvidenceKind, artifactID, label, actor, reason string) (Case, error) {
	return s.AttachEvidence(caseID, expectedRevision, EvidenceInput{Kind: kind, ArtifactID: artifactID, Label: label}, actor, reason)
}

// AttachEvidence adds evidence to an open case. Non-capture evidence does not
// affect an evidence hold. A capture added while a hold is (partly) applied is
// recorded as not yet protected, so the hold becomes PARTIAL until it is
// applied again; a released hold resets as before.
func (s *Store) AttachEvidence(caseID string, expectedRevision uint64, input EvidenceInput, actor, reason string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kind, artifactID, label := input.Kind, input.ArtifactID, input.Label
	if !validEvidenceArtifact(kind, artifactID) {
		return Case{}, errors.New("case evidence reference is invalid")
	}
	if err := validateQueryPin(kind, input.Query); err != nil {
		return Case{}, err
	}
	for _, value := range []struct {
		name, value string
		min, max    int
	}{{"evidence label", label, 1, 256}, {"case actor", actor, 1, 96}, {"case reason", reason, 1, 512}} {
		if err := validateText(value.name, value.value, value.min, value.max); err != nil {
			return Case{}, err
		}
	}
	current, err := s.read()
	if err != nil {
		return Case{}, err
	}
	index, item := findCase(current.Cases, caseID)
	if item == nil {
		return Case{}, os.ErrNotExist
	}
	if expectedRevision != 0 && item.Revision != expectedRevision {
		return Case{}, ErrRevisionChanged
	}
	if item.Status != StatusOpen {
		return Case{}, errors.New("closed cases cannot accept evidence; reopen the case first")
	}
	if len(item.Evidence) >= MaxEvidencePerCase {
		return Case{}, errors.New("case evidence limit exceeded")
	}
	for _, evidence := range item.Evidence {
		if evidence.Kind == kind && evidence.ArtifactID == artifactID {
			return Case{}, errors.New("evidence is already attached to this case")
		}
	}
	id, err := s.newID("evidence-", func(value string) bool {
		for _, evidence := range item.Evidence {
			if evidence.ID == value {
				return true
			}
		}
		return false
	})
	if err != nil {
		return Case{}, err
	}
	now := s.now()
	item.Revision++
	item.UpdatedAt = now
	item.Evidence = append(item.Evidence, Evidence{ID: id, Kind: kind, ArtifactID: artifactID, Label: label, AddedBy: actor, AddedAt: now, Query: cloneQueryPin(input.Query)})
	if !item.Hold.UpdatedAt.IsZero() {
		if item.Hold.State == HoldInactive && !item.Hold.DesiredActive {
			// A fully released hold resets on any membership change.
			item.Hold = Hold{State: HoldInactive, Results: []HoldResult{}}
		} else if kind == EvidenceCapture {
			failure := addedAfterHoldFailure
			if !item.Hold.DesiredActive {
				failure = ""
			}
			item.Hold.Results = append(item.Hold.Results, HoldResult{EvidenceID: id, ArtifactID: artifactID, Failure: failure})
			item.Hold.State = aggregateHoldState(item.Hold)
		}
	}
	if err := appendTimeline(item, "EVIDENCE_ADDED", actor, reason, now); err != nil {
		return Case{}, err
	}
	if err := item.Validate(); err != nil {
		return Case{}, err
	}
	current.Cases[index] = *item
	if err := s.write(current); err != nil {
		return Case{}, err
	}
	return *item, nil
}

func (s *Store) RecordHold(caseID string, expectedRevision uint64, desired bool, reason, actor, operationID string, results []HoldResult) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateText("hold reason", reason, 1, 512); err != nil {
		return Case{}, err
	}
	if err := validateText("hold actor", actor, 1, 96); err != nil {
		return Case{}, err
	}
	if !validOpaqueKey(operationID) {
		return Case{}, errors.New("hold operation identity is invalid")
	}
	current, err := s.read()
	if err != nil {
		return Case{}, err
	}
	index, item := findCase(current.Cases, caseID)
	if item == nil {
		return Case{}, os.ErrNotExist
	}
	if expectedRevision != 0 && item.Revision != expectedRevision {
		return Case{}, ErrRevisionChanged
	}
	captures := captureEvidenceMap(item.Evidence)
	if len(captures) == 0 {
		return Case{}, errors.New("case hold requires at least one capture reference")
	}
	if len(results) != len(captures) {
		return Case{}, errors.New("hold result set does not cover every capture")
	}
	all := true
	seen := map[string]struct{}{}
	for _, result := range results {
		if !evidenceIDPattern.MatchString(result.EvidenceID) || !captureIDPattern.MatchString(result.ArtifactID) || (result.Protected && result.Revision == 0) {
			return Case{}, errors.New("hold result is invalid")
		}
		if err := validateText("hold result failure", result.Failure, 0, 256); err != nil {
			return Case{}, err
		}
		if _, exists := seen[result.EvidenceID]; exists {
			return Case{}, errors.New("duplicate hold result")
		}
		if artifactID, exists := captures[result.EvidenceID]; !exists || artifactID != result.ArtifactID {
			return Case{}, errors.New("hold result does not match case evidence")
		}
		seen[result.EvidenceID] = struct{}{}
		if result.Protected != desired || result.Failure != "" {
			all = false
		}
	}
	state := HoldPartial
	if all {
		if desired {
			state = HoldActive
		} else {
			state = HoldInactive
		}
	}
	now := s.now()
	item.Revision++
	item.UpdatedAt = now
	item.Hold = Hold{State: state, DesiredActive: desired, Reason: reason, Actor: actor, OperationID: operationID, UpdatedAt: now, Results: append([]HoldResult(nil), results...)}
	action := "HOLD_PARTIAL"
	if state == HoldActive {
		action = "HOLD_APPLIED"
	} else if state == HoldInactive {
		action = "HOLD_RELEASED"
	}
	if err := appendTimeline(item, action, actor, reason, now); err != nil {
		return Case{}, err
	}
	if err := item.Validate(); err != nil {
		return Case{}, err
	}
	current.Cases[index] = *item
	if err := s.write(current); err != nil {
		return Case{}, err
	}
	return *item, nil
}

func (s *Store) SetStatus(caseID string, expectedRevision uint64, status Status, actor, reason string) (Case, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status != StatusOpen && status != StatusClosed {
		return Case{}, errors.New("case status is invalid")
	}
	if err := validateText("case actor", actor, 1, 96); err != nil {
		return Case{}, err
	}
	if err := validateText("case reason", reason, 1, 512); err != nil {
		return Case{}, err
	}
	current, err := s.read()
	if err != nil {
		return Case{}, err
	}
	index, item := findCase(current.Cases, caseID)
	if item == nil {
		return Case{}, os.ErrNotExist
	}
	if expectedRevision != 0 && item.Revision != expectedRevision {
		return Case{}, ErrRevisionChanged
	}
	if item.Status == status {
		return *item, nil
	}
	now := s.now()
	item.Revision++
	item.Status = status
	item.UpdatedAt = now
	if err := appendTimeline(item, "CASE_"+string(status), actor, reason, now); err != nil {
		return Case{}, err
	}
	if err := item.Validate(); err != nil {
		return Case{}, err
	}
	current.Cases[index] = *item
	if err := s.write(current); err != nil {
		return Case{}, err
	}
	return *item, nil
}

func (c Case) Validate() error {
	if c.Schema != Schema || !ValidCaseID(c.ID) || c.Revision == 0 || c.Revision != uint64(len(c.Timeline)) || len(c.Evidence) > MaxEvidencePerCase || len(c.Timeline) > MaxTimelineEvents || c.CreatedAt.IsZero() || c.UpdatedAt.Before(c.CreatedAt) || (c.Status != StatusOpen && c.Status != StatusClosed) {
		return errors.New("case is invalid")
	}
	for _, value := range []struct {
		name, value string
		min, max    int
	}{{"case name", c.Name, 1, 96}, {"case creator", c.CreatedBy, 1, 96}} {
		if err := validateText(value.name, value.value, value.min, value.max); err != nil {
			return err
		}
	}
	if err := validateDescription(c.Description); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, e := range c.Evidence {
		if !evidenceIDPattern.MatchString(e.ID) || !validEvidenceArtifact(e.Kind, e.ArtifactID) || e.AddedAt.Before(c.CreatedAt) || e.AddedAt.After(c.UpdatedAt) {
			return errors.New("case evidence is invalid")
		}
		if _, ok := seen[e.ID]; ok {
			return errors.New("duplicate case evidence identity")
		}
		seen[e.ID] = struct{}{}
		if err := validateText("evidence label", e.Label, 1, 256); err != nil {
			return err
		}
		if err := validateText("evidence actor", e.AddedBy, 1, 96); err != nil {
			return err
		}
		if err := validateQueryPin(e.Kind, e.Query); err != nil {
			return err
		}
	}
	if c.Hold.State != HoldInactive && c.Hold.State != HoldActive && c.Hold.State != HoldPartial {
		return errors.New("case hold state is invalid")
	}
	if c.Hold.UpdatedAt.IsZero() {
		if c.Hold.State != HoldInactive || c.Hold.DesiredActive || c.Hold.Reason != "" || c.Hold.Actor != "" || c.Hold.OperationID != "" || len(c.Hold.Results) != 0 {
			return errors.New("initial case hold state is invalid")
		}
	} else {
		if c.Hold.UpdatedAt.Before(c.CreatedAt) || c.Hold.UpdatedAt.After(c.UpdatedAt) || !validOpaqueKey(c.Hold.OperationID) {
			return errors.New("case hold operation identity is invalid")
		}
		if err := validateText("hold reason", c.Hold.Reason, 1, 512); err != nil {
			return err
		}
		if err := validateText("hold actor", c.Hold.Actor, 1, 96); err != nil {
			return err
		}
		captures := captureEvidenceMap(c.Evidence)
		if len(captures) == 0 || len(c.Hold.Results) != len(captures) {
			return errors.New("case hold result set is invalid")
		}
		all, holdSeen := true, map[string]struct{}{}
		for _, result := range c.Hold.Results {
			artifactID, exists := captures[result.EvidenceID]
			if !exists || artifactID != result.ArtifactID || (result.Protected && result.Revision == 0) {
				return errors.New("case hold result is invalid")
			}
			if err := validateText("hold result failure", result.Failure, 0, 256); err != nil {
				return err
			}
			if _, exists := holdSeen[result.EvidenceID]; exists {
				return errors.New("duplicate case hold result")
			}
			holdSeen[result.EvidenceID] = struct{}{}
			if result.Protected != c.Hold.DesiredActive || result.Failure != "" {
				all = false
			}
		}
		expectedState := HoldPartial
		if all && c.Hold.DesiredActive {
			expectedState = HoldActive
		} else if all {
			expectedState = HoldInactive
		}
		if c.Hold.State != expectedState {
			return errors.New("case hold aggregate state is invalid")
		}
	}
	previous := ""
	previousTime := c.CreatedAt
	for i, event := range c.Timeline {
		if event.Revision != uint64(i+1) || event.PreviousSHA256 != previous || event.OccurredAt.Before(previousTime) || event.OccurredAt.After(c.UpdatedAt) || !validTimelineAction(event.Action) || !validSHA(event.SHA256) {
			return errors.New("case timeline is invalid")
		}
		if err := validateText("timeline actor", event.Actor, 1, 96); err != nil {
			return err
		}
		if err := validateText("timeline reason", event.Reason, 1, 512); err != nil {
			return err
		}
		expected, err := eventDigest(event)
		if err != nil || expected != event.SHA256 {
			return errors.New("case timeline hash chain is invalid")
		}
		previous = event.SHA256
		previousTime = event.OccurredAt
	}
	if c.Timeline[0].Action != "CASE_CREATED" || !c.Timeline[0].OccurredAt.Equal(c.CreatedAt) || !c.Timeline[len(c.Timeline)-1].OccurredAt.Equal(c.UpdatedAt) {
		return errors.New("case timeline boundary is invalid")
	}
	return nil
}

func appendTimeline(item *Case, action, actor, reason string, now time.Time) error {
	if len(item.Timeline) >= MaxTimelineEvents {
		return errors.New("case timeline is full")
	}
	previous := ""
	if len(item.Timeline) > 0 {
		previous = item.Timeline[len(item.Timeline)-1].SHA256
	}
	event := TimelineEvent{Revision: item.Revision, Action: action, Actor: actor, Reason: reason, OccurredAt: now, PreviousSHA256: previous}
	digest, err := eventDigest(event)
	if err != nil {
		return err
	}
	event.SHA256 = digest
	item.Timeline = append(item.Timeline, event)
	return nil
}
func eventDigest(event TimelineEvent) (string, error) {
	event.SHA256 = ""
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func validEvidenceArtifact(kind EvidenceKind, id string) bool {
	switch kind {
	case EvidenceCapture:
		return captureIDPattern.MatchString(id)
	case EvidenceQuerySnapshot:
		return snapshotIDPattern.MatchString(id)
	case EvidenceCaptureExport:
		return exportIDPattern.MatchString(id)
	default:
		return false
	}
}
func captureEvidenceMap(items []Evidence) map[string]string {
	result := make(map[string]string)
	for _, item := range items {
		if item.Kind == EvidenceCapture {
			result[item.ID] = item.ArtifactID
		}
	}
	return result
}

func validOpaqueKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
func findCase(items []Case, id string) (int, *Case) {
	if !ValidCaseID(id) {
		return -1, nil
	}
	for i := range items {
		if items[i].ID == id {
			return i, &items[i]
		}
	}
	return -1, nil
}
func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func (s *Store) newID(prefix string, exists func(string) bool) (string, error) {
	random := s.Random
	if random == nil {
		random = rand.Read
	}
	for i := 0; i < 8; i++ {
		raw := make([]byte, 16)
		if _, err := random(raw); err != nil {
			return "", err
		}
		id := prefix + hex.EncodeToString(raw)
		if !exists(id) {
			return id, nil
		}
	}
	return "", errors.New("could not allocate unique identity")
}

func (s *Store) read() (ledger, error) {
	if s.Path == "" || !filepath.IsAbs(s.Path) {
		return ledger{}, errors.New("case store path must be absolute")
	}
	data, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return ledger{Schema: Schema, Cases: []Case{}}, nil
	}
	if err != nil {
		return ledger{}, err
	}
	if len(data) > 32<<20 {
		return ledger{}, errors.New("case ledger is too large")
	}
	var current ledger
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&current); err != nil {
		return ledger{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ledger{}, errors.New("case ledger has trailing data")
	}
	if current.Schema != Schema || len(current.Cases) > MaxCases {
		return ledger{}, errors.New("case ledger is invalid")
	}
	seen := map[string]struct{}{}
	for _, item := range current.Cases {
		if err := item.Validate(); err != nil {
			return ledger{}, err
		}
		if _, ok := seen[item.ID]; ok {
			return ledger{}, errors.New("duplicate case identity")
		}
		seen[item.ID] = struct{}{}
	}
	return current, nil
}
func (s *Store) write(current ledger) error {
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".cases-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(data, '\n')); err != nil {
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
	if err := os.Rename(name, s.Path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func validateText(label, value string, min, max int) error {
	if len(value) < min || len(value) > max || value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must contain between %d and %d trimmed bytes", label, min, max)
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}
func validSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validTimelineAction(value string) bool {
	switch value {
	case "CASE_CREATED", "EVIDENCE_ADDED", "EVIDENCE_REMOVED", "CASE_UPDATED", "HOLD_APPLIED", "HOLD_RELEASED", "HOLD_PARTIAL", "CASE_OPEN", "CASE_CLOSED":
		return true
	default:
		return false
	}
}
