package savedview

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/querylang"
)

const (
	SchemaVersion      = 1
	MaxViewsPerRequest = 100
	MaxOwnedViews      = 100
	MaxHistory         = 100
)

var (
	ErrNotFound  = errors.New("saved view not found")
	ErrConflict  = errors.New("saved view revision conflict")
	ErrForbidden = errors.New("saved view mutation is forbidden")
	ErrLimit     = errors.New("saved view owner limit reached")
	// ErrInvalid reports a request the saved view service rejected as
	// invalid (HTTP 400); errors.Is matches it on an *InvalidError.
	ErrInvalid = errors.New("saved view request is invalid")
)

// InvalidError carries the saved view service's own explanation for a
// rejected request.
type InvalidError struct{ Message string }

func (e *InvalidError) Error() string {
	if e.Message == "" {
		return ErrInvalid.Error()
	}
	return e.Message
}

func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

type Scope string

const (
	ScopePersonal Scope = "personal"
	ScopeShared   Scope = "shared"
)

type TimeBehavior struct {
	Mode          string     `json:"mode"`
	RollingWindow string     `json:"rolling_window,omitempty"`
	Start         *time.Time `json:"start,omitempty"`
	End           *time.Time `json:"end,omitempty"`
}

type SortTerm struct {
	Field     string `json:"field"`
	Direction string `json:"direction"`
}

type ChartConfig struct {
	Visible  bool   `json:"visible"`
	Metric   string `json:"metric,omitempty"`
	Interval string `json:"interval,omitempty"`
}

type Configuration struct {
	Scope          Scope        `json:"scope"`
	Name           string       `json:"name"`
	Description    string       `json:"description,omitempty"`
	Page           string       `json:"page"`
	CanonicalQuery string       `json:"canonical_query,omitempty"`
	TimeBehavior   TimeBehavior `json:"time_behavior"`
	Sort           []SortTerm   `json:"sort"`
	Columns        []string     `json:"columns"`
	PinnedColumns  []string     `json:"pinned_columns"`
	Density        string       `json:"density"`
	Chart          ChartConfig  `json:"chart"`
}

type View struct {
	Schema int    `json:"schema"`
	ID     string `json:"id"`
	Configuration
	Owner      string    `json:"owner"`
	LastEditor string    `json:"last_editor"`
	Revision   int64     `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Version struct {
	Revision  int64     `json:"revision"`
	Editor    string    `json:"editor"`
	ChangedAt time.Time `json:"changed_at"`
	Snapshot  View      `json:"snapshot"`
}

type Page struct {
	Schema int    `json:"schema"`
	Views  []View `json:"views"`
}

type History struct {
	Schema   int       `json:"schema"`
	ViewID   string    `json:"view_id"`
	Versions []Version `json:"versions"`
}

type ListFilter struct {
	Scope Scope
	Page  string
}

type Update struct {
	ExpectedRevision int64         `json:"expected_revision"`
	Configuration    Configuration `json:"configuration"`
}

type Export struct {
	Schema     int           `json:"schema"`
	ExportedAt time.Time     `json:"exported_at"`
	View       Configuration `json:"view"`
}

type Repository interface {
	List(context.Context, string, ListFilter) (Page, error)
	Get(context.Context, string, string) (View, error)
	Create(context.Context, string, Configuration) (View, error)
	Update(context.Context, string, string, Update) (View, error)
	Delete(context.Context, string, string, int64) error
	History(context.Context, string, string) (History, error)
}

func Normalize(configuration Configuration) (Configuration, error) {
	configuration.Name = strings.TrimSpace(configuration.Name)
	configuration.Description = strings.TrimSpace(configuration.Description)
	configuration.Page = strings.TrimSpace(configuration.Page)
	configuration.CanonicalQuery = strings.TrimSpace(configuration.CanonicalQuery)
	if configuration.Scope != ScopePersonal && configuration.Scope != ScopeShared {
		return Configuration{}, errors.New("saved view scope is invalid")
	}
	if !boundedText(configuration.Name, 1, 96) || !boundedText(configuration.Description, 0, 512) || configuration.Page != "live-traffic" {
		return Configuration{}, errors.New("saved view identity is invalid")
	}
	parsed, err := querylang.Parse(configuration.CanonicalQuery)
	if err != nil {
		return Configuration{}, err
	}
	configuration.CanonicalQuery = parsed.Canonical
	if err := validateTimeBehavior(configuration.TimeBehavior); err != nil {
		return Configuration{}, err
	}
	if configuration.TimeBehavior.Start != nil {
		start := configuration.TimeBehavior.Start.UTC()
		configuration.TimeBehavior.Start = &start
	}
	if configuration.TimeBehavior.End != nil {
		end := configuration.TimeBehavior.End.UTC()
		configuration.TimeBehavior.End = &end
	}
	if len(configuration.Sort) == 0 {
		configuration.Sort = []SortTerm{{Field: "occurred_at", Direction: "desc"}}
	}
	if len(configuration.Sort) > 3 {
		return Configuration{}, errors.New("saved view sort is too large")
	}
	seenSort := map[string]bool{}
	for _, term := range configuration.Sort {
		if !allowedField(term.Field) || term.Direction != "asc" && term.Direction != "desc" || seenSort[term.Field] {
			return Configuration{}, errors.New("saved view sort is invalid")
		}
		seenSort[term.Field] = true
	}
	if len(configuration.Columns) == 0 {
		configuration.Columns = []string{"source", "occurred_at", "device", "network"}
	}
	if len(configuration.Columns) > 16 || len(configuration.PinnedColumns) > 3 {
		return Configuration{}, errors.New("saved view columns are too large")
	}
	columns := map[string]bool{}
	for _, column := range configuration.Columns {
		if !allowedColumn(column) || columns[column] {
			return Configuration{}, errors.New("saved view columns are invalid")
		}
		columns[column] = true
	}
	pinned := map[string]bool{}
	for _, column := range configuration.PinnedColumns {
		if !columns[column] || pinned[column] {
			return Configuration{}, errors.New("saved view pinned columns are invalid")
		}
		pinned[column] = true
	}
	if configuration.Density == "" {
		configuration.Density = "comfortable"
	}
	if configuration.Density != "comfortable" && configuration.Density != "compact" {
		return Configuration{}, errors.New("saved view density is invalid")
	}
	if configuration.Chart.Visible {
		if configuration.Chart.Metric != "events" || !oneOf(configuration.Chart.Interval, "1m", "5m", "15m", "1h") {
			return Configuration{}, errors.New("saved view chart configuration is invalid")
		}
	} else if configuration.Chart.Metric != "" || configuration.Chart.Interval != "" {
		return Configuration{}, errors.New("hidden saved view chart has configuration")
	}
	return configuration, nil
}

func ValidateView(view View) error {
	normalized, err := Normalize(view.Configuration)
	if err != nil || !reflect.DeepEqual(normalized, view.Configuration) || view.Schema != SchemaVersion || !ValidID(view.ID) || !ValidActor(view.Owner) || !ValidActor(view.LastEditor) || view.Revision < 1 || view.CreatedAt.IsZero() || view.UpdatedAt.Before(view.CreatedAt) {
		return errors.New("saved view is invalid")
	}
	return nil
}

func validateTimeBehavior(value TimeBehavior) error {
	switch value.Mode {
	case "query":
		if value.RollingWindow != "" || value.Start != nil || value.End != nil {
			return errors.New("query time behavior has extra bounds")
		}
	case "rolling":
		if !oneOf(value.RollingWindow, "15m", "1h", "6h", "24h", "7d") || value.Start != nil || value.End != nil {
			return errors.New("rolling time behavior is invalid")
		}
	case "absolute":
		if value.RollingWindow != "" || value.Start == nil || value.End == nil || value.Start.IsZero() || value.End.IsZero() || !value.Start.Before(*value.End) || value.End.Sub(*value.Start) > 30*24*time.Hour {
			return errors.New("absolute time behavior is invalid")
		}
	default:
		return errors.New("saved view time behavior is invalid")
	}
	return nil
}

func ValidID(value string) bool {
	if len(value) != len("view-")+32 || !strings.HasPrefix(value, "view-") {
		return false
	}
	for _, char := range value[len("view-"):] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

func ValidActor(value string) bool {
	if len(value) < 1 || len(value) > 96 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._@-", char)) {
			return false
		}
	}
	return true
}

func boundedText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func allowedField(value string) bool {
	return oneOf(value, "occurred_at", "received_at", "source", "kind", "device", "source_ip", "destination_ip", "protocol", "service", "network_bytes", "confidence")
}

func allowedColumn(value string) bool {
	return oneOf(value, "source", "occurred_at", "received_at", "kind", "device", "network", "protocol", "service", "bytes", "confidence", "capture", "flow")
}
