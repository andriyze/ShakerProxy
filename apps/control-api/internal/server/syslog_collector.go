package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/syslogcollector"
)

// The network-gear syslog collector receives the lab router's own logs (UniFi
// first) and turns them into events and device identity. These endpoints read
// and write its configuration and read its status. Changing the configuration
// is a standing change, so it needs the administrator password, like the
// outbound forwarders.

type syslogCollectorView struct {
	Available      bool              `json:"available"`
	Enabled        bool              `json:"enabled"`
	BindAddress    string            `json:"bind_address"`
	TCP            bool              `json:"tcp"`
	UDP            bool              `json:"udp"`
	AllowedSources []string          `json:"allowed_sources"`
	Revision       int               `json:"revision"`
	UpdatedAt      time.Time         `json:"updated_at,omitzero"`
	UpdatedBy      string            `json:"updated_by,omitempty"`
	Status         *syslogStatusView `json:"status,omitempty"`
	// Setup is a short, static hint for the dashboard; the full steps are in
	// docs/network-gear-logs.md.
	Setup string `json:"setup"`
}

// syslogStatusView is the collector's state as the dashboard, the CLI and
// MCP read it: the receiver counts at the top level (where all three always
// read them), whether it is listening, and why not.
type syslogStatusView struct {
	syslogcollector.Stats
	GeneratedAt time.Time `json:"generated_at"`
	Listening   bool      `json:"listening"`
	Error       string    `json:"error,omitempty"`
}

// syslogStatusStale is how old the collector's status may get; it rewrites
// it every few seconds while its service runs.
const syslogStatusStale = time.Minute

const syslogSetupHint = "In UniFi Network → Settings → System, enable Remote Logging and set the server to ShakerProxy's lab address and this port. Restrict allowed sources to the router's IP."

func (s *Server) getSyslogCollector(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "the syslog collector endpoint does not accept query parameters")
		return
	}
	if s.syslogCollectorConfigPath == "" {
		writeError(w, http.StatusServiceUnavailable, "syslog_collector_unavailable", "the network-gear log collector is not configured on this appliance")
		return
	}
	config, err := syslogcollector.LoadConfig(s.syslogCollectorConfigPath)
	if err != nil {
		s.logger.Error("syslog collector config could not be read", "error", err)
		writeError(w, http.StatusInternalServerError, "syslog_collector_config_failed", "the collector configuration could not be read")
		return
	}
	writeJSON(w, http.StatusOK, s.syslogCollectorView(config))
}

type putSyslogCollectorRequest struct {
	Enabled          bool     `json:"enabled"`
	BindAddress      string   `json:"bind_address"`
	TCP              bool     `json:"tcp"`
	UDP              bool     `json:"udp"`
	AllowedSources   []string `json:"allowed_sources"`
	ExpectedRevision *int     `json:"expected_revision"`
	Password         string   `json:"password"`
}

func (s *Server) putSyslogCollector(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "the syslog collector endpoint does not accept query parameters")
		return
	}
	if s.syslogCollectorConfigPath == "" {
		writeError(w, http.StatusServiceUnavailable, "syslog_collector_unavailable", "the network-gear log collector is not configured on this appliance")
		return
	}
	var request putSyslogCollectorRequest
	if err := decodeJSONBounded(r, &request, 16<<10); err != nil {
		writeDecodeError(w, err, "syslog collector configuration")
		return
	}
	if !s.confirmAdministrator(w, r, request.Password, passwordRecent) {
		return
	}
	current, err := syslogcollector.LoadConfig(s.syslogCollectorConfigPath)
	if err != nil {
		s.logger.Error("syslog collector config could not be read", "error", err)
		writeError(w, http.StatusInternalServerError, "syslog_collector_config_failed", "the collector configuration could not be read")
		return
	}
	if request.ExpectedRevision != nil && *request.ExpectedRevision != current.Revision {
		writeError(w, http.StatusConflict, "revision_conflict", "the configuration changed since it was read; reload and try again")
		return
	}
	next := syslogcollector.DefaultFileConfig()
	next.Enabled = request.Enabled
	next.BindAddress = strings.TrimSpace(request.BindAddress)
	if next.BindAddress == "" {
		next.BindAddress = current.BindAddress
	}
	next.TCP = request.TCP
	next.UDP = request.UDP
	next.AllowedSources = normalizeSources(request.AllowedSources)
	next.Revision = current.Revision + 1
	next.UpdatedAt = time.Now().UTC()
	next.UpdatedBy = sessionUsername(r.Context())
	if err := next.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "syslog_collector_rejected", err.Error())
		return
	}
	if err := syslogcollector.SaveConfig(s.syslogCollectorConfigPath, next); err != nil {
		s.logger.Error("syslog collector config could not be written", "error", err)
		writeError(w, http.StatusInternalServerError, "syslog_collector_write_failed", "the collector configuration could not be saved")
		return
	}
	s.logger.Info("syslog collector configuration changed", "actor", next.UpdatedBy, "enabled", next.Enabled, "revision", next.Revision, "allowed_sources", len(next.AllowedSources))
	writeJSON(w, http.StatusOK, s.syslogCollectorView(next))
}

func (s *Server) syslogCollectorView(config syslogcollector.FileConfig) syslogCollectorView {
	view := syslogCollectorView{
		Available:      true,
		Enabled:        config.Enabled,
		BindAddress:    config.BindAddress,
		TCP:            config.TCP,
		UDP:            config.UDP,
		AllowedSources: config.AllowedSources,
		Revision:       config.Revision,
		UpdatedAt:      config.UpdatedAt,
		UpdatedBy:      config.UpdatedBy,
		Setup:          syslogSetupHint,
	}
	if view.AllowedSources == nil {
		view.AllowedSources = []string{}
	}
	if status, err := s.readSyslogStatus(); err == nil {
		view.Status = &syslogStatusView{Stats: status.Stats, GeneratedAt: status.GeneratedAt, Listening: status.Listening, Error: status.Error}
		if age := time.Since(status.GeneratedAt); config.Enabled && age > syslogStatusStale {
			view.Status.Listening = false
			view.Status.Error = "The collector service has not reported for " + age.Round(time.Second).String() + "; it may not be running (systemctl status shakerproxy-syslog-collectord)."
		}
	}
	return view
}

func (s *Server) readSyslogStatus() (*syslogcollector.Status, error) {
	if s.syslogCollectorStatusPath == "" {
		return nil, errors.New("no status path")
	}
	raw, err := os.ReadFile(s.syslogCollectorStatusPath)
	if err != nil {
		return nil, err
	}
	var status syslogcollector.Status
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// normalizeSources trims and drops empty entries so an empty string in the
// list never widens the allowlist; validation rejects a non-IP entry.
func normalizeSources(values []string) []string {
	sources := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		sources = append(sources, value)
	}
	return sources
}
