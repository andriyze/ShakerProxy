package syslogcollector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileConfig is the collector's persisted configuration. control-api writes it
// when an administrator changes the integration; the collector service reads it
// and (re)starts its listener to match. It defaults to disabled, so a missing
// or empty file keeps the collector inert.
type FileConfig struct {
	Schema         int       `json:"schema"`
	Enabled        bool      `json:"enabled"`
	BindAddress    string    `json:"bind_address"`
	TCP            bool      `json:"tcp"`
	UDP            bool      `json:"udp"`
	AllowedSources []string  `json:"allowed_sources"`
	Revision       int       `json:"revision"`
	UpdatedAt      time.Time `json:"updated_at,omitzero"`
	UpdatedBy      string    `json:"updated_by,omitempty"`
}

// ConfigSchema versions the persisted config.
const ConfigSchema = 1

// DefaultFileConfig is the off, safe starting point.
func DefaultFileConfig() FileConfig {
	return FileConfig{Schema: ConfigSchema, Enabled: false, BindAddress: defaultBindAddress, TCP: true, UDP: false}
}

// Validate checks the config is safe to run. Enabling requires at least one
// allowed source, so a configuration can never accept logs from everywhere.
func (c FileConfig) Validate() error {
	if c.Schema != ConfigSchema {
		return errors.New("syslog collector config schema is unsupported")
	}
	if c.Revision < 0 {
		return errors.New("syslog collector config revision is invalid")
	}
	if !strings.Contains(c.BindAddress, ":") || len(c.BindAddress) > 64 {
		return errors.New("syslog collector bind address must be host:port")
	}
	if len(c.AllowedSources) > 64 {
		return errors.New("too many allowed syslog sources")
	}
	if _, err := ParseAllowedSources(strings.Join(c.AllowedSources, ",")); err != nil {
		return err
	}
	if c.Enabled {
		if !c.TCP && !c.UDP {
			return errors.New("enable at least one of TCP or UDP")
		}
		if len(c.AllowedSources) == 0 {
			return errors.New("add at least one allowed source (the lab router's IP) before enabling")
		}
	}
	return nil
}

// ToReceiverConfig turns a validated file config into a receiver config.
func (c FileConfig) ToReceiverConfig() (Config, error) {
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	allowed, err := ParseAllowedSources(strings.Join(c.AllowedSources, ","))
	if err != nil {
		return Config{}, err
	}
	return Config{
		Enabled:        c.Enabled,
		BindAddress:    c.BindAddress,
		EnableTCP:      c.TCP,
		EnableUDP:      c.UDP,
		AllowedSources: allowed,
	}, nil
}

// LoadConfig reads the config file. A missing file returns the default
// (disabled) config, so the collector is off until configured.
func LoadConfig(path string) (FileConfig, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultFileConfig(), nil
	}
	if err != nil {
		return FileConfig{}, err
	}
	var config FileConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return FileConfig{}, errors.New("syslog collector config is not valid JSON")
	}
	if config.Schema == 0 {
		config.Schema = ConfigSchema
	}
	if config.BindAddress == "" {
		config.BindAddress = defaultBindAddress
	}
	if err := config.Validate(); err != nil {
		return FileConfig{}, err
	}
	return config, nil
}

// SaveConfig writes the config atomically with mode 0640. It stamps the schema
// and bumps nothing; the caller sets Revision/UpdatedAt/UpdatedBy.
func SaveConfig(path string, config FileConfig) error {
	config.Schema = ConfigSchema
	if err := config.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".syslog-config-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
