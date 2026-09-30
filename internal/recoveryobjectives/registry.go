package recoveryobjectives

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maxBytes = 256 << 10

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,95}$`)

type Registry struct {
	Schema     int         `json:"schema"`
	Revision   string      `json:"revision"`
	Statuses   []string    `json:"statuses"`
	Objectives []Objective `json:"objectives"`
}

type Objective struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	Environment      string   `json:"environment"`
	Scope            string   `json:"scope"`
	RTOSeconds       *int     `json:"rto_seconds,omitempty"`
	RPOSeconds       *int     `json:"rpo_seconds,omitempty"`
	DataLossContract string   `json:"data_loss_contract"`
	Evidence         []string `json:"evidence"`
	Limitations      []string `json:"limitations"`
}

func Load(repositoryRoot string) (*Registry, error) {
	return load(repositoryRoot, true)
}

func LoadRuntime(repositoryRoot string) (*Registry, error) {
	return load(repositoryRoot, false)
}

func load(repositoryRoot string, requireEvidence bool) (*Registry, error) {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, "schemas", "recovery-objectives.yaml")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 2 || info.Size() > maxBytes {
		return nil, errors.New("recovery objective registry is unavailable or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var registry Registry
	decoder := json.NewDecoder(io.LimitReader(file, maxBytes+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&registry) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("recovery objective registry is invalid")
	}
	if err := validate(root, registry, requireEvidence); err != nil {
		return nil, err
	}
	sort.Slice(registry.Objectives, func(i, j int) bool { return registry.Objectives[i].ID < registry.Objectives[j].ID })
	return &registry, nil
}

func validate(root string, registry Registry, requireEvidence bool) error {
	if registry.Schema != 1 || strings.TrimSpace(registry.Revision) == "" || len(registry.Objectives) == 0 || len(registry.Objectives) > 64 {
		return errors.New("recovery objective registry header is invalid")
	}
	statuses := map[string]bool{}
	for _, status := range registry.Statuses {
		if status != "verified" && status != "target" && status != "not-offered" || statuses[status] {
			return errors.New("recovery objective status vocabulary is invalid")
		}
		statuses[status] = true
	}
	if len(statuses) != 3 {
		return errors.New("recovery objective status vocabulary is incomplete")
	}
	seen := map[string]bool{}
	for _, objective := range registry.Objectives {
		if !identifierPattern.MatchString(objective.ID) || seen[objective.ID] || !statuses[objective.Status] || !bounded(objective.Name, 1, 128) || !bounded(objective.Environment, 1, 128) || !bounded(objective.Scope, 1, 1024) || !bounded(objective.DataLossContract, 1, 1024) || len(objective.Evidence) == 0 || len(objective.Evidence) > 16 || len(objective.Limitations) == 0 || len(objective.Limitations) > 16 {
			return fmt.Errorf("recovery objective %q is invalid", objective.ID)
		}
		seen[objective.ID] = true
		if objective.Status == "not-offered" && (objective.RTOSeconds != nil || objective.RPOSeconds != nil) || objective.Status != "not-offered" && (objective.RTOSeconds == nil || objective.RPOSeconds == nil) {
			return fmt.Errorf("recovery objective %q has an invalid RTO/RPO contract", objective.ID)
		}
		if objective.RTOSeconds != nil && (*objective.RTOSeconds < 1 || *objective.RTOSeconds > 604800) || objective.RPOSeconds != nil && (*objective.RPOSeconds < 0 || *objective.RPOSeconds > 604800) {
			return fmt.Errorf("recovery objective %q has an out-of-range RTO/RPO", objective.ID)
		}
		for _, evidence := range objective.Evidence {
			if !bounded(evidence, 1, 256) || filepath.IsAbs(evidence) || filepath.Clean(evidence) != evidence || strings.HasPrefix(evidence, "..") {
				return fmt.Errorf("recovery objective %q evidence path is invalid", objective.ID)
			}
			if requireEvidence {
				if err := requirePath(root, evidence); err != nil {
					return fmt.Errorf("recovery objective %q evidence: %w", objective.ID, err)
				}
			}
		}
		for _, limitation := range objective.Limitations {
			if !bounded(limitation, 1, 512) {
				return fmt.Errorf("recovery objective %q has an invalid limitation", objective.ID)
			}
		}
	}
	return nil
}

func requirePath(root, relative string) error {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, "..") {
		return errors.New("path is not repository-relative")
	}
	path := filepath.Join(root, relative)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("path is not a regular repository file")
	}
	return nil
}

func bounded(value string, minimum, maximum int) bool {
	return value == strings.TrimSpace(value) && len(value) >= minimum && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r")
}
