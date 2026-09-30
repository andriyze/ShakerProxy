package capabilityregistry

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

const maxRegistryBytes = 1 << 20

var identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:_[a-z0-9-]+)*$`)

type Bundle struct {
	Schema        int           `json:"schema"`
	Revision      string        `json:"revision"`
	Features      []Feature     `json:"features"`
	Glossary      []Term        `json:"glossary"`
	SupportMatrix SupportMatrix `json:"support_matrix"`
}

type featureFile struct {
	Schema           int       `json:"schema"`
	Revision         string    `json:"revision"`
	StatusVocabulary []string  `json:"status_vocabulary"`
	Features         []Feature `json:"features"`
}

type glossaryFile struct {
	Schema   int    `json:"schema"`
	Revision string `json:"revision"`
	Terms    []Term `json:"terms"`
}

type Feature struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Status           string   `json:"status"`
	Badge            string   `json:"badge"`
	Summary          string   `json:"summary"`
	OwningDocument   string   `json:"owning_document"`
	Evidence         []string `json:"evidence"`
	PromotionGate    string   `json:"promotion_gate"`
	EnabledByDefault bool     `json:"enabled_by_default"`
}

type Term struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Definition string `json:"definition"`
}

type SupportMatrix struct {
	Schema              int           `json:"schema"`
	Revision            string        `json:"revision"`
	CertificationLevels []string      `json:"certification_levels"`
	Environments        []Environment `json:"environments"`
}

type Environment struct {
	ID                    string               `json:"id"`
	OS                    string               `json:"os"`
	Architecture          string               `json:"architecture"`
	DockerFirewallBackend string               `json:"docker_firewall_backend"`
	Topology              string               `json:"topology"`
	Capabilities          []CapabilityEvidence `json:"capabilities"`
}

type CapabilityEvidence struct {
	FeatureID string   `json:"feature_id"`
	Level     string   `json:"level"`
	Evidence  []string `json:"evidence"`
}

func Load(repositoryRoot string) (*Bundle, error) {
	return load(repositoryRoot, true)
}

// LoadRuntime validates the immutable packaged registry without requiring its
// source-only evidence files to be copied into the production image.
func LoadRuntime(repositoryRoot string) (*Bundle, error) {
	return load(repositoryRoot, false)
}

func load(repositoryRoot string, requireEvidence bool) (*Bundle, error) {
	root, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	var features featureFile
	if err := decodeStrict(filepath.Join(root, "schemas", "feature-flags.yaml"), &features); err != nil {
		return nil, fmt.Errorf("load feature registry: %w", err)
	}
	var glossary glossaryFile
	if err := decodeStrict(filepath.Join(root, "schemas", "glossary.yaml"), &glossary); err != nil {
		return nil, fmt.Errorf("load glossary: %w", err)
	}
	var matrix SupportMatrix
	if err := decodeStrict(filepath.Join(root, "schemas", "support-matrix.yaml"), &matrix); err != nil {
		return nil, fmt.Errorf("load support matrix: %w", err)
	}
	bundle := &Bundle{Schema: 1, Revision: features.Revision, Features: features.Features, Glossary: glossary.Terms, SupportMatrix: matrix}
	if err := validate(root, features, glossary, matrix, requireEvidence); err != nil {
		return nil, err
	}
	sort.Slice(bundle.Features, func(i, j int) bool { return bundle.Features[i].ID < bundle.Features[j].ID })
	sort.Slice(bundle.Glossary, func(i, j int) bool { return bundle.Glossary[i].ID < bundle.Glossary[j].ID })
	sort.Slice(bundle.SupportMatrix.Environments, func(i, j int) bool {
		return bundle.SupportMatrix.Environments[i].ID < bundle.SupportMatrix.Environments[j].ID
	})
	return bundle, nil
}

func decodeStrict(path string, destination any) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > maxRegistryBytes {
		return errors.New("registry exceeds its size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxRegistryBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("registry contains trailing data or exceeds its size limit")
	}
	return nil
}

func validate(root string, features featureFile, glossary glossaryFile, matrix SupportMatrix, requireEvidence bool) error {
	if features.Schema != 1 || glossary.Schema != 1 || matrix.Schema != 1 {
		return errors.New("capability registry schema must be 1")
	}
	if strings.TrimSpace(features.Revision) == "" || features.Revision != glossary.Revision || features.Revision != matrix.Revision {
		return errors.New("feature, glossary, and support-matrix revisions must match")
	}
	statuses, err := uniqueSet("status vocabulary", features.StatusVocabulary)
	if err != nil {
		return err
	}
	levels, err := uniqueSet("certification levels", matrix.CertificationLevels)
	if err != nil {
		return err
	}
	terms := make(map[string]struct{}, len(glossary.Terms))
	for _, term := range glossary.Terms {
		if !identifierPattern.MatchString(term.ID) || strings.TrimSpace(term.Label) == "" || strings.TrimSpace(term.Definition) == "" {
			return fmt.Errorf("glossary term %q is invalid", term.ID)
		}
		if _, exists := terms[term.ID]; exists {
			return fmt.Errorf("glossary term %q is duplicated", term.ID)
		}
		terms[term.ID] = struct{}{}
	}
	for status := range statuses {
		if _, exists := terms[status]; !exists {
			return fmt.Errorf("feature status %q is absent from the glossary", status)
		}
	}
	featureIDs := make(map[string]struct{}, len(features.Features))
	for _, feature := range features.Features {
		if !identifierPattern.MatchString(feature.ID) || strings.TrimSpace(feature.Name) == "" || strings.TrimSpace(feature.Summary) == "" || strings.TrimSpace(feature.PromotionGate) == "" {
			return fmt.Errorf("feature %q is incomplete", feature.ID)
		}
		if _, exists := featureIDs[feature.ID]; exists {
			return fmt.Errorf("feature %q is duplicated", feature.ID)
		}
		featureIDs[feature.ID] = struct{}{}
		if _, exists := statuses[feature.Status]; !exists {
			return fmt.Errorf("feature %q uses unknown status %q", feature.ID, feature.Status)
		}
		if feature.Badge != strings.ToUpper(feature.Status) {
			return fmt.Errorf("feature %q badge must be derived from its status", feature.ID)
		}
		if err := validateRepositoryPath(root, feature.OwningDocument, requireEvidence); err != nil {
			return fmt.Errorf("feature %q owning document: %w", feature.ID, err)
		}
		if len(feature.Evidence) == 0 {
			return fmt.Errorf("feature %q has no evidence boundary", feature.ID)
		}
		for _, evidence := range feature.Evidence {
			if err := validateRepositoryPath(root, evidence, requireEvidence); err != nil {
				return fmt.Errorf("feature %q evidence: %w", feature.ID, err)
			}
		}
	}
	environmentIDs := make(map[string]struct{}, len(matrix.Environments))
	for _, environment := range matrix.Environments {
		if !identifierPattern.MatchString(environment.ID) || environment.OS == "" || environment.Architecture == "" || environment.DockerFirewallBackend == "" || environment.Topology == "" {
			return fmt.Errorf("support environment %q is incomplete", environment.ID)
		}
		if _, exists := environmentIDs[environment.ID]; exists {
			return fmt.Errorf("support environment %q is duplicated", environment.ID)
		}
		environmentIDs[environment.ID] = struct{}{}
		seenCapabilities := make(map[string]struct{}, len(environment.Capabilities))
		for _, capability := range environment.Capabilities {
			if _, exists := featureIDs[capability.FeatureID]; !exists {
				return fmt.Errorf("environment %q references unknown feature %q", environment.ID, capability.FeatureID)
			}
			if _, exists := seenCapabilities[capability.FeatureID]; exists {
				return fmt.Errorf("environment %q duplicates feature %q", environment.ID, capability.FeatureID)
			}
			seenCapabilities[capability.FeatureID] = struct{}{}
			if _, exists := levels[capability.Level]; !exists {
				return fmt.Errorf("environment %q uses unknown certification level %q", environment.ID, capability.Level)
			}
			if len(capability.Evidence) == 0 {
				return fmt.Errorf("environment %q capability %q has no evidence", environment.ID, capability.FeatureID)
			}
			for _, evidence := range capability.Evidence {
				if err := validateRepositoryPath(root, evidence, requireEvidence); err != nil {
					return fmt.Errorf("environment %q capability %q: %w", environment.ID, capability.FeatureID, err)
				}
			}
		}
		if len(seenCapabilities) != len(featureIDs) {
			return fmt.Errorf("environment %q must state a certification level for every feature", environment.ID)
		}
	}
	return nil
}

func uniqueSet(name string, values []string) (map[string]struct{}, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%s is empty", name)
	}
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return nil, fmt.Errorf("%s contains invalid value %q", name, value)
		}
		if _, exists := result[value]; exists {
			return nil, fmt.Errorf("%s contains duplicate value %q", name, value)
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func validateRepositoryPath(root, relative string, requireEvidence bool) error {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return fmt.Errorf("path %q is not a clean repository-relative path", relative)
	}
	path := filepath.Join(root, relative)
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return fmt.Errorf("path %q escapes the repository", relative)
	}
	if !requireEvidence {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("path %q is unavailable", relative)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q must not be a symlink", relative)
	}
	return nil
}
