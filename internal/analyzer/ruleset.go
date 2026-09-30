package analyzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const maxRulesetBytes = 4 << 20

var (
	rulesetIDPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	rulesetVersionPattern = regexp.MustCompile(`^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[1-9][0-9]{0,5}$`)
	engineVersionPattern  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	licensePattern        = regexp.MustCompile(`^[A-Za-z0-9.+-]{1,64}$`)
	ruleSIDPattern        = regexp.MustCompile(`\bsid:([0-9]+);`)
)

type RulesetManifest struct {
	Schema        int       `json:"schema"`
	RulesetID     string    `json:"ruleset_id"`
	Version       string    `json:"version"`
	Source        string    `json:"source"`
	License       string    `json:"license"`
	Engine        Engine    `json:"engine"`
	EngineVersion string    `json:"engine_version"`
	SHA256        string    `json:"sha256"`
	RuleCount     int       `json:"rule_count"`
	SIDMin        uint64    `json:"sid_min"`
	SIDMax        uint64    `json:"sid_max"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func LoadRulesetManifest(rulesPath, manifestPath string) (RulesetManifest, error) {
	if !absoluteRegularPath(rulesPath) || !absoluteRegularPath(manifestPath) || filepath.Clean(rulesPath) == filepath.Clean(manifestPath) {
		return RulesetManifest{}, errors.New("Suricata ruleset paths are invalid")
	}
	manifestBytes, err := readNoFollowFile(manifestPath, maxMetadataBytes)
	if err != nil {
		return RulesetManifest{}, err
	}
	var manifest RulesetManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(&struct{}{}) != io.EOF || manifest.Validate() != nil {
		return RulesetManifest{}, errors.New("Suricata ruleset manifest is invalid")
	}
	rules, err := readNoFollowFile(rulesPath, maxRulesetBytes)
	if err != nil {
		return RulesetManifest{}, err
	}
	if err := manifest.validateRules(rules); err != nil {
		return RulesetManifest{}, err
	}
	return manifest, nil
}

func (m RulesetManifest) Validate() error {
	if m.Schema != SchemaVersion || !rulesetIDPattern.MatchString(m.RulesetID) || !rulesetVersionPattern.MatchString(m.Version) || !validText(m.Source, 1, 512) || !licensePattern.MatchString(m.License) || m.Engine != EngineSuricata || !engineVersionPattern.MatchString(m.EngineVersion) || !sha256Pattern.MatchString(m.SHA256) || m.RuleCount < 1 || m.RuleCount > 100000 || m.SIDMin == 0 || m.SIDMax < m.SIDMin || m.SIDMax > 4294967295 || m.UpdatedAt.IsZero() {
		return errors.New("Suricata ruleset manifest is invalid")
	}
	return nil
}

func (m RulesetManifest) validateRules(rules []byte) error {
	if !utf8.Valid(rules) {
		return errors.New("Suricata ruleset is not valid UTF-8")
	}
	digest := sha256.Sum256(rules)
	if hex.EncodeToString(digest[:]) != m.SHA256 {
		return errors.New("Suricata ruleset hash does not match its manifest")
	}
	seen := make(map[uint64]struct{}, m.RuleCount)
	var minimum, maximum uint64
	count := 0
	for _, rawLine := range strings.Split(string(rules), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 64<<10 || !strings.HasPrefix(line, "alert ") {
			return errors.New("Suricata ruleset contains an unsupported rule line")
		}
		matches := ruleSIDPattern.FindAllStringSubmatch(line, -1)
		if len(matches) != 1 {
			return errors.New("Suricata rule must contain exactly one SID")
		}
		sid, err := strconv.ParseUint(matches[0][1], 10, 32)
		if err != nil || sid < m.SIDMin || sid > m.SIDMax {
			return errors.New("Suricata rule SID is outside the manifest range")
		}
		if _, duplicate := seen[sid]; duplicate {
			return errors.New("Suricata ruleset contains duplicate SIDs")
		}
		seen[sid] = struct{}{}
		if count == 0 || sid < minimum {
			minimum = sid
		}
		if sid > maximum {
			maximum = sid
		}
		count++
	}
	if count != m.RuleCount || minimum != m.SIDMin || maximum != m.SIDMax {
		return errors.New("Suricata ruleset inventory does not match its manifest")
	}
	return nil
}

func absoluteRegularPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) != "/" && filepath.Base(path) != "."
}
