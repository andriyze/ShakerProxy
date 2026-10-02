package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	zeekBinary         = "/usr/local/zeek/bin/zeek"
	zeekSiteScript     = "/etc/shakerproxy/zeek/shakerproxy.zeek"
	suricataBinary     = "/usr/bin/suricata"
	suricataConfig     = "/etc/shakerproxy/suricata/suricata.yaml"
	suricataRules      = "/etc/shakerproxy/suricata/suricata.rules"
	suricataRuleset    = "/etc/shakerproxy/suricata/suricata-ruleset.json"
	openCaptureFDPath  = "/proc/self/fd/3"
	maxCommandLogBytes = 1 << 20
)

type EventFile struct {
	Path     string
	ZeekPath string
}

// zeekIgnoredLogs are Zeek bookkeeping streams stamped with analysis
// wall-clock time rather than traffic time; ingesting them adds one noise
// event per analyzed artifact.
var zeekIgnoredLogs = map[string]bool{"packet_filter": true, "loaded_scripts": true, "stats": true, "telemetry": true, "telemetry_histogram": true}

type analysisSeedKey struct{}

// withAnalysisSeed carries per-artifact seed material to the parser so its
// randomized identifiers (Zeek connection and file UIDs) are reproducible when
// the same artifact is analyzed again.
func withAnalysisSeed(ctx context.Context, seed []byte) context.Context {
	return context.WithValue(ctx, analysisSeedKey{}, append([]byte(nil), seed...))
}

func zeekSeedValues(ctx context.Context) string {
	seed, _ := ctx.Value(analysisSeedKey{}).([]byte)
	if len(seed) == 0 {
		return ""
	}
	// Zeek reads 21 32-bit seeds from ZEEK_SEED_VALUES.
	values := make([]string, 0, 21)
	for counter := byte(0); len(values) < 21; counter++ {
		block := sha256.Sum256(append(append([]byte("shakerproxy-zeek-seed-v1\x00"), seed...), counter))
		for offset := 0; offset+4 <= len(block) && len(values) < 21; offset += 4 {
			values = append(values, strconv.FormatUint(uint64(binary.BigEndian.Uint32(block[offset:offset+4])), 10))
		}
	}
	return strings.Join(values, " ")
}

type Processor interface {
	Analyze(context.Context, *os.File, string) ([]EventFile, error)
}

type CommandProcessor struct {
	Engine              Engine
	SuricataRulesPath   string
	SuricataRulesetPath string
}

func (p CommandProcessor) Analyze(ctx context.Context, captureFile *os.File, outputDirectory string) ([]EventFile, error) {
	if captureFile == nil {
		return nil, errors.New("open capture file is required")
	}
	// A ring-buffer segment from a quiet period holds no packets. Suricata
	// refuses such a file ("failed to get first packet timestamp"), and there
	// is nothing to analyze in it anyway.
	if !captureHasPackets(captureFile) {
		return []EventFile{}, nil
	}
	if _, err := captureFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var binary string
	var arguments []string
	switch p.Engine {
	case EngineZeek:
		binary = zeekBinary
		arguments = zeekArguments()
	case EngineSuricata:
		rulesPath := p.SuricataRulesPath
		if rulesPath == "" {
			rulesPath = suricataRules
		}
		manifestPath := p.SuricataRulesetPath
		if manifestPath == "" {
			manifestPath = suricataRuleset
		}
		if _, err := LoadRulesetManifest(rulesPath, manifestPath); err != nil {
			return nil, err
		}
		binary = suricataBinary
		arguments = []string{"-c", suricataConfig, "-S", rulesPath, "--runmode", "single", "-r", openCaptureFDPath, "-l", outputDirectory}
	default:
		return nil, errors.New("unsupported analyzer engine")
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Dir = outputDirectory
	command.ExtraFiles = []*os.File{captureFile}
	command.Env = parserEnvironment(p.Engine, outputDirectory)
	if p.Engine == EngineZeek {
		if seeds := zeekSeedValues(ctx); seeds != "" {
			command.Env = append(command.Env, "ZEEK_SEED_VALUES="+seeds)
		}
	}
	command.WaitDelay = 5 * time.Second
	if err := isolateParserCommand(command); err != nil {
		return nil, err
	}
	logs := &boundedBuffer{Limit: maxCommandLogBytes}
	command.Stdout = logs
	command.Stderr = logs
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s offline analysis failed: %w: %s", strings.ToLower(string(p.Engine)), err, logs.String())
	}
	return discoverEventFiles(p.Engine, outputDirectory)
}

// zeekArguments reads the verified capture from the inherited descriptor,
// writes JSON logs, and loads the ShakerProxy protocol-discovery site policy
// (apps/analyzer-worker/zeek/shakerproxy.zeek, installed read-only in the image).
func zeekArguments() []string {
	return []string{"-C", "-r", openCaptureFDPath, "LogAscii::use_json=T", zeekSiteScript}
}

func parserEnvironment(engine Engine, outputDirectory string) []string {
	environment := []string{
		"HOME=/nonexistent",
		"TMPDIR=" + outputDirectory,
		"TZ=UTC",
	}
	switch engine {
	case EngineZeek:
		environment = append(environment,
			"PATH=/usr/local/zeek/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"PYTHONPATH=/usr/local/zeek/lib/zeek/python:",
		)
	case EngineSuricata:
		environment = append(environment,
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"LANG=C.utf8",
		)
	}
	return environment
}

func discoverEventFiles(engine Engine, outputDirectory string) ([]EventFile, error) {
	entries, err := os.ReadDir(outputDirectory)
	if err != nil {
		return nil, err
	}
	if len(entries) > MaxOutputFiles+8 {
		return nil, errors.New("analyzer output file count exceeds its safety limit")
	}
	files := make([]EventFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name != filepath.Base(name) || strings.Contains(name, "..") {
			return nil, errors.New("analyzer emitted an unsafe output name")
		}
		switch engine {
		case EngineZeek:
			if !strings.HasSuffix(name, ".log") || len(name) < 5 || len(name) > 132 {
				continue
			}
			path := strings.TrimSuffix(name, ".log")
			if !validLogName(path) {
				return nil, errors.New("Zeek emitted an unsafe log path")
			}
			if zeekIgnoredLogs[path] {
				continue
			}
			files = append(files, EventFile{Path: filepath.Join(outputDirectory, name), ZeekPath: path})
		case EngineSuricata:
			if name == "eve.json" {
				files = append(files, EventFile{Path: filepath.Join(outputDirectory, name)})
			}
		}
		if len(files) > MaxOutputFiles {
			return nil, errors.New("analyzer event file count exceeds its safety limit")
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if engine == EngineSuricata && len(files) != 1 {
		return nil, errors.New("Suricata did not produce exactly one EVE output")
	}
	return files, nil
}

func validLogName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

type boundedBuffer struct {
	Buffer bytes.Buffer
	Limit  int
	Full   bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.Limit - b.Buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
			b.Full = true
		}
		_, _ = b.Buffer.Write(value)
	} else {
		b.Full = true
	}
	return original, nil
}

func (b *boundedBuffer) String() string {
	value := strings.TrimSpace(b.Buffer.String())
	if b.Full {
		value += " [output truncated]"
	}
	return value
}

// captureHasPackets reports whether a PCAPNG file holds a packet block. It
// reports true for anything it cannot read as PCAPNG, so the engine decides.
func captureHasPackets(file *os.File) bool {
	const (
		sectionHeader  = 0x0A0D0D0A
		byteOrderMagic = 0x1A2B3C4D
	)
	reader := bufio.NewReader(io.NewSectionReader(file, 0, 1<<62))
	var order binary.ByteOrder = binary.LittleEndian
	header := make([]byte, 12)
	first := true
	for {
		if _, err := io.ReadFull(reader, header[:8]); err != nil {
			return !errors.Is(err, io.EOF)
		}
		consumed := 8
		if binary.LittleEndian.Uint32(header[:4]) == sectionHeader {
			if _, err := io.ReadFull(reader, header[8:12]); err != nil {
				return true
			}
			consumed = 12
			switch {
			case binary.LittleEndian.Uint32(header[8:12]) == byteOrderMagic:
				order = binary.LittleEndian
			case binary.BigEndian.Uint32(header[8:12]) == byteOrderMagic:
				order = binary.BigEndian
			default:
				return true
			}
		} else if first {
			return true
		}
		first = false
		switch order.Uint32(header[:4]) {
		case 2, 3, 6: // packet, simple packet and enhanced packet blocks
			return true
		}
		length := order.Uint32(header[4:8])
		if length < uint32(consumed) || length%4 != 0 {
			return true
		}
		if _, err := reader.Discard(int(length) - consumed); err != nil {
			return true
		}
	}
}
