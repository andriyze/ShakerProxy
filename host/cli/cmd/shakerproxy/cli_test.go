package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

var testNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func testCLI() (*cli, *bytes.Buffer, *bytes.Buffer) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	c := &cli{
		stdout:         stdout,
		stderr:         stderr,
		stdin:          strings.NewReader(""),
		socket:         "/nonexistent/shakerproxy-test/gatewayd.sock",
		now:            func() time.Time { return testNow },
		geteuid:        func() int { return 1000 },
		execProgram:    func(string, []string, []string) error { return errors.New("exec is disabled in tests") },
		runProgram:     func(string, []string) error { return errors.New("helpers are disabled in tests") },
		sleep:          func(time.Duration) {},
		findExecutable: func(candidates ...string) string { return "" },
	}
	return c, stdout, stderr
}

func runCLI(t *testing.T, c *cli, args ...string) (int, string, string) {
	t.Helper()
	stdout := c.stdout.(*bytes.Buffer)
	stderr := c.stderr.(*bytes.Buffer)
	stdout.Reset()
	stderr.Reset()
	code := c.main(args)
	return code, stdout.String(), stderr.String()
}

func TestBareCommandPrintsShortGroupedOverview(t *testing.T) {
	c, _, _ := testCLI()
	code, stdout, _ := runCLI(t, c)
	if code != exitOK {
		t.Fatalf("bare shakerproxy exited %d", code)
	}
	for _, want := range []string{"Devices & testing", "Traffic", "Setup & system", "devices", "watch [<ref>]", "status", "login", "shakerproxy help"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("overview is missing %q:\n%s", want, stdout)
		}
	}
	if len(featured) != 10 {
		t.Fatalf("overview lists %d commands, want the 10 most useful", len(featured))
	}
	if lines := strings.Count(stdout, "\n"); lines > 22 {
		t.Fatalf("overview is too long (%d lines):\n%s", lines, stdout)
	}
}

func TestEveryCommandHasHelpWithExampleAndExitsZero(t *testing.T) {
	c, _, _ := testCLI()
	for _, command := range commands {
		for _, args := range [][]string{{"help", command.name}, {command.name, "--help"}, {command.name, "-h"}, {command.name, "sub", "--help"}} {
			code, stdout, stderr := runCLI(t, c, args...)
			if code != exitOK || stderr != "" {
				t.Fatalf("%v exited %d: %s", args, code, stderr)
			}
			if !strings.Contains(stdout, "Usage:") || !strings.Contains(stdout, "Examples:") || !strings.Contains(stdout, "shakerproxy "+command.name) {
				t.Fatalf("%v help lacks usage or examples:\n%s", args, stdout)
			}
		}
		if len(command.examples) == 0 || command.summary == "" {
			t.Fatalf("command %s has no example or summary", command.name)
		}
	}
	code, stdout, _ := runCLI(t, c, "help")
	if code != exitOK || !strings.Contains(stdout, "Advanced") || !strings.Contains(stdout, "Exit codes: 0 success, 1 failure, 2 wrong usage.") {
		t.Fatalf("full help is incomplete (%d):\n%s", code, stdout)
	}
	if code, _, _ := runCLI(t, c, "--help"); code != exitOK {
		t.Fatalf("--help exited %d", code)
	}
}

func TestUnknownCommandSuggestsClosestAndExitsTwo(t *testing.T) {
	c, _, _ := testCLI()
	cases := map[string]string{"stauts": "status", "devics": "devices", "captrue": "capture", "reprot": "report", "doctr": "doctor", "wach": "watch"}
	for typo, want := range cases {
		code, stdout, stderr := runCLI(t, c, typo)
		if code != exitUsage || stdout != "" {
			t.Fatalf("%s exited %d", typo, code)
		}
		expected := `Unknown command "` + typo + `". Did you mean "` + want + `"?`
		if !strings.Contains(stderr, expected) {
			t.Fatalf("%s: stderr %q lacks %q", typo, stderr, expected)
		}
	}
	code, _, stderr := runCLI(t, c, "xyzzyplugh")
	if code != exitUsage || strings.Contains(stderr, "Did you mean") || !strings.Contains(stderr, "shakerproxy help") {
		t.Fatalf("unrelated word got a suggestion or wrong code %d: %s", code, stderr)
	}
	code, _, stderr = runCLI(t, c, "help", "stauts")
	if code != exitUsage || !strings.Contains(stderr, `Did you mean "status"?`) {
		t.Fatalf("help with a typo: %d %s", code, stderr)
	}
}

func TestUnknownSubcommandSuggestsAndShowsUsage(t *testing.T) {
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "capture", "strat")
	if code != exitUsage || !strings.Contains(stderr, `Unknown capture command "strat". Did you mean "start"?`) || !strings.Contains(stderr, "shakerproxy capture start") {
		t.Fatalf("capture typo: %d\n%s", code, stderr)
	}
	code, _, stderr = runCLI(t, c, "test")
	if code != exitUsage || !strings.Contains(stderr, "Missing test command. Choose one of: start, stop, list.") {
		t.Fatalf("missing subcommand: %d\n%s", code, stderr)
	}
}

func TestUsageErrorsExitTwoWithUsage(t *testing.T) {
	c, _, _ := testCLI()
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"status", "extra"}, `Unexpected extra argument "extra".`},
		{[]string{"doctor", "now"}, `Unexpected extra argument "now".`},
		{[]string{"devices", "--bogus"}, "Unknown option -bogus."},
		{[]string{"report"}, "Missing device reference."},
		{[]string{"decrypt", "tv", "maybe"}, "Say on or off"},
		{[]string{"search", "x", "--window", "forever"}, "--window must look like"},
		{[]string{"compare", "a", "b"}, "is not a test run ID"},
		{[]string{"block", "tv", "not a domain!"}, "is not a domain name"},
		{[]string{"capture", "stop", "bogus"}, "is not a capture ID"},
		{[]string{"--socket"}, "--socket needs a path"},
		{[]string{"device", ".."}, "is not a valid device reference"},
		{[]string{"report", "tv", "--window", "1h", "--session", "ts-0123456789abcdef01234567"}, "either --window or --session"},
	}
	for _, testCase := range cases {
		code, stdout, stderr := runCLI(t, c, testCase.args...)
		if code != exitUsage || stdout != "" || !strings.Contains(stderr, testCase.want) {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", testCase.args, code, stdout, stderr)
		}
	}
}

func TestGlobalFlagsWorkAnywhere(t *testing.T) {
	rest, options, err := extractGlobalFlags([]string{"status", "--socket", "/tmp/x.sock", "--json", "--no-color"})
	if err != nil || len(rest) != 1 || rest[0] != "status" || options.socket != "/tmp/x.sock" || !options.json || !options.noColor {
		t.Fatalf("flags after the command were not recognised: %v %+v %v", rest, options, err)
	}
	rest, options, err = extractGlobalFlags([]string{"-socket=/tmp/y.sock", "search", "--", "--json"})
	if err != nil || options.socket != "/tmp/y.sock" || options.json || strings.Join(rest, " ") != "search -- --json" {
		t.Fatalf("-- did not protect later arguments: %v %+v %v", rest, options, err)
	}
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "status", "--socket", "/nonexistent/other.sock")
	if code != exitFailure || !strings.Contains(stderr, "/nonexistent/other.sock") {
		t.Fatalf("--socket after the subcommand was ignored: %d %s", code, stderr)
	}
}

func TestInterspersedFlagParsing(t *testing.T) {
	flags := newFlags("x")
	html := flags.String("html", "", "")
	window := flags.String("window", "", "")
	positional, err := parseFlags("report", flags, []string{"Living room TV", "--html", "out.html", "--window=7d", "--", "--literal"})
	if err != nil || *html != "out.html" || *window != "7d" || strings.Join(positional, "|") != "Living room TV|--literal" {
		t.Fatalf("interspersed parsing failed: %v %q %q %v", positional, *html, *window, err)
	}
}

func TestMissingDaemonExplainsNextSteps(t *testing.T) {
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "status")
	if code != exitFailure || stdout != "" {
		t.Fatalf("missing daemon exited %d", code)
	}
	for _, want := range []string{"Error: The ShakerProxy gateway daemon is not running (no socket at /nonexistent/shakerproxy-test/gatewayd.sock)", "sudo systemctl start shakerproxy-gatewayd"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestPermissionDeniedSocketSuggestsSudoOrGroup(t *testing.T) {
	c, _, _ := testCLI()
	err := c.gatewayError(&net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", errPermission())})
	var hinted *hintError
	if !errors.As(err, &hinted) || !strings.Contains(strings.Join(hinted.hints, " "), "shakerproxy-host") {
		t.Fatalf("permission error has no sudo/group hint: %v", err)
	}
}

func TestSuggestAndEditDistance(t *testing.T) {
	if editDistance("stauts", "status") != 1 || editDistance("abc", "abc") != 0 || editDistance("", "abc") != 3 {
		t.Fatal("edit distance is wrong")
	}
	if got := canonicalName(suggest("protocl", commandNames())); got != "protocols" {
		t.Fatalf("unique prefix suggestion = %q", got)
	}
	if got := suggest("zz", commandNames()); got != "" {
		t.Fatalf("unexpected suggestion %q", got)
	}
	if lookupCommand("probe") == nil || lookupCommand("probe").name != "probe-connectivity" {
		t.Fatal("old spelling alias is missing")
	}
}

func TestTableRenderingAlignsStyledCellsAndTruncates(t *testing.T) {
	c, _, _ := testCLI()
	c.color = true
	listing := newTable("NAME", "STATUS")
	listing.add("Living room TV", c.statusWord("online"))
	listing.add(strings.Repeat("x", 60), c.statusWord("offline"))
	var buffer bytes.Buffer
	listing.render(&buffer, c)
	lines := strings.Split(strings.TrimRight(buffer.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("unexpected table:\n%s", buffer.String())
	}
	column := func(line, word string) int {
		plain := stripANSI(line)
		return utf8.RuneCountInString(plain[:strings.Index(plain, word)])
	}
	if column(lines[1], "online") != column(lines[2], "offline") {
		t.Fatalf("styled cells are misaligned:\n%s", stripANSI(buffer.String()))
	}
	if !strings.Contains(lines[2], "…") || strings.Contains(lines[2], strings.Repeat("x", 49)) {
		t.Fatalf("long cell was not truncated: %q", lines[2])
	}
	if visibleWidth("\x1b[32monline\x1b[0m") != 6 {
		t.Fatal("visible width counts escape codes")
	}
}

func TestSanitizeStripsTerminalEscapes(t *testing.T) {
	if got := sanitize("evil\x1b]0;title\x07name\r\n"); strings.ContainsAny(got, "\x1b\x07\r\n") {
		t.Fatalf("control characters survived: %q", got)
	}
}

func TestHumanFormatting(t *testing.T) {
	if humanBytes(999) != "999 B" || humanBytes(12_300) != "12.3 KB" || humanBytes(3_400_000) != "3.4 MB" {
		t.Fatalf("bytes: %s %s %s", humanBytes(999), humanBytes(12_300), humanBytes(3_400_000))
	}
	if humanCount(1234567) != "1,234,567" || humanCount(12) != "12" {
		t.Fatal("count formatting is wrong")
	}
	if humanAgo(testNow, testNow.Add(-5*time.Minute).Format(time.RFC3339)) != "5m ago" || humanAgo(testNow, "") != "-" {
		t.Fatal("relative time is wrong")
	}
}

// fakeGateway answers privileged requests from a table of results.
type fakeGateway struct {
	mu      sync.Mutex
	methods []string
	answer  func(method string, params json.RawMessage) (any, *gatewayprotocol.RPCError)
}

func startFakeGateway(t *testing.T, answer func(string, json.RawMessage) (any, *gatewayprotocol.RPCError)) (*fakeGateway, string) {
	t.Helper()
	directory, err := os.MkdirTemp("", "lgcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "gw.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	gateway := &fakeGateway{answer: answer}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				var request gatewayprotocol.Request
				if json.NewDecoder(connection).Decode(&request) != nil {
					return
				}
				gateway.mu.Lock()
				gateway.methods = append(gateway.methods, request.Method)
				gateway.mu.Unlock()
				result, rpcErr := gateway.answer(request.Method, request.Params)
				_ = json.NewEncoder(connection).Encode(gatewayprotocol.Response{JSONRPC: gatewayprotocol.JSONRPCVersion, ID: request.ID, Result: result, Error: rpcErr})
			}()
		}
	}()
	return gateway, socketPath
}

func (g *fakeGateway) calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.methods...)
}

func TestStatusIsHumanReadableWithWarningsAndJSONOnRequest(t *testing.T) {
	_, socket := startFakeGateway(t, func(method string, _ json.RawMessage) (any, *gatewayprotocol.RPCError) {
		return gatewayprotocol.Status{APIVersion: "v1", DaemonVersion: "1.2.3", OperatingMode: gatewayprotocol.ModeSetupSafe, CaptureAvailable: true, StartedAt: testNow.Add(-2 * time.Hour).Format(time.RFC3339Nano), Warnings: []string{"Capture status is unavailable."}}, nil
	})
	c, _, _ := testCLI()
	code, stdout, _ := runCLI(t, c, "status", "--socket", socket)
	if code != exitOK {
		t.Fatalf("status exited %d", code)
	}
	for _, want := range []string{"gateway daemon 1.2.3", "running for 2h 0m", "setup (safe)", "ready, nothing recording", "! Capture status is unavailable.", "Next: open https://127.0.0.1:8443/"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status lacks %q:\n%s", want, stdout)
		}
	}
	code, stdout, _ = runCLI(t, c, "--json", "status", "--socket", socket)
	var decoded map[string]any
	if code != exitOK || json.Unmarshal([]byte(stdout), &decoded) != nil || decoded["operating_mode"] != gatewayprotocol.ModeSetupSafe || decoded["warnings"] == nil {
		t.Fatalf("status --json is not the daemon JSON (%d):\n%s", code, stdout)
	}
}

func TestDoctorExitsNonZeroOnFail(t *testing.T) {
	overall := gatewayprotocol.DiagnosticFail
	_, socket := startFakeGateway(t, func(string, json.RawMessage) (any, *gatewayprotocol.RPCError) {
		return gatewayprotocol.DiagnosticReport{Schema: 1, Overall: overall, Checks: []gatewayprotocol.DiagnosticCheck{
			{Name: "interfaces", Status: gatewayprotocol.DiagnosticPass, Summary: "2 interfaces up", Observations: []string{"eth0 up"}},
			{Name: "disk", Status: overall, Summary: "Disk reserve is low", Observations: []string{"1% free"}},
		}}, nil
	})
	c, _, _ := testCLI()
	code, stdout, _ := runCLI(t, c, "doctor", "--socket", socket)
	if code != exitFailure || !strings.Contains(stdout, "FAIL") || !strings.Contains(stdout, "• 1% free") || strings.Contains(stdout, "eth0 up") {
		t.Fatalf("doctor FAIL (%d):\n%s", code, stdout)
	}
	if code, _, _ := runCLI(t, c, "doctor", "--json", "--socket", socket); code != exitFailure {
		t.Fatalf("doctor --json FAIL exited %d", code)
	}
	overall = gatewayprotocol.DiagnosticWarning
	code, stdout, _ = runCLI(t, c, "doctor", "-v", "--socket", socket)
	if code != exitOK || !strings.Contains(stdout, "WARN") || !strings.Contains(stdout, "eth0 up") {
		t.Fatalf("doctor WARNING (%d):\n%s", code, stdout)
	}
}

func TestCaptureStopFindsRunningCaptureAndWaits(t *testing.T) {
	id := "capture-0123456789abcdef0123456789abcdef"
	polls := 0
	gateway, socket := startFakeGateway(t, func(method string, _ json.RawMessage) (any, *gatewayprotocol.RPCError) {
		running := capture.View{Session: capture.Session{ID: id, Request: capture.StartRequest{Name: "tv"}}, Active: true, State: capture.StateRunning}
		switch method {
		case "ListCaptures":
			return []capture.View{running}, nil
		case "StopCapture":
			return running, nil
		case "GetCaptureStats":
			polls++
			if polls < 2 {
				return running, nil
			}
			return capture.View{Session: running.Session, State: capture.StateCompleted, Manifest: &capture.Manifest{SessionID: id, TotalSizeBytes: 2_000_000, PacketsCaptured: 1500, Files: []capture.CaptureFile{{Name: "a.pcapng"}}}}, nil
		}
		return nil, &gatewayprotocol.RPCError{Code: -32601, Message: "method not found"}
	})
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "capture", "stop", "--wait", "--socket", socket)
	if code != exitOK || !strings.Contains(stdout, "Stopped "+id+": 2.0 MB in 1 file, 1,500 packets.") {
		t.Fatalf("capture stop --wait (%d): %s %s", code, stdout, stderr)
	}
	if got := strings.Join(gateway.calls(), ","); got != "ListCaptures,StopCapture,GetCaptureStats,GetCaptureStats" {
		t.Fatalf("unexpected call sequence %s", got)
	}
}

func TestCaptureStartBuildsFriendlyDefaults(t *testing.T) {
	var request capture.StartRequest
	_, socket := startFakeGateway(t, func(method string, params json.RawMessage) (any, *gatewayprotocol.RPCError) {
		var decoded gatewayprotocol.StartCaptureParams
		_ = json.Unmarshal(params, &decoded)
		request = decoded.Request
		return capture.View{Session: capture.Session{ID: "capture-0123456789abcdef0123456789abcdef", Request: request.WithDefaults()}, Active: true}, nil
	})
	c, _, _ := testCLI()
	t.Setenv("SHAKERPROXY_API_TOKEN_FILE", filepath.Join(t.TempDir(), "absent-token"))
	code, stdout, stderr := runCLI(t, c, "capture", "start", "--device", "Bench camera", "--minutes", "5", "--full", "--socket", socket)
	if code != exitOK {
		t.Fatalf("capture start (%d): %s", code, stderr)
	}
	if request.Name != "Bench camera 2026-09-29 12:00" || request.Mode != capture.ModeFull || request.StopAfterSeconds != 300 || request.Description != "Device under test: Bench camera" || request.Administrator != "local-cli" {
		t.Fatalf("unexpected capture request %+v", request)
	}
	if !strings.Contains(stdout, "full-packet") || !strings.Contains(stdout, "stops automatically after 5m") {
		t.Fatalf("unexpected capture start output:\n%s", stdout)
	}
}

func TestCaptureExportAllVerifiesEveryFileAndHandsThemToSudoUser(t *testing.T) {
	id := "capture-0123456789abcdef0123456789abcdef"
	files := map[string][]byte{"ring_00001.pcapng": []byte("first-ring-file"), "ring_00002.pcapng": []byte("second")}
	manifest := &capture.Manifest{SessionID: id}
	for _, name := range []string{"ring_00001.pcapng", "ring_00002.pcapng"} {
		manifest.Files = append(manifest.Files, capture.CaptureFile{Name: name, SizeBytes: int64(len(files[name])), SHA256: fmt.Sprintf("%x", sha256.Sum256(files[name]))})
	}
	_, socket := startFakeGateway(t, func(method string, params json.RawMessage) (any, *gatewayprotocol.RPCError) {
		switch method {
		case "GetCaptureStats":
			return capture.View{Session: capture.Session{ID: id}, State: capture.StateCompleted, Manifest: manifest}, nil
		case "ReadCaptureArtifact":
			var request gatewayprotocol.ReadCaptureArtifactParams
			_ = json.Unmarshal(params, &request)
			content := files[request.FileName]
			digest := fmt.Sprintf("%x", sha256.Sum256(content))
			return capture.ArtifactChunk{SessionID: id, FileName: request.FileName, FileSHA256: digest, Offset: 0, TotalBytes: int64(len(content)), Data: content, EOF: true}, nil
		}
		return nil, &gatewayprotocol.RPCError{Code: -32601, Message: "method not found"}
	})
	base := t.TempDir()
	destination := filepath.Join(base, "pcaps", "tv", "run-1")
	if os.Geteuid() == 0 {
		t.Setenv("SUDO_UID", "4321")
		t.Setenv("SUDO_GID", "4321")
	}
	c, _, _ := testCLI()
	code, stdout, stderr := runCLI(t, c, "capture", "export", id, "--all", destination, "--socket", socket)
	if code != exitOK || !strings.Contains(stdout, "Exported 2 files") {
		t.Fatalf("capture export --all: %d\n%s\n%s", code, stdout, stderr)
	}
	for name, content := range files {
		path := filepath.Join(destination, name)
		data, err := os.ReadFile(path)
		if err != nil || string(data) != string(content) {
			t.Fatalf("%s: %q %v", name, data, err)
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", name, info.Mode())
		}
		if os.Geteuid() == 0 {
			if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != 4321 {
				t.Fatalf("%s is not owned by the sudo user: %+v", name, info.Sys())
			}
		}
	}
	if os.Geteuid() == 0 {
		for _, directory := range []string{filepath.Join(base, "pcaps"), filepath.Join(base, "pcaps", "tv"), destination} {
			info, err := os.Stat(directory)
			if stat, ok := info.Sys().(*syscall.Stat_t); err != nil || !ok || stat.Uid != 4321 {
				t.Fatalf("new export directory %s is not owned by the sudo user", directory)
			}
		}
	}
	code, _, stderr = runCLI(t, c, "capture", "export", id, "--all", destination, "--socket", socket)
	if code != exitFailure || !strings.Contains(stderr, "Refusing to overwrite") {
		t.Fatalf("second export overwrote files: %d %s", code, stderr)
	}
}

func TestLogsMapsServicesToJournalAndCompose(t *testing.T) {
	c, _, _ := testCLI()
	c.findExecutable = func(candidates ...string) string { return candidates[0] }
	var gotPath string
	var gotArgs []string
	c.runProgram = func(path string, args []string) error { gotPath, gotArgs = path, args; return nil }
	if code, _, stderr := runCLI(t, c, "logs", "gatewayd", "-f", "-n", "50"); code != exitOK {
		t.Fatalf("logs gatewayd: %s", stderr)
	}
	if gotPath != "/usr/bin/journalctl" || !strings.Contains(strings.Join(gotArgs, " "), "-n 50 -u shakerproxy-gatewayd.service -f") {
		t.Fatalf("unexpected journalctl call %s %v", gotPath, gotArgs)
	}
	if code, _, _ := runCLI(t, c, "logs", "control-api", "--since", "30m"); code != exitOK || gotPath != "/usr/bin/docker" || !strings.Contains(strings.Join(gotArgs, " "), "compose --project-name shakerproxy logs --no-color --timestamps --tail 200 --since 30m control-api") {
		t.Fatalf("unexpected docker call %s %v", gotPath, gotArgs)
	}
	if code, _, _ := runCLI(t, c, "logs"); code != exitOK || !strings.Contains(strings.Join(gotArgs, " "), "-u shakerproxy-*") {
		t.Fatalf("default logs %v", gotArgs)
	}
	code, _, stderr := runCLI(t, c, "logs", "gatewyd")
	if code != exitUsage || !strings.Contains(stderr, `Did you mean "gatewayd"?`) {
		t.Fatalf("logs typo: %d %s", code, stderr)
	}
	c.findExecutable = func(...string) string { return "" }
	code, _, stderr = runCLI(t, c, "logs", "dns")
	if code != exitFailure || !strings.Contains(stderr, "journalctl command was not found") {
		t.Fatalf("missing journalctl: %d %s", code, stderr)
	}
}

func TestLifecycleCommandsNeedRootAndPassConfirmation(t *testing.T) {
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "uninstall", "--purge-data")
	if code != exitFailure || !strings.Contains(stderr, "sudo shakerproxy uninstall") {
		t.Fatalf("non-root uninstall: %d %s", code, stderr)
	}
	c.geteuid = func() int { return 0 }
	c.findExecutable = func(candidates ...string) string { return candidates[0] }
	var gotArgs []string
	c.execProgram = func(path string, args []string, env []string) error { gotArgs = args; return nil }
	if code, _, stderr := runCLI(t, c, "uninstall", "--purge-data", "--yes"); code != exitOK {
		t.Fatalf("uninstall: %s", stderr)
	}
	if strings.Join(gotArgs, " ") != uninstallExecutable+" --purge-data --yes" {
		t.Fatalf("unexpected uninstall invocation %v", gotArgs)
	}
	if code, _, _ := runCLI(t, c, "uninstall", "--yes"); code != exitUsage {
		t.Fatal("--yes without --purge-data was accepted")
	}
	if code, _, _ := runCLI(t, c, "update", "now"); code != exitUsage {
		t.Fatal("update accepted an extra argument")
	}
	c.findExecutable = func(...string) string { return "" }
	code, _, stderr = runCLI(t, c, "repair")
	if code != exitFailure || !strings.Contains(stderr, "host package is not installed") {
		t.Fatalf("missing installer: %d %s", code, stderr)
	}
}

func TestVersionReportsAllComponents(t *testing.T) {
	_, socket := startFakeGateway(t, func(string, json.RawMessage) (any, *gatewayprotocol.RPCError) {
		return gatewayprotocol.Status{APIVersion: "v1", DaemonVersion: "2.0.0"}, nil
	})
	release := filepath.Join(t.TempDir(), "release.json")
	if err := os.WriteFile(release, []byte(`{"schema":1,"version":"2.0.1","channel":"beta","installed_at":"2026-09-20T10:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHAKERPROXY_RELEASE_METADATA", release)
	c, _, _ := testCLI()
	code, stdout, _ := runCLI(t, c, "--version", "--socket", socket)
	if code != exitOK || !strings.Contains(stdout, "shakerproxy CLI") || !strings.Contains(stdout, "2.0.0 (API v1)") || !strings.Contains(stdout, "2.0.1 · beta") {
		t.Fatalf("version (%d):\n%s", code, stdout)
	}
	t.Setenv("SHAKERPROXY_RELEASE_METADATA", filepath.Join(t.TempDir(), "absent.json"))
	c, _, _ = testCLI()
	code, stdout, _ = runCLI(t, c, "version", "--json")
	var decoded map[string]any
	if code != exitOK || json.Unmarshal([]byte(stdout), &decoded) != nil || decoded["cli"] != version || decoded["daemon"] != nil || decoded["daemon_error"] == nil {
		t.Fatalf("version --json without daemon (%d):\n%s", code, stdout)
	}
}

func TestAdminResetWritesRequestAndWaitsForPickup(t *testing.T) {
	directory := t.TempDir()
	requestPath := filepath.Join(directory, "admin-reset.request")
	t.Setenv("SHAKERPROXY_ADMIN_RESET_REQUEST", requestPath)
	t.Setenv("SHAKERPROXY_SETUP_TOKEN_PATH", filepath.Join(directory, "setup-token"))
	t.Setenv("SUDO_USER", "alice")
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "admin", "reset", "--yes")
	if code != exitFailure || !strings.Contains(stderr, "sudo shakerproxy admin reset") {
		t.Fatalf("non-root reset: %d %s", code, stderr)
	}
	c.geteuid = func() int { return 0 }
	code, _, stderr = runCLI(t, c, "admin", "reset")
	if code != exitUsage || !strings.Contains(stderr, "add --yes") {
		t.Fatalf("reset without terminal or --yes: %d %s", code, stderr)
	}
	var written []byte
	var mode os.FileMode
	c.now = time.Now
	c.sleep = func(time.Duration) {
		if data, err := os.ReadFile(requestPath); err == nil {
			info, _ := os.Stat(requestPath)
			written, mode = data, info.Mode().Perm()
			// Simulate the control API picking up the request.
			_ = os.WriteFile(filepath.Join(directory, "setup-token"), []byte("new-token\n"), 0o600)
			_ = os.Remove(requestPath)
		}
	}
	code, stdout, stderr := runCLI(t, c, "admin", "reset", "--yes")
	if code != exitOK {
		t.Fatalf("reset failed: %s", stderr)
	}
	var request map[string]string
	if json.Unmarshal(written, &request) != nil || request["requested_by"] != "alice" || request["requested_at"] == "" || mode != 0o600 {
		t.Fatalf("unexpected reset request %q mode %v", written, mode)
	}
	if !strings.Contains(stdout, "New one-time setup token: new-token") || !strings.Contains(stdout, "sudo shakerproxy login") || !strings.Contains(stdout, "API tokens were NOT revoked") {
		t.Fatalf("reset guidance incomplete:\n%s", stdout)
	}
	c.sleep = func(time.Duration) {}
	c.maxPolls = 2
	code, _, stderr = runCLI(t, c, "admin", "reset", "--yes")
	if code != exitFailure || !strings.Contains(stderr, "nothing was reset (the request was withdrawn)") {
		t.Fatalf("unconsumed reset: %d %s", code, stderr)
	}
	if _, err := os.Lstat(requestPath); !os.IsNotExist(err) {
		t.Fatal("an unconsumed request was left queued for a later surprise reset")
	}
	code, stdout, _ = runCLI(t, c, "admin", "reset", "--yes", "--no-wait")
	if _, err := os.Lstat(requestPath); code != exitOK || err != nil || !strings.Contains(stdout, "Reset requested") {
		t.Fatalf("--no-wait did not leave the request queued: %d %v %s", code, err, stdout)
	}
}

func errPermission() error { return syscall.EACCES }

func stripANSI(value string) string {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] == 0x1b {
			if end := strings.IndexByte(value[index:], 'm'); end >= 0 {
				index += end
				continue
			}
		}
		builder.WriteByte(value[index])
	}
	return builder.String()
}

func TestAppStatusShowsReadableTable(t *testing.T) {
	c, _, _ := testCLI()
	c.geteuid = func() int { return 0 }
	c.findExecutable = func(candidates ...string) string { return candidates[0] }
	output := `WARNING: noise
{"Service":"postgres","State":"running","Health":"healthy","Status":"Up 2 minutes (healthy)"}
{"Service":"edge","State":"running","Health":"","Status":"Up 2 minutes"}
{"Service":"zeek","State":"exited","Health":"","Status":"Exited (1)"}
`
	c.outputProgram = func(path string, args []string, env []string) ([]byte, error) {
		if path != appLifecycleExecutable || strings.Join(args, " ") != "status" {
			t.Fatalf("unexpected helper %s %v", path, args)
		}
		return []byte(output), nil
	}
	code, stdout, _ := runCLI(t, c, "app", "status")
	if code != exitFailure || !strings.Contains(stdout, "edge") || !strings.Contains(stdout, "healthy") ||
		!strings.Contains(stdout, "1 of 3 services need attention: zeek") || strings.Contains(stdout, `"Service"`) {
		t.Fatalf("app status: %d\n%s", code, stdout)
	}
	if strings.Index(stdout, "edge") > strings.Index(stdout, "postgres") {
		t.Fatalf("services should be sorted:\n%s", stdout)
	}
	output = `{"Service":"postgres","State":"running","Health":"healthy"}`
	code, stdout, _ = runCLI(t, c, "app", "status")
	if code != exitOK || !strings.Contains(stdout, "All 1 services are running.") {
		t.Fatalf("healthy app status: %d\n%s", code, stdout)
	}
	code, stdout, _ = runCLI(t, c, "--json", "app", "status")
	if code != exitOK || !strings.Contains(stdout, `"services"`) || !strings.Contains(stdout, `"Service": "postgres"`) {
		t.Fatalf("json app status: %d\n%s", code, stdout)
	}
}

func TestNetworkOffAsksForConfirmationWithoutATerminal(t *testing.T) {
	c, _, _ := testCLI()
	code, _, stderr := runCLI(t, c, "network", "off")
	if code != exitUsage || !strings.Contains(stderr, "add --yes") {
		t.Fatalf("network off without a terminal: %d %s", code, stderr)
	}
	code, _, stderr = runCLI(t, c, "network", "on")
	if code != exitUsage || !strings.Contains(stderr, "off") {
		t.Fatalf("unknown network subcommand: %d %s", code, stderr)
	}
}
