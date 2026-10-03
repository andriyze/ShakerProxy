package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const dev = "device-00000000000000000000000000000001"

func webhookChannel(secret string) Channel {
	return Channel{ID: "hook", Kind: ChannelWebhook, Name: "Ops webhook", Enabled: true, URL: "https://hooks.example.com/x", Secret: secret}
}

func TestConfigValidation(t *testing.T) {
	good := DefaultConfig()
	good.Channels = append(good.Channels, webhookChannel("s3cr3t"))
	good.Rules = []Rule{{ID: "r1", Trigger: TriggerCleartext, Channels: []string{InAppChannelID, "hook"}, Enabled: true}}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := []Config{
		{Schema: ConfigSchema}, // no in-app channel
		{Schema: ConfigSchema, Channels: []Channel{{ID: "in-app", Kind: ChannelInApp, Name: "x"}, {ID: "h", Kind: ChannelWebhook, Name: "h", URL: "http://x/"}}}, // non-https
		{Schema: ConfigSchema, Channels: DefaultConfig().Channels, Rules: []Rule{{ID: "r", Trigger: "NOPE", Channels: []string{"in-app"}, Enabled: true}}},       // unknown trigger
		{Schema: ConfigSchema, Channels: DefaultConfig().Channels, Rules: []Rule{{ID: "r", Trigger: TriggerNewDevice, Channels: []string{"missing"}}}},           // unknown channel
	}
	for index, config := range bad {
		if err := config.Validate(); err == nil {
			t.Fatalf("invalid config %d accepted", index)
		}
	}
}

func TestEvaluateMatchesScopeAndSeverity(t *testing.T) {
	config := DefaultConfig()
	config.Channels = append(config.Channels, webhookChannel(""))
	config.Rules = []Rule{
		{ID: "cleartext", Trigger: TriggerCleartext, Channels: []string{InAppChannelID, "hook"}, Enabled: true},
		{ID: "bypass-high", Trigger: TriggerBypassing, MinSeverity: SeverityCritical, Channels: []string{InAppChannelID}, Enabled: true},
		{ID: "one-device", Trigger: TriggerNewDevice, DeviceID: "device-0000000000000000000000000000000a", Channels: []string{InAppChannelID}, Enabled: true},
		{ID: "disabled", Trigger: TriggerCleartext, Channels: []string{InAppChannelID}},
	}
	now := time.Unix(1_790_000_000, 0).UTC()
	candidates := []Candidate{
		CleartextCandidate(dev, "iPhone", "http://login.example.com", "form-password", "password"),
		BypassingCandidate(dev, "iPhone", "192.168.10.130", ""),                 // WARNING < CRITICAL → no notification
		NewDeviceCandidate("device-0000000000000000000000000000000b", "TV", ""), // wrong device → no notification
	}
	fired, _ := Evaluate(candidates, config, nil, now)
	if len(fired) != 1 {
		t.Fatalf("expected 1 notification, got %d: %+v", len(fired), fired)
	}
	got := fired[0]
	if got.Trigger != TriggerCleartext || got.Severity != SeverityCritical {
		t.Fatalf("unexpected notification %+v", got)
	}
	if strings.Join(got.Channels, ",") != "hook,in-app" {
		t.Fatalf("channels = %v", got.Channels)
	}
	// The secret value must never appear; only the kind/location.
	if strings.Contains(got.Body, "password=") || strings.Contains(got.Title, "secret-value") {
		t.Fatalf("notification leaked a secret: %q / %q", got.Title, got.Body)
	}
}

func TestEvaluateDeduplicatesWithinWindow(t *testing.T) {
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "r", Trigger: TriggerBypassing, Channels: []string{InAppChannelID}, Enabled: true}}
	now := time.Unix(1_790_000_000, 0).UTC()
	candidate := BypassingCandidate(dev, "iPhone", "192.168.10.130", "")

	first, state := Evaluate([]Candidate{candidate}, config, nil, now)
	if len(first) != 1 {
		t.Fatalf("first pass: %d", len(first))
	}
	// Same subject a minute later — suppressed.
	second, state := Evaluate([]Candidate{candidate}, config, state, now.Add(time.Minute))
	if len(second) != 0 {
		t.Fatalf("repeat within window was not suppressed: %d", len(second))
	}
	// After the window — fires again.
	third, state := Evaluate([]Candidate{candidate}, config, state, now.Add(DedupWindow+time.Second))
	if len(third) != 1 {
		t.Fatalf("after window did not fire: %d", len(third))
	}
	// A different device is a different subject — fires immediately.
	other := BypassingCandidate("device-0000000000000000000000000000000c", "TV", "192.168.10.131", "")
	fourth, _ := Evaluate([]Candidate{other}, config, state, now.Add(DedupWindow+2*time.Second))
	if len(fourth) != 1 {
		t.Fatalf("new subject did not fire: %d", len(fourth))
	}
}

func TestFlaggedCategory(t *testing.T) {
	cases := map[string]string{
		"ads.doubleclick.net":   "advertising",
		"DOUBLECLICK.NET":       "advertising",
		"o123.ingest.sentry.io": "telemetry",
		"example.com":           "",
		"notdoubleclick.net":    "",
	}
	for domain, want := range cases {
		if got := FlaggedCategory(domain); got != want {
			t.Errorf("FlaggedCategory(%q) = %q, want %q", domain, got, want)
		}
	}
}

func TestRenderBodiesCarryNoSecret(t *testing.T) {
	n := CleartextToNotification(t)
	webhook := RenderWebhook(n)
	encoded, _ := json.Marshal(webhook)
	if strings.Contains(string(encoded), "hunter2") {
		t.Fatalf("webhook body leaked the secret: %s", encoded)
	}
	slack := RenderSlack(n)
	if _, ok := slack["text"].(string); !ok {
		t.Fatalf("slack body missing text")
	}
	if !strings.Contains(slack["text"].(string), n.Title) {
		t.Fatalf("slack text missing title: %v", slack["text"])
	}
}

// CleartextToNotification builds a stored notification from a cleartext
// candidate; the detector only ever passes the kind and location, never the
// value "hunter2".
func CleartextToNotification(t *testing.T) Notification {
	t.Helper()
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "r", Trigger: TriggerCleartext, Channels: []string{InAppChannelID}, Enabled: true}}
	fired, _ := Evaluate([]Candidate{CleartextCandidate(dev, "iPhone", "login.example.com", "form-password", "password")}, config, nil, time.Unix(1_790_000_000, 0).UTC())
	if len(fired) != 1 {
		t.Fatalf("expected 1 notification")
	}
	return fired[0]
}

func TestHTTPDelivererSignsAndShapesBodies(t *testing.T) {
	type received struct {
		body      []byte
		signature string
	}
	got := make(chan received, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		got <- received{body: body, signature: r.Header.Get("X-ShakerProxy-Signature")}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	deliverer := HTTPDeliverer{Client: server.Client()}
	n := CleartextToNotification(t)

	// Generic webhook, signed.
	secret := "s3cr3t"
	if err := deliverer.Deliver(context.Background(), Channel{Kind: ChannelWebhook, URL: server.URL, Secret: secret}, n); err != nil {
		t.Fatalf("webhook delivery failed: %v", err)
	}
	webhook := <-got
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(webhook.body)
	if webhook.signature != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("bad signature %q", webhook.signature)
	}
	var decoded WebhookBody
	if err := json.Unmarshal(webhook.body, &decoded); err != nil || decoded.Trigger != TriggerCleartext || decoded.Subject.DeviceID != dev {
		t.Fatalf("unexpected webhook body: %s", webhook.body)
	}
	if strings.Contains(string(webhook.body), "hunter2") {
		t.Fatalf("secret leaked to webhook")
	}

	// Slack shape.
	if err := deliverer.Deliver(context.Background(), Channel{Kind: ChannelSlack, URL: server.URL}, n); err != nil {
		t.Fatalf("slack delivery failed: %v", err)
	}
	slack := <-got
	var slackBody map[string]any
	if err := json.Unmarshal(slack.body, &slackBody); err != nil || slackBody["text"] == "" {
		t.Fatalf("unexpected slack body: %s", slack.body)
	}
}

func TestIsPublicUnicastRefusesInternalAddresses(t *testing.T) {
	refuse := []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1", "::1", "fe80::1", "100.64.0.1", "0.0.0.0"}
	for _, address := range refuse {
		if isPublicUnicast(net.ParseIP(address)) {
			t.Errorf("isPublicUnicast(%s) should be false", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "203.0.113.9", "2606:4700:4700::1111"} {
		if !isPublicUnicast(net.ParseIP(address)) {
			t.Errorf("isPublicUnicast(%s) should be true", address)
		}
	}
}

func TestLogAppendBoundsAndMarksRead(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/log.json"
	now := time.Unix(1_790_000_000, 0).UTC()
	batch := make([]Notification, MaxStored+10)
	for i := range batch {
		batch[i] = Notification{ID: "ntf-" + hex.EncodeToString([]byte{byte(i), byte(i >> 8)}), CreatedAt: now.Add(time.Duration(i) * time.Second)}
	}
	if err := AppendLog(path, batch, now); err != nil {
		t.Fatal(err)
	}
	log, err := LoadLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Notifications) != MaxStored {
		t.Fatalf("log not bounded: %d", len(log.Notifications))
	}
	if log.Unread() != MaxStored {
		t.Fatalf("unread = %d", log.Unread())
	}
	changed, err := MarkRead(path, nil)
	if err != nil || changed != MaxStored {
		t.Fatalf("mark read all: %d %v", changed, err)
	}
	log, _ = LoadLog(path)
	if log.Unread() != 0 {
		t.Fatalf("still unread after mark-all: %d", log.Unread())
	}
}

func TestLogWritesDoNotLoseEachOther(t *testing.T) {
	// The evaluator appends while a user marks everything read. Each
	// read-modify-write must see the other's result.
	path := t.TempDir() + "/log.json"
	const writers = 40
	done := make(chan error, 2*writers)
	for index := 0; index < writers; index++ {
		go func(index int) {
			done <- AppendLog(path, []Notification{{ID: "ntf-" + string(rune('a'+index%26)) + string(rune('a'+index/26)), CreatedAt: time.Now()}}, time.Now())
		}(index)
		go func() {
			_, err := MarkRead(path, nil)
			done <- err
		}()
	}
	for index := 0; index < 2*writers; index++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	log, err := LoadLog(path)
	if err != nil || len(log.Notifications) != writers {
		t.Fatalf("stored %d of %d notifications (%v)", len(log.Notifications), writers, err)
	}
}

func TestSecurityAlertsWithDifferentSignaturesAreDistinct(t *testing.T) {
	one := SecurityAlertCandidate(dev, "TV", "suricata.alert", "ET POLICY Cleartext password", SeverityWarning)
	two := SecurityAlertCandidate(dev, "TV", "suricata.alert", "ET MALWARE Beacon", SeverityWarning)
	again := SecurityAlertCandidate(dev, "TV", "suricata.alert", "ET POLICY Cleartext password", SeverityWarning)
	if one.Key == two.Key || one.Key != again.Key {
		t.Fatalf("keys: %q %q %q", one.Key, two.Key, again.Key)
	}
	config := DefaultConfig()
	config.Rules = []Rule{{ID: "r1", Trigger: TriggerSecurityAlert, Channels: []string{InAppChannelID}, Enabled: true}}
	fired, _ := Evaluate([]Candidate{one, two, again}, config, nil, time.Now())
	if len(fired) != 2 {
		t.Fatalf("fired %d notifications, want one per signature", len(fired))
	}
}

type scriptedDeliverer struct {
	errors []error
	calls  int
}

func (d *scriptedDeliverer) Deliver(context.Context, Channel, Notification) error {
	d.calls++
	if d.calls <= len(d.errors) {
		return d.errors[d.calls-1]
	}
	return nil
}

func TestDeliverWithRetryRetriesOnlyTransientFailures(t *testing.T) {
	previous := DeliveryBackoff
	DeliveryBackoff = time.Millisecond
	defer func() { DeliveryBackoff = previous }()

	transient := &scriptedDeliverer{errors: []error{io.ErrUnexpectedEOF, io.ErrUnexpectedEOF}}
	if err := DeliverWithRetry(context.Background(), transient, webhookChannel(""), Notification{}); err != nil || transient.calls != 3 {
		t.Fatalf("transient: err=%v calls=%d", err, transient.calls)
	}
	fatal := &scriptedDeliverer{errors: []error{permanent(io.EOF), nil}}
	if err := DeliverWithRetry(context.Background(), fatal, webhookChannel(""), Notification{}); err == nil || fatal.calls != 1 {
		t.Fatalf("permanent: err=%v calls=%d", err, fatal.calls)
	}
	down := &scriptedDeliverer{errors: []error{io.EOF, io.EOF, io.EOF, io.EOF}}
	if err := DeliverWithRetry(context.Background(), down, webhookChannel(""), Notification{}); err == nil || down.calls != DeliveryAttempts {
		t.Fatalf("down: err=%v calls=%d", err, down.calls)
	}
}

func TestDeliveryErrorsNameNeitherTheURLNorTheInternalAddress(t *testing.T) {
	gone := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusGone) }))
	defer gone.Close()
	err := HTTPDeliverer{Client: gone.Client()}.Deliver(context.Background(), Channel{Kind: ChannelSlack, URL: gone.URL + "/services/T0/B0/SECRETPATH"}, Notification{})
	var fatal permanentError
	if err == nil || !errors.As(err, &fatal) {
		t.Fatalf("a 410 is permanent: %v", err)
	}
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	client := closed.Client()
	closed.Close()
	err = HTTPDeliverer{Client: client}.Deliver(context.Background(), Channel{Kind: ChannelSlack, URL: closed.URL + "/services/T0/B0/SECRETPATH"}, Notification{})
	if err == nil || strings.Contains(err.Error(), "SECRETPATH") {
		t.Fatalf("delivery error names the URL: %v", err)
	}
	_, err = safeDialContext("localhost")(context.Background(), "tcp", "localhost:443")
	if err == nil || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "::1") {
		t.Fatalf("refusal names the address: %v", err)
	}
}

func TestMaskedURLKeepsOnlyTheService(t *testing.T) {
	if got := MaskedURL("https://hooks.slack.com/services/T0/B0/XXXX"); got != "https://hooks.slack.com/[redacted]" {
		t.Fatalf("masked = %q", got)
	}
	if MaskedURL("") != "" {
		t.Fatal("an empty URL stays empty")
	}
}

func TestEvalStateRoundTrips(t *testing.T) {
	path := t.TempDir() + "/state.json"
	empty, err := LoadEvalState(path)
	if err != nil || empty.Seeded || empty.LastFired == nil {
		t.Fatalf("absent state = %#v %v", empty, err)
	}
	at := time.Unix(1_800_000_000, 0).UTC()
	if err := SaveEvalState(path, EvalState{Seeded: true, LastFired: map[string]time.Time{"r1\x00k": at}, Known: []string{dev}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEvalState(path)
	if err != nil || !loaded.Seeded || !loaded.LastFired["r1\x00k"].Equal(at) || len(loaded.Known) != 1 || loaded.Known[0] != dev {
		t.Fatalf("loaded = %#v %v", loaded, err)
	}
}
