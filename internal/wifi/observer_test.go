package wifi

import (
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/wifi/wifitest"
)

const (
	labAP      = "aa:bb:cc:00:00:01"
	otherAP    = "aa:bb:cc:00:00:02"
	neighborAP = "10:22:33:00:00:09"
	phone      = "3c:22:fb:00:00:10"
	phoneRand  = "da:a1:19:00:00:01"
	stranger   = "f2:00:00:00:00:99"
)

var radio = wifitest.Radio{FrequencyMHz: 2437, SignalDBM: -50}

func labScope(nearby bool) *Scope {
	return CompileScope(ScopeFile{Schema: ScopeSchema, LabBSSIDs: []string{labAP}, LabSSIDs: []string{"ShakerProxy-Lab"}, LabMACs: []string{phone}, Nearby: nearby, GeneratedAt: testAt})
}

func feed(t *testing.T, observer *Observer, at time.Time, data []byte) {
	t.Helper()
	frame, ok := Decode(at, data)
	if !ok {
		t.Fatalf("frame did not decode")
	}
	observer.Observe(frame)
}

func kinds(events []Event) []string {
	out := []string{}
	for _, event := range events {
		out = append(out, event.Kind+":"+event.Payload.ClientMAC+":"+event.Payload.SSID)
	}
	return out
}

func TestObserverRecordsOnlyLabTrafficByDefault(t *testing.T) {
	observer := NewObserver(labScope(false))
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, stranger, "CoffeeShop", 1))
	feed(t, observer, testAt, wifitest.Beacon(radio, neighborAP, "Neighbors", 6, 0x0411, wifitest.RSN(0, 2)))
	feed(t, observer, testAt, wifitest.Deauthentication(radio, stranger, neighborAP, true, false, false, 3))
	if events := observer.Drain(); len(events) != 0 {
		t.Fatalf("bystander frames recorded: %v", kinds(events))
	}
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, phone, "HomeWiFi", 10))
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, stranger, "ShakerProxy-Lab", 2))
	feed(t, observer, testAt, wifitest.Beacon(radio, labAP, "ShakerProxy-Lab", 6, 0x0411, wifitest.RSN(0x0080, 2, 8)))
	events := observer.Drain()
	if len(events) != 3 {
		t.Fatalf("events = %v", kinds(events))
	}
	probe := events[0].Payload
	if events[0].Kind != KindProbe || probe.Scope != ScopeLab || probe.SSID != "HomeWiFi" || probe.Channel != 6 || probe.FrequencyMHz != 2437 || probe.SignalDBM == nil || *probe.SignalDBM != -50 || probe.Randomized {
		t.Fatalf("probe = %+v", probe)
	}
	if events[1].Payload.ClientMAC != stranger || events[1].Payload.SSID != "ShakerProxy-Lab" {
		t.Fatalf("a probe for the lab network was not kept: %+v", events[1])
	}
	beacon := events[2].Payload
	if events[2].Kind != KindBeaconSummary || beacon.Security != SecurityWPA2WPA3Personal || beacon.BSSID != labAP || beacon.Count != 1 {
		t.Fatalf("beacon = %+v", beacon)
	}
}

func TestObserverRecordsNearbyWhenOptedIn(t *testing.T) {
	observer := NewObserver(labScope(true))
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, stranger, "CoffeeShop", 1))
	feed(t, observer, testAt, wifitest.Beacon(radio, neighborAP, "Neighbors", 6, 0x0411, wifitest.RSN(0, 2)))
	events := observer.Drain()
	if len(events) != 2 || events[0].Payload.Scope != ScopeNearby || events[1].Payload.Scope != ScopeNearby {
		t.Fatalf("events = %+v", events)
	}
}

func TestObserverFoldsRepeatedProbes(t *testing.T) {
	observer := NewObserver(labScope(false))
	for second := 0; second < 25; second += 5 {
		feed(t, observer, testAt.Add(time.Duration(second)*time.Second), wifitest.ProbeRequest(radio, phone, "HomeWiFi", uint16(second)))
	}
	feed(t, observer, testAt.Add(31*time.Second), wifitest.ProbeRequest(radio, phone, "HomeWiFi", 40))
	feed(t, observer, testAt.Add(32*time.Second), wifitest.ProbeRequest(radio, phone, "Work", 41))
	if got := kinds(observer.Drain()); len(got) != 3 {
		t.Fatalf("probes = %v", got)
	}
}

func TestObserverFollowsAuthAssociationRoamingAndDisconnects(t *testing.T) {
	observer := NewObserver(labScope(false))
	client := "02:11:22:33:44:55" // not known yet: learned from the lab AP
	at := testAt
	feed(t, observer, at, wifitest.Beacon(radio, labAP, "ShakerProxy-Lab", 6, 0x0411, wifitest.RSN(0, 2)))
	feed(t, observer, at, wifitest.Authentication(radio, client, labAP, false, 0, 1, 0))
	feed(t, observer, at.Add(time.Millisecond), wifitest.Authentication(radio, client, labAP, true, 0, 2, 0))
	feed(t, observer, at.Add(2*time.Millisecond), wifitest.Authentication(radio, client, labAP, true, 0, 2, 0)) // retry
	feed(t, observer, at.Add(3*time.Millisecond), wifitest.AssociationRequest(radio, client, labAP, "ShakerProxy-Lab", "", 5))
	feed(t, observer, at.Add(4*time.Millisecond), wifitest.AssociationResponse(radio, client, labAP, false, 0))
	// The device later roams to another access point of a network that is
	// not the lab's: it is a lab device now, so this is recorded.
	feed(t, observer, at.Add(time.Minute), wifitest.AssociationRequest(radio, client, otherAP, "Office", labAP, 6))
	feed(t, observer, at.Add(time.Minute+time.Millisecond), wifitest.AssociationResponse(radio, client, otherAP, true, 0))
	feed(t, observer, at.Add(2*time.Minute), wifitest.Deauthentication(radio, client, otherAP, true, false, false, 15))
	feed(t, observer, at.Add(2*time.Minute+time.Millisecond), wifitest.Deauthentication(radio, client, otherAP, true, true, true, 0))
	events := observer.Drain()
	want := []string{KindBeaconSummary, KindAuth, KindAssoc, KindAssoc, KindDeauth, KindDisassoc}
	if len(events) != len(want) {
		t.Fatalf("events = %v", kinds(events))
	}
	for index, kind := range want {
		if events[index].Kind != kind {
			t.Fatalf("event %d = %s, want %s (%v)", index, events[index].Kind, kind, kinds(events))
		}
	}
	auth := events[1].Payload
	if auth.Algorithm != "open" || auth.Success == nil || !*auth.Success || auth.SSID != "ShakerProxy-Lab" || auth.Direction != DirectionFromAP {
		t.Fatalf("auth = %+v", auth)
	}
	first := events[2].Payload
	if first.Reassociation || first.PreviousBSSID != "" || first.SSID != "ShakerProxy-Lab" || first.Success == nil || !*first.Success {
		t.Fatalf("association = %+v", first)
	}
	roam := events[3].Payload
	if !roam.Reassociation || roam.PreviousBSSID != labAP || roam.BSSID != otherAP || roam.SSID != "Office" {
		t.Fatalf("roam = %+v", roam)
	}
	deauth := events[4].Payload
	if deauth.ReasonCode == nil || *deauth.ReasonCode != 15 || deauth.Direction != DirectionFromAP || deauth.Reason == "" {
		t.Fatalf("deauth = %+v", deauth)
	}
	protected := events[5].Payload
	if !protected.Protected || protected.ReasonCode != nil {
		t.Fatalf("protected disassociation = %+v", protected)
	}
	if _, learned := observer.Learned()[client]; !learned {
		t.Fatal("the client of the lab access point was not learned")
	}
}

func TestObserverReportsFailedAuthenticationAndUnansweredAssociation(t *testing.T) {
	observer := NewObserver(labScope(false))
	feed(t, observer, testAt, wifitest.Authentication(radio, phone, labAP, true, 3, 1, 1))
	feed(t, observer, testAt.Add(time.Second), wifitest.AssociationRequest(radio, phone, labAP, "ShakerProxy-Lab", "", 7))
	observer.Flush(testAt.Add(2 * time.Second))
	events := observer.Drain()
	if len(events) != 1 || events[0].Kind != KindAuth || events[0].Payload.Success == nil || *events[0].Payload.Success || events[0].Payload.Algorithm != "sae" {
		t.Fatalf("events = %+v", events)
	}
	observer.Flush(testAt.Add(5 * time.Second))
	events = observer.Drain()
	if len(events) != 1 || events[0].Kind != KindAssoc || !events[0].Payload.NoResponse || events[0].At != testAt.Add(time.Second) {
		t.Fatalf("unanswered association = %+v", events)
	}
}

func TestObserverSummarizesBeaconsPerWindow(t *testing.T) {
	observer := NewObserver(labScope(false))
	for index := 0; index < 10; index++ {
		strength := wifitest.Radio{FrequencyMHz: 2437, SignalDBM: -40 - index}
		feed(t, observer, testAt.Add(time.Duration(index)*time.Second), wifitest.Beacon(strength, labAP, "ShakerProxy-Lab", 6, 0x0411, wifitest.RSN(0, 2)))
	}
	if events := observer.Drain(); len(events) != 1 {
		t.Fatalf("first sighting = %v", kinds(events))
	}
	observer.Flush(testAt.Add(4 * time.Minute))
	if events := observer.Drain(); len(events) != 0 {
		t.Fatalf("summary before the window ended: %v", kinds(events))
	}
	observer.Flush(testAt.Add(5 * time.Minute))
	events := observer.Drain()
	if len(events) != 1 {
		t.Fatalf("summary = %v", kinds(events))
	}
	summary := events[0].Payload
	if summary.Count != 9 || *summary.SignalMinDBM != -49 || *summary.SignalMaxDBM != -41 {
		t.Fatalf("summary = %+v (min %d max %d)", summary, *summary.SignalMinDBM, *summary.SignalMaxDBM)
	}
}

func TestObserverNotesPossibleMatchesConservatively(t *testing.T) {
	observer := NewObserver(labScope(false))
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, phone, "HomeWiFi", 100))
	observer.Drain()
	// Same model fingerprint, continuing sequence: a possible match.
	feed(t, observer, testAt.Add(2*time.Second), wifitest.ProbeRequest(radio, phoneRand, "Work", 103))
	events := observer.Drain()
	if len(events) != 1 || events[0].Payload.PossibleMAC != phone || events[0].Payload.ClientMAC != phoneRand || !events[0].Payload.Randomized {
		t.Fatalf("possible match = %+v", events)
	}
	// A different model, or a sequence that does not continue, is not.
	feed(t, observer, testAt.Add(3*time.Second), wifitest.ProbeRequestWith(radio, "de:00:00:00:00:02", "Work", 105, wifitest.OtherProbeElements()))
	feed(t, observer, testAt.Add(4*time.Second), wifitest.ProbeRequest(radio, "de:00:00:00:00:03", "Work", 3000))
	feed(t, observer, testAt.Add(time.Minute), wifitest.ProbeRequest(radio, "de:00:00:00:00:04", "Work", 106))
	if events := observer.Drain(); len(events) != 0 {
		t.Fatalf("unrelated randomized probes recorded: %v", kinds(events))
	}
}

func TestObserverIgnoresFingerprintsSharedByLabDevices(t *testing.T) {
	scope := CompileScope(ScopeFile{Schema: ScopeSchema, LabMACs: []string{phone, "3c:22:fb:00:00:11"}, GeneratedAt: testAt})
	observer := NewObserver(scope)
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, phone, "A", 100))
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, "3c:22:fb:00:00:11", "B", 500))
	observer.Drain()
	feed(t, observer, testAt.Add(time.Second), wifitest.ProbeRequest(radio, phoneRand, "C", 101))
	if events := observer.Drain(); len(events) != 0 {
		t.Fatalf("a fingerprint two lab devices share matched: %v", kinds(events))
	}
}

func TestObserverRemembersLearnedAddresses(t *testing.T) {
	observer := NewObserver(labScope(false))
	observer.Remember(map[string]time.Time{"02:11:22:33:44:55": testAt, "02:11:22:33:44:66": testAt.Add(-31 * 24 * time.Hour), "bad": testAt}, testAt)
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, "02:11:22:33:44:55", "HomeWiFi", 1))
	feed(t, observer, testAt, wifitest.ProbeRequest(radio, "02:11:22:33:44:66", "HomeWiFi", 1))
	if events := observer.Drain(); len(events) != 1 || events[0].Payload.ClientMAC != "02:11:22:33:44:55" {
		t.Fatalf("events = %v", kinds(events))
	}
}

func TestEventEncodeIsAHostEvent(t *testing.T) {
	event := Event{Kind: KindProbe, At: testAt, Payload: Payload{Scope: ScopeLab, ClientMAC: phone, SSID: "HomeWiFi"}}
	encoded, err := event.Encode("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"source":"HOST"`, `"kind":"wifi.probe"`, `"ssid":"HomeWiFi"`, `"scope":"lab"`} {
		if !contains(string(encoded), want) {
			t.Fatalf("encoded event %s lacks %s", encoded, want)
		}
	}
	if _, err := (Event{Kind: "wifi.other", At: testAt, Payload: Payload{Scope: ScopeLab}}).Encode("x"); err == nil {
		t.Fatal("unknown kind encoded")
	}
	if _, err := (Event{Kind: KindProbe, At: testAt}).Encode("x"); err == nil {
		t.Fatal("event without a scope encoded")
	}
}

func TestScopeFileValidation(t *testing.T) {
	valid := ScopeFile{Schema: ScopeSchema, LabBSSIDs: []string{labAP}, LabSSIDs: []string{"Lab"}, LabMACs: []string{phone}, GeneratedAt: testAt}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ScopeFile){
		"schema":     func(s *ScopeFile) { s.Schema = 2 },
		"time":       func(s *ScopeFile) { s.GeneratedAt = time.Time{} },
		"group mac":  func(s *ScopeFile) { s.LabMACs = []string{"01:00:5e:00:00:01"} },
		"bad mac":    func(s *ScopeFile) { s.LabBSSIDs = []string{"nope"} },
		"empty ssid": func(s *ScopeFile) { s.LabSSIDs = []string{""} },
	} {
		scope := valid
		change(&scope)
		if scope.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func contains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}
