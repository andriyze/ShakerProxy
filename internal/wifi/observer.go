package wifi

import (
	"sort"
	"strconv"
	"time"
)

// Event kinds the worker emits (HOST events).
const (
	KindProbe           = "wifi.probe"
	KindAuth            = "wifi.auth"
	KindAssoc           = "wifi.assoc"
	KindDeauth          = "wifi.deauth"
	KindDisassoc        = "wifi.disassoc"
	KindBeaconSummary   = "wifi.beacon_summary"
	DirectionFromClient = "from_client"
	DirectionFromAP     = "from_ap"
)

// Kinds lists the event kinds in display order.
var Kinds = []string{KindProbe, KindAuth, KindAssoc, KindDeauth, KindDisassoc, KindBeaconSummary}

// PossibleMatchConfidence is the confidence of a probe from a randomized
// address attributed to a lab device because its fingerprint and sequence
// numbers continue that device's: a hint, never proof.
const PossibleMatchConfidence = 20

// Payload is the body of a Wi-Fi event. Every string in it came off the air
// and is untrusted.
type Payload struct {
	Scope      string `json:"scope"`
	ClientMAC  string `json:"client_mac,omitempty"`
	Randomized bool   `json:"randomized_mac,omitempty"`
	BSSID      string `json:"bssid,omitempty"`
	SSID       string `json:"ssid,omitempty"`
	// Wildcard marks a probe for any network; Hidden a network that does
	// not broadcast its name.
	Wildcard     bool   `json:"wildcard,omitempty"`
	Hidden       bool   `json:"hidden,omitempty"`
	Channel      int    `json:"channel,omitempty"`
	FrequencyMHz int    `json:"frequency_mhz,omitempty"`
	SignalDBM    *int   `json:"signal_dbm,omitempty"`
	SignalMinDBM *int   `json:"signal_min_dbm,omitempty"`
	SignalMaxDBM *int   `json:"signal_max_dbm,omitempty"`
	Count        int    `json:"count,omitempty"`
	Direction    string `json:"direction,omitempty"`
	// Deauthentication and disassociation.
	ReasonCode *int   `json:"reason_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// Protected frames were encrypted by management frame protection, so
	// their reason cannot be read.
	Protected bool `json:"protected,omitempty"`
	// Authentication and association.
	StatusCode    *int   `json:"status_code,omitempty"`
	Status        string `json:"status,omitempty"`
	Success       *bool  `json:"success,omitempty"`
	NoResponse    bool   `json:"no_response,omitempty"`
	Algorithm     string `json:"algorithm,omitempty"`
	Reassociation bool   `json:"reassociation,omitempty"`
	// PreviousBSSID is the access point a device left when it roamed.
	PreviousBSSID string `json:"previous_bssid,omitempty"`
	Security      string `json:"security,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	// PossibleMAC is the lab device address a randomized probe probably
	// belongs to (see PossibleMatchConfidence).
	PossibleMAC string `json:"possible_mac,omitempty"`
}

// Event is one Wi-Fi observation.
type Event struct {
	Kind    string
	At      time.Time
	Payload Payload
}

// Frame is one captured management frame with its radio details.
type Frame struct {
	At    time.Time
	Radio Radiotap
	Frame Management
}

const (
	probeWindow       = 30 * time.Second
	beaconWindow      = 5 * time.Minute
	assocResponseWait = 3 * time.Second
	retryWindow       = 2 * time.Second
	learnedLifetime   = 30 * 24 * time.Hour
	sequenceWindow    = 30 * time.Second
	sequenceGap       = 64
	maxProbeKeys      = 4096
	maxBeacons        = 2048
	maxPendingAssoc   = 1024
	maxLearned        = 4096
	maxFingerprints   = 2048
	maxSequences      = 4096
	maxRecentKeys     = 4096
	maxNetworkNames   = 2048
)

type probeKey struct {
	client MAC
	ssid   string
}

type beaconState struct {
	firstAt, emittedAt time.Time
	ssid               SSID
	channel, frequency int
	security           string
	min, max           int
	hasSignal          bool
	count              int
	scope              string
	emitted            bool
}

type pendingAssoc struct {
	at            time.Time
	ssid          SSID
	reassociation bool
	currentAP     MAC
	frequency     int
	signal        *int
	scope         string
}

type assocKey struct{ client, bssid MAC }

type sequenceState struct {
	value uint16
	at    time.Time
}

type networkName struct {
	ssid     SSID
	security string
	at       time.Time
}

// Observer turns frames into events, applying the privacy scope and the
// rate limits: a probe for the same network from the same address once per
// 30 seconds, one summary per access point every 5 minutes, and retries of
// the same frame within 2 seconds dropped.
type Observer struct {
	scope *Scope

	probes       map[probeKey]time.Time
	beacons      map[MAC]*beaconState
	pending      map[assocKey]pendingAssoc
	learned      map[MAC]time.Time
	fingerprints map[string]MAC
	ambiguous    map[string]bool
	sequences    map[MAC]sequenceState
	recent       map[string]time.Time
	networks     map[MAC]networkName
	associated   map[MAC]MAC
	events       []Event
}

// NewObserver starts with an empty state.
func NewObserver(scope *Scope) *Observer {
	return &Observer{
		scope: scope, probes: map[probeKey]time.Time{}, beacons: map[MAC]*beaconState{}, pending: map[assocKey]pendingAssoc{},
		learned: map[MAC]time.Time{}, fingerprints: map[string]MAC{}, ambiguous: map[string]bool{}, sequences: map[MAC]sequenceState{},
		recent: map[string]time.Time{}, networks: map[MAC]networkName{}, associated: map[MAC]MAC{},
	}
}

// SetScope replaces the scope, for example when the tester opts in to
// nearby devices or a new lab device appears.
func (o *Observer) SetScope(scope *Scope) { o.scope = scope }

// Learned returns the lab device addresses the observer learned from
// associations with the lab's access point, for the worker to keep.
func (o *Observer) Learned() map[string]time.Time {
	result := make(map[string]time.Time, len(o.learned))
	for mac, at := range o.learned {
		result[mac.String()] = at
	}
	return result
}

// Remember restores learned lab device addresses.
func (o *Observer) Remember(learned map[string]time.Time, now time.Time) {
	for value, at := range learned {
		if mac, ok := ParseMAC(value); ok && now.Sub(at) < learnedLifetime && len(o.learned) < maxLearned {
			o.learned[mac] = at
		}
	}
}

// Drain returns the events produced so far, in time order.
func (o *Observer) Drain() []Event {
	events := o.events
	o.events = nil
	sort.SliceStable(events, func(left, right int) bool { return events[left].At.Before(events[right].At) })
	return events
}

// labClient reports an address that belongs to a lab device.
func (o *Observer) labClient(mac MAC) bool {
	if o.scope.LabMAC(mac) {
		return true
	}
	_, learned := o.learned[mac]
	return learned
}

// scopeOf decides whether a frame between client and bssid may be
// recorded, and as what.
func (o *Observer) scopeOf(client, bssid MAC, ssid string) (string, bool) {
	if o.scope.LabBSSID(bssid) || o.labClient(client) || o.scope.LabSSID(ssid) {
		return ScopeLab, true
	}
	if o.scope.Nearby() {
		return ScopeNearby, true
	}
	return "", false
}

func (o *Observer) learn(client MAC, at time.Time) {
	if client.Group() || client.Zero() {
		return
	}
	if _, known := o.learned[client]; !known && len(o.learned) >= maxLearned {
		o.expireLearned(at)
		if len(o.learned) >= maxLearned {
			return
		}
	}
	o.learned[client] = at
}

func (o *Observer) expireLearned(now time.Time) {
	for mac, at := range o.learned {
		if now.Sub(at) >= learnedLifetime {
			delete(o.learned, mac)
		}
	}
}

// retried reports the same frame seen within the retry window.
func (o *Observer) retried(key string, at time.Time) bool {
	if last, ok := o.recent[key]; ok && at.Sub(last) >= 0 && at.Sub(last) < retryWindow {
		return true
	}
	if len(o.recent) >= maxRecentKeys {
		for value, last := range o.recent {
			if at.Sub(last) >= retryWindow {
				delete(o.recent, value)
			}
		}
		if len(o.recent) >= maxRecentKeys {
			return false
		}
	}
	o.recent[key] = at
	return false
}

func signal(radio Radiotap) *int {
	if !radio.HasSignal {
		return nil
	}
	value := radio.SignalDBM
	return &value
}

func intPointer(value int) *int { return &value }

func boolPointer(value bool) *bool { return &value }

func (o *Observer) emit(kind string, at time.Time, payload Payload) {
	o.events = append(o.events, Event{Kind: kind, At: at.UTC(), Payload: payload})
}

func radioChannel(radio Radiotap, frame Management) (int, int) {
	frequency := radio.FrequencyMHz
	channel := ChannelForFrequency(frequency)
	if channel == 0 {
		channel = frame.Channel()
		if channel != 0 && frequency == 0 {
			frequency = FrequencyForChannel(channel)
		}
	}
	return channel, frequency
}

// Observe processes one frame.
func (o *Observer) Observe(input Frame) {
	if input.Radio.BadFCS || input.At.IsZero() {
		return
	}
	frame := input.Frame
	at := input.At.UTC()
	switch frame.Subtype {
	case SubtypeProbeRequest:
		o.observeProbe(at, input.Radio, frame)
	case SubtypeBeacon, SubtypeProbeResponse:
		o.observeNetwork(at, input.Radio, frame)
	case SubtypeAuthentication:
		o.observeAuth(at, input.Radio, frame)
	case SubtypeAssocRequest, SubtypeReassocRequest:
		o.observeAssocRequest(at, input.Radio, frame)
	case SubtypeAssocResponse, SubtypeReassocResponse:
		o.observeAssocResponse(at, input.Radio, frame)
	case SubtypeDeauthentication, SubtypeDisassociation:
		o.observeDisconnect(at, input.Radio, frame)
	}
}

func (o *Observer) noteSequence(client MAC, frame Management, at time.Time) {
	if !o.labClient(client) {
		return
	}
	if _, known := o.sequences[client]; !known && len(o.sequences) >= maxSequences {
		return
	}
	o.sequences[client] = sequenceState{value: frame.Sequence, at: at}
}

func (o *Observer) learnFingerprint(client MAC, fingerprint string) {
	if fingerprint == "" || o.ambiguous[fingerprint] {
		return
	}
	if owner, known := o.fingerprints[fingerprint]; known {
		if owner != client {
			// Two lab devices share it (same model): it identifies neither.
			delete(o.fingerprints, fingerprint)
			if len(o.ambiguous) < maxFingerprints {
				o.ambiguous[fingerprint] = true
			}
		}
		return
	}
	if len(o.fingerprints) < maxFingerprints {
		o.fingerprints[fingerprint] = client
	}
}

// possibleMatch finds the lab device a probe from an unknown randomized
// address probably came from: the same fingerprint as exactly one lab
// device, and a sequence number continuing that device's within seconds.
func (o *Observer) possibleMatch(client MAC, frame Management, fingerprint string, at time.Time) (MAC, bool) {
	if !client.Randomized() || fingerprint == "" {
		return MAC{}, false
	}
	owner, ok := o.fingerprints[fingerprint]
	if !ok || owner == client {
		return MAC{}, false
	}
	last, ok := o.sequences[owner]
	if !ok || at.Sub(last.at) < 0 || at.Sub(last.at) > sequenceWindow {
		return MAC{}, false
	}
	gap := (int(frame.Sequence) - int(last.value) + 4096) % 4096
	if gap == 0 || gap > sequenceGap {
		return MAC{}, false
	}
	return owner, true
}

func (o *Observer) observeProbe(at time.Time, radio Radiotap, frame Management) {
	client := frame.Addr2
	if client.Group() || client.Zero() {
		return
	}
	ssid := frame.SSID()
	if !ssid.Present {
		return
	}
	fingerprint := frame.Fingerprint()
	scope, keep := o.scopeOf(client, frame.Addr3, ssid.Name)
	if !keep && frame.Addr1 != frame.Addr3 {
		scope, keep = o.scopeOf(client, frame.Addr1, ssid.Name)
	}
	possible, matched := MAC{}, false
	if o.labClient(client) {
		o.learnFingerprint(client, fingerprint)
	} else if candidate, ok := o.possibleMatch(client, frame, fingerprint, at); ok {
		possible, matched = candidate, true
		scope, keep = ScopeLab, true
	}
	defer o.noteSequence(client, frame, at)
	if matched {
		// The randomized address continues the lab device's sequence, so
		// track it too for the next frame.
		o.sequences[possible] = sequenceState{value: frame.Sequence, at: at}
	}
	if !keep {
		return
	}
	key := probeKey{client: client, ssid: ssid.Name}
	if last, seen := o.probes[key]; seen && at.Sub(last) >= 0 && at.Sub(last) < probeWindow {
		return
	}
	if _, seen := o.probes[key]; !seen && len(o.probes) >= maxProbeKeys {
		for value, last := range o.probes {
			if at.Sub(last) >= probeWindow {
				delete(o.probes, value)
			}
		}
		if len(o.probes) >= maxProbeKeys {
			return
		}
	}
	o.probes[key] = at
	channel, frequency := radioChannel(radio, frame)
	payload := Payload{
		Scope: scope, ClientMAC: client.String(), Randomized: client.Randomized(),
		SSID: ssid.Name, Wildcard: ssid.Wildcard, Channel: channel, FrequencyMHz: frequency,
		SignalDBM: signal(radio), Direction: DirectionFromClient, Fingerprint: fingerprint,
	}
	if !frame.Addr3.Group() {
		payload.BSSID = frame.Addr3.String()
	}
	if matched {
		payload.PossibleMAC = possible.String()
	}
	o.emit(KindProbe, at, payload)
}

func (o *Observer) observeNetwork(at time.Time, radio Radiotap, frame Management) {
	bssid := frame.Addr3
	if bssid.Group() || bssid.Zero() || !frame.TransmitterIsBSSID() {
		return
	}
	ssid := frame.SSID()
	security := frame.NetworkSecurity()
	if ssid.Present && (!ssid.Hidden || o.networks[bssid].ssid.Name == "") {
		if _, known := o.networks[bssid]; known || len(o.networks) < maxNetworkNames {
			o.networks[bssid] = networkName{ssid: ssid, security: security, at: at}
		}
	}
	if frame.Subtype != SubtypeBeacon {
		return
	}
	scope := ""
	switch {
	case o.scope.LabBSSID(bssid) || o.scope.LabSSID(ssid.Name):
		scope = ScopeLab
	case o.scope.Nearby():
		scope = ScopeNearby
	default:
		return
	}
	channel, frequency := radioChannel(radio, frame)
	state, known := o.beacons[bssid]
	if !known {
		if len(o.beacons) >= maxBeacons {
			return
		}
		state = &beaconState{firstAt: at}
		o.beacons[bssid] = state
	}
	state.ssid, state.security, state.scope = ssid, security, scope
	if channel != 0 {
		state.channel, state.frequency = channel, frequency
	}
	state.count++
	if radio.HasSignal {
		if !state.hasSignal || radio.SignalDBM < state.min {
			state.min = radio.SignalDBM
		}
		if !state.hasSignal || radio.SignalDBM > state.max {
			state.max = radio.SignalDBM
		}
		state.hasSignal = true
	}
	// The first sighting is reported at once, then a summary per window.
	if !state.emitted {
		o.emitBeacon(bssid, state, at)
	}
}

func (o *Observer) emitBeacon(bssid MAC, state *beaconState, at time.Time) {
	payload := Payload{
		Scope: state.scope, BSSID: bssid.String(), SSID: state.ssid.Name, Hidden: state.ssid.Hidden,
		Channel: state.channel, FrequencyMHz: state.frequency, Security: state.security, Count: state.count,
		Direction: DirectionFromAP,
	}
	if state.hasSignal {
		payload.SignalMinDBM, payload.SignalMaxDBM = intPointer(state.min), intPointer(state.max)
		payload.SignalDBM = intPointer(state.max)
	}
	o.emit(KindBeaconSummary, at, payload)
	state.emitted, state.emittedAt = true, at
	state.firstAt, state.count, state.hasSignal = at, 0, false
}

func (o *Observer) clientAndDirection(frame Management) (MAC, MAC, string) {
	bssid := frame.Addr3
	if frame.TransmitterIsBSSID() {
		return frame.Addr1, bssid, DirectionFromAP
	}
	return frame.Addr2, bssid, DirectionFromClient
}

func (o *Observer) networkSSID(bssid MAC) SSID {
	return o.networks[bssid].ssid
}

func (o *Observer) observeAuth(at time.Time, radio Radiotap, frame Management) {
	client, bssid, direction := o.clientAndDirection(frame)
	if client.Group() || client.Zero() || bssid.Group() {
		return
	}
	if direction == DirectionFromClient {
		o.noteSequence(client, frame, at)
	}
	ssid := o.networkSSID(bssid)
	scope, keep := o.scopeOf(client, bssid, ssid.Name)
	if !keep {
		return
	}
	if o.scope.LabBSSID(bssid) {
		o.learn(client, at)
	}
	failed := frame.HasStatus && frame.StatusCode != 0 && direction == DirectionFromAP
	if direction != DirectionFromAP || !(authComplete(frame.AuthAlgorithm, frame.AuthSequence) || failed) {
		return
	}
	if o.retried(KindAuth+client.String()+bssid.String(), at) {
		return
	}
	channel, frequency := radioChannel(radio, frame)
	success := frame.StatusCode == 0
	o.emit(KindAuth, at, Payload{
		Scope: scope, ClientMAC: client.String(), Randomized: client.Randomized(), BSSID: bssid.String(), SSID: ssid.Name,
		Channel: channel, FrequencyMHz: frequency, SignalDBM: signal(radio), Direction: direction,
		Algorithm: AuthAlgorithmName(frame.AuthAlgorithm), StatusCode: intPointer(int(frame.StatusCode)),
		Status: StatusText(frame.StatusCode), Success: boolPointer(success),
	})
}

func (o *Observer) observeAssocRequest(at time.Time, radio Radiotap, frame Management) {
	client, bssid := frame.Addr2, frame.Addr1
	if client.Group() || client.Zero() || bssid.Group() {
		return
	}
	ssid := frame.SSID()
	if !ssid.Present || ssid.Name == "" {
		ssid = o.networkSSID(bssid)
	}
	scope, keep := o.scopeOf(client, bssid, ssid.Name)
	if !keep {
		return
	}
	if o.scope.LabBSSID(bssid) || o.scope.LabSSID(ssid.Name) {
		o.learn(client, at)
	}
	o.learnFingerprint(client, frame.Fingerprint())
	o.noteSequence(client, frame, at)
	key := assocKey{client: client, bssid: bssid}
	if _, known := o.pending[key]; !known && len(o.pending) >= maxPendingAssoc {
		return
	}
	_, frequency := radioChannel(radio, frame)
	o.pending[key] = pendingAssoc{
		at: at, ssid: ssid, reassociation: frame.Subtype == SubtypeReassocRequest, currentAP: frame.CurrentAP,
		frequency: frequency, signal: signal(radio), scope: scope,
	}
}

func (o *Observer) observeAssocResponse(at time.Time, radio Radiotap, frame Management) {
	client, bssid := frame.Addr1, frame.Addr2
	if client.Group() || client.Zero() || bssid.Group() || !frame.TransmitterIsBSSID() {
		return
	}
	key := assocKey{client: client, bssid: bssid}
	request, requested := o.pending[key]
	delete(o.pending, key)
	ssid := request.ssid
	if !requested {
		ssid = o.networkSSID(bssid)
	}
	scope, keep := o.scopeOf(client, bssid, ssid.Name)
	if !keep {
		return
	}
	if o.retried(KindAssoc+client.String()+bssid.String(), at) {
		return
	}
	success := frame.StatusCode == 0
	channel, frequency := radioChannel(radio, frame)
	payload := Payload{
		Scope: scope, ClientMAC: client.String(), Randomized: client.Randomized(), BSSID: bssid.String(), SSID: ssid.Name,
		Channel: channel, FrequencyMHz: frequency, SignalDBM: request.signal, Direction: DirectionFromAP,
		StatusCode: intPointer(int(frame.StatusCode)), Status: StatusText(frame.StatusCode), Success: boolPointer(success),
		Reassociation: frame.Subtype == SubtypeReassocResponse || request.reassociation,
	}
	previous, hadPrevious := o.associated[client]
	switch {
	case request.currentAP != (MAC{}) && request.currentAP != bssid:
		payload.PreviousBSSID = request.currentAP.String()
	case hadPrevious && previous != bssid:
		payload.PreviousBSSID = previous.String()
	}
	if success {
		if _, known := o.associated[client]; known || len(o.associated) < maxLearned {
			o.associated[client] = bssid
		}
		if _, named := o.networks[bssid]; !named && ssid.Name != "" && len(o.networks) < maxNetworkNames {
			o.networks[bssid] = networkName{ssid: ssid, at: at}
		}
	}
	o.emit(KindAssoc, at, payload)
}

func (o *Observer) observeDisconnect(at time.Time, radio Radiotap, frame Management) {
	client, bssid, direction := o.clientAndDirection(frame)
	if bssid.Group() || bssid.Zero() {
		return
	}
	ssid := o.networkSSID(bssid)
	scope, keep := o.scopeOf(client, bssid, ssid.Name)
	if !keep {
		return
	}
	kind := KindDeauth
	if frame.Subtype == SubtypeDisassociation {
		kind = KindDisassoc
	}
	if o.retried(kind+client.String()+bssid.String()+strconv.Itoa(int(frame.ReasonCode)), at) {
		return
	}
	channel, frequency := radioChannel(radio, frame)
	payload := Payload{
		Scope: scope, BSSID: bssid.String(), SSID: ssid.Name, Channel: channel, FrequencyMHz: frequency,
		SignalDBM: signal(radio), Direction: direction, Protected: frame.Protected,
	}
	if !client.Group() {
		payload.ClientMAC, payload.Randomized = client.String(), client.Randomized()
	}
	if frame.HasReason {
		payload.ReasonCode, payload.Reason = intPointer(int(frame.ReasonCode)), ReasonText(frame.ReasonCode)
	}
	if !client.Group() && o.associated[client] == bssid {
		delete(o.associated, client)
	}
	o.emit(kind, at, payload)
}

// Flush reports association requests that got no answer and the access
// points whose summary window ended, as of now.
func (o *Observer) Flush(now time.Time) {
	now = now.UTC()
	for key, request := range o.pending {
		if now.Sub(request.at) < assocResponseWait {
			continue
		}
		delete(o.pending, key)
		o.emit(KindAssoc, request.at, Payload{
			Scope: request.scope, ClientMAC: key.client.String(), Randomized: key.client.Randomized(), BSSID: key.bssid.String(),
			SSID: request.ssid.Name, Channel: ChannelForFrequency(request.frequency), FrequencyMHz: request.frequency,
			SignalDBM: request.signal, Direction: DirectionFromClient, NoResponse: true, Success: boolPointer(false),
			Status: "no response from the access point", Reassociation: request.reassociation,
		})
	}
	for bssid, state := range o.beacons {
		if now.Sub(state.emittedAt) < beaconWindow {
			continue
		}
		if state.count == 0 {
			if now.Sub(state.emittedAt) >= 2*beaconWindow {
				delete(o.beacons, bssid)
			}
			continue
		}
		o.emitBeacon(bssid, state, now)
	}
	for key, at := range o.probes {
		if now.Sub(at) >= probeWindow {
			delete(o.probes, key)
		}
	}
	for mac, state := range o.sequences {
		if now.Sub(state.at) >= sequenceWindow {
			delete(o.sequences, mac)
		}
	}
	for key, at := range o.recent {
		if now.Sub(at) >= retryWindow {
			delete(o.recent, key)
		}
	}
	o.expireLearned(now)
}
