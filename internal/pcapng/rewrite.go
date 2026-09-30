package pcapng

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"
)

const SelectionRuleSchema = 2

var ErrInexactSelection = errors.New("PCAPNG packet selection is not exact")

type SelectionIdentityKind string

const (
	SelectionIdentityMAC SelectionIdentityKind = "MAC"
	SelectionIdentityIP  SelectionIdentityKind = "IP"
)

// SelectionIdentity binds one unicast identity to its own optional half-open
// validity window. Per-identity windows prevent a reused IP address from being
// treated as permanent device ownership.
type SelectionIdentity struct {
	Kind    SelectionIdentityKind `json:"kind"`
	Value   string                `json:"value"`
	StartAt *time.Time            `json:"start_at,omitempty"`
	EndAt   *time.Time            `json:"end_at,omitempty"`
}

type SelectionRule struct {
	Schema     int                 `json:"schema"`
	Identities []SelectionIdentity `json:"identities"`
}

func (r SelectionRule) Validate() error {
	if r.Schema != SelectionRuleSchema || len(r.Identities) == 0 || len(r.Identities) > MaxObservedIdentities {
		return errors.New("PCAPNG selection identity population is invalid")
	}
	for index, identity := range r.Identities {
		if err := identity.validate(); err != nil {
			return err
		}
		if index > 0 && compareSelectionIdentity(r.Identities[index-1], identity) >= 0 {
			return errors.New("PCAPNG selection identities are not unique and sorted")
		}
		if index > 0 && sameSelectionValue(r.Identities[index-1], identity) && windowsOverlapOrTouch(r.Identities[index-1], identity) {
			return errors.New("PCAPNG selection contains unmerged identity windows")
		}
	}
	return nil
}

func (r SelectionRule) Overlaps(startAt, endAt time.Time) bool {
	if r.Validate() != nil || startAt.IsZero() || !startAt.Before(endAt) {
		return false
	}
	for _, identity := range r.Identities {
		if identity.StartAt == nil || identity.StartAt.Before(endAt) && startAt.Before(*identity.EndAt) {
			return true
		}
	}
	return false
}

func (r SelectionRule) MayMatch(membership Membership) bool {
	if r.Validate() != nil || membership.Validate() != nil || !membership.Exact() {
		return false
	}
	macs := make(map[string]struct{}, len(membership.MACAddresses))
	for _, value := range membership.MACAddresses {
		macs[value] = struct{}{}
	}
	ips := make(map[string]struct{}, len(membership.IPAddresses))
	for _, value := range membership.IPAddresses {
		ips[value] = struct{}{}
	}
	for _, identity := range r.Identities {
		if identity.Kind == SelectionIdentityMAC {
			if _, exists := macs[identity.Value]; exists {
				return true
			}
		} else if _, exists := ips[identity.Value]; exists {
			return true
		}
	}
	return false
}

// CanonicalSelectionRule returns a sorted, duplicate-free rule suitable for a
// durable deletion preview. Callers must supply both time bounds or neither.
func CanonicalSelectionRule(macs, ips []string, startAt, endAt *time.Time) (SelectionRule, error) {
	identities := make([]SelectionIdentity, 0, len(macs)+len(ips))
	for _, value := range macs {
		identities = append(identities, SelectionIdentity{Kind: SelectionIdentityMAC, Value: value, StartAt: startAt, EndAt: endAt})
	}
	for _, value := range ips {
		identities = append(identities, SelectionIdentity{Kind: SelectionIdentityIP, Value: value, StartAt: startAt, EndAt: endAt})
	}
	return CanonicalWindowedSelectionRule(identities)
}

func CanonicalWindowedSelectionRule(identities []SelectionIdentity) (SelectionRule, error) {
	canonical := make([]SelectionIdentity, len(identities))
	for index, identity := range identities {
		canonical[index] = identity
		if identity.StartAt != nil {
			start := identity.StartAt.UTC().Round(0)
			canonical[index].StartAt = &start
		}
		if identity.EndAt != nil {
			end := identity.EndAt.UTC().Round(0)
			canonical[index].EndAt = &end
		}
		if err := canonical[index].validate(); err != nil {
			return SelectionRule{}, err
		}
	}
	sort.Slice(canonical, func(i, j int) bool { return compareSelectionIdentity(canonical[i], canonical[j]) < 0 })
	canonical = mergeSelectionWindows(canonical)
	rule := SelectionRule{Schema: SelectionRuleSchema, Identities: canonical}
	if err := rule.Validate(); err != nil {
		return SelectionRule{}, err
	}
	return rule, nil
}

type RewriteResult struct {
	Schema           int        `json:"schema"`
	InputBytes       uint64     `json:"input_bytes"`
	OutputBytes      uint64     `json:"output_bytes"`
	PacketsRead      uint64     `json:"packets_read"`
	PacketsWritten   uint64     `json:"packets_written"`
	PacketsRemoved   uint64     `json:"packets_removed"`
	OutputMembership Membership `json:"output_membership"`
}

type rewriteInterface struct {
	linkType            uint16
	timestampResolution byte
	timestampOffset     int64
}

type rewriteSection struct {
	order      binary.ByteOrder
	interfaces []rewriteInterface
}

type compiledSelection struct {
	macs map[string][]SelectionIdentity
	ips  map[string][]SelectionIdentity
}

type countingWriter struct {
	writer io.Writer
	bytes  uint64
}

func (w *countingWriter) Write(value []byte) (int, error) {
	n, err := w.writer.Write(value)
	w.bytes += uint64(n)
	if err == nil && n != len(value) {
		err = io.ErrShortWrite
	}
	return n, err
}

// Rewrite streams one structurally valid PCAPNG and omits exactly matched
// packet blocks. It never mutates the input and does not buffer whole captures.
func Rewrite(reader io.Reader, writer io.Writer, rule SelectionRule) (RewriteResult, error) {
	return RewriteContext(context.Background(), reader, writer, rule)
}

// RewriteContext is Rewrite with cancellation between bounded PCAPNG blocks.
// Cancellation is safe because callers have not yet installed the output.
func RewriteContext(ctx context.Context, reader io.Reader, writer io.Writer, rule SelectionRule) (RewriteResult, error) {
	if ctx == nil {
		return RewriteResult{}, errors.New("PCAPNG rewrite context is unavailable")
	}
	if reader == nil || writer == nil {
		return RewriteResult{}, errors.New("PCAPNG rewrite streams are unavailable")
	}
	if err := rule.Validate(); err != nil {
		return RewriteResult{}, err
	}
	selection := compiledSelection{macs: make(map[string][]SelectionIdentity), ips: make(map[string][]SelectionIdentity)}
	for _, identity := range rule.Identities {
		if identity.Kind == SelectionIdentityMAC {
			selection.macs[identity.Value] = append(selection.macs[identity.Value], identity)
		} else {
			selection.ips[identity.Value] = append(selection.ips[identity.Value], identity)
		}
	}
	output := &countingWriter{writer: writer}
	collector := membershipCollector{membership: Membership{Schema: MembershipSchema, State: MembershipExact}, linkTypes: map[uint16]struct{}{}, macs: map[string]struct{}{}, ips: map[string]struct{}{}}
	result := RewriteResult{Schema: 1}
	var section *rewriteSection
	for {
		if err := ctx.Err(); err != nil {
			return RewriteResult{}, err
		}
		block, blockType, order, err := readBlock(reader, rewriteReadSection(section))
		if errors.Is(err, io.EOF) {
			if section == nil {
				return RewriteResult{}, fmt.Errorf("%w: section header is absent", ErrInvalidPCAPNG)
			}
			break
		}
		if err != nil {
			return RewriteResult{}, err
		}
		result.InputBytes += uint64(len(block))
		if blockType == 0x0a0d0d0a {
			if order.Uint16(block[12:14]) != 1 || order.Uint16(block[14:16]) != 0 {
				return RewriteResult{}, fmt.Errorf("%w: section version is unsupported", ErrInvalidPCAPNG)
			}
			section = &rewriteSection{order: order}
			if _, err := output.Write(block); err != nil {
				return RewriteResult{}, err
			}
			continue
		}
		if section == nil {
			return RewriteResult{}, fmt.Errorf("%w: data precedes the section header", ErrInvalidPCAPNG)
		}
		if blockType == 1 {
			configuration, err := parseRewriteInterface(block, section.order)
			if err != nil || len(section.interfaces) >= maxInterfaces {
				return RewriteResult{}, fmt.Errorf("%w: interface block is invalid", ErrInvalidPCAPNG)
			}
			section.interfaces = append(section.interfaces, configuration)
			if _, err := output.Write(block); err != nil {
				return RewriteResult{}, err
			}
			continue
		}
		packet, configuration, timestamp, packetBlock, err := rewritePacket(block, blockType, section)
		if err != nil {
			return RewriteResult{}, err
		}
		if !packetBlock {
			if _, err := output.Write(block); err != nil {
				return RewriteResult{}, err
			}
			continue
		}
		result.PacketsRead++
		identities, limitation := packetIdentities(configuration.linkType, packet)
		if limitation != "" {
			return RewriteResult{}, fmt.Errorf("%w: %s", ErrInexactSelection, limitation)
		}
		matched, err := selection.matches(identities, configuration, timestamp)
		if err != nil {
			return RewriteResult{}, err
		}
		if matched {
			result.PacketsRemoved++
			continue
		}
		if _, err := output.Write(block); err != nil {
			return RewriteResult{}, err
		}
		result.PacketsWritten++
		collector.observe(packetObservation{linkType: configuration.linkType, data: packet})
	}
	collector.finish()
	if !collector.membership.Exact() || collector.membership.PacketCount != result.PacketsWritten {
		return RewriteResult{}, errors.New("rewritten PCAPNG membership is inconsistent")
	}
	result.OutputBytes = output.bytes
	result.OutputMembership = collector.membership
	return result, nil
}

func rewriteReadSection(section *rewriteSection) *sectionState {
	if section == nil {
		return nil
	}
	return &sectionState{order: section.order}
}

func parseRewriteInterface(block []byte, order binary.ByteOrder) (rewriteInterface, error) {
	if len(block) < 20 {
		return rewriteInterface{}, errors.New("truncated interface block")
	}
	configuration := rewriteInterface{linkType: order.Uint16(block[8:10]), timestampResolution: 6}
	options := block[16 : len(block)-4]
	seenResolution := false
	seenOffset := false
	for len(options) > 0 {
		if len(options) < 4 {
			return rewriteInterface{}, errors.New("truncated interface option")
		}
		code := order.Uint16(options[0:2])
		length := int(order.Uint16(options[2:4]))
		padded := (length + 3) &^ 3
		if len(options) < 4+padded {
			return rewriteInterface{}, errors.New("truncated interface option value")
		}
		value := options[4 : 4+length]
		options = options[4+padded:]
		switch code {
		case 0:
			if length != 0 || len(options) != 0 {
				return rewriteInterface{}, errors.New("invalid end-of-options marker")
			}
		case 9:
			if seenResolution || length != 1 {
				return rewriteInterface{}, errors.New("invalid timestamp-resolution option")
			}
			configuration.timestampResolution = value[0]
			seenResolution = true
		case 14:
			if seenOffset || length != 8 {
				return rewriteInterface{}, errors.New("invalid timestamp-offset option")
			}
			configuration.timestampOffset = int64(order.Uint64(value))
			seenOffset = true
		}
		if code == 0 {
			break
		}
	}
	return configuration, nil
}

func rewritePacket(block []byte, blockType uint32, section *rewriteSection) ([]byte, rewriteInterface, *uint64, bool, error) {
	var interfaceID uint32
	var captured, original uint32
	var offset int
	var timestamp *uint64
	switch blockType {
	case 2:
		if len(block) < 32 {
			return nil, rewriteInterface{}, nil, true, fmt.Errorf("%w: packet block is truncated", ErrInvalidPCAPNG)
		}
		interfaceID = uint32(section.order.Uint16(block[8:10]))
		value := uint64(section.order.Uint32(block[12:16]))<<32 | uint64(section.order.Uint32(block[16:20]))
		timestamp = &value
		captured, original, offset = section.order.Uint32(block[20:24]), section.order.Uint32(block[24:28]), 28
	case 3:
		if len(block) < 16 || len(section.interfaces) == 0 {
			return nil, rewriteInterface{}, nil, true, fmt.Errorf("%w: simple packet block is invalid", ErrInvalidPCAPNG)
		}
		original = section.order.Uint32(block[8:12])
		available := uint32(len(block) - 16)
		captured = original
		if captured > available {
			captured = available
		}
		if captured > maxCapturedPacket {
			return nil, rewriteInterface{}, nil, true, fmt.Errorf("%w: simple packet exceeds its bound", ErrInvalidPCAPNG)
		}
		return block[12 : 12+captured], section.interfaces[0], nil, true, nil
	case 6:
		if len(block) < 32 {
			return nil, rewriteInterface{}, nil, true, fmt.Errorf("%w: enhanced packet block is truncated", ErrInvalidPCAPNG)
		}
		interfaceID = section.order.Uint32(block[8:12])
		value := uint64(section.order.Uint32(block[12:16]))<<32 | uint64(section.order.Uint32(block[16:20]))
		timestamp = &value
		captured, original, offset = section.order.Uint32(block[20:24]), section.order.Uint32(block[24:28]), 28
	default:
		return nil, rewriteInterface{}, nil, false, nil
	}
	packet, err := packetData(block, offset, captured)
	if err != nil || captured > original || interfaceID >= uint32(len(section.interfaces)) {
		return nil, rewriteInterface{}, nil, true, fmt.Errorf("%w: packet block is invalid", ErrInvalidPCAPNG)
	}
	return packet, section.interfaces[interfaceID], timestamp, true, nil
}

func (s compiledSelection) matches(observed identities, configuration rewriteInterface, timestamp *uint64) (bool, error) {
	var candidates []SelectionIdentity
	for _, value := range observed.macs {
		candidates = append(candidates, s.macs[value]...)
	}
	for _, value := range observed.ips {
		candidates = append(candidates, s.ips[value]...)
	}
	if len(candidates) == 0 {
		return false, nil
	}
	for _, candidate := range candidates {
		if candidate.StartAt == nil {
			return true, nil
		}
	}
	if timestamp == nil {
		return false, fmt.Errorf("%w: matched packet has no timestamp", ErrInexactSelection)
	}
	observedAt, err := configuration.observedAt(*timestamp)
	if err != nil {
		return false, err
	}
	for _, candidate := range candidates {
		if !observedAt.Before(*candidate.StartAt) && observedAt.Before(*candidate.EndAt) {
			return true, nil
		}
	}
	return false, nil
}

func (configuration rewriteInterface) observedAt(timestamp uint64) (time.Time, error) {
	resolution := configuration.timestampResolution
	var denominator uint64 = 1
	exponent := resolution & 0x7f
	if resolution&0x80 != 0 {
		if exponent > 29 {
			return time.Time{}, fmt.Errorf("%w: binary timestamp resolution is finer than supported", ErrInexactSelection)
		}
		denominator = uint64(1) << exponent
	} else {
		if exponent > 9 {
			return time.Time{}, fmt.Errorf("%w: decimal timestamp resolution is finer than supported", ErrInexactSelection)
		}
		for index := byte(0); index < exponent; index++ {
			denominator *= 10
		}
	}
	seconds := timestamp / denominator
	if seconds > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("%w: packet timestamp is out of range", ErrInexactSelection)
	}
	wholeSeconds := int64(seconds)
	if configuration.timestampOffset > 0 && wholeSeconds > math.MaxInt64-configuration.timestampOffset || configuration.timestampOffset < 0 && wholeSeconds < math.MinInt64-configuration.timestampOffset {
		return time.Time{}, fmt.Errorf("%w: packet timestamp offset overflows", ErrInexactSelection)
	}
	nanoseconds := int64((timestamp % denominator) * 1_000_000_000 / denominator)
	return time.Unix(wholeSeconds+configuration.timestampOffset, nanoseconds).UTC(), nil
}

func (identity SelectionIdentity) validate() error {
	switch identity.Kind {
	case SelectionIdentityMAC:
		if canonicalMAC(identity.Value) != identity.Value {
			return errors.New("PCAPNG selection contains a non-canonical MAC address")
		}
	case SelectionIdentityIP:
		if !validObservableIPString(identity.Value) {
			return errors.New("PCAPNG selection contains a non-canonical IP address")
		}
	default:
		return errors.New("PCAPNG selection identity kind is invalid")
	}
	if (identity.StartAt == nil) != (identity.EndAt == nil) {
		return errors.New("PCAPNG selection identity time bounds must be supplied together")
	}
	if identity.StartAt != nil && (identity.StartAt.Location() != time.UTC || identity.EndAt.Location() != time.UTC || !identity.StartAt.Before(*identity.EndAt)) {
		return errors.New("PCAPNG selection identity time range is invalid or non-canonical")
	}
	return nil
}

func compareSelectionIdentity(left, right SelectionIdentity) int {
	if left.Kind < right.Kind {
		return -1
	}
	if left.Kind > right.Kind {
		return 1
	}
	if left.Value < right.Value {
		return -1
	}
	if left.Value > right.Value {
		return 1
	}
	if left.StartAt == nil && right.StartAt != nil {
		return -1
	}
	if left.StartAt != nil && right.StartAt == nil {
		return 1
	}
	if left.StartAt != nil {
		if left.StartAt.Before(*right.StartAt) {
			return -1
		}
		if left.StartAt.After(*right.StartAt) {
			return 1
		}
		if left.EndAt.Before(*right.EndAt) {
			return -1
		}
		if left.EndAt.After(*right.EndAt) {
			return 1
		}
	}
	return 0
}

func sameSelectionValue(left, right SelectionIdentity) bool {
	return left.Kind == right.Kind && left.Value == right.Value
}

func windowsOverlapOrTouch(left, right SelectionIdentity) bool {
	return left.StartAt == nil || right.StartAt == nil || !right.StartAt.After(*left.EndAt)
}

func mergeSelectionWindows(identities []SelectionIdentity) []SelectionIdentity {
	result := make([]SelectionIdentity, 0, len(identities))
	for _, identity := range identities {
		if len(result) == 0 || !sameSelectionValue(result[len(result)-1], identity) || !windowsOverlapOrTouch(result[len(result)-1], identity) {
			result = append(result, identity)
			continue
		}
		previous := &result[len(result)-1]
		if previous.StartAt == nil {
			continue
		}
		if identity.StartAt == nil {
			*previous = identity
			continue
		}
		if identity.EndAt.After(*previous.EndAt) {
			end := *identity.EndAt
			previous.EndAt = &end
		}
	}
	return result
}
