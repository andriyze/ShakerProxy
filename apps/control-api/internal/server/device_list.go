package server

import (
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	deviceinventory "shakerproxy.dev/shakerproxy/internal/inventory"
)

type deviceListQuery struct {
	View              string
	Search            string
	Interface         string
	VLANID            *int
	Vendor            string
	Category          string
	Tag               string
	IPFamily          string
	MinimumConfidence *int
	Warnings          string
	Sort              string
	Direction         string
}

var deviceListInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$`)
var deviceListCategoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func parseDeviceListQuery(values url.Values) (deviceListQuery, error) {
	allowed := map[string]bool{"view": true, "q": true, "interface": true, "vlan_id": true, "vendor": true, "category": true, "tag": true, "ip_family": true, "min_confidence": true, "warnings": true, "sort": true, "direction": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return deviceListQuery{}, errors.New("device query contains an unsupported or repeated parameter")
		}
	}
	// Tags are stored lower-case, so tag (and category) filters are normalized
	// instead of rejecting "?tag=Camera".
	query := deviceListQuery{View: values.Get("view"), Search: strings.TrimSpace(values.Get("q")), Interface: values.Get("interface"), Vendor: strings.TrimSpace(values.Get("vendor")), Category: strings.ToLower(strings.TrimSpace(values.Get("category"))), Tag: strings.ToLower(strings.TrimSpace(values.Get("tag"))), IPFamily: values.Get("ip_family"), Warnings: values.Get("warnings"), Sort: values.Get("sort"), Direction: values.Get("direction")}
	if query.View == "" {
		query.View = "all"
	}
	if query.Sort == "" {
		query.Sort = "last_seen"
	}
	if query.Direction == "" {
		query.Direction = "desc"
	}
	if query.View != "all" && query.View != "online" && query.View != "recent" || query.Sort != "name" && query.Sort != "last_seen" && query.Sort != "first_seen" && query.Sort != "confidence" || query.Direction != "asc" && query.Direction != "desc" {
		return deviceListQuery{}, errors.New("device view, sort, or direction is invalid")
	}
	if query.IPFamily != "" && query.IPFamily != "ipv4" && query.IPFamily != "ipv6" || query.Warnings != "" && query.Warnings != "present" && query.Warnings != "none" {
		return deviceListQuery{}, errors.New("device IP family or warning filter is invalid")
	}
	if !validDeviceListText(query.Search, 128) || !validDeviceListText(query.Vendor, 256) {
		return deviceListQuery{}, errors.New("device search or vendor filter is invalid")
	}
	if query.Interface != "" && !deviceListInterfacePattern.MatchString(query.Interface) || query.Category != "" && !deviceListCategoryPattern.MatchString(query.Category) || query.Tag != "" && (!validDeviceListText(query.Tag, 64) || query.Tag != strings.ToLower(strings.TrimSpace(query.Tag))) {
		return deviceListQuery{}, errors.New("device interface, category, or tag filter is invalid")
	}
	if raw := values.Get("vlan_id"); raw != "" {
		vlanID, err := strconv.Atoi(raw)
		if err != nil || vlanID < 1 || vlanID > 4094 {
			return deviceListQuery{}, errors.New("device VLAN filter is invalid")
		}
		query.VLANID = &vlanID
	}
	if raw := values.Get("min_confidence"); raw != "" {
		minimum, err := strconv.Atoi(raw)
		if err != nil || minimum < 0 || minimum > 100 {
			return deviceListQuery{}, errors.New("device confidence filter is invalid")
		}
		query.MinimumConfidence = &minimum
	}
	return query, nil
}

func validDeviceListText(value string, maximum int) bool {
	if len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func filterAndSortDevices(devices []deviceinventory.Device, query deviceListQuery, generatedAt time.Time) []deviceinventory.Device {
	filtered := make([]deviceinventory.Device, 0, len(devices))
	recentSince := generatedAt.Add(-24 * time.Hour)
	for _, device := range devices {
		if query.View == "online" && !device.Online || query.View == "recent" && device.LastSeen.Before(recentSince) || query.Search != "" && !deviceMatchesSearch(device, query.Search) || query.Interface != "" && !deviceHasInterface(device, query.Interface) || query.VLANID != nil && !deviceHasVLAN(device, *query.VLANID) || query.Vendor != "" && !deviceMatchesVendor(device, query.Vendor) || query.Category != "" && device.Category != query.Category || query.Tag != "" && !containsExact(device.Tags, query.Tag) || query.IPFamily != "" && !deviceHasIPFamily(device, query.IPFamily) || query.MinimumConfidence != nil && device.AttributionConfidence < *query.MinimumConfidence || query.Warnings == "present" && len(device.AttributionWarnings) == 0 || query.Warnings == "none" && len(device.AttributionWarnings) != 0 {
			continue
		}
		filtered = append(filtered, device)
	}
	sort.Slice(filtered, func(left, right int) bool {
		comparison := compareDevices(filtered[left], filtered[right], query.Sort)
		if query.Direction == "desc" {
			comparison = -comparison
		}
		return comparison < 0
	})
	return filtered
}

func deviceHasIPFamily(device deviceinventory.Device, family string) bool {
	wanted := map[string]string{"ipv4": "IPv4", "ipv6": "IPv6"}[family]
	for _, address := range device.Addresses {
		if address.Family == wanted {
			return true
		}
	}
	return false
}

func compareDevices(left, right deviceinventory.Device, field string) int {
	var comparison int
	switch field {
	case "name":
		comparison = strings.Compare(strings.ToLower(deviceDisplayName(left)), strings.ToLower(deviceDisplayName(right)))
	case "first_seen":
		comparison = left.FirstSeen.Compare(right.FirstSeen)
	case "confidence":
		comparison = left.AttributionConfidence - right.AttributionConfidence
	default:
		comparison = left.LastSeen.Compare(right.LastSeen)
	}
	if comparison == 0 {
		comparison = strings.Compare(left.ID, right.ID)
	}
	return comparison
}

func deviceDisplayName(device deviceinventory.Device) string {
	if device.FriendlyName != "" {
		return device.FriendlyName
	}
	if len(device.SuggestedNames) > 0 {
		return device.SuggestedNames[0].Name
	}
	if len(device.Hostnames) > 0 {
		return device.Hostnames[len(device.Hostnames)-1].Hostname
	}
	return device.ID
}

func deviceMatchesSearch(device deviceinventory.Device, search string) bool {
	needle := strings.ToLower(search)
	values := []string{device.ID, device.FriendlyName, device.Owner, device.Location, device.Category, device.Notes, string(device.VendorState)}
	if device.Vendor != nil {
		values = append(values, device.Vendor.Name, device.Vendor.Assignment)
	}
	for _, item := range device.AliasHistory {
		values = append(values, item.FriendlyName, item.PreviousFriendlyName)
	}
	for _, item := range device.SuggestedNames {
		values = append(values, item.Name)
	}
	for _, item := range device.Identities {
		values = append(values, item.Value)
	}
	for _, item := range device.Addresses {
		values = append(values, item.Address, item.Interface)
	}
	for _, item := range device.Hostnames {
		values = append(values, item.Hostname)
	}
	values = append(values, device.Tags...)
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func deviceHasInterface(device deviceinventory.Device, interfaceName string) bool {
	for _, address := range device.Addresses {
		if address.Interface == interfaceName {
			return true
		}
	}
	return false
}

func deviceHasVLAN(device deviceinventory.Device, vlanID int) bool {
	for _, address := range device.Addresses {
		if address.VLANID != nil && *address.VLANID == vlanID {
			return true
		}
	}
	return false
}

func deviceMatchesVendor(device deviceinventory.Device, vendor string) bool {
	if strings.EqualFold(string(device.VendorState), vendor) {
		return true
	}
	return device.Vendor != nil && strings.EqualFold(device.Vendor.Name, vendor)
}

func containsExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
