package capture

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildDumpcapArgumentsUsesOnlyDerivedBoundedValues(t *testing.T) {
	root := t.TempDir()
	session := validSession(t, root)
	directory := filepath.Join(root, session.ID, "artifacts")
	arguments, err := BuildDumpcapArguments(session, directory, session.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"-i", "lab0", "-s", "256", "-B", "8", "-n", "--temp-dir", directory, "-w", filepath.Join(directory, "capture.pcapng"), "-b", "filesize:8192", "-b", "duration:30", "-b", "files:64", "-a", "duration:3600"}
	if !reflect.DeepEqual(arguments, expected) {
		t.Fatalf("unexpected arguments:\nwant %#v\n got %#v", expected, arguments)
	}
}

func TestBuildDumpcapArgumentsRejectsElapsedSession(t *testing.T) {
	session := validSession(t, t.TempDir())
	if _, err := BuildDumpcapArguments(session, filepath.Join("/tmp", session.ID, "artifacts"), session.StopAt.Add(time.Second)); err == nil {
		t.Fatal("elapsed capture unexpectedly accepted")
	}
}

func TestOutputTrackerReportsPacketsAndDrops(t *testing.T) {
	tracker := &captureOutputTracker{status: WorkerStatus{Schema: SchemaVersion}}
	tracker.observe("Packets: 41")
	tracker.observe("Packets received/dropped on interface 'lab0': 44/5 (pcap:2/dumpcap:1/flushed:1/ps_ifdrop:3) (89.8%)")
	status := tracker.snapshot()
	if status.PacketsCaptured != 41 || status.PacketsReceived != 44 || status.KernelDrops != 5 || status.DumpcapDrops != 2 {
		t.Fatalf("unexpected status: %#v", status)
	}
}

// An inline bridge with ShakerProxy's access point records both device-side
// ports into one ring; each interface gets the same snapshot length and
// buffer, and dumpcap's per-interface drop lines are summed.
func TestBridgeRecordingAddsTheAccessPoint(t *testing.T) {
	root := t.TempDir()
	session := validSession(t, root)
	session.Source.AccessPointName, session.Source.AccessPointStableID = "wlan0", "usb-wlan0"
	directory := filepath.Join(root, session.ID, "artifacts")
	arguments, err := BuildDumpcapArguments(session, directory, session.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"-i", "lab0", "-s", "256", "-B", "8", "-i", "wlan0", "-s", "256", "-B", "8", "-n", "--temp-dir", directory, "-w", filepath.Join(directory, "capture.pcapng"), "-b", "filesize:8192", "-b", "duration:30", "-b", "files:64", "-a", "duration:3600"}
	if !reflect.DeepEqual(arguments, expected) {
		t.Fatalf("unexpected arguments:\nwant %#v\n got %#v", expected, arguments)
	}
	for name, source := range map[string]Source{
		"same interface":    {InterfaceName: "lab0", InterfaceStableID: "pci-lab0", AccessPointName: "lab0", AccessPointStableID: "usb-wlan0"},
		"same identity":     {InterfaceName: "lab0", InterfaceStableID: "pci-lab0", AccessPointName: "wlan0", AccessPointStableID: "pci-lab0"},
		"name only":         {InterfaceName: "lab0", InterfaceStableID: "pci-lab0", AccessPointName: "wlan0"},
		"unsafe name":       {InterfaceName: "lab0", InterfaceStableID: "pci-lab0", AccessPointName: "wlan0 -w /etc", AccessPointStableID: "usb-wlan0"},
		"single-arm filter": {InterfaceName: "lab0", InterfaceStableID: "pci-lab0", SingleArmGateway: "192.0.2.1", SingleArmLabCIDR: "192.0.2.0/24", AccessPointName: "wlan0", AccessPointStableID: "usb-wlan0"},
	} {
		if err := source.Validate(); err == nil {
			t.Fatalf("%s: accepted %+v", name, source)
		}
	}

	tracker := &captureOutputTracker{status: WorkerStatus{Schema: SchemaVersion}}
	tracker.observe("Packets received/dropped on interface 'lab0': 44/5 (pcap:2/dumpcap:1/flushed:1/ps_ifdrop:3) (89.8%)")
	tracker.observe("Packets received/dropped on interface 'wlan0': 10/2 (pcap:1/dumpcap:1/flushed:0/ps_ifdrop:0) (83.3%)")
	tracker.observe("Packets received/dropped on interface 'lab0': 50/5 (pcap:2/dumpcap:1/flushed:1/ps_ifdrop:3) (90.9%)")
	if status := tracker.snapshot(); status.PacketsReceived != 60 || status.KernelDrops != 6 || status.DumpcapDrops != 3 {
		t.Fatalf("per-interface counters were not summed: %#v", status)
	}
}

func TestOutputTrackerPublishesOnlyPreviousDumpcapFile(t *testing.T) {
	tracker := &captureOutputTracker{status: WorkerStatus{Schema: SchemaVersion}}
	tracker.observe("File: /var/lib/shakerproxy/pcap/capture_00001_20260901120000.pcapng")
	if closed := tracker.drainClosedFiles(); len(closed) != 0 {
		t.Fatalf("live dumpcap file was published as closed: %#v", closed)
	}
	tracker.observe("File: /var/lib/shakerproxy/pcap/capture_00002_20260901120100.pcapng")
	closed := tracker.drainClosedFiles()
	if !reflect.DeepEqual(closed, []string{"capture_00001_20260901120000.pcapng"}) {
		t.Fatalf("rotation did not publish exactly the previous file: %#v", closed)
	}
	tracker.observe("File: ../../session.json")
	tracker.observe("File: /var/lib/shakerproxy/pcap/not-a-capture.txt")
	if closed := tracker.drainClosedFiles(); len(closed) != 0 {
		t.Fatalf("unsafe dumpcap output changed the closed-file feed: %#v", closed)
	}
}

// Live analysis needs read access to each segment as soon as dumpcap starts
// it, including rotations dumpcap 4.6 reports on its packet counter line.
func TestOutputTrackerSharesEachSegmentDumpcapStarts(t *testing.T) {
	var shared []string
	tracker := &captureOutputTracker{status: WorkerStatus{Schema: SchemaVersion}, shareStarted: func(name string) { shared = append(shared, name) }}
	tracker.consume(strings.NewReader(strings.Join([]string{
		"Capturing on 'ens18'",
		"File: /var/lib/shakerproxy/pcap/capture-x/artifacts/capture_00001_20261001092146.pcapng",
		"Packets: 12",
		"Packets: 14 File: /var/lib/shakerproxy/pcap/capture-x/artifacts/capture_00002_20261001092217.pcapng",
		"Packets: 18",
		"File: ../../session.json",
	}, "\n")))
	if want := []string{"capture_00001_20261001092146.pcapng", "capture_00002_20261001092217.pcapng"}; !reflect.DeepEqual(shared, want) {
		t.Fatalf("shared %#v, want %#v", shared, want)
	}
}

// dumpcap 4.6 (Ubuntu 26.04) reports a rotation on the packet counter line
// rather than on its own line; missing it left every running capture's
// segments unpublished, so analyzers never produced traffic events.
func TestOutputTrackerDetectsDumpcap46RotationsOnTheCounterLine(t *testing.T) {
	tracker := &captureOutputTracker{status: WorkerStatus{Schema: SchemaVersion}}
	for _, line := range []string{
		"Capturing on 'ens18'",
		"File: /var/lib/shakerproxy/pcap/capture-x/artifacts/capture_00001_20261001092146.pcapng",
		"Packets: 12",
		"Packets: 14 File: /var/lib/shakerproxy/pcap/capture-x/artifacts/capture_00002_20261001092217.pcapng",
		"Packets: 18",
	} {
		tracker.observe(line)
	}
	if closed := tracker.drainClosedFiles(); !reflect.DeepEqual(closed, []string{"capture_00001_20261001092146.pcapng"}) {
		t.Fatalf("dumpcap 4.6 rotation was not detected: %#v", closed)
	}
	if got := tracker.snapshot().PacketsCaptured; got != 18 {
		t.Fatalf("packet counter = %d, want 18", got)
	}
}

// Regression from a single-arm home lab: the shared LAN carried the router's
// mDNS on four subnets and other hosts' traffic, outnumbering the phone under
// test about ten to one.
func TestSingleArmCaptureRecordsOnlyTrafficThroughShakerProxy(t *testing.T) {
	session := validSession(t, t.TempDir())
	session.Source.SingleArmGateway, session.Source.SingleArmLabCIDR = "192.168.10.177", "192.168.10.0/24"
	directory := filepath.Join(t.TempDir(), session.ID, "artifacts")
	previous := interfaceHardwareAddress
	interfaceHardwareAddress = func(string) (string, error) { return "bc:24:11:43:c2:5e", nil }
	t.Cleanup(func() { interfaceHardwareAddress = previous })
	arguments, err := BuildDumpcapArguments(session, directory, session.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	want := "(ether host bc:24:11:43:c2:5e and not (ether src bc:24:11:43:c2:5e and ether multicast) and (not host 192.168.10.177 or (dst host 192.168.10.177 and dst port 53) or (src host 192.168.10.177 and src port 53))) or (ether multicast and not ether src bc:24:11:43:c2:5e)"
	if !strings.Contains(strings.Join(arguments, "\x00"), "-f\x00"+want) {
		t.Fatalf("single-arm capture filter = %q, want %q", arguments, want)
	}
}

// Regression from a single-arm EC2 lab: the one interface also carried
// ShakerProxy's NATed copy of each flow, so every connection was recorded
// twice and ShakerProxy itself looked like a device.
func TestSingleArmCaptureExcludesShakerProxyUpstreamTraffic(t *testing.T) {
	session := validSession(t, t.TempDir())
	session.Source.SingleArmGateway, session.Source.SingleArmLabCIDR = "172.31.47.80", "172.31.32.0/20"
	directory := filepath.Join(t.TempDir(), session.ID, "artifacts")
	// Without the interface's MAC address the earlier directional scope applies.
	previous := interfaceHardwareAddress
	interfaceHardwareAddress = func(string) (string, error) { return "", errors.New("no address") }
	t.Cleanup(func() { interfaceHardwareAddress = previous })
	arguments, err := BuildDumpcapArguments(session, directory, session.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(arguments, "\x00")
	if !strings.Contains(joined, "-f\x00not ((src host 172.31.47.80 and not dst net 172.31.32.0/20) or (dst host 172.31.47.80 and not src net 172.31.32.0/20))") {
		t.Fatalf("single-arm capture has no upstream exclusion: %q", arguments)
	}
	for _, invalid := range [][2]string{{"172.31.47.80; rm", "172.31.32.0/20"}, {"10.0.0.1", "172.31.32.0/20"}, {"172.31.47.80", "172.31.47.0/20"}, {"fd00::1", "fd00::/64"}, {"172.31.47.80", ""}} {
		session.Source.SingleArmGateway, session.Source.SingleArmLabCIDR = invalid[0], invalid[1]
		if _, err := BuildDumpcapArguments(session, directory, session.StartedAt); err == nil {
			t.Fatalf("invalid single-arm scope %q was accepted", invalid)
		}
	}
	session.Source.SingleArmGateway, session.Source.SingleArmLabCIDR = "", ""
	arguments, _ = BuildDumpcapArguments(session, directory, session.StartedAt)
	if strings.Contains(strings.Join(arguments, " "), " -f ") {
		t.Fatalf("a two-NIC lab must not get a capture filter: %q", arguments)
	}
}
