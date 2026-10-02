package daemon

import (
	"strings"
	"testing"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/gatewayprotocol"
)

// A coverage capture records only the virtual test lab's client bridge, and
// only while the coverage check has built it.
func TestCoverageCaptureRecordsOnlyTheTestLabBridge(t *testing.T) {
	host := gatewayprotocol.HostInspection{Interfaces: []gatewayprotocol.Interface{
		{Name: "ens18", StableID: "pci-0000:00:12.0", OperState: "up"},
		{Name: "lgtest-client", StableID: "mac-02:00:00:00:00:01", OperState: "up"},
	}}
	source, err := coverageSourceFrom(host)
	if err != nil || source.InterfaceName != "lgtest-client" || source.SingleArmGateway != "" || source.SingleArmLabCIDR != "" {
		t.Fatalf("source = %+v err=%v", source, err)
	}
	if err := source.Validate(); err != nil {
		t.Fatalf("coverage source is invalid: %v", err)
	}
	if _, err := coverageSourceFrom(gatewayprotocol.HostInspection{Interfaces: host.Interfaces[:1]}); err == nil || !strings.Contains(err.Error(), "not prepared") {
		t.Fatalf("missing bridge: err=%v", err)
	}
	request := capture.StartRequest{Name: "Visibility coverage", Mode: capture.ModeFull, SegmentSeconds: 10, MaxFiles: 4, StopAfterSeconds: 120,
		IdempotencyKey: "coverage-0123456789abcdef", Administrator: "admin", CoverageLab: true, Automatic: true}
	if err := request.Validate(); err == nil {
		t.Fatal("the automatic recording must never record the coverage lab")
	}
	request.Automatic = false
	if err := request.Validate(); err != nil {
		t.Fatalf("coverage capture request rejected: %v", err)
	}
}
