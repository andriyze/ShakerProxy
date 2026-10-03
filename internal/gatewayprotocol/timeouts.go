package gatewayprotocol

import "time"

// DefaultMethodTimeout bounds privileged calls that are not listed in
// MethodTimeout. It covers local state reads and small bounded mutations.
const DefaultMethodTimeout = 10 * time.Second

// MaxMethodTimeout is the longest budget any privileged method may use. Clients
// reject larger budgets so a stuck daemon cannot hold a caller indefinitely.
const MaxMethodTimeout = 2 * time.Minute

// MethodTimeout returns the end-to-end budget for one privileged gateway call:
// the time a client waits for the response and the time the daemon keeps the
// connection open for dispatch and response delivery. The daemon adds a short
// grace period on top so it never closes a connection before its client gives
// up.
func MethodTimeout(method string) time.Duration {
	switch method {
	case "ProbeConnectivity", "GetDiagnostics", "InspectHost", "GetServicePortPlan",
		"ValidateNetworkPlan", "PreviewNetworkPlan", "StageNetworkPlan":
		// Host inspection walks interfaces, firewall state, and SSH sessions;
		// the connectivity probe alone has a 7 second internal budget.
		return 20 * time.Second
	case "BeginCaptureImport", "AppendCaptureImport":
		// Appending a chunk is quick; the final chunk validates and finalizes
		// the whole upload (a scan and a copy of up to the import size).
		return MaxMethodTimeout
	case "StartCapture", "StopCapture", "SetLabRecording", "GetCaptureStats", "ListCaptures", "ReadCaptureArtifact", "ReadCaptureFlow",
		"ApplyTrafficPolicy", "RollbackTrafficPolicy", "PreviewTrafficPolicy",
		"SetOperatingMode", "EnableEmergencyBypass", "DisableEmergencyBypass",
		"SetCaptureEvidenceHold", "SetVPN", "AddVPNPeer", "RevokeVPNPeer",
		"SetWiFiMonitor", "GetWiFiMonitor":
		return 30 * time.Second
	case "CommitNetworkPlan", "ConfirmNetworkPlan", "RollbackNetworkPlan", "RevertNetworkPlan", "SignalNetworkHealth",
		"PreviewCaptureDeletion", "PreviewCaptureDeletionUntil", "DeleteCapture",
		"PreviewCaptureRetention", "ApplyCaptureRetentionPolicy", "StartCaptureRetentionRun",
		"RecordCaptureRetentionItemOutcome", "RunCaptureRetentionSchedulerOnce":
		return time.Minute
	case "PreviewPCAPSelection", "RewritePCAP", "DeletePCAPArtifact":
		// Shared-PCAP sanitization reads and rewrites whole capture files.
		return MaxMethodTimeout
	default:
		return DefaultMethodTimeout
	}
}
