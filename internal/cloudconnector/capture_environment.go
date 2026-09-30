package cloudconnector

import (
	"os"
	"strings"
)

func ConnectorCapabilities() []string {
	capabilities := []string{DiagnosticsCapability, DeviceNamingCapability}
	if LocalCaptureControlConfigured() {
		capabilities = append(capabilities, CaptureControlCapability)
	}
	return capabilities
}

func LocalCaptureControlConfigured() bool {
	control := LocalCaptureControlFromEnvironment()
	if _, err := normalizeLocalControlURL(control.BaseURL); err != nil {
		return false
	}
	if _, err := readLocalControlToken(control.TokenFile); err != nil {
		return false
	}
	if _, err := control.secureHTTPClient(); err != nil {
		return false
	}
	return true
}

func LocalCaptureControlFromEnvironment() LocalCaptureControl {
	return LocalCaptureControl{
		BaseURL:   strings.TrimSpace(os.Getenv("SHAKERPROXY_LOCAL_CONTROL_URL")),
		TokenFile: environmentValueOr("SHAKERPROXY_LOCAL_CONTROL_TOKEN_FILE", DefaultLocalControlToken),
		CAFile:    environmentValueOr("SHAKERPROXY_LOCAL_CONTROL_CA_FILE", DefaultLocalControlCA),
		StartPath: strings.TrimSpace(os.Getenv("SHAKERPROXY_LOCAL_CAPTURE_START_PATH")),
		StopPath:  strings.TrimSpace(os.Getenv("SHAKERPROXY_LOCAL_CAPTURE_STOP_PATH")),
	}
}

func environmentValueOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
