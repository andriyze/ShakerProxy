package cloudconnector

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

const defaultPublicPKIRoot = "/var/lib/shakerproxy/public"

// MarshalJSON enriches sensor heartbeats with public interception-CA metadata.
// The private interception key is service-private and is never read by the
// connector. A missing public CA is not a heartbeat failure: the sensor may be
// enrolled before interception PKI has been provisioned.
func (heartbeat Heartbeat) MarshalJSON() ([]byte, error) {
	type heartbeatAlias Heartbeat
	copyHeartbeat := heartbeatAlias(heartbeat)
	copyHeartbeat.Payload = cloneHeartbeatPayload(heartbeat.Payload)

	publicRoot := strings.TrimSpace(os.Getenv("SHAKERPROXY_PUBLIC_ROOT"))
	if publicRoot == "" {
		publicRoot = defaultPublicPKIRoot
	}
	publicCA, err := LoadPublicInterceptionCA(publicRoot)
	switch {
	case err == nil:
		copyHeartbeat.Payload["interception_ca"] = map[string]any{
			"available":          true,
			"certificate_pem":    publicCA.CertificatePEM,
			"sha256_fingerprint": publicCA.SHA256Fingerprint,
			"not_after":          publicCA.NotAfter,
			"private_key_export": false,
		}
	case errors.Is(err, os.ErrNotExist):
		copyHeartbeat.Payload["interception_ca"] = map[string]any{
			"available":          false,
			"private_key_export": false,
		}
	default:
		// Corrupt public metadata must be visible to Fleet without leaking local
		// filesystem details or preventing ordinary connector health reporting.
		copyHeartbeat.Payload["interception_ca"] = map[string]any{
			"available":          false,
			"invalid":            true,
			"private_key_export": false,
		}
	}
	return json.Marshal(copyHeartbeat)
}

func cloneHeartbeatPayload(source map[string]any) map[string]any {
	result := make(map[string]any, len(source)+1)
	for key, value := range source {
		if key == "interception_ca" {
			continue
		}
		result[key] = value
	}
	return result
}
