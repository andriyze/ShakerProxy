package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/capture"
	"shakerproxy.dev/shakerproxy/internal/httpexchange"
	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

// A cleartext HTTP exchange that carried a secret (the fixture sends a
// session cookie) is flagged by kind and location in the response, and the
// secret value never appears in the exposures.
func TestHTTPExchangeFlagsCleartextSecrets(t *testing.T) {
	conversation := pcapngtest.NewKeepAliveHTTP(exchangeAt.Add(-30 * time.Millisecond))
	server, session, _, _ := exchangeServer(t, func(request capture.FlowRequest) capture.FlowResult {
		return capture.FlowResult{Schema: 1, SessionID: request.SessionID, Client: request.Client, Server: request.Server, SegmentsRead: 2, PacketsMatched: len(conversation.Packets), ClientData: conversation.Client, ServerData: conversation.Server, FromStart: true, Closed: true}
	})
	response := getExchange(t, server, authenticatedJSONRequest(http.MethodGet, "/api/v1/events/"+exchangeRecordID+"/http-exchange", "", session, ""))
	found := false
	for _, exposure := range response.Exposures {
		if exposure.Kind == httpexchange.ExposureCleartextCookie {
			found = true
		}
		if strings.Contains(exposure.Where, "secret") {
			t.Fatalf("exposure leaked the cookie value: %+v", exposure)
		}
	}
	if !found {
		t.Fatalf("the cleartext cookie was not flagged: %+v", response.Exposures)
	}
}
