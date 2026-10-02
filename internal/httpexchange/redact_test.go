package httpexchange

import (
	"strings"
	"testing"
)

func TestRedactExchangesRemovesCredentialsForTokenReaders(t *testing.T) {
	exchanges := []Exchange{{
		Request: &Request{
			Method: "POST", Target: "/login?user=tv&access_token=abc123&lang=en", Proto: "HTTP/1.1",
			Headers: Headers{Items: []Header{
				{Name: "Host", Value: "api.example.com"},
				{Name: "Authorization", Value: "Bearer eyJhbGciOi", Sensitive: true},
				{Name: "X-Api-Key", Value: "k-123"},
			}},
			Body: Body{ContentType: "application/x-www-form-urlencoded", PreviewEncoding: "utf-8", Preview: "username=tv&password=hunter2&remember=1"},
		},
		Response: &Response{
			StatusCode: 200,
			Headers:    Headers{Items: []Header{{Name: "Set-Cookie", Value: "sid=s3cret; HttpOnly"}, {Name: "Content-Type", Value: "application/json"}}},
			Body:       Body{ContentType: "application/json", PreviewEncoding: "utf-8", Preview: `{"ok":true,"token":"t-\"9","user":{"name":"tv","Password":"x"}}`},
		},
	}}
	redacted := RedactExchanges(exchanges)
	request, response := redacted[0].Request, redacted[0].Response
	if request.Target != "/login?user=tv&access_token=%5Bredacted%5D&lang=en" {
		t.Fatalf("target = %q", request.Target)
	}
	for _, header := range append(request.Headers.Items, response.Headers.Items...) {
		secret := header.Name == "Authorization" || header.Name == "X-Api-Key" || header.Name == "Set-Cookie"
		if secret != (header.Value == Redacted) || secret && !header.Sensitive {
			t.Fatalf("header %#v", header)
		}
	}
	if request.Body.Preview != "username=tv&password=%5Bredacted%5D&remember=1" {
		t.Fatalf("form body = %q", request.Body.Preview)
	}
	if strings.Contains(response.Body.Preview, "t-") || strings.Contains(response.Body.Preview, `"x"`) || !strings.Contains(response.Body.Preview, `"name":"tv"`) {
		t.Fatalf("JSON body = %q", response.Body.Preview)
	}
	// The original stays intact for the administrator's own view.
	if exchanges[0].Request.Headers.Items[1].Value != "Bearer eyJhbGciOi" || !strings.Contains(exchanges[0].Request.Body.Preview, "hunter2") {
		t.Fatal("redaction changed the caller's exchanges")
	}
}

func TestRedactLeavesBinaryPreviewsAndPlainTargetsAlone(t *testing.T) {
	exchanges := []Exchange{{Request: &Request{Target: "/index.html", Body: Body{ContentType: "application/x-www-form-urlencoded", PreviewEncoding: "hex", Preview: "70617373776f72643d31"}}}}
	redacted := RedactExchanges(exchanges)
	if redacted[0].Request.Target != "/index.html" || redacted[0].Request.Body.Preview != "70617373776f72643d31" || redacted[0].Response != nil {
		t.Fatalf("redacted = %#v", redacted[0].Request)
	}
}
