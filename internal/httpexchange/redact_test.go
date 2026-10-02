package httpexchange

import (
	"net/url"
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

func TestRedactWithholdsBinaryPreviewsAndLeavesPlainTargetsAlone(t *testing.T) {
	// The hex preview spells "password=1".
	exchanges := []Exchange{{Request: &Request{Target: "/index.html", Body: Body{ContentType: "application/x-www-form-urlencoded", BodyBytes: 10, PreviewEncoding: "hex", PreviewBytes: 10, Preview: "70617373776f72643d31"}}}}
	redacted := RedactExchanges(exchanges)
	body := redacted[0].Request.Body
	if redacted[0].Request.Target != "/index.html" || body.Preview != "" || body.PreviewBytes != 0 || body.BodyBytes != 10 || body.Note == "" || redacted[0].Response != nil {
		t.Fatalf("redacted = %#v", redacted[0].Request)
	}
	if exchanges[0].Request.Body.Preview != "70617373776f72643d31" {
		t.Fatal("redaction changed the caller's exchange")
	}
}

func TestRedactFindsCredentialsWhateverTheBodyLooksLike(t *testing.T) {
	cases := []struct{ name, contentType, preview, secret string }{
		{"multipart", "multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--x--", "hunter2"},
		{"xml", "application/xml", "<login><user>a</user><password>hunter2</password></login>", "hunter2"},
		{"json number", "application/json", `{"user":"a","pin":1234}`, "1234"},
		{"mislabelled form", "text/plain", "user=a&password=hunter2", "hunter2"},
		{"json as text", "text/plain", `{"access_token":"eyJhbGciOi"}`, "eyJhbGciOi"},
	}
	for _, test := range cases {
		redacted := RedactExchanges([]Exchange{{Request: &Request{Target: "/", Body: Body{ContentType: test.contentType, Preview: test.preview}}}})
		preview := redacted[0].Request.Body.Preview
		if strings.Contains(preview, test.secret) || !strings.Contains(preview, Redacted) && !strings.Contains(preview, url.QueryEscape(Redacted)) {
			t.Errorf("%s: %q", test.name, preview)
		}
	}
	if got := RedactExchanges([]Exchange{{Request: &Request{Target: "/", Headers: Headers{Items: []Header{{Name: "X-CSRF-Token", Value: "abc"}}}}}}); got[0].Request.Headers.Items[0].Value != Redacted {
		t.Fatalf("X-CSRF-Token = %q", got[0].Request.Headers.Items[0].Value)
	}
}
