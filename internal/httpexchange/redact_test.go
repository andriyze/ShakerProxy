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

func TestRedactCoversEveryCredentialFieldInEveryShape(t *testing.T) {
	// One list drives every matcher: a name the query redactor knows must
	// also be found in JSON, multipart and XML bodies.
	const secret = "S3cretValue"
	for _, field := range credentialFields {
		shapes := map[string]Body{
			"json":      {ContentType: "application/json", Preview: `{"` + field + `":"` + secret + `"}`},
			"multipart": {ContentType: "multipart/form-data; boundary=x", Preview: "--x\r\nContent-Disposition: form-data; name=\"" + field + "\"\r\n\r\n" + secret + "\r\n--x--"},
			"form":      {ContentType: "application/x-www-form-urlencoded", Preview: "a=1&" + field + "=" + secret},
		}
		if !markupNames[field] {
			shapes["xml"] = Body{ContentType: "application/xml", Preview: "<r><" + field + ">" + secret + "</" + field + "></r>"}
		}
		for shape, body := range shapes {
			redacted := RedactExchanges([]Exchange{{Request: &Request{Target: "/", Body: body}}})
			if strings.Contains(redacted[0].Request.Body.Preview, secret) {
				t.Errorf("%s in %s: %q", field, shape, redacted[0].Request.Body.Preview)
			}
		}
		target := RedactExchanges([]Exchange{{Request: &Request{Target: "/x?" + field + "=" + secret}}})[0].Request.Target
		if strings.Contains(target, secret) {
			t.Errorf("%s in the query: %q", field, target)
		}
	}
}

func TestRedactClosesBodyAndQueryGaps(t *testing.T) {
	cases := []struct{ name, contentType, preview, secret, keep string }{
		{"json key", "application/json", `{"key":"k-9f2c41d07e5b","region":"us-east-1"}`, "k-9f2c41d07e5b", "us-east-1"},
		{"json sig and code", "application/json", `{"sig":"abc1","code":"493021"}`, "493021", ""},
		{"camelCase", "application/json", `{"accessToken":"eyJhbGciOi","refresh-token":"r-1"}`, "eyJhbGciOi", ""},
		{"nested object", "application/json", `{"token":{"jwt":"eyJhbGciOi","exp":5},"user":"tv"}`, "eyJhbGciOi", `"user":"tv"`},
		{"nested array", "application/json", `{"credentials":1,"secret":["a-1",{"b":"]x"}],"ok":true}`, "a-1", `"ok":true`},
		{"cut-off container", "application/json", `{"token":{"jwt":"eyJhbGciOi`, "eyJhbGciOi", ""},
		{"mislabelled form with spaces", "text/plain", "user=tv&password=hunter 2\n", "hunter 2", "user=tv"},
		{"form over lines", "text/plain", "user=tv\npassword=hunter2\n", "hunter2", "user=tv"},
		{"nested form name", "application/x-www-form-urlencoded", "user%5Bemail%5D=a&user%5Bpassword%5D=hunter2", "hunter2", "user%5Bemail%5D=a"},
		{"semicolon form", "application/x-www-form-urlencoded", "user=tv;password=hunter2", "hunter2", "user=tv"},
		{"url inside json", "application/json", `{"next":"/cb?code=493021&state=x"}`, "493021", "state=x"},
		{"plist", "application/xml", "<dict><key>password</key><string>hunter2</string><key>name</key><string>tv</string></dict>", "hunter2", "<string>tv</string>"},
	}
	for _, test := range cases {
		redacted := RedactExchanges([]Exchange{{Request: &Request{Target: "/", Body: Body{ContentType: test.contentType, Preview: test.preview}}}})
		preview := redacted[0].Request.Body.Preview
		if strings.Contains(preview, test.secret) || !strings.Contains(preview, test.keep) {
			t.Errorf("%s: %q", test.name, preview)
		}
	}
	if target := redactTarget("/cb?user=tv;code=493021;state=x"); target != "/cb?user=tv;code=%5Bredacted%5D;state=x" {
		t.Errorf("semicolon query = %q", target)
	}
	// Everyday markup named like a credential holds no secret.
	html := RedactExchanges([]Exchange{{Response: &Response{Body: Body{ContentType: "text/html", Preview: "<p>Run <code>make</code></p><key>name</key>"}}}})
	if preview := html[0].Response.Body.Preview; !strings.Contains(preview, "<code>make</code>") || !strings.Contains(preview, "<key>name</key>") {
		t.Errorf("markup = %q", preview)
	}
}
