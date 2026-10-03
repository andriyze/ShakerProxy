package httpexchange

import (
	"strings"
	"testing"
)

func header(name, value string) Header { return Header{Name: name, Value: value} }

func TestExposuresFindsCleartextSecretsByKindAndLocation(t *testing.T) {
	exchanges := []Exchange{
		{
			Request: &Request{
				Method:  "POST",
				Target:  "/login?api_key=abcd1234&page=2",
				Headers: Headers{Items: []Header{header("Authorization", "Basic dXNlcjpwYXNz"), header("Cookie", "session=deadbeef")}},
				Body:    Body{ContentType: "application/x-www-form-urlencoded", PreviewEncoding: "text", Preview: "user=alice&password=hunter2"},
			},
			Response: &Response{StatusCode: 200, Headers: Headers{Items: []Header{header("Set-Cookie", "session=deadbeef; HttpOnly")}}},
		},
	}
	got := Exposures(exchanges, true)
	want := map[ExposureKind]bool{ExposureBasicAuth: false, ExposureCleartextCookie: false, ExposureTokenInURL: false, ExposureFormPassword: false}
	for _, exposure := range got {
		if _, ok := want[exposure.Kind]; !ok {
			t.Fatalf("unexpected exposure kind %q", exposure.Kind)
		}
		want[exposure.Kind] = true
		if exposure.Where == "" {
			t.Fatalf("exposure %q has no location", exposure.Kind)
		}
	}
	for kind, found := range want {
		if !found {
			t.Fatalf("missing exposure kind %q in %+v", kind, got)
		}
	}
	// The secret values must never appear in the exposure report.
	for _, exposure := range got {
		for _, secret := range []string{"hunter2", "dXNlcjpwYXNz", "deadbeef", "abcd1234"} {
			if strings.Contains(exposure.Where, secret) {
				t.Fatalf("exposure %+v leaked a secret", exposure)
			}
		}
	}
}

func TestExposuresIgnoresEncryptedFlows(t *testing.T) {
	exchanges := []Exchange{{Request: &Request{Target: "/login?token=abc", Headers: Headers{Items: []Header{header("Authorization", "Bearer abc")}}}}}
	if got := Exposures(exchanges, false); got != nil {
		t.Fatalf("a decrypted/encrypted flow reported exposures: %+v", got)
	}
}

func TestExposuresIgnoresNonCredentialTraffic(t *testing.T) {
	exchanges := []Exchange{{
		Request: &Request{
			Target:  "/search?q=cats&page=2",
			Headers: Headers{Items: []Header{header("User-Agent", "curl/8"), header("Accept", "*/*")}},
			Body:    Body{ContentType: "application/x-www-form-urlencoded", PreviewEncoding: "text", Preview: "query=cats&count=10"},
		},
		Response: &Response{StatusCode: 200, Headers: Headers{Items: []Header{header("Content-Type", "text/html")}}},
	}}
	if got := Exposures(exchanges, true); len(got) != 0 {
		t.Fatalf("non-credential traffic reported exposures: %+v", got)
	}
}

func TestExposuresFindsSecretsInOtherBodyTypes(t *testing.T) {
	cases := []struct {
		name, contentType, preview string
	}{
		{"json", "application/json", `{"user":"a","password":"hunter2"}`},
		{"json number", "application/json", `{"pin":1234}`},
		{"multipart", "multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--x--"},
		{"xml", "application/xml", "<login><password>hunter2</password></login>"},
		{"json mislabelled text", "text/plain", `{"access_token":"xyz"}`},
	}
	for _, test := range cases {
		got := Exposures([]Exchange{{Request: &Request{Target: "/", Body: Body{ContentType: test.contentType, PreviewEncoding: "text", Preview: test.preview}}}}, true)
		found := false
		for _, exposure := range got {
			if exposure.Kind == ExposureFormPassword {
				found = true
			}
			if strings.Contains(exposure.Where, "hunter2") || strings.Contains(exposure.Where, "xyz") {
				t.Fatalf("%s leaked a secret: %+v", test.name, exposure)
			}
		}
		if !found {
			t.Errorf("%s: no form-password exposure in %+v", test.name, got)
		}
	}
}

func TestExposuresDoesNotScanBinaryBodies(t *testing.T) {
	// A hex preview that decodes to "password=1" must not be scanned.
	got := Exposures([]Exchange{{Request: &Request{Target: "/", Body: Body{ContentType: "application/x-www-form-urlencoded", PreviewEncoding: "hex", Preview: "70617373776f72643d31"}}}}, true)
	if len(got) != 0 {
		t.Fatalf("a binary body was scanned: %+v", got)
	}
}

func TestExposuresDeduplicates(t *testing.T) {
	request := &Request{Target: "/?token=a", Headers: Headers{Items: []Header{header("Cookie", "s=1")}}}
	got := Exposures([]Exchange{{Request: request}, {Request: request}}, true)
	if len(got) != 2 {
		t.Fatalf("expected one token-in-url and one cookie exposure, got %+v", got)
	}
}

func TestExposuresToleratesGarbledInput(t *testing.T) {
	big := strings.Repeat("password=", 100000)
	_ = Exposures([]Exchange{
		{Request: &Request{Target: "/?" + big, Body: Body{ContentType: "application/json", PreviewEncoding: "text", Preview: strings.Repeat("{", 50000)}}},
		{Request: nil, Response: nil},
	}, true)
}

func TestURLCredentialParamsNamesOnly(t *testing.T) {
	names := URLCredentialParams("/a?api_key=secret&q=1&password=p")
	if len(names) != 2 {
		t.Fatalf("names = %v", names)
	}
	for _, name := range names {
		if name != "api_key" && name != "password" {
			t.Fatalf("unexpected %q", name)
		}
		if strings.Contains(name, "secret") || strings.Contains(name, "=p") {
			t.Fatalf("name %q carried a value", name)
		}
	}
	if URLCredentialParams("/a") != nil || URLCredentialParams("/a?q") != nil {
		t.Fatal("no-credential targets reported params")
	}
}
