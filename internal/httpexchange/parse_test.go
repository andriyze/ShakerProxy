package httpexchange

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
	"time"

	"shakerproxy.dev/shakerproxy/internal/pcapng/pcapngtest"
)

func TestKeepAliveExchangesWithChunkedGzipAndBinaryBodies(t *testing.T) {
	conversation := pcapngtest.NewKeepAliveHTTP(time.Date(2026, 10, 2, 3, 30, 0, 0, time.UTC))
	result := Parse(conversation.Client, conversation.Server)
	if len(result.Exchanges) != 2 || len(result.Notes) != 0 {
		t.Fatalf("exchanges = %d notes = %v", len(result.Exchanges), result.Notes)
	}
	first := result.Exchanges[0]
	if first.Request.Method != "GET" || first.Request.Target != "/api/status?verbose=1" || first.Request.Proto != "HTTP/1.1" {
		t.Fatalf("first request = %+v", first.Request)
	}
	names := []string{}
	for _, header := range first.Request.Headers.Items {
		names = append(names, header.Name)
		if header.Name == "Cookie" && !header.Sensitive {
			t.Fatal("the Cookie header was not marked sensitive")
		}
	}
	if strings.Join(names, ",") != "Host,User-Agent,Cookie,Accept-Encoding" {
		t.Fatalf("headers lost their order: %v", names)
	}
	body := first.Response.Body
	if first.Response.StatusCode != 200 || first.Response.Status != "OK" || !body.DecodedPreview || body.PreviewEncoding != "utf-8" || body.Preview != conversation.JSON || !body.Complete || body.Truncated {
		t.Fatalf("chunked gzip JSON body = %+v", body)
	}
	second := result.Exchanges[1]
	if second.Request.Method != "POST" || second.Request.Body.Preview != "name=phone&value=42" {
		t.Fatalf("form request = %+v", second.Request)
	}
	png := second.Response.Body
	if second.Response.StatusCode != 201 || png.PreviewEncoding != "hex" || png.BodyBytes != int64(len(conversation.PNG)) || !strings.HasPrefix(png.Preview, "00000000  89 50 4e 47 0d 0a 1a 0a") || !strings.Contains(png.Preview, "|.PNG....") {
		t.Fatalf("binary body = %+v", png)
	}
}

func TestMidStreamRecordingsHeadAnd100ContinueAreHandled(t *testing.T) {
	client := "ers: tail of an earlier request\r\n\r\nHEAD /index.html HTTP/1.1\r\nHost: a\r\n\r\nPOST /x HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi"
	server := "earlier body bytes" +
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5000\r\n\r\n" + // HEAD: no body follows
		"HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 204 No Content\r\n\r\n"
	result := Parse([]byte(client), []byte(server))
	if result.SkippedClientBytes == 0 || result.SkippedServerBytes != len("earlier body bytes") || len(result.Exchanges) != 2 {
		t.Fatalf("mid-stream parse = %+v", result)
	}
	if result.Exchanges[0].Request.Method != "HEAD" || result.Exchanges[0].Response.Body.BodyBytes != 0 || result.Exchanges[1].Response.StatusCode != 204 {
		t.Fatalf("HEAD and 100-continue were mispaired: %+v", result.Exchanges)
	}
	if len(result.Notes) == 0 || !strings.Contains(result.Notes[0], "middle of this connection") {
		t.Fatalf("notes = %v", result.Notes)
	}
}

// The test VM's GrapheneOS connectivity check, recorded headers-only: the
// snap length cut the 210-byte request 20 bytes short.
func TestARequestCutInsideItsHeadersShowsWhatWasRecorded(t *testing.T) {
	client := "GET /generate_204 HTTP/1.1\r\nUser-Agent: GrapheneOS\r\nHost: connectivitycheck.grapheneos.network\r\nConnection: Keep-Al"
	server := "HTTP/1.1 204 No Content\r\nServer: nginx\r\nConnection: close\r\n\r\n"
	result := Parse([]byte(client), []byte(server))
	if len(result.Exchanges) != 1 || result.Exchanges[0].Request == nil || result.Exchanges[0].Response == nil {
		t.Fatalf("cut request = %+v", result)
	}
	request := result.Exchanges[0].Request
	if request.Method != "GET" || request.Target != "/generate_204" || len(request.Headers.Items) != 2 || request.Headers.Items[1].Value != "connectivitycheck.grapheneos.network" || request.Body.Complete {
		t.Fatalf("partial request = %+v", request)
	}
	if result.Exchanges[0].Response.StatusCode != 204 {
		t.Fatalf("response = %+v", result.Exchanges[0].Response)
	}
	if got := Parse([]byte("GET /x HTT"), nil); len(got.Exchanges) != 0 {
		t.Fatalf("a request cut inside its first line was shown: %+v", got)
	}
}

func TestBodiesTheRecordingCutShortAreMarkedIncomplete(t *testing.T) {
	server := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\nonly part"
	result := Parse([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), []byte(server))
	body := result.Exchanges[0].Response.Body
	if body.Complete || body.Preview != "only part" || body.Note == "" {
		t.Fatalf("cut body = %+v", body)
	}
}

func TestDecompressionIsBoundedAndUnknownEncodingsAreShownRaw(t *testing.T) {
	var bomb bytes.Buffer
	writer := gzip.NewWriter(&bomb)
	_, _ = writer.Write(bytes.Repeat([]byte("a"), 50<<20))
	_ = writer.Close()
	server := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", bomb.Len()) + bomb.String()
	started := time.Now()
	result := Parse([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), []byte(server))
	body := result.Exchanges[0].Response.Body
	if len(body.Preview) != MaxBodyPreviewBytes || !body.Truncated || !body.DecodedPreview || time.Since(started) > 5*time.Second {
		t.Fatalf("gzip bomb preview = %d bytes truncated=%v", len(body.Preview), body.Truncated)
	}
	brotli := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: br\r\nContent-Length: 4\r\n\r\n\x0b\x02\x80a"
	body = Parse([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), []byte(brotli)).Exchanges[0].Response.Body
	if body.PreviewEncoding != "hex" || body.DecodedPreview || !strings.Contains(body.Note, "br-encoded") {
		t.Fatalf("brotli body = %+v", body)
	}
}

func TestHeadersAndNonHTTPStreamsAreBounded(t *testing.T) {
	long := strings.Repeat("v", MaxHeaderValueBytes+10)
	result := Parse([]byte("GET / HTTP/1.1\r\nHost: a\r\nX-Long: "+long+"\r\n\r\n"), nil)
	header := result.Exchanges[0].Request.Headers.Items[1]
	if len(header.Value) != MaxHeaderValueBytes || !header.Truncated {
		t.Fatalf("long header = %d bytes truncated=%v", len(header.Value), header.Truncated)
	}
	if got := Parse([]byte("\x16\x03\x01 TLS bytes"), []byte("\x16\x03\x03 more")); len(got.Exchanges) != 0 {
		t.Fatalf("TLS bytes were read as HTTP: %+v", got)
	}
}

func FuzzParseNeverPanics(f *testing.F) {
	conversation := pcapngtest.NewKeepAliveHTTP(time.Unix(0, 0))
	f.Add(conversation.Client, conversation.Server)
	f.Fuzz(func(t *testing.T, client, server []byte) {
		_ = Parse(client, server)
	})
}
