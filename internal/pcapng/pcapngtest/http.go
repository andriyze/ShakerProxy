package pcapngtest

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"time"
)

// KeepAliveHTTP is an HTTP/1.1 keep-alive connection with two exchanges:
// GET /api/status answered with a chunked, gzip-compressed JSON body, then
// POST /upload (a form) answered with a PNG. The first request is split in
// two segments that arrive out of order, and the first segment is then
// retransmitted. Client and Server are the reassembled streams the packets
// must produce.
type KeepAliveHTTP struct {
	Packets []Packet
	Client  []byte
	Server  []byte
	JSON    string
	PNG     []byte
}

func NewKeepAliveHTTP(start time.Time) KeepAliveHTTP {
	const clientISN, serverISN = uint32(1000), uint32(5000)
	json := `{"status":"ok","note":"<script>alert(1)</script>"}`
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write([]byte(json))
	_ = writer.Close()
	half := compressed.Len() / 2
	chunked := fmt.Sprintf("%x\r\n", half) + compressed.String()[:half] + "\r\n" + fmt.Sprintf("%x\r\n", compressed.Len()-half) + compressed.String()[half:] + "\r\n0\r\n\r\n"
	png := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, bytes.Repeat([]byte{0x00, 0xff}, 20)...)

	request1 := "GET /api/status?verbose=1 HTTP/1.1\r\nHost: device.example\r\nUser-Agent: test-phone\r\nCookie: session=secret\r\nAccept-Encoding: gzip\r\n\r\n"
	response1 := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked
	form := "name=phone&value=42"
	request2 := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: device.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(form), form)
	response2 := fmt.Sprintf("HTTP/1.1 201 Created\r\nContent-Type: image/png\r\nContent-Length: %d\r\n\r\n", len(png)) + string(png)

	at := func(milliseconds int) time.Time { return start.Add(time.Duration(milliseconds) * time.Millisecond) }
	split := 30
	clientSeq := clientISN + 1
	serverSeq := serverISN + 1
	packets := []Packet{
		{At: at(0), FromClient: true, Seq: clientISN, Flags: FlagSYN},
		{At: at(10), FromClient: false, Seq: serverISN, Ack: clientISN + 1, Flags: FlagSYN | FlagACK},
		{At: at(20), FromClient: true, Seq: clientSeq, Ack: serverSeq, Flags: FlagACK},
		// The second part of request 1 arrives first, then the first part,
		// which is also retransmitted.
		{At: at(30), FromClient: true, Seq: clientSeq + uint32(split), Ack: serverSeq, Flags: FlagACK | FlagPSH, Payload: []byte(request1[split:])},
		{At: at(31), FromClient: true, Seq: clientSeq, Ack: serverSeq, Flags: FlagACK, Payload: []byte(request1[:split])},
		{At: at(40), FromClient: true, Seq: clientSeq, Ack: serverSeq, Flags: FlagACK, Payload: []byte(request1[:split])},
		{At: at(60), FromClient: false, Seq: serverSeq, Ack: clientSeq + uint32(len(request1)), Flags: FlagACK | FlagPSH, Payload: []byte(response1)},
		{At: at(80), FromClient: true, Seq: clientSeq + uint32(len(request1)), Ack: serverSeq + uint32(len(response1)), Flags: FlagACK | FlagPSH, Payload: []byte(request2)},
		{At: at(100), FromClient: false, Seq: serverSeq + uint32(len(response1)), Ack: clientSeq + uint32(len(request1)+len(request2)), Flags: FlagACK | FlagPSH, Payload: []byte(response2)},
		{At: at(120), FromClient: true, Seq: clientSeq + uint32(len(request1)+len(request2)), Flags: FlagFIN | FlagACK},
	}
	return KeepAliveHTTP{Packets: packets, Client: []byte(request1 + request2), Server: []byte(response1 + response2), JSON: json, PNG: png}
}
