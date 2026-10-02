package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func freeAddress(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		connection, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		return connection.LocalAddr().String()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func TestDNSQueryEncodesTheProbeName(t *testing.T) {
	query := dnsQuery("gw-ab12.coverage.shakerproxy.test", 1, 0x5301)
	want := []byte{0x53, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'g', 'w', '-', 'a', 'b', '1', '2'}
	if !bytes.HasPrefix(query, want) || !bytes.HasSuffix(query, []byte{4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}) {
		t.Fatalf("query = %x", query)
	}
}

func TestCoverageTargetEndpointsAnswerTheProbes(t *testing.T) {
	ntp, echo, ssh := freeAddress(t, "udp"), freeAddress(t, "udp"), freeAddress(t, "tcp")
	go serveNTP(ntp)
	go serveUDPEcho(echo)
	go serveSSHBanner(ssh)
	time.Sleep(100 * time.Millisecond)
	request := make([]byte, 48)
	request[0] = 0x23
	if sent, detail := udpExchange(ntp, request, true); !sent || detail != "answered" {
		t.Fatalf("NTP: sent=%v %s", sent, detail)
	}
	if sent, detail := udpExchange(echo, []byte("coverage"), true); !sent || detail != "answered" {
		t.Fatalf("UDP echo: sent=%v %s", sent, detail)
	}
	connection, err := net.DialTimeout("tcp", ssh, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	banner := make([]byte, 64)
	n, _ := connection.Read(banner)
	if !strings.HasPrefix(string(banner[:n]), "SSH-2.0-") {
		t.Fatalf("SSH banner = %q", banner[:n])
	}
}
