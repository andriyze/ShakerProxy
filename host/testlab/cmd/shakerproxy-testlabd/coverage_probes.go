package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

// runCoverageProbes runs inside a virtual client's namespace: one of each
// traffic type, then the outcomes as one JSON line on stdout.
func runCoverageProbes(planJSON string) int {
	var plan coverage.Plan
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil {
		fmt.Fprintln(os.Stderr, "invalid coverage plan:", err)
		return 2
	}
	outcomes := coverageProbes(plan)
	if err := json.NewEncoder(os.Stdout).Encode(outcomes); err != nil {
		return 1
	}
	return 0
}

type probeFunc func(coverage.Plan) (sent bool, detail string)

func coverageProbes(plan coverage.Plan) []coverage.ProbeOutcome {
	target := coverage.TargetIPv4
	at := func(port int) string { return net.JoinHostPort(target, strconv.Itoa(port)) }
	probes := map[string]probeFunc{
		coverage.ProbeDNSGateway: func(p coverage.Plan) (bool, string) {
			return udpExchange(net.JoinHostPort(coverage.GatewayIPv4, "53"), dnsQuery(p.DNSGatewayName, 1, 0x5301), true)
		},
		coverage.ProbeDNSDirect: func(p coverage.Plan) (bool, string) {
			return udpExchange(at(53), dnsQuery(p.DNSDirectName, 1, 0x5302), true)
		},
		coverage.ProbeDoT: func(p coverage.Plan) (bool, string) { return tlsHandshake(at(coverage.PortDoT), p.DoTServerName) },
		coverage.ProbeDoH: func(coverage.Plan) (bool, string) { return dohLookup(at(coverage.PortDoH)) },
		coverage.ProbeDoQ: func(p coverage.Plan) (bool, string) { return quicInitial(at(coverage.PortDoT), p.DoQServerName, "doq") },
		coverage.ProbeHTTP: func(p coverage.Plan) (bool, string) {
			client := http.Client{Timeout: 4 * time.Second}
			response, err := client.Get("http://" + at(coverage.PortHTTP) + p.HTTPPath)
			if err != nil {
				return false, err.Error()
			}
			response.Body.Close()
			return true, "HTTP " + strconv.Itoa(response.StatusCode)
		},
		coverage.ProbeHTTPS: func(p coverage.Plan) (bool, string) { return tlsHandshake(at(coverage.PortHTTPS), p.TLSServerName) },
		coverage.ProbeQUIC: func(p coverage.Plan) (bool, string) {
			return quicInitial(at(coverage.QUICPort), p.QUICServerName, "h3")
		},
		coverage.ProbeTCP: func(coverage.Plan) (bool, string) {
			connection, err := net.DialTimeout("tcp", at(coverage.PortTCPOdd), 3*time.Second)
			if err != nil {
				return false, err.Error()
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = connection.Write([]byte("shakerproxy coverage\n"))
			_, _ = bufio.NewReader(connection).ReadString('\n')
			return true, "connected"
		},
		coverage.ProbeUDP: func(coverage.Plan) (bool, string) {
			return udpExchange(at(coverage.PortUDPOdd), []byte("shakerproxy coverage"), true)
		},
		coverage.ProbeICMP: func(coverage.Plan) (bool, string) { return icmpEcho(target) },
		coverage.ProbeSSH: func(coverage.Plan) (bool, string) {
			connection, err := net.DialTimeout("tcp", at(coverage.PortSSH), 3*time.Second)
			if err != nil {
				return false, err.Error()
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
			banner, _ := bufio.NewReader(connection).ReadString('\n')
			_, _ = connection.Write([]byte("SSH-2.0-ShakerProxyCoverageClient_1.0\r\n"))
			time.Sleep(200 * time.Millisecond)
			return true, bound(banner, 128)
		},
		coverage.ProbeNTP: func(coverage.Plan) (bool, string) {
			request := make([]byte, 48)
			request[0] = 0x23 // version 4, mode 3 (client)
			binary.BigEndian.PutUint32(request[40:44], uint32(time.Now().Unix()+2208988800))
			return udpExchange(at(coverage.PortNTP), request, true)
		},
		coverage.ProbeMDNS: func(p coverage.Plan) (bool, string) {
			return udpExchange(net.JoinHostPort(coverage.MDNSGroup, strconv.Itoa(coverage.MDNSPort)), dnsQuery(p.MDNSService, 12, 0), false)
		},
		coverage.ProbeSSDP: func(coverage.Plan) (bool, string) {
			search := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
			return udpExchange(net.JoinHostPort(coverage.SSDPGroup, strconv.Itoa(coverage.SSDPPort)), []byte(search), false)
		},
	}
	outcomes := make([]coverage.ProbeOutcome, 0, len(coverage.Probes))
	for _, probe := range coverage.Probes {
		if probe.ID == coverage.ProbeIPv6 {
			outcomes = append(outcomes, coverage.ProbeOutcome{ID: probe.ID, Skipped: true,
				Detail: "The virtual test lab is IPv4-only, so IPv6 is not probed; the routing inspection checks whether IPv6 can bypass ShakerProxy."})
			continue
		}
		run, ok := probes[probe.ID]
		if !ok {
			outcomes = append(outcomes, coverage.ProbeOutcome{ID: probe.ID, Skipped: true, Detail: "No probe for this traffic type yet."})
			continue
		}
		sentAt := time.Now().UTC()
		sent, detail := run(plan)
		outcomes = append(outcomes, coverage.ProbeOutcome{ID: probe.ID, SentAt: sentAt, Sent: sent, Detail: bound(detail, 256)})
	}
	return outcomes
}

// dnsQuery builds one DNS question for name with type qtype (1 = A,
// 12 = PTR) and recursion desired.
func dnsQuery(name string, qtype uint16, id uint16) []byte {
	var message bytes.Buffer
	_ = binary.Write(&message, binary.BigEndian, [6]uint16{id, 0x0100, 1, 0, 0, 0})
	start := 0
	for index := 0; index <= len(name); index++ {
		if index == len(name) || name[index] == '.' {
			if label := name[start:index]; label != "" {
				message.WriteByte(byte(len(label)))
				message.WriteString(label)
			}
			start = index + 1
		}
	}
	message.WriteByte(0)
	_ = binary.Write(&message, binary.BigEndian, [2]uint16{qtype, 1})
	return message.Bytes()
}

// udpExchange sends one datagram and, when wait is set, waits briefly for
// an answer. Sending is what the analyzers need to see.
func udpExchange(address string, payload []byte, wait bool) (bool, string) {
	connection, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		return false, err.Error()
	}
	defer connection.Close()
	if _, err := connection.Write(payload); err != nil {
		return false, err.Error()
	}
	if !wait {
		time.Sleep(200 * time.Millisecond)
		return true, "sent"
	}
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := make([]byte, 1500)
	if _, err := connection.Read(reply); err != nil {
		return true, "sent; no answer"
	}
	return true, "answered"
}

// The probes talk only to the virtual target's self-signed endpoints inside
// the isolated test namespaces, so they skip certificate verification like
// the test lab's existing TLS probe; only the handshake itself matters.
func tlsHandshake(address, serverName string) (bool, string) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return false, err.Error()
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = bufio.NewReader(connection).ReadString('\n')
	return true, "handshake completed"
}

func dohLookup(address string) (bool, string) {
	client := http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: coverage.DoHResolverSNI, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}}
	response, err := client.Post("https://"+address+"/dns-query", "application/dns-message", bytes.NewReader(dnsQuery("example.com", 1, 0)))
	if err != nil {
		return false, err.Error()
	}
	response.Body.Close()
	return true, "DoH " + strconv.Itoa(response.StatusCode)
}

// icmpEcho sends two echo requests over an unprivileged ICMP datagram
// socket; setupCoverage allows those in the client's namespace, so the
// service needs no raw-socket capability.
func icmpEcho(target string) (bool, string) {
	connection, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false, err.Error()
	}
	defer connection.Close()
	destination := &net.UDPAddr{IP: net.ParseIP(target)}
	answered := 0
	for sequence := 1; sequence <= 2; sequence++ {
		message := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: sequence, Data: []byte("shakerproxy coverage")}}
		packet, err := message.Marshal(nil)
		if err != nil {
			return false, err.Error()
		}
		if _, err := connection.WriteTo(packet, destination); err != nil {
			return false, err.Error()
		}
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		reply := make([]byte, 1500)
		if _, _, err := connection.ReadFrom(reply); err == nil {
			answered++
		}
	}
	return true, fmt.Sprintf("2 echo requests, %d answered", answered)
}

func quicInitial(address, serverName, alpn string) (bool, string) {
	packet, err := coverage.BuildQUICInitial(serverName, alpn)
	if err != nil {
		return false, err.Error()
	}
	destination, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return false, err.Error()
	}
	// Unconnected, so the target's ICMP port-unreachable for the first
	// datagram cannot fail the retransmission.
	connection, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return false, err.Error()
	}
	defer connection.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := connection.WriteTo(packet, destination); err != nil {
			return false, err.Error()
		}
		time.Sleep(150 * time.Millisecond)
	}
	return true, "QUIC Initial sent"
}
