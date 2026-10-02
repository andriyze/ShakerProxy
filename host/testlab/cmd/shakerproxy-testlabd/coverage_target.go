package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"shakerproxy.dev/shakerproxy/internal/coverage"
)

// Endpoints the virtual target adds for the visibility coverage probes. Each
// answers just enough for the analyzers to recognise the protocol.

func serveCoverageEndpoints(certificate tls.Certificate) {
	go serveSSHBanner(":" + strconv.Itoa(coverage.PortSSH))
	go serveNTP(":" + strconv.Itoa(coverage.PortNTP))
	go serveTCPEcho(":" + strconv.Itoa(coverage.PortTCPOdd))
	go serveUDPEcho(":" + strconv.Itoa(coverage.PortUDPOdd))
	go serveDoH(certificate, ":"+strconv.Itoa(coverage.PortDoH))
}

func serveSSHBanner(address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		listenFailed(address, err)
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte("SSH-2.0-ShakerProxyCoverage_1.0\r\n"))
			_, _ = bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
		}(connection)
	}
}

func serveNTP(address string) {
	connection, err := net.ListenPacket("udp", address)
	if err != nil {
		listenFailed(address, err)
	}
	defer connection.Close()
	buffer := make([]byte, 128)
	for {
		n, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		if n < 48 {
			continue
		}
		response := make([]byte, 48)
		response[0] = 0x24 // no leap warning, version 4, mode 4 (server)
		response[1] = 2    // stratum
		copy(response[24:32], buffer[40:48])
		_, _ = connection.WriteTo(response, peer)
	}
}

func serveTCPEcho(address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		listenFailed(address, err)
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.Copy(conn, io.LimitReader(conn, 4096))
		}(connection)
	}
}

func serveUDPEcho(address string) {
	connection, err := net.ListenPacket("udp", address)
	if err != nil {
		listenFailed(address, err)
	}
	defer connection.Close()
	buffer := make([]byte, 2048)
	for {
		n, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		_, _ = connection.WriteTo(buffer[:n], peer)
	}
}

// serveDoH answers DNS over HTTPS with an empty response to the query.
func serveDoH(certificate tls.Certificate, address string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		query, err := io.ReadAll(io.LimitReader(r.Body, 512))
		if err != nil || len(query) < 12 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		query[2] |= 0x80
		query[3] |= 0x80
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(query)
	})
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 3 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}}
	_ = server.ListenAndServeTLS("", "")
}

// listenFailed stops the target: a target missing an endpoint makes its probe
// fail for a reason the coverage report could not name.
func listenFailed(address string, err error) {
	fmt.Fprintf(os.Stderr, "virtual target cannot listen on %s: %v\n", address, err)
	os.Exit(3)
}
