package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

func handleHelperMode() bool {
	if len(os.Args) <= 1 {
		return false
	}
	switch os.Args[1] {
	case "--target-server":
		targetServer()
		return true
	case "--probe-dns":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		if err := probeDNS(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("dns response received")
		return true
	case "--probe-tls":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		if err := probeTLS(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("tls handshake completed")
		return true
	default:
		return false
	}
}

func targetServer() {
	certificate, err := selfSignedCertificate()
	if err != nil {
		os.Exit(1)
	}
	go serveHTTP()
	go serveTLS(certificate, ":8443")
	go serveTLS(certificate, ":853")
	go serveDNS()
	select {}
}

func serveHTTP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		_, _ = w.Write([]byte(host + "\n"))
	})
	_ = http.ListenAndServe(":8080", mux)
}

func serveTLS(certificate tls.Certificate, address string) {
	listener, err := tls.Listen("tcp", address, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_, _ = conn.Write([]byte("shakerproxy-testlab\n"))
		}(connection)
	}
}

func serveDNS() {
	connection, err := net.ListenPacket("udp", ":53")
	if err != nil {
		return
	}
	defer connection.Close()
	buffer := make([]byte, 512)
	for {
		n, address, err := connection.ReadFrom(buffer)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		response := append([]byte(nil), buffer[:n]...)
		response[2] |= 0x80
		response[3] |= 0x80
		_, _ = connection.WriteTo(response, address)
	}
}

func probeDNS(address string) error {
	connection, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	query := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 'l', 'a', 'b', 'g', 'a', 't', 'e',
		0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	if _, err = connection.Write(query); err != nil {
		return err
	}
	buffer := make([]byte, 512)
	n, err := connection.Read(buffer)
	if err != nil {
		return err
	}
	if n < 12 || buffer[2]&0x80 == 0 {
		return errors.New("invalid DNS response")
	}
	return nil
}

func probeTLS(address string) error {
	connection, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		address,
		&tls.Config{
			InsecureSkipVerify: true, // deterministic self-signed test target only
			MinVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	return nil
}

func selfSignedCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "shakerproxy-test-target"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(targetIPv4)},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certificatePEM, privateKeyPEM)
}
