package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"shakerproxy.dev/shakerproxy/internal/cloudconnector"
)

func main() {
	flags := flag.NewFlagSet("shakerproxy-cloud", flag.ExitOnError)
	socket := flags.String("socket", envOr("SHAKERPROXY_CLOUD_CONNECTOR_SOCKET", "/run/shakerproxy-cloud/connector.sock"), "cloud connector local socket")
	_ = flags.Parse(os.Args[1:])
	args := flags.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	client := unixHTTPClient(*socket)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	var err error
	switch args[0] {
	case "status":
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		err = request(ctx, client, http.MethodGet, "http://localhost/v1/status", nil)
	case "enroll":
		err = enroll(ctx, client, args[1:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func enroll(ctx context.Context, client *http.Client, args []string) error {
	flags := flag.NewFlagSet("shakerproxy-cloud enroll", flag.ContinueOnError)
	cloudURL := flags.String("cloud", "", "ShakerProxy Cloud connector URL")
	token := flags.String("token", "", "single-use enrollment token")
	name := flags.String("name", "", "sensor name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("usage: shakerproxy-cloud enroll --cloud https://... --token TOKEN --name SENSOR")
	}
	if strings.TrimSpace(*cloudURL) == "" || strings.TrimSpace(*token) == "" || strings.TrimSpace(*name) == "" {
		return errors.New("cloud URL, enrollment token, and sensor name are required")
	}
	return request(ctx, client, http.MethodPost, "http://localhost/v1/enroll", cloudconnector.LocalEnrollmentRequest{CloudURL: *cloudURL, Token: *token, Name: *name})
}

func request(ctx context.Context, client *http.Client, method, endpoint string, body any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("contact local cloud connector: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("local cloud connector rejected request with HTTP %d", resp.StatusCode)
	}
	var value any
	if len(data) != 0 {
		if err := json.Unmarshal(data, &value); err != nil {
			return errors.New("local cloud connector returned invalid JSON")
		}
	}
	formatted, _ := json.MarshalIndent(value, "", "  ")
	fmt.Println(string(formatted))
	return nil
}

func unixHTTPClient(socket string) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: transport, Timeout: 35 * time.Second}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: shakerproxy-cloud status | enroll --cloud URL --token TOKEN --name SENSOR")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
