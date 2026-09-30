package testlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func (c Client) Status(ctx context.Context) (Status, error) {
	var response Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &response); err != nil {
		return Status{}, err
	}
	return response, nil
}

func (c Client) Run(ctx context.Context, profile Profile) (Run, error) {
	if !ValidProfile(profile) {
		return Run{}, errors.New("invalid test-lab profile")
	}
	var response Run
	if err := c.do(ctx, http.MethodPost, "/v1/run", RunRequest{Profile: profile}, &response); err != nil {
		return Run{}, err
	}
	return response, nil
}

func (c Client) Cleanup(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/cleanup", map[string]any{}, nil)
}

func (c Client) do(ctx context.Context, method, path string, body any, output any) error {
	socketPath := c.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultRunTimeout + 10*time.Second
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if len(encoded) > 8<<10 {
			return errors.New("test-lab request is too large")
		}
		payload = bytes.NewReader(encoded)
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, Timeout: timeout}
	request, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, payload)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("test-lab service unavailable: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, 1<<20)
	if response.StatusCode < 200 || response.StatusCode > 299 {
		message, _ := io.ReadAll(io.LimitReader(limited, 4096))
		return fmt.Errorf("test-lab service returned %d: %s", response.StatusCode, string(message))
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, limited)
		return nil
	}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode test-lab response: %w", err)
	}
	return nil
}
